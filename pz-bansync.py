#!/usr/bin/env python3
"""
pz-bansync —— PZ 服务器封禁列表与 banserver API 双向同步
在 PZ 服务器本机运行
"""
import json
import logging
import socket
import sqlite3
import ssl
import struct
import sys
import time
import urllib.request
from pathlib import Path

# ==================== 配置区 ====================
API_BASE     = "https://banserver.zuckertech.cn:8088/"   # ban联服器 API 地址
API_USERNAME = "your_api_username"                       # ban联服器 API 用户名
API_PASSWORD = "your_api_password"                       # ban联服器 API 密码

RCON_HOST = "127.0.0.1"
RCON_PORT = 27015
RCON_PASS = "your_rcon_password"                      # RCON 密码

PZ_DB = "your_pz_server Server.db"                    # PZ 服务器数据库路径

SYNC_INTERVAL = 300                                   # 同步间隔（秒）
LOG_FILE = Path("your_log_file.log")

# ============ 同步模式 ============
#   "full"     —— 完全同步（默认）：
#                 banserver 新增 → PZ 加封禁
#                 banserver 移除 → PZ 解封
#                 结果：两边完全一致
#
#   "add_only" —— 只增不减：
#                 只把 banserver 的新封禁加到 PZ
#                 不处理 PZ 里"banserver 已经没有"的记录
#                 结果：PZ 的封禁列表只会增加，不会减少
#
# 建议：首次接入用 "add_only" 观察一段时间，确认无误后再改成 "full"
SYNC_MODE = "full"
# ==================================================

log = logging.getLogger("pz-bansync")


# ---------------- RCON（Source RCON 协议 + 响应排空） ----------------
class RconClient:
    SERVERDATA_AUTH            = 3
    SERVERDATA_AUTH_RESPONSE   = 2
    SERVERDATA_EXECCOMMAND     = 2
    SERVERDATA_RESPONSE_VALUE  = 0

    def __init__(self, host, port, password):
        self.host, self.port, self.password = host, port, password
        self.sock = None
        self.req_id = 0

    def _next_id(self):
        self.req_id += 1
        return self.req_id

    def _send(self, pkt_id, pkt_type, body):
        body_b = body.encode("utf-8")
        payload = struct.pack("<ii", pkt_id, pkt_type) + body_b + b"\x00\x00"
        self.sock.sendall(struct.pack("<i", len(payload)) + payload)

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("RCON 连接被关闭")
            buf += chunk
        return buf

    def _recv_packet(self):
        ln = struct.unpack("<i", self._recv_exact(4))[0]
        data = self._recv_exact(ln)
        pid, ptype = struct.unpack("<ii", data[:8])
        body = data[8:-2].decode("utf-8", errors="replace")
        return pid, ptype, body

    def _drain(self, timeout=0.3):
        """清空 socket 里所有待读数据，避免上一条命令的残留污染下一条"""
        self.sock.settimeout(timeout)
        try:
            while True:
                try:
                    d = self.sock.recv(8192)
                    if not d:
                        break
                except socket.timeout:
                    break
        finally:
            self.sock.settimeout(5)

    def connect(self):
        self.sock = socket.create_connection((self.host, self.port), timeout=10)
        pkt_id = self._next_id()
        self._send(pkt_id, self.SERVERDATA_AUTH, self.password)
        pid, ptype, body = self._recv_packet()
        if pid == -1:
            raise PermissionError("RCON 认证失败")
        self._drain(0.3)

    def command(self, cmd):
        self._drain(0.3)
        pkt_id = self._next_id()
        self._send(pkt_id, self.SERVERDATA_EXECCOMMAND, cmd)

        responses = []
        self.sock.settimeout(5)
        try:
            _, _, body = self._recv_packet()
            responses.append(body)
        except socket.timeout:
            return ""
        finally:
            self.sock.settimeout(5)

        self.sock.settimeout(0.5)
        try:
            while True:
                try:
                    _, _, body = self._recv_packet()
                    responses.append(body)
                except socket.timeout:
                    break
        except Exception:
            pass
        finally:
            self.sock.settimeout(5)

        return "\n".join(responses)

    def close(self):
        if self.sock:
            try: self.sock.close()
            except Exception: pass


# ---------------- HTTP ----------------
def _post_json(url, data, timeout=15):
    body = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json"},
        method="POST")
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _get_json(url, headers=None, timeout=20):
    req = urllib.request.Request(url, headers=headers or {})
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def api_login():
    return _post_json(
        f"{API_BASE}/api/auth/login",
        {"identifier": API_USERNAME, "password": API_PASSWORD},
    )["access_token"]


def api_fetch_active_bans(token):
    r = _get_json(
        f"{API_BASE}/api/external/bans?offset=0&limit=100000",
        headers={"Authorization": f"Bearer {token}"})
    out = {}
    for b in r.get("data", []):
        sid = (b.get("steam_id") or "").strip()
        if sid:
            out[sid] = b.get("reason") or ""
    return out


# ---------------- PZ 数据库 ----------------
def pz_read_banned_ids(db_path):
    p = Path(db_path)
    if not p.exists():
        log.warning(f"PZ 数据库不存在: {db_path}")
        return None
    try:
        conn = sqlite3.connect(f"file:{p}?mode=ro&immutable=1", uri=True, timeout=5)
        try:
            cur = conn.cursor()
            cur.execute("SELECT steamid FROM bannedid")
            return {str(r[0]).strip() for r in cur.fetchall() if r and r[0]}
        finally:
            conn.close()
    except Exception as e:
        log.warning(f"读 PZ 数据库失败: {e}")
        return None


def pz_update_reason(db_path, steam_id, reason):
    """RCON banid 执行后，把 reason 补写到数据库（可选）"""
    if not reason:
        return
    try:
        conn = sqlite3.connect(db_path, timeout=10)
        try:
            cur = conn.cursor()
            cur.execute("UPDATE bannedid SET reason = ? WHERE steamid = ?", (reason, steam_id))
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        log.warning(f"写 reason 失败 ({steam_id}): {e}")


# ---------------- 同步 ----------------
def sync_once(rcon, token):
    log.info("-" * 50)

    api_bans = api_fetch_active_bans(token)
    api_set = set(api_bans.keys())
    log.info(f"API active bans: {len(api_set)}")

    pz_set = pz_read_banned_ids(PZ_DB)
    if pz_set is None:
        log.error("读 PZ 数据库失败，跳过本轮")
        return
    log.info(f"PZ current bans: {len(pz_set)}")

    to_ban = api_set - pz_set
    to_unban = pz_set - api_set

    # ============ 关键：根据模式决定是否处理 to_unban ============
    if SYNC_MODE == "add_only":
        log.info(f"待新增: {len(to_ban)} | 待移除: {len(to_unban)}（add_only 模式，跳过移除）")
    else:
        log.info(f"待新增: {len(to_ban)} | 待移除: {len(to_unban)}")

    # 新增：两种模式都执行
    for sid in sorted(to_ban):
        try:
            resp = rcon.command(f"banid {sid}")
            log.info(f"[+] ban {sid} -> {resp.strip()!r}")
            pz_update_reason(PZ_DB, sid, api_bans.get(sid, ""))
        except Exception as e:
            log.error(f"ban {sid} 失败: {e}")

    # 移除：仅 full 模式执行
    if SYNC_MODE == "full":
        for sid in sorted(to_unban):
            try:
                resp = rcon.command(f"unbanid {sid}")
                log.info(f"[-] unban {sid} -> {resp.strip()!r}")
            except Exception as e:
                log.error(f"unban {sid} 失败: {e}")
    elif to_unban:
        log.info(f"（add_only 模式：{len(to_unban)} 条待移除记录已忽略）")


def main():
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
    fh.setFormatter(fmt)
    root.addHandler(fh)

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    root.addHandler(sh)

    # 校验模式
    global SYNC_MODE
    SYNC_MODE = SYNC_MODE.strip().lower()
    if SYNC_MODE not in ("full", "add_only"):
        log.error(f"SYNC_MODE 值非法: {SYNC_MODE!r}，可选 'full' 或 'add_only'，已回退为 'full'")
        SYNC_MODE = "full"

    log.info("=" * 60)
    log.info("pz-bansync 启动")
    log.info("  API:      %s", API_BASE)
    log.info("  RCON:     %s:%d", RCON_HOST, RCON_PORT)
    log.info("  DB:       %s", PZ_DB)
    log.info("  间隔:     %d 秒", SYNC_INTERVAL)
    log.info("  同步模式: %s", "full（完全同步）" if SYNC_MODE == "full" else "add_only（只增不减）")
    log.info("=" * 60)

    while True:
        try:
            token = api_login()
        except Exception as e:
            log.error(f"API 登录失败: {e}")
            time.sleep(SYNC_INTERVAL)
            continue

        rcon = RconClient(RCON_HOST, RCON_PORT, RCON_PASS)
        try:
            rcon.connect()
            log.info("RCON connected")
        except Exception as e:
            log.error(f"RCON 连接失败: {e}")
            time.sleep(SYNC_INTERVAL)
            continue

        try:
            sync_once(rcon, token)
        except Exception:
            log.exception("同步异常")
        finally:
            rcon.close()

        time.sleep(SYNC_INTERVAL)


if __name__ == "__main__":
    main()