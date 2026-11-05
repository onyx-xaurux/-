#!/usr/bin/env python3
import sys
import os
import json
import base64
import re
import socket
import subprocess
import tempfile
import time
import hashlib
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

# ==========================================
# 1. ПАРСЕРЫ КЛЮЧЕЙ
# ==========================================

def _b64(s: str) -> str:
    s = s.strip().replace("-", "+").replace("_", "/")
    return s + "=" * (-len(s) % 4)

def parse_vless(uri: str) -> dict | None:
    u = urlparse(uri)
    if not u.hostname or not u.port: return None
    q = parse_qs(u.query)
    ob = {
        "type": "vless", "server": u.hostname, "server_port": int(u.port),
        "uuid": unquote(u.username or ""),
        "tls": {"enabled": True, "server_name": (q.get("sni") or q.get("host") or [u.hostname])[0]},
    }
    flow = (q.get("flow") or [""])[0]
    if flow: ob["flow"] = flow
    sec = (q.get("security") or ["tls"])[0]
    if sec == "reality":
        ob["tls"] = {
            "enabled": True, "server_name": (q.get("sni") or [u.hostname])[0],
            "reality": {"enabled": True, "public_key": (q.get("pbk") or [""])[0], "short_id": (q.get("sid") or [""])[0]},
            "utls": {"enabled": True, "fingerprint": (q.get("fp") or ["chrome"])[0]},
        }
    elif sec == "none":
        ob["tls"] = {"enabled": False}
    net = (q.get("type") or q.get("network") or ["tcp"])[0]
    if net == "ws":
        ob["transport"] = {"type": "ws", "path": (q.get("path") or ["/"])[0], "headers": {"Host": (q.get("host") or [u.hostname])[0]}}
    elif net == "grpc":
        ob["transport"] = {"type": "grpc", "service_name": (q.get("serviceName") or [""])[0]}
    elif net in ("http", "h2"):
        ob["transport"] = {"type": "http", "path": (q.get("path") or ["/"])[0], "host": [(q.get("host") or [u.hostname])[0]]}
    return ob

def parse_trojan(uri: str) -> dict | None:
    u = urlparse(uri)
    if not u.hostname or not u.port: return None
    q = parse_qs(u.query)
    ob = {
        "type": "trojan", "server": u.hostname, "server_port": int(u.port),
        "password": unquote(u.username or ""),
        "tls": {"enabled": True, "server_name": (q.get("sni") or q.get("peer") or [u.hostname])[0], "insecure": (q.get("allowInsecure") or ["0"])[0] == "1"},
    }
    net = (q.get("type") or ["tcp"])[0]
    if net == "ws":
        ob["transport"] = {"type": "ws", "path": (q.get("path") or ["/"])[0], "headers": {"Host": (q.get("host") or [u.hostname])[0]}}
    elif net == "grpc":
        ob["transport"] = {"type": "grpc", "service_name": (q.get("serviceName") or [""])[0]}
    return ob

def parse_vmess(uri: str) -> dict | None:
    try:
        raw = base64.b64decode(_b64(uri[8:])).decode("utf-8", "ignore")
        v = json.loads(raw)
    except Exception: return None
    ob = {
        "type": "vmess", "server": v.get("add"), "server_port": int(v.get("port", 0)),
        "uuid": v.get("id"), "security": v.get("scy", "auto"), "alter_id": int(v.get("aid", 0)),
    }
    if v.get("tls"): ob["tls"] = {"enabled": True, "server_name": v.get("sni") or v.get("host") or v.get("add")}
    net = v.get("net", "tcp")
    if net == "ws":
        ob["transport"] = {"type": "ws", "path": v.get("path", "/"), "headers": {"Host": v.get("host", v.get("add"))}}
    elif net == "grpc":
        ob["transport"] = {"type": "grpc", "service_name": v.get("path", "")}
    return ob

def parse_ss(uri: str) -> dict | None:
    body = uri[5:].split("#", 1)[0]
    if "@" not in body: return None
    userpart, hostpart = body.rsplit("@", 1)
    try: method_pass = base64.b64decode(_b64(userpart)).decode()
    except Exception: method_pass = userpart
    if ":" not in method_pass: return None
    method, password = method_pass.split(":", 1)
    hp = urlparse("ss://" + hostpart)
    return {"type": "shadowsocks", "server": hp.hostname, "server_port": int(hp.port), "method": method, "password": password}

def parse_hysteria2(uri: str) -> dict | None:
    u = urlparse(uri)
    if not u.hostname or not u.port: return None
    q = parse_qs(u.query)
    return {
        "type": "hysteria2", "server": u.hostname, "server_port": int(u.port),
        "password": unquote(u.username or ""),
        "tls": {"enabled": True, "server_name": (q.get("sni") or [u.hostname])[0], "insecure": (q.get("insecure") or ["0"])[0] == "1"},
    }

PARSERS = {
    "vless://": parse_vless, "trojan://": parse_trojan,
    "vmess://": parse_vmess, "ss://": parse_ss,
    "hysteria2://": parse_hysteria2, "hy2://": parse_hysteria2,
}

def to_outbound(uri: str) -> dict | None:
    uri = uri.strip()
    for prefix, fn in PARSERS.items():
        if uri.lower().startswith(prefix): return fn(uri)
    return None

# ==========================================
# 2. ЗАГРУЗКА ПОДПИСОК
# ==========================================

URI_RE = re.compile(r"^(vless|vmess|trojan|ss|ssr|hysteria2|hy2|tuic)://", re.I)
UA_DEFAULT = "v2rayN/6.42"

def _try_b64(text: str) -> str | None:
    s = text.strip().replace("\n", "").replace("\r", "").replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        dec = base64.b64decode(s, validate=True).decode("utf-8", "ignore")
        if URI_RE.search(dec): return dec
    except Exception: pass
    return None

def extract_from_text(text: str) -> list[str]:
    dec = _try_b64(text)
    if dec: text = dec
    t = text.lstrip()
    if t.startswith("{") or t.startswith("["):
        try:
            data = json.loads(text)
            if isinstance(data, list):
                return [x.strip() for x in data if isinstance(x, str) and URI_RE.match(x.strip())]
        except Exception: pass
    return [line.strip() for line in text.splitlines() if URI_RE.match(line.strip())]

def fetch_subscription(url: str, ua: str = UA_DEFAULT, timeout: float = 20) -> list[str]:
    r = requests.get(url, headers={"User-Agent": ua}, timeout=timeout)
    r.raise_for_status()
    return extract_from_text(r.text)

def load_all(subs_file: str) -> dict[str, list[str]]:
    out = {}
    if not Path(subs_file).exists(): return out
    lines = [l.strip() for l in Path(subs_file).read_text().splitlines() if l.strip() and not l.startswith("#")]
    for i, raw in enumerate(lines, 1):
        ua = UA_DEFAULT
        url = raw
        if ";ua=" in url: url, ua = url.split(";ua=", 1)
        url, ua = url.strip(), ua.strip()
        print(f"[sub {i}/{len(lines)}] {url[:60]}...", flush=True)
        try:
            keys = fetch_subscription(url, ua=ua)
            print(f"    -> {len(keys)} ключей", flush=True)
            out[url] = keys
        except Exception as e:
            print(f"    !! ошибка: {e}", flush=True)
            out[url] = []
    return out

# ==========================================
# 3. ПРОВЕРКА ЧЕРЕЗ SING-BOX
# ==========================================

KEYS_FILE = Path(os.getenv("KEYS_FILE", "keys/keys.txt"))
SUBS_FILE = Path(os.getenv("SUBS_FILE", "keys/subs.txt"))
PROBE_URL = os.getenv("PROBE_URL", "https://www.gstatic.com/generate_204")
TIMEOUT = float(os.getenv("TIMEOUT", "15"))
SINGBOX = os.getenv("SINGBOX", "./sing-box")
WORKERS = int(os.getenv("WORKERS", "8"))
REPORT = Path("report.json")
REPORT_MD = Path("report.md")

def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def check_one(uri: str) -> dict:
    out = to_outbound(uri)
    if not out: return {"ok": False, "error": "unsupported/parse error"}

    port = free_port()
    cfg = {
        "log": {"level": "error"},
        "inbounds": [{"type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": port}],
        "outbounds": [out, {"type": "direct", "tag": "direct"}],
    }
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(cfg, f)
        cfg_path = f.name

    proc = subprocess.Popen([SINGBOX, "run", "-c", cfg_path], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    for _ in range(40):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1): break
        except OSError:
            if proc.poll() is not None: break
            time.sleep(0.2)

    t0 = time.time()
    ok, err = False, None
    try:
        r = requests.get(PROBE_URL, proxies={"http": f"socks5h://127.0.0.1:{port}", "https": f"socks5h://127.0.0.1:{port}"}, timeout=TIMEOUT)
        ok = r.status_code in (200, 204)
        if not ok: err = f"HTTP {r.status_code}"
    except Exception as e:
        err = f"{type(e).__name__}: {e}"
    finally:
        proc.terminate()
        try: proc.wait(timeout=3)
        except subprocess.TimeoutExpired: proc.kill()
        try: os.unlink(cfg_path)
        except OSError: pass

    return {
        "type": out.get("type", "unknown"), 
        "server": f'{out.get("server", "unknown")}:{out.get("server_port", "?")}',
        "ok": ok, 
        "latency_ms": int((time.time() - t0) * 1000) if ok else None,
        "error": err,
    }

# ==========================================
# 4. СБОР ИСТОЧНИКОВ И MAIN
# ==========================================

def key_id(uri: str) -> str:
    return hashlib.sha1(uri.encode()).hexdigest()[:12]

def collect_sources() -> list[dict]:
    by_uri: dict[str, dict] = {}
    if KEYS_FILE.exists():
        for line in KEYS_FILE.read_text().splitlines():
            uri = line.strip()
            if not uri or uri.startswith("#"): continue
            by_uri.setdefault(uri, {"uri": uri, "sources": []})["sources"].append(f"file:{KEYS_FILE.name}")
    
    subs = load_all(str(SUBS_FILE))
    for url, keys in subs.items():
        for uri in keys:
            by_uri.setdefault(uri, {"uri": uri, "sources": []})["sources"].append(f"sub:{url}")
    return list(by_uri.values())

def main():
    items = collect_sources()
    if not items:
        print("Нет ни ключей, ни подписок", file=sys.stderr)
        sys.exit(2)

    print(f"К проверке: {len(items)} уникальных ключей, воркеров: {WORKERS}", flush=True)

    results = []
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futures = {ex.submit(check_one, it["uri"]): it for it in items}
        done = 0
        for fut in as_completed(futures):
            it = futures[fut]
            r = fut.result()
            done += 1
            
            r_type = r.get("type", "unknown")
            r_server = r.get("server", "unknown")
            mark = "OK" if r["ok"] else "FAIL"
            tail = f'{r["latency_ms"]}ms' if r["ok"] else r.get("error", "unknown error")
            
            print(f"[{done}/{len(items)}] {mark} {r_type} {r_server} ({tail})", flush=True)
            
            results.append({
                "id": key_id(it["uri"]), 
                "type": r_type, 
                "server": r_server,
                "ok": r["ok"], 
                "latency_ms": r["latency_ms"], 
                "error": r.get("error"),
                "sources": it["sources"], 
                "uri_short": it["uri"][:100] + ("..." if len(it["uri"]) > 100 else ""),
            })

    results.sort(key=lambda x: (not x["ok"], x["latency_ms"] or 10**9))
    REPORT.write_text(json.dumps(results, indent=2, ensure_ascii=False))

    total = len(results)
    ok = sum(1 for r in results if r["ok"])
    by_sub: dict[str, dict] = {}
    for r in results:
        for src in r["sources"]:
            if not src.startswith("sub:"): continue
            s = by_sub.setdefault(src[4:], {"total": 0, "ok": 0})
            s["total"] += 1
            if r["ok"]: s["ok"] += 1

    lines = ["## Проверка ключей и подписок", "", f"Всего уникальных ключей: **{total}**, рабочих: **{ok}**, битых: **{total-ok}**", ""]
    if by_sub:
        lines += ["### По подпискам", "", "| Подписка | Работает | Всего |", "|---|---|---|"]
        for url, s in sorted(by_sub.items(), key=lambda x: -x[1]["ok"]):
            short = url if len(url) <= 60 else url[:57] + "..."
            lines.append(f"| `{short}` | {s['ok']} | {s['total']} |")
        lines.append("")

    lines += ["### Ключи", "", "| # | Тип | Сервер | OK | Задержка / Ошибка | Источник |", "|---|-----|--------|----|-------------------|----------|"]
    for i, r in enumerate(results, 1):
        status = "✅" if r["ok"] else "❌"
        info = f'{r["latency_ms"]} ms' if r["ok"] else (r.get("error") or "")
        src = ", ".join(("keys.txt" if s.startswith("file:") else "sub:" + s[4:][:40] + ("..." if len(s[4:]) > 40 else "")) for s in r["sources"])
        lines.append(f'| {i} | {r["type"]} | {r["server"]} | {status} | {info} | {src} |')

    REPORT_MD.write_text("\n".join(lines))
    if ok == 0: sys.exit(1)

if __name__ == "__main__":
    main()
