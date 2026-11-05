#!/usr/bin/env python3
import sys
from pathlib import Path

# ВАЖНО: добавляем папку скрипта в sys.path ДО импорта локальных модулей
sys.path.insert(0, str(Path(__file__).resolve().parent))

import json
import os
import socket
import subprocess
import tempfile
import time
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

# Теперь эти импорты сработают, так как путь добавлен выше
from gen_singbox import to_outbound
from fetch_subs import load_all

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
    if not out:
        return {"ok": False, "error": "unsupported/parse error"}

    port = free_port()
    cfg = {
        "log": {"level": "error"},
        "inbounds": [{"type": "socks", "tag": "in",
                      "listen": "127.0.0.1", "listen_port": port}],
        "outbounds": [out, {"type": "direct", "tag": "direct"}],
    }
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(cfg, f)
        cfg_path = f.name

    proc = subprocess.Popen([SINGBOX, "run", "-c", cfg_path],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    for _ in range(40):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                break
        except OSError:
            if proc.poll() is not None:
                break
            time.sleep(0.2)

    t0 = time.time()
    ok, err = False, None
    try:
        r = requests.get(
            PROBE_URL,
            proxies={"http": f"socks5h://127.0.0.1:{port}",
                     "https": f"socks5h://127.0.0.1:{port}"},
            timeout=TIMEOUT,
        )
        ok = r.status_code in (200, 204)
        if not ok:
            err = f"HTTP {r.status_code}"
    except Exception as e:
        err = f"{type(e).__name__}: {e}"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
        try:
            os.unlink(cfg_path)
        except OSError:
            pass

    return {
        "type": out["type"],
        "server": f'{out.get("server")}:{out.get("server_port")}',
        "ok": ok,
        "latency_ms": int((time.time() - t0) * 1000) if ok else None,
        "error": err,
    }


def key_id(uri: str) -> str:
    return hashlib.sha1(uri.encode()).hexdigest()[:12]


def collect_sources() -> list[dict]:
    """[{uri, sources: [str,...]}] с дедупликацией по uri."""
    by_uri: dict[str, dict] = {}

    # 1) одиночные ключи
    if KEYS_FILE.exists():
        for line in KEYS_FILE.read_text().splitlines():
            uri = line.strip()
            if not uri or uri.startswith("#"):
                continue
            by_uri.setdefault(uri, {"uri": uri, "sources": []})["sources"].append(
                f"file:{KEYS_FILE.name}")

    # 2) подписки
    if SUBS_FILE.exists():
        subs = load_all(str(SUBS_FILE))
        errors = subs.pop("__errors__", []) if "__errors__" in subs else []
        if errors:
            print(f"[!] Ошибки подписок: {errors}", file=sys.stderr)
        for url, keys in subs.items():
            for uri in keys:
                by_uri.setdefault(uri, {"uri": uri, "sources": []})["sources"].append(
                    f"sub:{url}")

    return list(by_uri.values())


def main():
    items = collect_sources()
    if not items:
        print("Нет ни ключей, ни подписок", file=sys.stderr)
        sys.exit(2)

    print(f"К проверке: {len(items)} уникальных ключей, воркеров: {WORKERS}",
          flush=True)

    results = []
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futures = {ex.submit(check_one, it["uri"]): it for it in items}
        done = 0
        for fut in as_completed(futures):
            it = futures[fut]
            r = fut.result()
            done += 1
            mark = "OK" if r["ok"] else "FAIL"
            tail = f'{r["latency_ms"]}ms' if r["ok"] else r.get("error")
            print(f"[{done}/{len(items)}] {mark} {r['type']} {r['server']} ({tail})",
                  flush=True)
            results.append({
                "id": key_id(it["uri"]),
                "type": r["type"],
                "server": r["server"],
                "ok": r["ok"],
                "latency_ms": r["latency_ms"],
                "error": r.get("error"),
                "sources": it["sources"],
                "uri_short": it["uri"][:100] + ("..." if len(it["uri"]) > 100 else ""),
            })

    results.sort(key=lambda x: (not x["ok"], x["latency_ms"] or 10**9))
    REPORT.write_text(json.dumps(results, indent=2, ensure_ascii=False))

    # ---- сводка ----
    total = len(results)
    ok = sum(1 for r in results if r["ok"])
    by_sub: dict[str, dict] = {}
    for r in results:
        for src in r["sources"]:
            if not src.startswith("sub:"):
                continue
            s = by_sub.setdefault(src[4:], {"total": 0, "ok": 0})
            s["total"] += 1
            if r["ok"]:
                s["ok"] += 1

    lines = [
        "## Проверка ключей и подписок",
        "",
        f"Всего уникальных ключей: **{total}**, рабочих: **{ok}**, битых: **{total-ok}**",
        "",
    ]

    if by_sub:
        lines += ["### По подпискам", "",
                  "| Подписка | Работает | Всего |", "|---|---|---|"]
        for url, s in sorted(by_sub.items(), key=lambda x: -x[1]["ok"]):
            short = url if len(url) <= 60 else url[:57] + "..."
            lines.append(f"| `{short}` | {s['ok']} | {s['total']} |")
        lines.append("")

    lines += ["### Ключи", "",
              "| # | Тип | Сервер | OK | Задержка / Ошибка | Источник |",
              "|---|-----|--------|----|-------------------|----------|"]
    for i, r in enumerate(results, 1):
        status = "✅" if r["ok"] else "❌"
        info = f'{r["latency_ms"]} ms' if r["ok"] else (r.get("error") or "")
        src = ", ".join(
            ("keys.txt" if s.startswith("file:") else "sub:" + s[4:][:40] + ("..." if len(s[4:]) > 40 else ""))
            for s in r["sources"]
        )
        lines.append(f'| {i} | {r["type"]} | {r["server"]} | {status} | {info} | {src} |')

    REPORT_MD.write_text("\n".join(lines))

    if ok == 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
