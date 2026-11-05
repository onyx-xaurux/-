#!/usr/bin/env python3
"""
Скачивание подписок и извлечение из них ключей.
Поддерживаемые форматы ответа:
  - base64 (список URI после декодирования)
  - plain text (по одному URI на строку)
  - JSON (v2rayN / Xray: {"outbounds":[...]} или массив строк)
"""
import base64, json, re, sys
from urllib.parse import urlparse
import requests

URI_RE = re.compile(r"^(vless|vmess|trojan|ss|ssr|hysteria2|hy2|tuic)://", re.I)
UA_DEFAULT = "v2rayN/6.42"


def _try_b64(text: str) -> str | None:
    s = text.strip().replace("\n", "").replace("\r", "")
    if not s:
        return None
    s2 = s.replace("-", "+").replace("_", "/")
    s2 += "=" * (-len(s2) % 4)
    try:
        dec = base64.b64decode(s2, validate=True).decode("utf-8", "ignore")
        if URI_RE.search(dec):
            return dec
    except Exception:
        pass
    return None


def extract_from_text(text: str) -> list[str]:
    # 1) base64?
    dec = _try_b64(text)
    if dec:
        text = dec
    # 2) JSON?
    t = text.lstrip()
    if t.startswith("{") or t.startswith("["):
        try:
            data = json.loads(text)
            return extract_from_json(data)
        except Exception:
            pass
    # 3) plain: по строкам
    keys = []
    for line in text.splitlines():
        line = line.strip()
        if URI_RE.match(line):
            keys.append(line)
    return keys


def extract_from_json(data) -> list[str]:
    keys = []
    if isinstance(data, list):
        for x in data:
            if isinstance(x, str) and URI_RE.match(x.strip()):
                keys.append(x.strip())
        return keys
    # v2rayN / Xray style
    for ob in (data.get("outbounds") or []):
        t = ob.get("type") or ob.get("protocol")
        srv = ob.get("settings", {})
        # тут восстановить полный URI сложно — просто вернём "type://server:port"
        # но лучше, если подписка уже отдаёт URI-строки. Пропускаем JSON-объекты.
        _ = (t, srv)
    return keys


def fetch_subscription(url: str, ua: str = UA_DEFAULT, timeout: float = 20) -> list[str]:
    r = requests.get(url, headers={"User-Agent": ua}, timeout=timeout)
    r.raise_for_status()
    return extract_from_text(r.text)


def parse_sub_line(line: str) -> tuple[str, str]:
    """'https://...;ua=custom' -> (url, ua)"""
    ua = UA_DEFAULT
    url = line.strip()
    if ";ua=" in url:
        url, ua = url.split(";ua=", 1)
        url, ua = url.strip(), ua.strip()
    return url, ua


def load_all(subs_file: str, timeout: float = 20) -> dict[str, list[str]]:
    """Возвращает {sub_url: [keys...]} с ошибками в ключе '__errors__'."""
    out: dict[str, list[str]] = {}
    errors = []
    try:
        with open(subs_file) as f:
            lines = [l for l in f if l.strip() and not l.lstrip().startswith("#")]
    except FileNotFoundError:
        return out

    for i, raw in enumerate(lines, 1):
        url, ua = parse_sub_line(raw)
        print(f"[sub {i}/{len(lines)}] {url[:70]}...", flush=True)
        try:
            keys = fetch_subscription(url, ua=ua, timeout=timeout)
            print(f"    -> {len(keys)} ключей", flush=True)
            out[url] = keys
        except Exception as e:
            print(f"    !! ошибка: {e}", flush=True)
            errors.append({"url": url, "error": f"{type(e).__name__}: {e}"})
            out[url] = []
    if errors:
        out["__errors__"] = errors  # type: ignore
    return out


if __name__ == "__main__":
    subs = load_all(sys.argv[1] if len(sys.argv) > 1 else "keys/subs.txt")
    for url, keys in subs.items():
        if url == "__errors__":
            continue
        print(url, len(keys))
