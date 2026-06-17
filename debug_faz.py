#!/usr/bin/env python3
"""
debug_faz.py — Kiem tra ket noi FAZ va cac log event co san.

Chay:
  python debug_faz.py
"""

import json
import ssl
import http.cookiejar
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timedelta

ROOT = Path(__file__).resolve().parent
cfg  = json.loads((ROOT / "settings.json").read_text(encoding="utf-8"))
sec  = json.loads((ROOT / "secrets.json").read_text(encoding="utf-8"))

FAZ_BASE = cfg["faz"]["url"].rstrip("/")
USERNAME = cfg["faz"]["username"]
PASSWORD = sec["faz_password"]
ADOM     = cfg["faz"]["adom"]
DEVICE   = cfg["devices"][0]
DEVID    = DEVICE.get("faz_devid", "")

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode    = ssl.CERT_NONE

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(cj),
    urllib.request.HTTPSHandler(context=SSL_CTX),
)

_id = 0
csrf = None


def next_id():
    global _id
    _id += 1
    return _id


def get_cookie(name):
    for c in cj:
        if c.name == name:
            return c.value
    return None


def post(url, body):
    global csrf
    headers = {
        "Content-Type":     "application/json",
        "Accept":           "application/json, text/plain, */*",
        "Referer":          f"{FAZ_BASE}/ui/logview/logs/logview_all/31/26",
        "Origin":           FAZ_BASE,
        "X-Requested-With": "XMLHttpRequest",
    }
    if csrf:
        headers["xsrf-token"] = csrf
    raw = json.dumps(body).encode()
    req = urllib.request.Request(url, data=raw, headers=headers, method="POST")
    try:
        with opener.open(req, timeout=30) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        txt = e.read().decode("utf-8", errors="replace")
        print(f"  HTTP {e.code}: {txt[:500]}")
        return {}


def pp(label, obj):
    print(f"\n{'='*65}\n{label}\n{'='*65}")
    print(json.dumps(obj, indent=2, ensure_ascii=False)[:2000])


print(f"FAZ    : {FAZ_BASE}")
print(f"User   : {USERNAME}")
print(f"Device : {DEVICE['name']}  faz_devid={DEVID}")


# ── Step 1: JSONRPC login ─────────────────────────────────────────────────────
r1 = post(f"{FAZ_BASE}/jsonrpc", {
    "id": next_id(), "method": "exec",
    "params": [{"url": "/sys/login/user",
                "data": {"user": USERNAME, "passwd": PASSWORD}}]
})
if "session" not in r1:
    print("\nJSONRPC login FAIL:", r1)
    raise SystemExit(1)
session = r1["session"]
print(f"\nJSONRPC OK  session={session[:12]}...")


# ── Step 2: flatui_auth (Web UI login) → set cookie CURRENT_SESSION ───────────
r2 = post(f"{FAZ_BASE}/cgi-bin/module/flatui_auth", {
    "url":    "/gui/userauth",
    "method": "login",
    "params": {"username": USERNAME, "secretkey": PASSWORD, "logintype": 0},
})
csrf = get_cookie("HTTP_CSRF_TOKEN")
has_session = bool(get_cookie("CURRENT_SESSION"))
pp("flatui_auth response", r2)
print(f"\nCookies: { [(c.name, c.value[:20]) for c in cj] }")
print(f"CSRF   : {csrf}")
print(f"SESSION: {has_session}")

if not has_session:
    print("\nERROR: Khong co CURRENT_SESSION cookie - dung lai")
    raise SystemExit(1)


# ── Step 3: /p/logview/logsearch/run/ ─────────────────────────────────────────
now   = datetime.now()
start = (now - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
end   = now.strftime("%Y-%m-%d %H:%M:%S")

run_body = {
    "osType":        31,
    "logtype":       26,
    "timeOrder":     "desc",
    "caseSensitive": False,
    "device":        [{"devid": "All_Device"}],
    "filter":        f" data_sourceid={DEVID}",
    "isLocalEvent":  False,
    "limit":         20,
    "serverTime":    {"start": start, "end": end},
}

r3 = post(f"{FAZ_BASE}/p/logview/logsearch/run/", run_body)
pp("logsearch/run response", r3)

tid = r3.get("tid")
if not tid:
    print("\nERROR: Khong co tid - xem response o tren")
    raise SystemExit(1)

print(f"\ntid = {tid}")


# ── Step 4: /p/logview/logsearch/fetch/ ───────────────────────────────────────
import time
for i in range(10):
    r4 = post(f"{FAZ_BASE}/p/logview/logsearch/fetch/", {
        "tid":          tid,
        "limit":        20,
        "offset":       0,
        "isLocalEvent": False,
    })
    pct = r4.get("percentage", 100)
    print(f"\nFetch attempt {i+1}: percentage={pct}%  rows={len(r4.get('data') or [])}")
    if pct >= 100:
        break
    time.sleep(0.5)

data = r4.get("data") or []
print(f"\nTong {len(data)} log(s) trong 24h (filter: data_sourceid={DEVID})")
for i, row in enumerate(data[:5], 1):
    print(f"\n  [{i}]")
    print(f"     itime        : {row.get('itime','?')}")
    print(f"     event_action : {row.get('event_action','?')}")
    print(f"     event_message: {row.get('event_message','?')[:100]}")
    print(f"     user         : {row.get('user_name') or row.get('euid_name','?')}")

# ── Logout ────────────────────────────────────────────────────────────────────
post(f"{FAZ_BASE}/jsonrpc", {
    "id": next_id(), "method": "exec", "session": session,
    "params": [{"url": "/sys/logout"}]
})
print("\n\nLogout OK.")