#!/usr/bin/env python3
"""
telegram_notify.py — Gửi cảnh báo thay đổi firewall rule qua Telegram đi Direct Internet.
"""

import json
import logging
import urllib.request
from datetime import datetime

log = logging.getLogger("telegram")

_MAX_LEN = 4096

_ACTION_HEADER = {
    "add":     ("🟢", "ADD RULE (THÊM MỚI)"),
    "edit":    ("🟡", "EDIT RULE (SỬA)"),
    "delete":  ("🔴", "DELETE RULE (XÓA)"),
    "move":    ("🔵", "MOVE RULE (DI CHUYỂN)"),
    "clone":   ("🟣", "CLONE RULE (NHÂN BẢN)"),
    "disable": ("🟠", "DISABLE RULE (TẮT)"),
    "enable":  ("🟢", "ENABLE RULE (BẬT LẠI)"),
}

_DEV_ICON = {
    "004_DC-FW-DMZ":     "🛡",
    "004_DC-FW-PARTNER": "🔒",
    "004_DC-FW-INTERNET": "🔒",
}


def _send_raw(token: str, chat_id: str, text: str) -> bool:
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    
    # Đóng gói dữ liệu gửi đi (giữ lại parse_mode để hiển thị đậm/nhạt HTML)
    payload = json.dumps({
        "chat_id":                  chat_id,
        "text":                     text[:_MAX_LEN],
        "parse_mode":               "HTML",
        "disable_web_page_preview": True,
    }).encode("utf-8")
    
    req = urllib.request.Request(
        url, data=payload, headers={"Content-Type": "application/json"}
    )
    
    try:
        # Gửi request thẳng Internet bằng urlopen mặc định công nghệ cao không proxy
        with urllib.request.urlopen(req, timeout=15) as r:
            body = json.loads(r.read().decode("utf-8"))
            
        if body.get("ok"):
            log.info("Telegram OK   msg_id=%s", body["result"]["message_id"])
            return True
        log.error("Telegram FAIL: %s", body)
        return False

    except Exception as e:
        log.error("Telegram exception: %s", e)
        return False


def build_alert_custom(ev: dict) -> str:
    """
    Tạo cấu trúc tin nhắn Telegram theo đúng format yêu cầu.
    """
    action     = str(ev.get("action", "")).lower()
    icon, verb = _ACTION_HEADER.get(action, ("ℹ️", action.upper()))
    dev_name   = ev.get("device_name", "?")
    dev_icon   = _DEV_ICON.get(dev_name, "🖥")
    platform   = ev.get("platform", "FortiGate")
    cfgpath    = ev.get("cfgpath", "")
    pol_id     = ev.get("cfgobj") or "—"
    user       = ev.get("user", "—")
    ui         = ev.get("ui", "")
    date_s     = ev.get("date", "")
    time_s     = ev.get("time", "")
    
    user_info  = f"{user} ({ui})" if ui else user
    cfgattr    = ev.get("cfgattr", "")

    lines = [
        f"{icon} <b>{verb}</b>",
        f"{'─' * 30}",
        f"{dev_icon} <b>Thiết bị  :</b> <code>{dev_name}</code>",
        f"🔧 <b>Platform  :</b> <code>{platform}</code>",
        f"📂 <b>Đối tượng :</b> <code>{cfgpath}</code>",
        f"🏷  <b>RULE ID   :</b> <code>{pol_id}</code>",
        f"👤 <b>User :</b> <code>{user_info}</code>",
        f"🕐 <b>Thời gian :</b> <code>{date_s} {time_s}</code>",
    ]
    if cfgattr:
        lines.append(f"📝 <b>Chi tiết  :</b> <code>{cfgattr}</code>")
    return "\n".join(lines)


def send_test(token: str, chat_id: str, devices: list, faz_ok: bool) -> bool:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "📡 <b>Hệ thống giám sát Firewall qua FortiAnalyzer</b>",
        f"🕐 Thời gian: <code>{now}</code>",
        f"📊 Kết nối FAZ API: " + ("✅ <b>SUCCESS</b>" if faz_ok else "❌ <b>FAILED</b>"),
    ]
    return _send_raw(token, chat_id, "\n".join(lines))