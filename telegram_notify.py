#!/usr/bin/env python3
"""
telegram_notify.py — Gui canh bao Telegram cho reset_monitor.py.

He thong CHI CON DUY NHAT 1 chuc nang: canh bao phien ket noi SHB <->
NAPAS bi RESET (server-rst/client-rst), qua build_alert_reset(). Cac ham
lien quan canh bao THAY DOI RULE (add/edit/delete/move/clone/disable/
enable) da bi go bo hoan toan cung voi monitor.py.
"""

import json
import logging
import urllib.request
from datetime import datetime

log = logging.getLogger("telegram")

_MAX_LEN = 4096

_DEV_ICON = {
    "004_DC-FW-PARTNER": "🔒",
}

# Nhan dien nhanh Napas DC1/DC2 de hien thi trong alert reset (chi de hien
# thi cho de doc, khong anh huong logic loc - loc that su nam o
# settings.json["reset_monitor"]["napas_dst_ips"]).
_NAPAS_DC_LABEL = {
    "10.1.253.2": "NAPAS-PROD-DC1",
    "10.1.249.2": "NAPAS-PROD-DC2",
}

_RESET_ACTION_HEADER = {
    "server-rst": ("🔴", "SERVER RESET (NAPAS RESET KẾT NỐI)"),
    "client-rst": ("🟠", "CLIENT RESET (SHB RESET KẾT NỐI)"),
}

# Phan loai muc do dua tren duration (xem reset_filter.classify_reset_duration).
# FAST_RESET: bi tu choi/reset gan nhu ngay lap tuc (duration<=5s) - dang
# chu y hon vi thuong la dau hieu ket noi/dich vu bi tu choi o tang cao hon.
# LONG_CONN_RESET: da truyen du lieu 1 thoi gian roi moi bi reset - it
# nghiem trong hon, co the la ket thuc phien binh thuong hoac don dep
# ket noi treo qua lau.
_RESET_CLASS_ICON = {
    "FAST_RESET":      "⚡",
    "LONG_CONN_RESET": "⏳",
}
_RESET_CLASS_TEXT = {
    "FAST_RESET":      "RESET NHANH (≤5s",
    "LONG_CONN_RESET": "RESET SAU KẾT NỐI KÉO DÀI (đã truyền dữ liệu trước khi bị reset",
}
_ACTION_SOURCE_TEXT = {
    "server-rst": "Server reset từ NAPAS)",
    "client-rst": "Client reset từ SHB)",
}


def _build_reset_class_label(reset_class: str, action: str) -> tuple:
    """
    Ghep nhan phan loai (FAST_RESET/LONG_CONN_RESET) VOI nguon reset
    (server-rst=NAPAS / client-rst=SHB) thanh 1 dong duy nhat, vi du:
      "RESET NHANH (≤5s - Server reset từ NAPAS)"
      "RESET NHANH (≤5s - Client reset từ SHB)"
    """
    icon = _RESET_CLASS_ICON.get(reset_class, "⚠️")
    base = _RESET_CLASS_TEXT.get(reset_class, f"RESET ({reset_class or '?'}")
    src  = _ACTION_SOURCE_TEXT.get(action, f"{action or '?'})")
    label = f"{base} - {src}"
    return icon, label


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


def build_alert_reset(ev: dict, device_name: str = "?", platform: str = "FortiGate") -> str:
    """
    Tao tin nhan Telegram canh bao 1 phien ket noi SHB <-> NAPAS bi RESET
    (Firewall Action = server-rst / client-rst), dung boi reset_monitor.py.

    ev = dict da qua reset_filter.normalize_reset_event().
    """
    action     = str(ev.get("action", "")).lower()
    icon, verb = _RESET_ACTION_HEADER.get(action, ("⚠️", f"RESET ({action.upper() or '?'})"))
    dev_icon   = _DEV_ICON.get(device_name, "🖥")

    src_ip   = ev.get("srcip", "—")
    dst_ip   = ev.get("dstip", "—")
    napas_dc = _NAPAS_DC_LABEL.get(dst_ip, "")
    dst_disp = f"{dst_ip} ({napas_dc})" if napas_dc else dst_ip

    src_port = ev.get("srcport", "—")
    dst_port = ev.get("dstport", "—")
    policy   = ev.get("policyid") or "—"
    session  = ev.get("sessionid") or "—"
    duration = ev.get("duration", 0)
    sentbyte = ev.get("sentbyte", 0)
    rcvdbyte = ev.get("rcvdbyte", 0)
    service  = ev.get("service") or "—"
    date_s   = ev.get("date", "")
    time_s   = ev.get("time", "")

    reset_class = ev.get("reset_class", "")
    class_icon, class_label = _build_reset_class_label(reset_class, action)

    burst_1m = ev.get("burst_1m")
    burst_5m = ev.get("burst_5m")

    lines = [
        f"{icon} <b>{verb}</b>",
        f"{'─' * 30}",
        f"{dev_icon} <b>Thiết bị     :</b> <code>{device_name}</code>",
        f"🔧 <b>Platform     :</b> <code>{platform}</code>",
        f"📡 <b>Source (SHB) :</b> <code>{src_ip}:{src_port}</code>",
        f"🎯 <b>Dest (NAPAS) :</b> <code>{dst_disp}:{dst_port}</code>",
        f"🧾 <b>Service      :</b> <code>{service}</code>",
        f"🏷  <b>Policy ID    :</b> <code>{policy}</code>",
        f"🔑 <b>Session ID   :</b> <code>{session}</code>",
        f"⏱  <b>Duration     :</b> <code>{duration}s</code>  (sent={sentbyte}B, rcvd={rcvdbyte}B)",
        f"🕐 <b>Thời gian    :</b> <code>{date_s} {time_s}</code>",
    ]
    if class_label:
        lines.append(f"{class_icon} <b>Phân loại    :</b> {class_label}")
    if burst_1m is not None and burst_5m is not None:
        lines.append(f"📊 <b>Tần suất     :</b> {burst_1m} lần RESET trong 1 phút, {burst_5m} lần trong 5 phút")
    return "\n".join(lines)


def build_alert_system(title: str, message: str, severity: str = "warning") -> str:
    """
    Canh bao VE CHINH HE THONG GIAM SAT (khong phai ve su kien reset) -
    dung cho:
      - Loi FAZ query lien tiep nhieu lan (nghi ngo token het han, FAZ
        down, network loi keo dai)
      - Heartbeat/dead-man switch (neu co cau hinh)

    severity: "warning" (⚠️) hoac "critical" (🆘) hoac "recovered" (✅)
    """
    icon = {"warning": "⚠️", "critical": "🆘", "recovered": "✅"}.get(severity, "⚠️")
    lines = [
        f"{icon} <b>{title}</b>",
        f"{'─' * 30}",
        message,
        f"{'─' * 30}",
        f"🕐 <code>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</code>",
    ]
    return "\n".join(lines)


def build_alert_window_summary(stats: dict, window_minutes: int, device_name: str = "?", platform: str = "FortiGate") -> str:
    """
    Tin TONG HOP dinh ky (moi window_minutes phut, mac dinh 5) dem so
    lan RESET xay ra trong khoang do - gui THEM (khong thay the) cac
    alert ca nhan gui ngay lap tuc cho tung phien. Dung state tich luy
    qua nhieu lan chay (xem reset_monitor.py - state["window_*"]) vi
    interval_minutes moi lan quet co the nho hon window_minutes (vi du
    quet 1 phut/lan nhung tong hop 5 phut/lan).

    stats: dict voi cac key count/server/client/fast/long/first_time/last_time.
    """
    dev_icon = _DEV_ICON.get(device_name, "🖥")
    total  = stats.get("count", 0)
    server = stats.get("server", 0)
    client = stats.get("client", 0)
    fast   = stats.get("fast", 0)
    long_  = stats.get("long", 0)
    first_t = stats.get("first_time") or "—"
    last_t  = stats.get("last_time") or "—"

    lines = [
        f"📈 <b>TỔNG HỢP {window_minutes} PHÚT GẦN NHẤT</b>",
        f"{'─' * 30}",
        f"{dev_icon} <b>Thiết bị     :</b> <code>{device_name}</code>",
        f"🔧 <b>Platform     :</b> <code>{platform}</code>",
        f"📊 <b>Tổng số RESET:</b> <b>{total}</b> phiên",
        f"   └ server-rst (NAPAS): {server}  |  client-rst (SHB): {client}",
        f"   └ ⚡ Reset nhanh (≤5s): {fast}  |  ⏳ Sau kết nối kéo dài: {long_}",
        f"🕐 <b>Từ:</b> <code>{first_t}</code>  <b>đến:</b> <code>{last_t}</code>",
    ]
    if total == 0:
        lines.append(f"✅ <i>Không có phiên RESET nào trong {window_minutes} phút qua</i>")
    return "\n".join(lines)


def send_test(token: str, chat_id: str, devices: list, faz_ok: bool) -> bool:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "📡 <b>Hệ thống giám sát Firewall qua FortiAnalyzer</b>",
        f"🕐 Thời gian: <code>{now}</code>",
        f"📊 Kết nối FAZ API: " + ("✅ <b>SUCCESS</b>" if faz_ok else "❌ <b>FAILED</b>"),
    ]
    return _send_raw(token, chat_id, "\n".join(lines))