#!/usr/bin/env python3
"""
telegram_notify.py

Gui canh bao Telegram cho reset_monitor.py.

CHUC NANG:
  1. Canh bao NAPAS server reset (server-rst).
  2. Canh bao SHB client reset theo threshold.
  3. Tong hop NAPAS server reset sau cua so 10 phut.
  4. Canh bao loi / phuc hoi he thong giam sat.

Luu y:
  - Duration CHI LA THONG TIN HIEN THI.
  - Duration khong duoc dung de loai bo server-rst.
  - Server-rst du 1s, 5s, 7s, 30s... deu duoc ghi nhan.
"""

import json
import logging
import urllib.request
from datetime import datetime

log = logging.getLogger("telegram")

_MAX_LEN = 4096


# ============================================================
# DEVICE ICON
# ============================================================

_DEV_ICON = {
    "004_DC-FW-PARTNER": "🔒",
}


# ============================================================
# NAPAS DC LABEL
# ============================================================

_NAPAS_DC_LABEL = {
    "10.1.153.2": "NAPAS-PROD-DC1",
    "10.1.249.2": "NAPAS-PROD-DC2",
    "10.1.253.2": "NAPAS-PROD-DC1",
}


# ============================================================
# RESET ACTION
# ============================================================

_RESET_ACTION_HEADER = {
    "server-rst": (
        "🔴",
        "SERVER RESET (NAPAS RESET KẾT NỐI)"
    ),
    "client-rst": (
        "🟠",
        "CLIENT RESET (SHB RESET KẾT NỐI)"
    ),
}


# ============================================================
# SEVERITY
# ============================================================

_SEVERITY_BANNER = {
    "CRITICAL": (
        "🔴🔴🔴 "
        "<b>CẢNH BÁO NGHIÊM TRỌNG — TẦN SUẤT RESET RẤT CAO</b> "
        "🔴🔴🔴"
    ),

    "WARNING": (
        "🟠 "
        "<b>CẢNH BÁO — TẦN SUẤT RESET TĂNG BẤT THƯỜNG</b>"
    ),
}


# ============================================================
# RESET CLASS
# ============================================================

_RESET_CLASS_ICON = {
    "FAST_RESET": "⚡",
    "LONG_CONN_RESET": "⏳",
}

_RESET_CLASS_TEXT = {
    "FAST_RESET": "RESET NHANH (≤5s",
    "LONG_CONN_RESET": (
        "RESET SAU KẾT NỐI KÉO DÀI "
        "(đã truyền dữ liệu trước khi bị reset"
    ),
}

_ACTION_SOURCE_TEXT = {
    "server-rst": "Server reset từ NAPAS)",
    "client-rst": "Client reset từ SHB)",
}


def _build_reset_class_label(
    reset_class: str,
    action: str
) -> tuple:
    """
    Chi dung de phan loai thong tin.

    QUAN TRONG:
    reset_class KHONG duoc dung de quyet dinh co alert server-rst hay khong.
    """

    icon = _RESET_CLASS_ICON.get(
        reset_class,
        "⚠️"
    )

    base = _RESET_CLASS_TEXT.get(
        reset_class,
        f"RESET ({reset_class or '?'}"
    )

    src = _ACTION_SOURCE_TEXT.get(
        action,
        f"{action or '?'}"
    )

    label = f"{base} - {src}"

    return icon, label


# ============================================================
# RAW TELEGRAM
# ============================================================

def _send_raw(
    token: str,
    chat_id: str,
    text: str
) -> bool:

    url = (
        f"https://api.telegram.org/"
        f"bot{token}/sendMessage"
    )

    payload = json.dumps({
        "chat_id": chat_id,
        "text": text[:_MAX_LEN],
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json"
        }
    )

    try:

        with urllib.request.urlopen(
            req,
            timeout=15
        ) as response:

            body = json.loads(
                response.read().decode("utf-8")
            )

        if body.get("ok"):

            log.info(
                "Telegram OK msg_id=%s",
                body["result"]["message_id"]
            )

            return True

        log.error(
            "Telegram FAIL: %s",
            body
        )

        return False

    except Exception as e:

        log.error(
            "Telegram exception: %s",
            e
        )

        return False


# ============================================================
# GENERIC RESET ALERT
# ============================================================

def build_alert_reset(
    ev: dict,
    device_name: str = "?",
    platform: str = "FortiGate"
) -> str:
    """
    Tao alert reset chi tiet.

    Dung cho test / alert reset chung.
    """

    action = str(
        ev.get("action", "")
    ).lower()

    icon, verb = _RESET_ACTION_HEADER.get(
        action,
        (
            "⚠️",
            f"RESET ({action.upper() or '?'})"
        )
    )

    dev_icon = _DEV_ICON.get(
        device_name,
        "🖥"
    )

    src_ip = ev.get(
        "srcip",
        "—"
    )

    dst_ip = ev.get(
        "dstip",
        "—"
    )

    napas_dc = _NAPAS_DC_LABEL.get(
        dst_ip,
        ""
    )

    dst_disp = (
        f"{dst_ip} ({napas_dc})"
        if napas_dc
        else dst_ip
    )

    src_port = ev.get(
        "srcport",
        "—"
    )

    dst_port = ev.get(
        "dstport",
        "—"
    )

    policy = ev.get(
        "policyid"
    ) or "—"

    session = ev.get(
        "sessionid"
    ) or "—"

    duration = ev.get(
        "duration",
        0
    )

    sentbyte = ev.get(
        "sentbyte",
        0
    )

    rcvdbyte = ev.get(
        "rcvdbyte",
        0
    )

    service = ev.get(
        "service"
    ) or "—"

    date_s = ev.get(
        "date",
        ""
    )

    time_s = ev.get(
        "time",
        ""
    )

    reset_class = ev.get(
        "reset_class",
        ""
    )

    class_icon, class_label = (
        _build_reset_class_label(
            reset_class,
            action
        )
    )

    burst_1m = ev.get(
        "burst_1m"
    )

    burst_5m = ev.get(
        "burst_5m"
    )

    severity = ev.get(
        "severity",
        "NORMAL"
    )

    sev_banner = _SEVERITY_BANNER.get(
        severity,
        ""
    )

    if action == "server-rst":

        reset_text = (
            "Server reset connection from NAPAS"
        )

    elif action == "client-rst":

        reset_text = (
            "Client reset connection from SHB"
        )

    else:

        reset_text = (
            f"Reset connection ({action or '?'})"
        )

    lines = []

    if sev_banner:

        lines.append(
            sev_banner
        )

        lines.append(
            f"{'─' * 30}"
        )

    lines += [

        f"{icon} <b>{verb}</b>",

        f"{'─' * 30}",

        f"{dev_icon} "
        f"<b>Thiết bị     :</b> "
        f"<code>{device_name}</code>",

        f"🔧 "
        f"<b>Platform     :</b> "
        f"<code>{platform}</code>",

        f"📡 "
        f"<b>Source (SHB) :</b> "
        f"<code>{src_ip}:{src_port}</code>",

        f"🎯 "
        f"<b>Dest (NAPAS) :</b> "
        f"<code>{dst_disp}:{dst_port}</code>",

        f"🧾 "
        f"<b>Service      :</b> "
        f"<code>{service}</code>",

        f"🏷  "
        f"<b>Policy ID    :</b> "
        f"<code>{policy}</code>",

        f"🔑 "
        f"<b>Session ID   :</b> "
        f"<code>{session}</code>",

        f"🔄 "
        f"<b>Reset        :</b> "
        f"{reset_text}",

        f"⏱️ "
        f"<b>Duration     :</b> "
        f"<code>{duration}s</code> "
        f"| TX: <code>{sentbyte}B</code> "
        f"| RX: <code>{rcvdbyte}B</code>",

        f"🕐 "
        f"<b>Thời gian    :</b> "
        f"<code>{date_s} {time_s}</code>",
    ]

    if class_label:

        lines.append(
            f"{class_icon} "
            f"<b>Phân loại    :</b> "
            f"{class_label}"
        )

    if (
        burst_1m is not None
        and burst_5m is not None
    ):

        lines.append(
            f"📊 "
            f"<b>Tần suất     :</b> "
            f"{burst_1m} lần RESET trong 1 phút, "
            f"{burst_5m} lần trong 5 phút"
        )

    return "\n".join(lines)


# ============================================================
# SYSTEM ALERT
# ============================================================

def build_alert_system(
    title: str,
    message: str,
    severity: str = "warning"
) -> str:

    icon = {
        "warning": "⚠️",
        "critical": "🆘",
        "recovered": "✅",
    }.get(
        severity,
        "⚠️"
    )

    lines = [

        f"{icon} <b>{title}</b>",

        f"{'─' * 30}",

        message,

        f"{'─' * 30}",

        f"🕐 "
        f"<code>"
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        f"</code>",
    ]

    return "\n".join(lines)


# ============================================================
# GENERAL WINDOW SUMMARY
# ============================================================

def build_alert_window_summary(
    stats: dict,
    window_minutes: int,
    device_name: str = "?",
    platform: str = "FortiGate",
    severity: str = "NORMAL"
) -> str:

    dev_icon = _DEV_ICON.get(
        device_name,
        "🖥"
    )

    total = stats.get(
        "count",
        0
    )

    server = stats.get(
        "server",
        0
    )

    client = stats.get(
        "client",
        0
    )

    fast = stats.get(
        "fast",
        0
    )

    long_ = stats.get(
        "long",
        0
    )

    first_t = stats.get(
        "first_time"
    ) or "—"

    last_t = stats.get(
        "last_time"
    ) or "—"

    sev_banner = _SEVERITY_BANNER.get(
        severity,
        ""
    )

    lines = []

    if sev_banner:

        lines.append(
            sev_banner
        )

        lines.append(
            f"{'─' * 30}"
        )

    lines += [

        f"📈 "
        f"<b>TỔNG HỢP {window_minutes} PHÚT GẦN NHẤT</b>",

        f"{'─' * 30}",

        f"{dev_icon} "
        f"<b>Thiết bị     :</b> "
        f"<code>{device_name}</code>",

        f"🔧 "
        f"<b>Platform     :</b> "
        f"<code>{platform}</code>",

        f"📊 "
        f"<b>Tổng số RESET:</b> "
        f"<b>{total}</b> phiên",

        f"   └ server-rst (NAPAS): "
        f"{server}  |  "
        f"client-rst (SHB): {client}",

        f"   └ ⚡ Reset nhanh (≤5s): "
        f"{fast}  |  "
        f"⏳ Sau kết nối kéo dài: {long_}",

        f"🕐 "
        f"<b>Từ:</b> "
        f"<code>{first_t}</code>  "

        f"<b>đến:</b> "
        f"<code>{last_t}</code>",
    ]

    if total == 0:

        lines.append(
            f"✅ "
            f"<i>Không có phiên RESET nào "
            f"trong {window_minutes} phút qua</i>"
        )

    return "\n".join(lines)


# ============================================================
# CLIENT GROUP THRESHOLD ALERT
# ============================================================

_CATEGORY_DISPLAY = {

    "SERVER_FAST": (
        "🔴",
        "NAPAS SERVER RESET (NHANH ≤5s)"
    ),

    "SERVER_LONG": (
        "🔴",
        "NAPAS SERVER RESET (SAU KẾT NỐI KÉO DÀI)"
    ),

    "CLIENT_FAST": (
        "🟠",
        "SHB CLIENT RESET (NHANH ≤5s)"
    ),

    "CLIENT_LONG": (
        "🟠",
        "SHB CLIENT RESET (SAU KẾT NỐI KÉO DÀI)"
    ),
}


def build_alert_group_threshold(
    status: str,
    category: str,
    service: str,
    dst_ip: str,
    policy: str,
    burst_1m: int,
    burst_5m: int,
    thresholds: dict,
    device_name: str = "?",
    platform: str = "FortiGate"
) -> str:

    status_icon = {
        "WARNING": "⚠️",
        "CRITICAL": "🆘",
        "RECOVERED": "✅",
    }.get(
        status,
        "⚠️"
    )

    cat_icon, cat_label = _CATEGORY_DISPLAY.get(
        category,
        ("ℹ️", category)
    )

    dev_icon = _DEV_ICON.get(
        device_name,
        "🖥"
    )

    napas_dc = _NAPAS_DC_LABEL.get(
        dst_ip,
        ""
    )

    dst_disp = (
        f"{dst_ip} ({napas_dc})"
        if napas_dc
        else dst_ip
    )

    title = (
        f"{status_icon} "
        f"<b>{status} — {cat_label}</b>"
    )

    lines = [

        title,

        f"{'─' * 30}",

        f"{dev_icon} "
        f"<b>Thiết bị    :</b> "
        f"<code>{device_name}</code>",

        f"🔧 "
        f"<b>Platform    :</b> "
        f"<code>{platform}</code>",

        f"🧾 "
        f"<b>Service     :</b> "
        f"<code>{service}</code>",

        f"🎯 "
        f"<b>Destination :</b> "
        f"<code>{dst_disp}</code>",

        f"🏷  "
        f"<b>Policy ID   :</b> "
        f"<code>{policy}</code>",

        f"{'─' * 30}",

        f"{cat_icon} "
        f"<b>{cat_label}:</b>",

        f"   1 phút : <b>{burst_1m}</b>",

        f"   5 phút : <b>{burst_5m}</b>",
    ]

    if status != "RECOVERED":

        warn_1m = thresholds.get(
            "warning_1m",
            "—"
        )

        warn_5m = thresholds.get(
            "warning_5m",
            "—"
        )

        crit_1m = thresholds.get(
            "critical_1m",
            "—"
        )

        crit_5m = thresholds.get(
            "critical_5m",
            "—"
        )

        lines.append(
            f"{'─' * 30}"
        )

        lines.append(
            "<b>Threshold:</b>"
        )

        lines.append(
            f"   Warning  : "
            f"≥{warn_1m}/1 phút "
            f"hoặc ≥{warn_5m}/5 phút"
        )

        lines.append(
            f"   Critical : "
            f"≥{crit_1m}/1 phút "
            f"hoặc ≥{crit_5m}/5 phút"
        )

    else:

        lines.append(
            f"{'─' * 30}"
        )

        lines.append(
            "✅ "
            "<i>Đã trở về dưới ngưỡng cảnh báo.</i>"
        )

    lines.append(
        f"{'─' * 30}"
    )

    lines.append(
        f"<b>Status:</b> {status}"
    )

    return "\n".join(lines)


# ============================================================
# IMMEDIATE NAPAS SERVER RESET
# ============================================================

def build_alert_server_reset_immediate(
    ev: dict,
    device_name: str = "?",
    platform: str = "FortiGate"
) -> str:
    """
    Alert tuc thoi khi phat hien NAPAS server-rst.

    QUAN TRONG:
    - Khong loc theo Duration.
    - Duration > 5s van alert.
    - Duration chi hien thi thong tin.
    """

    dst_ip = ev.get(
        "dstip",
        "—"
    )

    napas_label = _NAPAS_DC_LABEL.get(
        dst_ip,
        dst_ip
    )

    dev_icon = _DEV_ICON.get(
        device_name,
        "🖥"
    )

    duration = ev.get(
        "duration",
        0
    )

    sentbyte = ev.get(
        "sentbyte",
        0
    )

    rcvdbyte = ev.get(
        "rcvdbyte",
        0
    )

    action = str(
        ev.get(
            "action",
            ""
        )
    ).lower()

    if action == "server-rst":

        reset_text = (
            "Server reset connection from NAPAS"
        )

    elif action == "client-rst":

        reset_text = (
            "Client reset connection from SHB"
        )

    else:

        reset_text = (
            f"Reset connection ({action or '?'})"
        )

    lines = [

        "🆘 "
        "<b>CRITICAL — NAPAS SERVER RESET</b>",

        f"{'─' * 30}",

        f"🔒 "
        f"<b>Thiết bị     :</b> "
        f"<code>{device_name}</code>",

        f"🔧 "
        f"<b>Platform     :</b> "
        f"<code>{platform}</code>",

        f"📡 "
        f"<b>Source (SHB) :</b> "
        f"<code>"
        f"{ev.get('srcip', '?')}:"
        f"{ev.get('srcport', '?')}"
        f"</code>",

        f"🎯 "
        f"<b>Dest (NAPAS) :</b> "
        f"<code>{napas_label}</code> "
        f"(<code>"
        f"{dst_ip}:"
        f"{ev.get('dstport', '?')}"
        f"</code>)",

        f"🧾 "
        f"<b>Service      :</b> "
        f"<code>{ev.get('service', '?')}</code>",

        f"🏷  "
        f"<b>Policy ID    :</b> "
        f"<code>{ev.get('policyid', '?')}</code>",

        f"🔑 "
        f"<b>Session ID   :</b> "
        f"<code>{ev.get('sessionid', '?')}</code>",

        f"🔄 "
        f"<b>Reset        :</b> "
        f"{reset_text}",

        f"⏱️ "
        f"<b>Duration     :</b> "
        f"<code>{duration}s</code> "
        f"| TX: <code>{sentbyte}B</code> "
        f"| RX: <code>{rcvdbyte}B</code>",

        f"🕐 "
        f"<b>Thời gian    :</b> "
        f"<code>"
        f"{ev.get('date', '?')} "
        f"{ev.get('time', '?')}"
        f"</code>",

        f"⚠️ "
        f"<b>Action       :</b> "
        f"Owner kiểm tra dịch vụ sang NAPAS.",

        f"📊 "
        f"<b>Tiếp theo    :</b> "
        f"Hệ thống sẽ tổng hợp số lần NAPAS reset trong 10 phút.",
    ]

    return "\n".join(lines)


# ============================================================
# NAPAS SERVER RESET 10-MIN SUMMARY
# ============================================================

def build_alert_server_reset_summary(
    total: int,
    per_server: dict,
    window_minutes: int,
    period_start: str,
    period_end: str,
    high_rate_per_min: float = 3.0,
    device_name: str = "?",
    platform: str = "FortiGate"
) -> str:
    """
    Tong hop NAPAS server-rst sau cua so 10 phut.

    high_rate_per_min:
        Chi dung de danh gia muc do tan suat.
        KHONG dung de loc alert server-rst dau tien.
    """

    dev_icon = _DEV_ICON.get(
        device_name,
        "🖥"
    )

    rate = (
        total / window_minutes
        if window_minutes
        else 0.0
    )

    top_servers = sorted(
        per_server.items(),
        key=lambda kv: -kv[1]
    )

    lines = [

        f"📊 "
        f"<b>NAPAS SERVER RESET – "
        f"{window_minutes} MIN SUMMARY</b>",

        f"{'─' * 30}",

        f"{dev_icon} "
        f"<b>Thiết bị       :</b> "
        f"<code>{device_name}</code> "
        f"({platform})",

        f"⏱️ "
        f"<b>Period         :</b> "
        f"<code>{period_start}</code> "
        f"→ "
        f"<code>{period_end}</code>",

        f"🔴 "
        f"<b>Total Server Reset :</b> "
        f"<b>{total}</b> lần",

        f"🖥️ "
        f"<b>Affected Server   :</b> "
        f"<b>{len(per_server)}</b> server(s)",

        f"{'─' * 30}",

        "<b>Top Reset:</b>",
    ]

    if not top_servers:

        lines.append(
            "   • Không có server reset."
        )

    else:

        for dst_ip, count in top_servers[:5]:

            label = _NAPAS_DC_LABEL.get(
                dst_ip,
                dst_ip
            )

            lines.append(
                f"   • {label} "
                f"(<code>{dst_ip}</code>): "
                f"<b>{count}</b> lần"
            )

        if len(top_servers) > 5:

            lines.append(
                f"   • ... và "
                f"{len(top_servers) - 5} "
                f"server khác"
            )

    lines.append(
        f"{'─' * 30}"
    )

    lines.append(
        f"📈 "
        f"<b>Reset Rate</b> : "
        f"{rate:.1f}/phút"
    )

    if rate >= high_rate_per_min:

        lines.append(
            "🚨 "
            "<b>Đánh giá</b>: "
            "Tần suất NAPAS reset cao, "
            "cần Owner kiểm tra và xử lý."
        )

    else:

        lines.append(
            "ℹ️ "
            "<b>Đánh giá</b>: "
            f"Tần suất NAPAS reset chưa vượt "
            f"ngưỡng {high_rate_per_min:.1f}/phút, "
            "tiếp tục theo dõi."
        )

    return "\n".join(lines)


# ============================================================
# TELEGRAM TEST
# ============================================================

def send_test(
    token: str,
    chat_id: str,
    devices: list,
    faz_ok: bool
) -> bool:

    now = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    lines = [

        "📡 "
        "<b>Hệ thống giám sát Firewall "
        "qua FortiAnalyzer</b>",

        f"🕐 "
        f"Thời gian: "
        f"<code>{now}</code>",

        f"📊 "
        f"Kết nối FAZ API: "
        + (
            "✅ <b>SUCCESS</b>"
            if faz_ok
            else "❌ <b>FAILED</b>"
        ),
    ]

    return _send_raw(
        token,
        chat_id,
        "\n".join(lines)
    )