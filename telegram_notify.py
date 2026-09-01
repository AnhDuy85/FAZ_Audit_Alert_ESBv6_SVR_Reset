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
import time
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
    "10.1.249.2": "NAPAS-PROD-DC2",
    "10.1.253.2": "NAPAS-PROD-DC1",
}

_RESET_ACTION_HEADER = {
    "server-rst": ("🔴", "SERVER RESET (NAPAS RESET KẾT NỐI)"),
    "client-rst": ("🟠", "CLIENT RESET (SHB RESET KẾT NỐI)"),
}

# Banner muc do nghiem trong dua tren TAN SUAT - dung boi build_alert_reset()
# (legacy, chi con dung trong debug_reset.py --send) - hien o DAU tin de
# can bo owner thay NGAY tam quan trong, khong can doc het tin moi biet.
_SEVERITY_BANNER = {
    "CRITICAL": "🔴🔴🔴 <b>CẢNH BÁO NGHIÊM TRỌNG — TẦN SUẤT RESET RẤT CAO</b> 🔴🔴🔴",
    "WARNING":  "🟠 <b>CẢNH BÁO — TẦN SUẤT RESET TĂNG BẤT THƯỜNG</b>",
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


def _send_raw(token: str, chat_id: str, text: str, max_retries: int = 3) -> bool:
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

    # Timeout tang tu 30s (truoc day 15s - qua ngan, de bi "read operation
    # timed out" khi mang cham/qua proxy cong ty). THU LAI toi da
    # max_retries lan neu loi mang (khong retry neu Telegram tra ve loi
    # nghiep vu ro rang nhu sai token/chat_id - retry se khong giai quyet
    # duoc loi do).
    last_exc = None
    for attempt in range(1, max_retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                body = json.loads(r.read().decode("utf-8"))

            if body.get("ok"):
                log.info("Telegram OK   msg_id=%s", body["result"]["message_id"])
                return True
            log.error("Telegram FAIL (loi nghiep vu, khong retry): %s", body)
            return False

        except Exception as e:
            last_exc = e
            log.warning("Telegram exception (lan %d/%d): %s", attempt, max_retries, e)
            if attempt < max_retries:
                time.sleep(2 * attempt)  # backoff: 2s, 4s, ...

    log.error("Telegram FAIL sau %d lan thu - loi cuoi: %s", max_retries, last_exc)
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
    severity = ev.get("severity", "NORMAL")
    sev_banner = _SEVERITY_BANNER.get(severity, "")

    lines = []
    if sev_banner:
        lines.append(sev_banner)
        lines.append(f"{'─' * 30}")
    lines += [
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


_DIRECTION_LABEL = {
    "SERVER": {
        "title_immediate": "NAPAS SERVER RESET",
        "title_summary":   "NAPAS SERVER RESET",
        "actor":           "NAPAS",
        "reset_from":      "Server reset connection from NAPAS",
        "action_hint":     "Owner kiểm tra dịch vụ sang NAPAS.",
        "total_label":     "Total Server Reset",
        "affected_label":  "Affected Server",
        "top_label":       "Top Reset",
    },
    "CLIENT": {
        "title_immediate": "SHB CLIENT RESET",
        "title_summary":   "SHB CLIENT RESET",
        "actor":           "SHB",
        "reset_from":      "Client reset connection from SHB",
        "action_hint":     "Owner kiểm tra ứng dụng/kết nối phía SHB.",
        "total_label":     "Total Client Reset",
        "affected_label":  "Affected Server (NAPAS)",
        "top_label":       "Top Reset (theo NAPAS server)",
    },
}


def build_alert_reset_window_immediate(direction: str, ev: dict, window_minutes: int = 10,
                                         device_name: str = "?", platform: str = "FortiGate") -> str:
    """
    Alert TUC THOI khi phat hien 1 phien RESET (server-rst HOAC
    client-rst - xac dinh boi `direction`="SERVER"/"CLIENT"), KHONG phan
    biet FAST/LONG - ban than su kien reset da la dieu can canh bao ngay
    de NOC/IT xu ly su co + dam bao dich vu, khong can cho tich luy.

    Day la alert MO CUA SO tong hop `window_minutes` phut RIENG cho tung
    huong (xem reset_monitor.py -> state["srv_window_*"] cho SERVER,
    state["cli_window_*"] cho CLIENT - 2 cua so DOC LAP nhau) - CHI gui 1
    lan cho MOI cua so (khi phat hien phien DAU TIEN cua 1 dot reset),
    cac phien tiep theo trong cung cua so CHI duoc ghi nhan, KHONG gui
    alert rieng (tranh alert storm).
    """
    lbl = _DIRECTION_LABEL[direction]
    dst_ip = ev.get("dstip", "—")
    napas_label = _NAPAS_DC_LABEL.get(dst_ip, dst_ip)
    dev_icon = _DEV_ICON.get(device_name, "🖥")
    duration = ev.get("duration", 0)
    sentbyte = ev.get("sentbyte", 0)
    rcvdbyte = ev.get("rcvdbyte", 0)

    lines = [
        f"🆘 <b>CRITICAL — {lbl['title_immediate']}</b>",
        f"{'─' * 30}",
        f"{dev_icon} <b>Thiết bị</b> : <code>{device_name}</code>",
        f"🔧 <b>Platform</b> : <code>{platform}</code>",
        f"📡 <b>Source (SHB)</b> : <code>{ev.get('srcip','?')}:{ev.get('srcport','?')}</code>",
        f"🎯 <b>Dest (NAPAS)</b> : <code>{napas_label}</code> (<code>{dst_ip}:{ev.get('dstport','?')}</code>)",
        f"🧾 <b>Service</b> : <code>{ev.get('service','?')}</code>",
        f"🏷 <b>Policy ID</b> : <code>{ev.get('policyid','?')}</code>",
        f"🔑 <b>Session ID</b> : <code>{ev.get('sessionid','?')}</code>",
        f"🔄 <b>Reset</b> : {lbl['reset_from']}",
        f"⏱️ <b>Duration</b> : <code>{duration}s</code> | TX: <code>{sentbyte}B</code> | RX: <code>{rcvdbyte}B</code>",
        f"🕐 <b>Thời gian</b> : <code>{ev.get('date')} {ev.get('time')}</code>",
        f"⚠️ <b>Action</b> : {lbl['action_hint']}",
        #f"📊 <b>Tiếp theo</b> : Hệ thống sẽ tổng hợp số lần {lbl['actor']} reset trong {window_minutes} phút.",
    ]
    return "\n".join(lines)


def build_alert_reset_window_summary(direction: str, total: int, per_server: dict, window_minutes: int,
                                       period_start: str, period_end: str,
                                       high_rate_per_min: float = 3.0,
                                       device_name: str = "?", platform: str = "FortiGate") -> str:
    """
    Tin TONG HOP sau khi CUA SO tong hop (mo boi
    build_alert_reset_window_immediate) da du window_minutes phut - gui
    DUY NHAT 1 LAN khi dong cua so, dem breakdown theo TUNG SERVER NAPAS
    (destination IP) bi anh huong - dung chung cho ca 2 huong SERVER/CLIENT.

    per_server: dict {dstip: so_lan_reset}.
    """
    lbl = _DIRECTION_LABEL[direction]
    dev_icon = _DEV_ICON.get(device_name, "🖥")
    rate = (total / window_minutes) if window_minutes else 0.0
    top_servers = sorted(per_server.items(), key=lambda kv: -kv[1])

    lines = [
        f"📊 <b>{lbl['title_summary']} – {window_minutes} MIN SUMMARY</b>",
        f"{'─' * 30}",
        f"{dev_icon} <b>Thiết bị</b>       : <code>{device_name}</code> ({platform})",
        f"⏱️ <b>Period</b>        : <code>{period_start}</code> → <code>{period_end}</code>",
        f"🔴 <b>{lbl['total_label']}</b> : <b>{total}</b> lần",
        f"🖥️ <b>{lbl['affected_label']}</b>   : <b>{len(per_server)}</b> server(s)",
        f"{'─' * 30}",
        f"<b>{lbl['top_label']}:</b>",
    ]
    for dst_ip, cnt in top_servers[:5]:
        label = _NAPAS_DC_LABEL.get(dst_ip, dst_ip)
        lines.append(f"   • {label} (<code>{dst_ip}</code>): <b>{cnt}</b> lần")
    if len(top_servers) > 5:
        lines.append(f"   • ... và {len(top_servers) - 5} server khác")

    lines.append(f"{'─' * 30}")
    lines.append(f"📈 <b>Reset Rate</b> : {rate:.1f}/phút")
    if rate >= high_rate_per_min:
        lines.append("📌 <b>Đánh giá</b>: Reset xảy ra liên tục, cần tiếp tục theo dõi/xử lý.")
    else:
        lines.append("📌 <b>Đánh giá</b>: Tần suất reset ở mức chấp nhận được, tiếp tục theo dõi.")
    lines.append(f"🔁 <i>Vẫn đang trong đợt sự cố — sẽ tiếp tục tổng hợp mỗi {window_minutes} phút cho đến khi hết reset.</i>")
    return "\n".join(lines)


def build_alert_reset_window_resolved(direction: str, window_minutes: int,
                                        device_name: str = "?", platform: str = "FortiGate") -> str:
    """
    Tin RESOLVED - gui khi 1 chu ky window_minutes phut TRON VEN KHONG
    co phien RESET moi nao (cho huong nay) - bao hieu dot su co da ket
    thuc/duoc xu ly xong. Sau tin nay, cua so DONG HOAN TOAN - lan
    RESET tiep theo (cung huong) se lai trigger ALERT TUC THOI + mo dot
    moi tu dau (xem reset_monitor.py).
    """
    lbl = _DIRECTION_LABEL[direction]
    dev_icon = _DEV_ICON.get(device_name, "🖥")

    lines = [
        f"✅ <b>RESOLVED — {lbl['title_summary']}</b>",
        f"{'─' * 30}",
        f"{dev_icon} <b>Thiết bị</b> : <code>{device_name}</code> ({platform})",
        f"{'─' * 30}",
        f"✅ Không phát hiện thêm phiên {lbl['actor']} reset nào trong {window_minutes} phút qua.",
        f"📌 <b>Đánh giá</b>: Đợt sự cố đã kết thúc / được xử lý xong.",
    ]
    return "\n".join(lines)


# Giu lai 2 ham cu (build_alert_server_reset_immediate/summary) duoi dang
# alias goi thang toi ham tong quat, de tuong thich nguoc voi code/test cu.
def build_alert_server_reset_immediate(ev: dict, device_name: str = "?", platform: str = "FortiGate") -> str:
    return build_alert_reset_window_immediate("SERVER", ev, device_name, platform)


def build_alert_server_reset_summary(total: int, per_server: dict, window_minutes: int,
                                       period_start: str, period_end: str,
                                       high_rate_per_min: float = 3.0,
                                       device_name: str = "?", platform: str = "FortiGate") -> str:
    return build_alert_reset_window_summary("SERVER", total, per_server, window_minutes,
                                              period_start, period_end, high_rate_per_min,
                                              device_name, platform)