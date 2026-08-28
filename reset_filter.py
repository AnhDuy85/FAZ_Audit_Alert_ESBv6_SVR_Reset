"""
reset_filter.py — Chuan hoa log TRAFFIC (server-rst / client-rst) tu FAZ
sang dinh dang chuan de reset_monitor.py / telegram_notify.py xu ly.
"""

from datetime import datetime, timezone


def _to_int(val, default=0):
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def classify_reset_duration(duration: int) -> str:
    """
    Phan loai muc do dua tren thoi gian song cua phien truoc khi bi RESET:

    - "FAST_RESET"      : duration <= 5s - ket noi bi tu choi/reset GAN NHU
                          NGAY LAP TUC sau khi thiet lap (pattern thay
                          nhieu lan lien tuc voi sent~60B/rcvd~40B, dien
                          hinh cua bat tay TCP bi tu choi o tang ung dung
                          hoac firewall/NAPAS chan). Dang can chu y hon.
    - "LONG_CONN_RESET" : duration > 5s - ket noi da truyen du lieu mot
                          thoi gian (vai chuc giay den vai ngay) truoc
                          khi bi reset - co the la ket thuc phien binh
                          thuong hoac ket noi "treo" qua lau moi bi don
                          dep (vi du duration hang tram nghin giay).

    Nguong 5s la uoc luong ban dau dua tren du lieu thuc te da quan sat
    (nhieu phien server-rst lap lai voi duration=5s dung 1 mau) - co the
    chinh lai neu thuc te co nguong khac phu hop hon.
    """
    return "FAST_RESET" if duration <= 5 else "LONG_CONN_RESET"


def normalize_reset_event(row: dict) -> dict:
    """
    Chuan hoa 1 dong log traffic (server-rst/client-rst) tu FAZ.

    Cac field da doi chieu voi raw log thuc te (xem faz_client.py):
      date, time, action, srcip, dstip, srcport, dstport, policyid,
      sessionid, duration, sentbyte, rcvdbyte, service, app.
    """
    if not row:
        return {}

    # ve chu thuong / xoa ky tu dac biet o key, tranh truong hop FAZ tra
    # ve key khac hoa (vi du "SrcIP" thay vi "srcip")
    raw = {}
    for k, v in row.items():
        clean_key = str(k).lower().replace(" ", "").replace("/", "").replace("_", "").replace("-", "")
        raw[clean_key] = v

    action_val = str(raw.get("action") or "").lower()

    date_val = raw.get("date") or ""
    time_val = raw.get("time") or raw.get("itime") or ""
    # "itime" trong raw log co dang "2026-08-20 09:58:24" (date+time gop) -
    # neu date/time rieng da co san (truong hop thuong gap) thi uu tien
    # dung truc tiep, chi tach itime khi thieu.
    if (not date_val or not time_val) and raw.get("itime"):
        parts = str(raw["itime"]).strip().split()
        if len(parts) >= 2:
            date_val = date_val or parts[0]
            time_val = parts[1]

    duration_val = _to_int(raw.get("duration"))

    return {
        "action":      action_val,               # server-rst / client-rst
        "date":        date_val,
        "time":        time_val,
        "srcip":       raw.get("srcip") or "",
        "dstip":       raw.get("dstip") or "",
        "srcport":     _to_int(raw.get("srcport")),
        "dstport":     _to_int(raw.get("dstport")),
        "policyid":    raw.get("policyid") or "",
        "sessionid":   raw.get("sessionid") or "",
        "duration":    duration_val,
        "sentbyte":    _to_int(raw.get("sentbyte")),
        "rcvdbyte":    _to_int(raw.get("rcvdbyte")),
        "service":     raw.get("service") or "",
        "app":         raw.get("app") or "",
        "reset_class": classify_reset_duration(duration_val),
    }


def dedup_key(ev: dict) -> tuple:
    """Khoa dedup 1 phien reset - dung sessionid neu co, fallback ve
    (srcip, dstip, srcport, dstport, date, time)."""
    if ev.get("sessionid"):
        return ("sid", ev["sessionid"])
    return ("nosid", ev.get("srcip"), ev.get("dstip"), ev.get("srcport"),
            ev.get("dstport"), ev.get("date"), ev.get("time"))


def _parse_event_dt(ev: dict):
    try:
        return datetime.strptime(f"{ev.get('date')} {ev.get('time')}", "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return None


def enrich_burst_counts(events: list) -> list:
    """
    Voi 1 list events da qua normalize_reset_event(), tinh THEM 2 field
    moi cho MOI event:
      - burst_1m: so luong RESET (ca server-rst + client-rst gop chung)
                  xay ra trong vong 1 PHUT TINH LUI VE TRUOC tu thoi
                  diem cua chinh event do (bao gom ca chinh no).
      - burst_5m: tuong tu, cua so 5 PHUT.

    Dem tren TOAN BO cac phien khop dieu kien SHB<->NAPAS trong CUNG 1
    LAN QUET (khong phan biet srcip/dstip cu the) - phan anh muc do
    "dot/burst" RESET tong the, giup nhan biet nhanh khi co nhieu ket
    noi bi reset lien tuc trong thoi gian ngan.

    LUU Y: chi dem duoc trong PHAM VI DA TRUY VAN (vi du
    interval_minutes=10 phut moi lan quet) - neu burst thuc te vuot ra
    ngoai khoang da fetch (vi du xay ra sat dau/cuoi khoang quet) thi so
    dem co the bi thieu mot phan. Khong goi them FAZ de tranh ton chi
    phi - chap nhan sai so nho o bien.
    """
    parsed = [(ev, _parse_event_dt(ev)) for ev in events]

    for ev, dt in parsed:
        if dt is None:
            ev["burst_1m"] = 1
            ev["burst_5m"] = 1
            continue
        c1 = sum(1 for _, dt2 in parsed if dt2 and 0 <= (dt - dt2).total_seconds() <= 60)
        c5 = sum(1 for _, dt2 in parsed if dt2 and 0 <= (dt - dt2).total_seconds() <= 300)
        ev["burst_1m"] = c1
        ev["burst_5m"] = c5

    return events