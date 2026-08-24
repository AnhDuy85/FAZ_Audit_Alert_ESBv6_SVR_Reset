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


def classify_severity(burst_5m: int, critical_threshold: int = 20, warning_threshold: int = 5) -> str:
    """
    Phan loai MUC DO NGHIEM TRONG dua tren TAN SUAT (burst_5m - so lan
    RESET trong 5 phut gan nhat), KHONG phai dua tren duration cua 1
    phien don le. Day la co so DE CAN BO OWNER QUYET DINH CO CAN XU LY
    GAP HAY KHONG - khac voi classify_reset_duration() (chi mo ta 1
    phien rieng le nhanh/cham).

    Ly do dung burst_5m thay vi duration: 1 phien RESET rieng le (du la
    server-rst hay client-rst, nhanh hay cham) thuong la BINH THUONG
    (co the do ung dung tu dong reconnect, do mang thoang qua...). Nhung
    NHIEU phien RESET LIEN TUC trong thoi gian ngan (vi du 48 lan/5 phut)
    la dau hieu RO RANG cua SU CO THAT (NAPAS tu choi hang loat, hoac
    loi cau hinh/service tren SHB).

    Nguong mac dinh (co the chinh qua settings.json ->
    reset_monitor.severity_critical_burst / severity_warning_burst):
      - CRITICAL: burst_5m >= 20  (vi du: 48 lan/5 phut da quan sat thuc te)
      - WARNING : burst_5m >= 5 va < 20
      - NORMAL  : burst_5m < 5   (vi du: 2 lan/5 phut da quan sat thuc te)
    """
    if burst_5m >= critical_threshold:
        return "CRITICAL"
    if burst_5m >= warning_threshold:
        return "WARNING"
    return "NORMAL"


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


def classify_category(action: str, reset_class: str) -> str:
    """
    Phan loai 1 phien RESET vao 1 trong 4 nhom (category), ket hop
    HUONG (server-rst=NAPAS chu dong / client-rst=SHB chu dong) VOI
    TOC DO (FAST_RESET <=5s / LONG_CONN_RESET >5s):

      SERVER_FAST  - NAPAS reset GAN NHU NGAY LAP TUC - dau hieu RO
                      RANG request bi tu choi/khong xu ly duoc phia
                      NAPAS. Category QUAN TRONG NHAT, can nhay nhat.
      CLIENT_LONG  - SHB tu dong dong ket noi sau khi da hoat dong 1
                      thoi gian - THUONG LA BINH THUONG (het session,
                      app tu dong ket thuc, timeout thong thuong).
      SERVER_LONG  - NAPAS dong ket noi sau khi da hoat dong lau - it
                      dang lo ngai hon SERVER_FAST.
      CLIENT_FAST  - SHB tu reset ngay lap tuc - co the la loi cau hinh/
                      logic phia SHB, dang chu y trung binh.

    4 nhom nay co Y NGHIA VAN HANH KHAC NHAU HOAN TOAN, KHONG duoc gop
    chung 1 threshold - xem classify_group_severity() va
    settings.json -> reset_monitor.threshold_matrix.
    """
    side  = "SERVER" if action == "server-rst" else "CLIENT" if action == "client-rst" else "OTHER"
    speed = "FAST" if reset_class == "FAST_RESET" else "LONG"
    return f"{side}_{speed}"


def group_key(ev: dict, category: str) -> str:
    """
    Khoa nhom de dem tan suat THEO TUNG SERVICE/DESTINATION RIENG,
    KHONG cong don toan bo firewall lai voi nhau - tranh truong hop
    3 service khac nhau moi service 2 reset (binh thuong) bi cong
    thanh 6 reset roi bao dong sai.

    Gom: policyid + service + dstip + category (huong+toc do).
    """
    return f"{ev.get('policyid') or '-'}|{ev.get('service') or '-'}|{ev.get('dstip') or '-'}|{category}"


def classify_group_severity(burst_1m: int, burst_5m: int, thresholds: dict) -> str:
    """
    Phan loai NORMAL/WARNING/CRITICAL cho 1 GROUP (khong phai 1 event
    rieng le), dua tren nguong RIENG cua category do (xem
    settings.json -> reset_monitor.threshold_matrix). Dung logic OR:
    vuot NGUONG 1 PHUT HOAC nguong 5 PHUT la du de nang muc, khong can
    ca 2 cung vuot.

    thresholds: dict co cac key warning_1m/warning_5m/critical_1m/critical_5m.
    Thieu key nao thi coi nhu khong co dieu kien do (khong bao gio kich hoat).
    """
    crit_1m = thresholds.get("critical_1m")
    crit_5m = thresholds.get("critical_5m")
    if (crit_1m is not None and burst_1m >= crit_1m) or (crit_5m is not None and burst_5m >= crit_5m):
        return "CRITICAL"

    warn_1m = thresholds.get("warning_1m")
    warn_5m = thresholds.get("warning_5m")
    if (warn_1m is not None and burst_1m >= warn_1m) or (warn_5m is not None and burst_5m >= warn_5m):
        return "WARNING"

    return "NORMAL"


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