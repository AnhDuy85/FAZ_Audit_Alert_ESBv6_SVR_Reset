#!/usr/bin/env python3
"""
reset_monitor.py — Canh bao RESET ket noi (server-rst / client-rst) giua
SHB (ESB) va NAPAS, doc du lieu tu FAZ LOG TRAFFIC.

Day la luong CANH BAO RIENG, DOC LAP voi monitor.py (monitor.py canh bao
THAY DOI RULE tu log EVENT/SYSTEM; script nay canh bao PHIEN KET NOI BI
RESET tu log TRAFFIC). Dung chung faz_client.py, telegram_notify.py,
settings.json/secrets.json voi monitor.py, nhung doc them block
settings["reset_monitor"].

Chay:
  python reset_monitor.py            # 1 lan
  python reset_monitor.py --loop     # lap dinh ky theo interval_minutes
  python reset_monitor.py --test     # test Telegram + FAZ connection

Cau hinh trong settings.json (xem README_reset_monitor.md hoac phan
"reset_monitor" duoc them vao settings.json):
  reset_monitor.enabled
  reset_monitor.device_name        (ten thiet bi trong devices[])
  reset_monitor.interval_minutes
  reset_monitor.max_rows
  reset_monitor.shb_src_ips        (dai IP nguon SHB/ESB)
  reset_monitor.napas_dst_ips      (dai IP dich NAPAS DC1/DC2)
  reset_monitor.dst_ports          ([35787, 35789])
  reset_monitor.watch_actions      (["server-rst", "client-rst"])
"""

import argparse
import json
import logging
import sys
import time
from datetime import datetime
from pathlib import Path

import urllib3  # type: ignore
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import faz_client as _faz
import reset_filter as _rf
import telegram_notify as _tg

FAZClient = _faz.FAZClient
FAZError  = _faz.FAZError

normalize_reset_event = _rf.normalize_reset_event
dedup_key             = _rf.dedup_key
enrich_burst_counts    = _rf.enrich_burst_counts
_send_raw              = _tg._send_raw
build_alert_reset      = _tg.build_alert_reset
build_alert_system     = _tg.build_alert_system
build_alert_window_summary = _tg.build_alert_window_summary

LOG_DIR   = _ROOT / "logs"
LOG_FILE  = LOG_DIR / "reset_monitor.log"
CFG_FILE  = _ROOT / "settings.json"
SEC_FILE  = _ROOT / "secrets.json"
SEEN_FILE  = LOG_DIR / "reset_seen.json"    # dedup giua cac lan chay (tranh spam khi interval overlap)
STATE_FILE = LOG_DIR / "monitor_state.json"  # dem loi lien tiep, cho co che canh bao he thong (#1)

LOG_DIR.mkdir(exist_ok=True)
logging.basicConfig(
    level   = logging.INFO,
    format  = "%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt = "%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
    ],
)
log = logging.getLogger("reset_monitor")


def load_config() -> dict:
    if not CFG_FILE.exists() or not SEC_FILE.exists():
        log.error("Thieu file cau hinh settings.json hoac secrets.json")
        raise SystemExit(1)
    try:
        cfg = json.loads(CFG_FILE.read_text(encoding="utf-8"))
        sec = json.loads(SEC_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        log.error("JSON loi: %s", e)
        raise SystemExit(1)

    cfg["telegram"]["bot_token"] = sec["telegram_bot_token"]
    cfg["faz"]["api_token"] = sec.get("faz_api_token", "")
    return cfg


def _load_seen() -> set:
    if not SEEN_FILE.exists():
        return set()
    try:
        raw = json.loads(SEEN_FILE.read_text(encoding="utf-8"))
        return set(tuple(k) for k in raw)
    except Exception:
        return set()


def _save_seen(seen: set):
    try:
        # Gioi han so luong luu de file khong phinh vo han
        trimmed = list(seen)[-5000:]
        SEEN_FILE.write_text(json.dumps([list(k) for k in trimmed], ensure_ascii=False), encoding="utf-8")
    except Exception as e:
        log.warning("Khong ghi duoc %s: %s", SEEN_FILE, e)


def _load_state() -> dict:
    """
    State rieng cho:
      (a) co che canh bao he thong (#1): dem so lan FAZ query LOI LIEN TIEP.
      (b) TONG HOP dinh ky (moi summary_interval_minutes phut): tich luy
          so dem RESET qua NHIEU LAN CHAY (quan trong khi
          interval_minutes=1 - 1 lan quet KHONG du du lieu cho 1 tong
          hop 5 phut, phai cong don qua state).

    Neu STATE_FILE khong con (vi du AWX khong co persistent volume,
    workspace bi xoa moi lan chay), ham nay tra ve trang thai rong -
    KHONG crash, nhung ca 2 co che (a) va (b) se KHONG hoat dong dung
    qua cac lan chay rieng biet (chi dung trong pham vi 1 lan --loop dai).
    """
    default = {
        "consecutive_fail": 0, "alerted_down": False,
        "window_start_ts": None, "window_count": 0, "window_server": 0,
        "window_client": 0, "window_fast": 0, "window_long": 0,
        "window_first_time": None, "window_last_time": None,
    }
    if not STATE_FILE.exists():
        return default
    try:
        loaded = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        default.update(loaded)
        return default
    except Exception:
        return default


def _save_state(state: dict):
    try:
        STATE_FILE.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")
    except Exception as e:
        log.warning("Khong ghi duoc %s: %s", STATE_FILE, e)


def _send_heartbeat(rm_cfg: dict):
    """
    Ping URL heartbeat ben ngoai (vi du healthchecks.io, Cronitor, hoac
    endpoint noi bo tuong tu) MOI LAN chay THANH CONG - day la co che
    "dead-man switch" THAT SU: neu reset_monitor.py NGUNG CHAY HOAN TOAN
    (AWX job bi xoa, cron bi tat, server sap...), chinh script se KHONG
    CON co hoi tu bao loi duoc nua - phai dua vao 1 dich vu BEN NGOAI
    theo doi "co nhan duoc ping dung han khong" va tu canh bao khi mat
    tin hieu qua lau.

    Bo qua neu KHONG cau hinh reset_monitor.heartbeat_url trong
    settings.json (mac dinh khong bat, khong bat buoc).
    """
    url = rm_cfg.get("heartbeat_url")
    if not url:
        return
    try:
        import urllib.request
        req = urllib.request.Request(url, method="GET")
        urllib.request.urlopen(req, timeout=10)
        log.debug("Heartbeat ping OK -> %s", url)
    except Exception as e:
        # Khong lam gi them - day chi la "best effort", ban than viec
        # mat heartbeat se duoc dich vu ben ngoai phat hien va canh bao,
        # khong can reset_monitor.py tu xu ly loi nay.
        log.warning("Heartbeat ping loi (bo qua): %s", e)


def run_once(cfg: dict) -> int:
    rm_cfg  = cfg.get("reset_monitor")
    tg_cfg  = cfg["telegram"]
    faz_cfg = cfg["faz"]
    devices = {d["name"]: d for d in cfg["devices"]}

    if not rm_cfg or not rm_cfg.get("enabled"):
        log.info("reset_monitor dang bi tat (settings.json -> reset_monitor.enabled=false)")
        return 0

    if not faz_cfg.get("enabled"):
        log.error("FAZ dang bi tat (enabled=false) - reset_monitor bat buoc phai co FAZ")
        return 0

    dev_name = rm_cfg["device_name"]
    dev = devices.get(dev_name)
    if not dev:
        log.error("Khong tim thay thiet bi '%s' trong devices[] cua settings.json", dev_name)
        return 0

    faz = FAZClient(faz_cfg["url"], faz_cfg["api_token"], faz_cfg.get("adom", "root"))

    minutes = rm_cfg["interval_minutes"]
    # ── Buffer: quet RONG HON interval_minutes 1 chut (mac dinh +1 phut) ──
    # de khong bo sot neu 1 lan chay bi tre/cham (nhat la khi
    # interval_minutes=1, sat voi thoi gian thuc thi cua 1 lan chay).
    # An toan vi dedup theo sessionid da tu loai bo trung lap o phan
    # overlap giua 2 lan quet lien tiep.
    query_minutes = rm_cfg.get("query_lookback_minutes", minutes + 1)
    seen = _load_seen()
    state = _load_state()
    fail_threshold = rm_cfg.get("consecutive_fail_threshold", 3)

    try:
        raw_logs = faz.query_traffic_resets(
            devname    = dev_name,
            minutes    = query_minutes,
            src_ips    = rm_cfg["shb_src_ips"],
            dst_ips    = rm_cfg["napas_dst_ips"],
            dst_ports  = rm_cfg["dst_ports"],
            actions    = rm_cfg.get("watch_actions", ["server-rst", "client-rst"]),
            max_rows   = rm_cfg.get("max_rows", 200),
        )
    except Exception as e:
        log.warning("FAZ traffic query loi (device=%s): %s", dev_name, e)

        # ── #1: Dem loi LIEN TIEP, canh bao rieng khi vuot nguong ──────
        # (thay vi im lang bo qua nhu truoc - day chinh la lo hong lon
        # nhat: token FAZ het han/network down se khong ai biet).
        state["consecutive_fail"] = state.get("consecutive_fail", 0) + 1
        _save_state(state)

        if state["consecutive_fail"] >= fail_threshold and not state.get("alerted_down"):
            msg = (
                f"FAZ traffic query LỖI <b>{state['consecutive_fail']}</b> lần liên tiếp "
                f"(thiết bị <code>{dev_name}</code>).\nLỗi gần nhất: <code>{e}</code>\n\n"
                f"⚠️ Hệ thống <b>reset_monitor.py</b> có thể đang KHÔNG hoạt động đúng "
                f"— kiểm tra <code>faz_api_token</code> hoặc kết nối mạng tới FAZ ngay."
            )
            _send_raw(tg_cfg["bot_token"], tg_cfg["chat_id"],
                       build_alert_system("HỆ THỐNG GIÁM SÁT GẶP SỰ CỐ", msg, severity="critical"))
            state["alerted_down"] = True
            _save_state(state)
        return 0

    # ── Query thanh cong: neu truoc do dang bao "down", gui alert ──────
    # "da phuc hoi" 1 lan, reset lai bo dem.
    if state.get("consecutive_fail", 0) > 0:
        if state.get("alerted_down"):
            _send_raw(
                tg_cfg["bot_token"], tg_cfg["chat_id"],
                build_alert_system(
                    "HỆ THỐNG GIÁM SÁT ĐÃ PHỤC HỒI",
                    f"FAZ traffic query đã thành công trở lại sau {state['consecutive_fail']} lần lỗi liên tiếp.",
                    severity="recovered",
                ),
            )
        state["consecutive_fail"] = 0
        state["alerted_down"] = False
        _save_state(state)

    _send_heartbeat(rm_cfg)

    num_logs = len(raw_logs) if raw_logs else 0
    log.info("FAZ traffic device=%s (%s) -> %d phien reset trong %d phut (query lookback=%d phut)",
              dev["devid"], dev_name, num_logs, minutes, query_minutes)

    total_alerts = 0
    new_seen = set(seen)

    # ── Chuan hoa TOAN BO batch truoc, roi tinh burst_1m/burst_5m tren ──
    # CHINH batch nay (khong goi them FAZ). LUU Y: voi interval_minutes
    # nho (vi du 1 phut), burst_1m/burst_5m o day CHI mang tinh tham
    # khao trong pham vi 1 lan quet - so lieu CHINH XAC qua nhieu phut
    # nam o phan TONG HOP DINH KY ben duoi (dung state["window_*"],
    # tich luy qua nhieu lan chay).
    all_events = [normalize_reset_event(row) for row in raw_logs]
    all_events = [ev for ev in all_events if ev]
    all_events = enrich_burst_counts(all_events)

    # ── Loc ra cac event CHUA gui (chua co trong seen) ──────────────────
    to_alert = []
    for ev in all_events:
        key = dedup_key(ev)
        if key in seen:
            continue
        new_seen.add(key)
        to_alert.append(ev)

    # ── LUON gui alert NGAY LAP TUC cho TUNG phien moi phat hien - ──────
    # KHONG con gop/giu lai nua (theo yeu cau: "co canh bao thi canh bao
    # luon"). Viec tong hop dem so lan la CONG THEM o duoi, khong thay
    # the alert ca nhan nay.
    for ev in to_alert:
        alert_text = build_alert_reset(ev, device_name=dev_name, platform=dev.get("platform", "FortiGate"))
        ok = _send_raw(tg_cfg["bot_token"], tg_cfg["chat_id"], alert_text)
        if ok:
            total_alerts += 1

        # ── Cong don vao cua so tong hop dinh ky (persist qua state) ────
        state["window_count"]  = state.get("window_count", 0) + 1
        if ev.get("action") == "server-rst":
            state["window_server"] = state.get("window_server", 0) + 1
        elif ev.get("action") == "client-rst":
            state["window_client"] = state.get("window_client", 0) + 1
        if ev.get("reset_class") == "FAST_RESET":
            state["window_fast"] = state.get("window_fast", 0) + 1
        elif ev.get("reset_class") == "LONG_CONN_RESET":
            state["window_long"] = state.get("window_long", 0) + 1
        evt_time = f"{ev.get('date')} {ev.get('time')}"
        if not state.get("window_first_time"):
            state["window_first_time"] = evt_time
        state["window_last_time"] = evt_time

        if state.get("window_start_ts") is None:
            state["window_start_ts"] = time.time()

        time.sleep(1.5)

    _save_seen(new_seen)

    # ── TONG HOP DINH KY: neu da du summary_interval_minutes phut ke tu ──
    # khi cua so bat dau, gui 1 tin dem tong so RESET trong khoang do,
    # roi reset lai cua so. Chay o CUOI ham de: (a) van tinh ca cac event
    # vua xu ly trong lan nay, (b) van chay ngay ca khi lan nay khong co
    # event moi nao (de bao "0 phien trong 5 phut qua" neu can theo doi).
    summary_minutes = rm_cfg.get("summary_interval_minutes", 5)
    window_start = state.get("window_start_ts")
    if window_start is not None and (time.time() - window_start) >= summary_minutes * 60:
        stats = {
            "count":  state.get("window_count", 0),
            "server": state.get("window_server", 0),
            "client": state.get("window_client", 0),
            "fast":   state.get("window_fast", 0),
            "long":   state.get("window_long", 0),
            "first_time": state.get("window_first_time"),
            "last_time":  state.get("window_last_time"),
        }
        summary_text = build_alert_window_summary(stats, summary_minutes, device_name=dev_name, platform=dev.get("platform", "FortiGate"))
        _send_raw(tg_cfg["bot_token"], tg_cfg["chat_id"], summary_text)
        log.info("Da gui TONG HOP %d phut: %d phien RESET", summary_minutes, stats["count"])

        # Reset cua so cho ky tiep theo
        state["window_start_ts"]   = time.time()
        state["window_count"]      = 0
        state["window_server"]     = 0
        state["window_client"]     = 0
        state["window_fast"]       = 0
        state["window_long"]       = 0
        state["window_first_time"] = None
        state["window_last_time"]  = None

    _save_state(state)
    return total_alerts


def main() -> int:
    parser = argparse.ArgumentParser(description="SHB <-> NAPAS Connection Reset Monitor via FAZ Traffic Log")
    parser.add_argument("--loop", action="store_true", help="Chay lap dinh ky")
    parser.add_argument("--test", action="store_true", help="Test ket noi Telegram + FAZ")
    args = parser.parse_args()

    cfg = load_config()

    if args.test:
        log.info("[1/2] Kiem tra Telegram...")
        sample_ev = normalize_reset_event({
            "action": "server-rst", "srcip": "10.4.38.54", "dstip": "10.1.249.2",
            "srcport": 57498, "dstport": 35789, "policyid": "872",
            "sessionid": "181156104", "duration": 5, "sentbyte": 60, "rcvdbyte": 40,
            "service": "NAPAS-PROD-ACQ_35789", "date": "2026-08-20", "time": "09:58:23",
        })
        tg_ok = _send_raw(
            cfg["telegram"]["bot_token"], cfg["telegram"]["chat_id"],
            build_alert_reset(sample_ev, device_name="004_DC-FW-PARTNER", platform="FortiGate-501E"),
        )

        log.info("[2/2] Kiem tra FortiAnalyzer qua API Token...")
        faz = FAZClient(cfg["faz"]["url"], cfg["faz"]["api_token"], cfg["faz"].get("adom", "root"))
        faz_ok = faz.test_connection()

        log.info("==> TEST KET QUA: Telegram=%s | FAZ_API_Token=%s",
                  "OK" if tg_ok else "FAIL", "OK" if faz_ok else "FAIL")
        return 0

    if args.loop:
        rm_cfg = cfg.get("reset_monitor") or {}
        interval = rm_cfg.get("interval_minutes", 10) * 60
        log.info("LOOP MODE STARTED (reset_monitor) - Quet moi %d phut.", rm_cfg.get("interval_minutes", 10))
        while True:
            try:
                run_once(cfg)
            except KeyboardInterrupt:
                break
            except Exception as e:
                log.error("Loi: %s", e)
            time.sleep(interval)
        return 0

    run_once(cfg)
    return 0


if __name__ == "__main__":
    sys.exit(main())