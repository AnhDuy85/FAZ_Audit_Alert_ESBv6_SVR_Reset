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
_send_raw              = _tg._send_raw
build_alert_system     = _tg.build_alert_system
build_alert_reset_window_immediate = _tg.build_alert_reset_window_immediate
build_alert_reset_window_summary   = _tg.build_alert_reset_window_summary
build_alert_reset_window_resolved  = _tg.build_alert_reset_window_resolved

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
      (b) "srv_window_*" / "cli_window_*": cua so tong hop TUC THOI +
          RENEW/RESOLVED cho rieng tung huong (SERVER=NAPAS, CLIENT=SHB) -
          PHAI persist qua cac lan chay moi hoat dong dung (xem GHI CHU
          VE DEDUP TREN AWX trong README).

    Neu STATE_FILE khong con (vi du AWX khong co persistent volume,
    workspace bi xoa moi lan chay), ham nay tra ve trang thai rong -
    KHONG crash, nhung ca 2 co che (a)/(b) se KHONG hoat dong dung qua
    cac lan chay rieng biet (chi dung trong pham vi 1 lan --loop dai).
    """
    default = {
        "consecutive_fail": 0, "alerted_down": False,
        "srv_window_open": False, "srv_window_start_ts": None,
        "srv_window_total": 0, "srv_window_per_server": {},
        "srv_window_first_time": None, "srv_window_last_time": None,
        "cli_window_open": False, "cli_window_start_ts": None,
        "cli_window_total": 0, "cli_window_per_server": {},
        "cli_window_first_time": None, "cli_window_last_time": None,
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

    # ── Chuan hoa TOAN BO batch truoc ─────────────────────────────────────
    all_events = [normalize_reset_event(row) for row in raw_logs]
    all_events = [ev for ev in all_events if ev]

    # ── Loc ra cac event CHUA gui (chua co trong seen) ──────────────────
    to_alert = []
    for ev in all_events:
        key = dedup_key(ev)
        if key in seen:
            continue
        new_seen.add(key)
        to_alert.append(ev)

    # ══════════════════════════════════════════════════════════════════
    # CA SERVER RESET (NAPAS) VA CLIENT RESET (SHB): alert TUC THOI +
    # cua so tong hop RIENG cho tung huong (2 cua so DOC LAP nhau)
    # ══════════════════════════════════════════════════════════════════
    # Mo hinh 2 pha, AP DUNG CHO CA 2 HUONG (theo yeu cau moi nhat - truoc
    # day chi ap dung cho server-rst, client-rst dung group+threshold):
    #   1. Phien RESET DAU TIEN cua 1 huong (khi cua so huong do dang
    #      DONG) -> gui ALERT TUC THOI + MO cua so tong hop
    #      server_reset_window_minutes phut (mac dinh 10, dung chung cho
    #      ca 2 huong).
    #   2. Cac phien TIEP THEO CUNG HUONG trong cung cua so -> CHI ghi
    #      nhan (dem theo tung server/destination), KHONG gui alert rieng
    #      - tranh alert storm.
    #   3. Het cua so -> gui 1 TIN TONG HOP DUY NHAT roi DONG cua so - cho
    #      lan RESET tiep theo (cung huong) se lai MO cua so moi.
    # 2 huong hoan toan DOC LAP: server-rst dang co "bao" khong anh huong
    # gi den cua so cua client-rst va nguoc lai.
    now_ts = time.time()
    srv_window_minutes = rm_cfg.get("server_reset_window_minutes", 10)

    _WINDOW_STATE_PREFIX = {"server-rst": "srv", "client-rst": "cli"}
    _WINDOW_DIRECTION = {"server-rst": "SERVER", "client-rst": "CLIENT"}

    for ev in to_alert:
        action = ev.get("action", "")
        prefix = _WINDOW_STATE_PREFIX.get(action)
        direction = _WINDOW_DIRECTION.get(action)
        if prefix is None:
            log.warning("Action la khong xac dinh, bo qua: %s", action)
            continue

        evt_time = f"{ev.get('date')} {ev.get('time')}"
        dst_ip = ev.get("dstip", "?")
        open_key  = f"{prefix}_window_open"
        start_key = f"{prefix}_window_start_ts"
        total_key = f"{prefix}_window_total"
        per_key   = f"{prefix}_window_per_server"
        first_key = f"{prefix}_window_first_time"
        last_key  = f"{prefix}_window_last_time"

        if not state.get(open_key):
            # Chua co cua so nao dang mo cho HUONG NAY -> day la phien
            # DAU TIEN cua 1 dot reset moi -> gui ALERT TUC THOI, roi MO
            # cua so.
            immediate_text = build_alert_reset_window_immediate(
                direction, ev, window_minutes=srv_window_minutes,
                device_name=dev_name, platform=dev.get("platform", "FortiGate"))
            ok = _send_raw(tg_cfg["bot_token"], tg_cfg["chat_id"], immediate_text)
            if ok:
                total_alerts += 1
            state[open_key] = True
            state[start_key] = now_ts
            state[total_key] = 0
            state[per_key] = {}
            state[first_key] = evt_time
            state[last_key] = evt_time
            log.warning("%s RESET dau tien - MO cua so tong hop %d phut (dst=%s)",
                        direction, srv_window_minutes, dst_ip)

        # Ghi nhan phien nay vao cua so (du vua mo hay dang mo san) -
        # KHONG gui alert rieng cho cac phien nay.
        state[total_key] = state.get(total_key, 0) + 1
        per_server = state.setdefault(per_key, {})
        per_server[dst_ip] = per_server.get(dst_ip, 0) + 1

        # ── QUAN TRONG: FAZ tra ve log theo thu tu "desc" (MOI NHAT ──────
        # TRUOC) - neu 1 lan quet bat duoc NHIEU phien cung luc, KHONG
        # duoc gan first_time/last_time theo THU TU XU LY TRONG VONG LAP
        # (se bi DAO NGUOC: first_time thanh moi nhat, last_time thanh cu
        # nhat). Phai so sanh THOI GIAN THAT (chuoi "YYYY-MM-DD HH:MM:SS"
        # so sanh dung theo thu tu chuoi ky tu) de luon giu dung
        # first_time = SOM NHAT, last_time = MUON NHAT bat ke thu tu xu ly.
        if state.get(first_key) is None or evt_time < state[first_key]:
            state[first_key] = evt_time
        if state.get(last_key) is None or evt_time > state[last_key]:
            state[last_key] = evt_time

    _save_seen(new_seen)

    # ── KIEM TRA CUOI MOI CHU KY cho TUNG HUONG neu da du ─────────────────
    # server_reset_window_minutes phut ke tu khi bat dau chu ky hien tai:
    #   - Neu chu ky nay CO reset moi (total > 0) -> gui TONG HOP, sau do
    #     RENEW chu ky (bat dau lai dem tu 0, KHONG dong cua so) - tiep
    #     tuc lap lai cho den khi het reset. Day chinh la "alert lien tuc
    #     den khi xu ly xong".
    #   - Neu chu ky nay HOAN TOAN KHONG co reset moi (total == 0, tuc 1
    #     chu ky day du im lang) -> gui RESOLVED, DONG han cua so - cho
    #     lan RESET tiep theo (cung huong) se lai trigger ALERT TUC THOI
    #     tu dau.
    # Chay o day (ngoai vong lap, moi lan run_once) de van dung han chu
    # ky ke ca khi lan quet nay khong co phien moi nao.
    for prefix, direction in (("srv", "SERVER"), ("cli", "CLIENT")):
        open_key  = f"{prefix}_window_open"
        start_key = f"{prefix}_window_start_ts"
        total_key = f"{prefix}_window_total"
        per_key   = f"{prefix}_window_per_server"
        first_key = f"{prefix}_window_first_time"
        last_key  = f"{prefix}_window_last_time"

        win_start = state.get(start_key)
        if not (state.get(open_key) and win_start is not None and (now_ts - win_start) >= srv_window_minutes * 60):
            continue

        total_this_cycle = state.get(total_key, 0)

        if total_this_cycle > 0:
            # Chu ky nay CO hoat dong -> gui TONG HOP, roi RENEW (khong dong)
            summary_text = build_alert_reset_window_summary(
                direction,
                total=total_this_cycle,
                per_server=state.get(per_key, {}),
                window_minutes=srv_window_minutes,
                period_start=state.get(first_key) or "—",
                period_end=state.get(last_key) or "—",
                high_rate_per_min=rm_cfg.get("server_reset_high_rate_per_min", 3.0),
                device_name=dev_name, platform=dev.get("platform", "FortiGate"),
            )
            _send_raw(tg_cfg["bot_token"], tg_cfg["chat_id"], summary_text)
            log.warning("Da gui %s RESET SUMMARY (%d phut): %d lan, %d server - RENEW chu ky, van con dot su co",
                        direction, srv_window_minutes, total_this_cycle, len(state.get(per_key, {})))

            # RENEW: bat dau lai chu ky dem moi tu bay gio, KHONG dong cua so.
            state[start_key] = now_ts
            state[total_key] = 0
            state[per_key] = {}
            state[first_key] = None
            state[last_key] = None
        else:
            # 1 chu ky day du KHONG co reset moi nao -> RESOLVED, dong han.
            resolved_text = build_alert_reset_window_resolved(
                direction, window_minutes=srv_window_minutes,
                device_name=dev_name, platform=dev.get("platform", "FortiGate"),
            )
            _send_raw(tg_cfg["bot_token"], tg_cfg["chat_id"], resolved_text)
            log.info("Da gui %s RESET RESOLVED - dong han cua so (khong co reset moi trong %d phut)",
                      direction, srv_window_minutes)

            state[open_key] = False
            state[start_key] = None
            state[total_key] = 0
            state[per_key] = {}
            state[first_key] = None
            state[last_key] = None

    _save_state(state)
    return total_alerts


def main() -> int:
    parser = argparse.ArgumentParser(description="SHB <-> NAPAS Connection Reset Monitor via FAZ Traffic Log")
    parser.add_argument("--loop", action="store_true", help="Chay lap dinh ky")
    parser.add_argument("--test", action="store_true", help="Test ket noi Telegram + FAZ")
    args = parser.parse_args()

    cfg = load_config()

    if args.test:
        log.info("[1/2] Kiem tra Telegram (mo hinh moi: TUC THOI + TONG HOP, ca 2 huong)...")
        rm_cfg_test = cfg.get("reset_monitor") or {}
        results = {}

        for direction, action, sample_dst in (
            ("SERVER", "server-rst", "10.1.249.2"),
            ("CLIENT", "client-rst", "10.1.249.2"),
        ):
            sample_ev = normalize_reset_event({
                "action": action, "srcip": "10.4.38.54", "dstip": sample_dst,
                "srcport": 57498, "dstport": 35789, "policyid": "872",
                "sessionid": "181156104", "duration": 5, "sentbyte": 60, "rcvdbyte": 40,
                "service": "NAPAS-PROD-ACQ_35789", "date": "2026-08-20", "time": "09:58:23",
            })
            ok_immediate = _send_raw(
                cfg["telegram"]["bot_token"], cfg["telegram"]["chat_id"],
                build_alert_reset_window_immediate(direction, sample_ev, window_minutes=rm_cfg_test.get("server_reset_window_minutes", 10), device_name="004_DC-FW-PARTNER", platform="FortiGate-501E"),
            )

            sample_per_server = {"10.1.249.2": 28, "10.1.253.2": 20}
            ok_summary = _send_raw(
                cfg["telegram"]["bot_token"], cfg["telegram"]["chat_id"],
                build_alert_reset_window_summary(
                    direction, total=48, per_server=sample_per_server,
                    window_minutes=rm_cfg_test.get("server_reset_window_minutes", 10),
                    period_start="2026-08-20 09:58:00", period_end="2026-08-20 10:08:00",
                    high_rate_per_min=rm_cfg_test.get("server_reset_high_rate_per_min", 3.0),
                    device_name="004_DC-FW-PARTNER", platform="FortiGate-501E",
                ),
            )
            results[direction] = (ok_immediate, ok_summary)

        log.info("[2/2] Kiem tra FortiAnalyzer qua API Token...")
        faz = FAZClient(cfg["faz"]["url"], cfg["faz"]["api_token"], cfg["faz"].get("adom", "root"))
        faz_ok = faz.test_connection()

        log.info("==> TEST KET QUA:")
        for direction, (ok_i, ok_s) in results.items():
            log.info("    %s: tuc_thoi=%s  tong_hop=%s", direction,
                      "OK" if ok_i else "FAIL", "OK" if ok_s else "FAIL")
        log.info("    FAZ_API_Token=%s", "OK" if faz_ok else "FAIL")
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
                log.exception("Loi khong luong truoc trong run_once() - xem traceback day du ben duoi de debug:")
            time.sleep(interval)
        return 0

    run_once(cfg)
    return 0


if __name__ == "__main__":
    sys.exit(main())