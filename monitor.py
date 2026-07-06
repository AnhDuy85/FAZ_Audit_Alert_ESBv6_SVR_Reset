#!/usr/bin/env python3
import argparse
import json
import logging
import sys
import time
from pathlib import Path

# === BỔ SUNG 2 DÒNG NÀY ĐỂ CHẶN INSECUREREQUESTWARNING ===
import urllib3 # type: ignore
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# ========================================================

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import faz_client as _faz
import event_filter as _ef
import telegram_notify as _tg

FAZClient = _faz.FAZClient
FAZError  = _faz.FAZError

is_config_change    = _ef.is_config_change
normalize_faz_event = _ef.normalize_faz_event
_send_raw           = _tg._send_raw
build_alert_custom  = _tg.build_alert_custom

LOG_DIR  = _ROOT / "logs"
LOG_FILE = LOG_DIR / "monitor.log"
CFG_FILE = _ROOT / "settings.json"
SEC_FILE = _ROOT / "secrets.json"

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
log = logging.getLogger("monitor")

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
    cfg["faz"]["api_token"] = sec.get("faz_api_token", "")  # Map Token bảo mật
    return cfg

def run_once(cfg: dict) -> int:
    mon_cfg = cfg["monitor"]
    tg_cfg  = cfg["telegram"]
    faz_cfg = cfg["faz"]
    devices = cfg["devices"]

    if not faz_cfg.get("enabled"):
        log.error("FAZ dang bi tat (enabled=false)")
        return 0

    # Khởi tạo Client bằng API Token
    faz = FAZClient(faz_cfg["url"], faz_cfg["api_token"], faz_cfg.get("adom", "root"))

    # Tính toán khoảng thời gian quét để hiển thị trên log
    now_ts = int(time.time())
    start_ts = now_ts - (mon_cfg["interval_minutes"] * 60)
    
    time_fmt = "%Y-%m-%d %H:%M:%S"
    str_start = time.strftime(time_fmt, time.localtime(start_ts))
    str_now = time.strftime(time_fmt, time.localtime(now_ts))

    total_alerts = 0
    
    for dev in devices:
        dev_name = dev["name"]
        devid    = dev.get("devid")

        if not devid:
            continue

        try:
            # Truy vấn log từ FAZ
            raw_logs = faz.query_device_events(
                devid    = devid,
                minutes  = mon_cfg["interval_minutes"],
                max_rows = mon_cfg["max_rows"],
            )
        except Exception as e:
            log.warning("FAZ device=%s -> LOI TRUY VAN: %s", devid, e)
            continue

        num_logs = len(raw_logs) if raw_logs else 0
        
        # IN LOG TRẠNG THÁI RA MÀN HÌNH (Đúng form anh cần, kể cả 0 logs)
        log.info("FAZ device=%s (%s) -> %d log(s)  [%s ~ %s]", devid, dev_name, num_logs, str_start, str_now)

        if num_logs > 0:
            for row in raw_logs:
                ev = normalize_faz_event(row)
                if ev and is_config_change(ev, mon_cfg["watch_actions"], mon_cfg["watch_keywords"]):
                    ev["device_name"] = dev_name
                    ev["platform"]    = dev.get("platform", "FortiGate")
                    
                    alert_text = build_alert_custom(ev)
                    ok = _send_raw(tg_cfg["bot_token"], tg_cfg["chat_id"], alert_text)
                    if ok:
                        total_alerts += 1
                    time.sleep(1.5)

    return total_alerts

def main() -> int:
    parser = argparse.ArgumentParser(description="FortiGate Rule Change Monitor via FAZ API Token")
    parser.add_argument("--loop", action="store_true", help="Chay lap dinh ky")
    parser.add_argument("--test", action="store_true", help="Test ket noi")
    args = parser.parse_args()
    
    cfg = load_config()
    if args.test:
        log.info("[1/2] Kiem tra Telegram...")
        sample_ev = {
            "action": "edit", "device_name": "004_DC-FW-PARTNER", "platform": "FortiGate-501E",
            "cfgpath": "firewall.policy", "cfgobj": "859", "user": "truongtrilinh_a",
            "ui": "GUI(10.4.1.50)", "date": "2026-06-10", "time": "15:54:22"
        }
        tg_ok = _send_raw(cfg["telegram"]["bot_token"], cfg["telegram"]["chat_id"], build_alert_custom(sample_ev))
        
        log.info("[2/2] Kiem tra FortiAnalyzer qua API Token...")
        faz = FAZClient(cfg["faz"]["url"], cfg["faz"]["api_token"], cfg["faz"].get("adom", "root"))
        faz_ok = faz.test_connection()
            
        log.info("==> TEST KET QUA: Telegram=%s | FAZ_API_Token=%s", "OK" if tg_ok else "FAIL", "OK" if faz_ok else "FAIL")
        return 0
        
    if args.loop:
        interval = cfg["monitor"]["interval_minutes"] * 60
        log.info("LOOP MODE STARTED (API Token) - Quet moi %d phut.", cfg["monitor"]["interval_minutes"])
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