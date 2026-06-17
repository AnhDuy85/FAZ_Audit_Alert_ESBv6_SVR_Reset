#!/usr/bin/env python3
import argparse
import json
import logging
import sys
import time
from datetime import datetime
from pathlib import Path

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
    cfg["faz"]["password"] = sec.get("faz_password", "")
    return cfg

def run_once(cfg: dict) -> int:
    mon_cfg = cfg["monitor"]
    tg_cfg  = cfg["telegram"]
    faz_cfg = cfg["faz"]
    devices = cfg["devices"]

    if not faz_cfg.get("enabled"):
        log.error("FAZ dang bi tat (enabled=false)")
        return 0

    try:
        faz = FAZClient(faz_cfg["url"], faz_cfg["username"], faz_cfg["password"], faz_cfg.get("adom", "root"))
        faz.login()
    except FAZError as e:
        log.error("Khong the login vao FortiAnalyzer: %s", e)
        return 0

    total_alerts = 0
    try:
        for dev in devices:
            dev_name = dev["name"]
            devid    = dev.get("devid")

            if not devid:
                continue

            try:
                raw_logs = faz.query_device_events(
                    devid    = devid,
                    minutes  = mon_cfg["interval_minutes"],
                    max_rows = mon_cfg["max_rows"],
                )
            except FAZError as e:
                log.warning("Loi truy van FAZ cho %s: %s", dev_name, e)
                continue

            for row in raw_logs:
                ev = normalize_faz_event(row)
                if ev and is_config_change(ev, mon_cfg["watch_actions"], mon_cfg["watch_keywords"]):
                    # Gán thêm dữ liệu cứng phục vụ hiển thị alert
                    ev["device_name"] = dev_name
                    ev["platform"]    = dev.get("platform", "FortiGate")
                    
                    # Sinh template html alert và thực hiện đẩy qua proxy sang Telegram
                    alert_text = build_alert_custom(ev)
                    ok = _send_raw(tg_cfg["bot_token"], tg_cfg["chat_id"], alert_text)
                    if ok:
                        total_alerts += 1
                    time.sleep(1.5)
                
    finally:
        faz.logout()

    return total_alerts

def main() -> int:
    parser = argparse.ArgumentParser(description="FortiGate Rule Change Monitor via FAZ")
    parser.add_argument("--loop", action="store_true", help="Chay lap dinh ky")
    parser.add_argument("--test", action="store_true", help="Test ket noi")
    args = parser.parse_args()
    
    cfg = load_config()
    if args.test:
        log.info("[1/2] Kiem tra Telegram...")
        # Bắn mẫu thử cấu hình yêu cầu qua Telegram để verify định dạng trực quan
        sample_ev = {
            "action": "edit", "device_name": "004_DC-FW-PARTNER", "platform": "FortiGate-501E",
            "cfgpath": "firewall.policy", "cfgobj": "859", "user": "truongtrilinh_a",
            "ui": "GUI(10.4.1.50)", "date": "2026-06-10", "time": "15:54:22"
        }
        tg_ok = _send_raw(cfg["telegram"]["bot_token"], cfg["telegram"]["chat_id"], build_alert_custom(sample_ev))
        
        log.info("[2/2] Kiem tra FortiAnalyzer...")
        faz_ok = False
        try:
            faz = FAZClient(cfg["faz"]["url"], cfg["faz"]["username"], cfg["faz"]["password"], cfg["faz"].get("adom", "root"))
            faz.login()
            faz_ok = True
            faz.logout()
        except:
            pass
            
        log.info("==> TEST KET QUA: Telegram=%s | FAZ=%s", "OK" if tg_ok else "FAIL", "OK" if faz_ok else "FAIL")
        return 0
        
    if args.loop:
        interval = cfg["monitor"]["interval_minutes"] * 60
        log.info("LOOP MODE STARTED - Quet moi %d phut.", cfg["monitor"]["interval_minutes"])
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