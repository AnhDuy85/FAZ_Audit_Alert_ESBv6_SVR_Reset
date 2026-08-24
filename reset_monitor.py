#!/usr/bin/env python3
"""
reset_monitor.py

Canh bao RESET ket noi SHB <-> NAPAS,
doc du lieu tu FAZ TRAFFIC LOG.

LOGIC CUOI:

1. NAPAS SERVER RESET (server-rst)
   - Phat hien reset -> alert ngay neu day la reset dau tien
     cua cua so 10 phut.
   - Duration khong duoc dung de bo qua event.
   - Moi Duration deu duoc ghi nhan.
   - Cac reset tiep theo trong cung cua so 10 phut:
       + khong gui Telegram rieng
       + tiep tuc dem.
   - Het 10 phut:
       + gui summary
       + tong so reset
       + breakdown tung NAPAS server
       + reset rate
       + danh gia.
   - Sau do mo cua so moi khi co server-rst tiep theo.

2. SHB CLIENT RESET (client-rst)
   - Van monitor.
   - Phan loai CLIENT_FAST / CLIENT_LONG.
   - Dung threshold_matrix.
   - WARNING / CRITICAL / RECOVERED.

3. FAZ query error
   - Dem loi lien tiep.
   - Vuot threshold -> Telegram critical.
   - Query thanh cong tro lai -> Telegram recovered.

4. Heartbeat
   - Best effort neu cau hinh heartbeat_url.
"""

import argparse
import json
import logging
import sys
import time
from pathlib import Path

import urllib3

urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)


# ============================================================
# PATH
# ============================================================

_ROOT = Path(__file__).resolve().parent

if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


# ============================================================
# IMPORT PROJECT MODULES
# ============================================================

import faz_client as _faz
import reset_filter as _rf
import telegram_notify as _tg


FAZClient = _faz.FAZClient
FAZError = _faz.FAZError


normalize_reset_event = (
    _rf.normalize_reset_event
)

dedup_key = (
    _rf.dedup_key
)

enrich_burst_counts = (
    _rf.enrich_burst_counts
)

classify_severity = (
    _rf.classify_severity
)

classify_category = (
    _rf.classify_category
)

classify_group_severity = (
    _rf.classify_group_severity
)

group_key_fn = (
    _rf.group_key
)


_send_raw = (
    _tg._send_raw
)

build_alert_reset = (
    _tg.build_alert_reset
)

build_alert_system = (
    _tg.build_alert_system
)

build_alert_window_summary = (
    _tg.build_alert_window_summary
)

build_alert_group_threshold = (
    _tg.build_alert_group_threshold
)

build_alert_server_reset_immediate = (
    _tg.build_alert_server_reset_immediate
)

build_alert_server_reset_summary = (
    _tg.build_alert_server_reset_summary
)


# ============================================================
# FILES
# ============================================================

LOG_DIR = _ROOT / "logs"

LOG_FILE = (
    LOG_DIR / "reset_monitor.log"
)

CFG_FILE = (
    _ROOT / "settings.json"
)

SEC_FILE = (
    _ROOT / "secrets.json"
)

SEEN_FILE = (
    LOG_DIR / "reset_seen.json"
)

STATE_FILE = (
    LOG_DIR / "monitor_state.json"
)


LOG_DIR.mkdir(
    exist_ok=True
)


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(

    level=logging.INFO,

    format=(
        "%(asctime)s  "
        "%(levelname)-8s  "
        "%(message)s"
    ),

    datefmt="%Y-%m-%d %H:%M:%S",

    handlers=[

        logging.StreamHandler(
            sys.stdout
        ),

        logging.FileHandler(
            LOG_FILE,
            encoding="utf-8"
        ),
    ],
)


log = logging.getLogger(
    "reset_monitor"
)


# ============================================================
# CONFIG
# ============================================================

def load_config() -> dict:

    if (
        not CFG_FILE.exists()
        or not SEC_FILE.exists()
    ):

        log.error(
            "Thieu file cau hinh "
            "settings.json hoac secrets.json"
        )

        raise SystemExit(1)

    try:

        cfg = json.loads(
            CFG_FILE.read_text(
                encoding="utf-8"
            )
        )

        sec = json.loads(
            SEC_FILE.read_text(
                encoding="utf-8"
            )
        )

    except json.JSONDecodeError as e:

        log.error(
            "JSON loi: %s",
            e
        )

        raise SystemExit(1)

    try:

        cfg["telegram"]["bot_token"] = (
            sec["telegram_bot_token"]
        )

    except KeyError:

        log.error(
            "Thieu telegram_bot_token trong secrets.json"
        )

        raise SystemExit(1)

    cfg["faz"]["api_token"] = (
        sec.get(
            "faz_api_token",
            ""
        )
    )

    return cfg


# ============================================================
# SEEN STATE
# ============================================================

def _load_seen() -> set:

    if not SEEN_FILE.exists():
        return set()

    try:

        raw = json.loads(
            SEEN_FILE.read_text(
                encoding="utf-8"
            )
        )

        return set(
            tuple(k)
            for k in raw
        )

    except Exception:

        return set()


def _save_seen(
    seen: set
):

    try:

        # Giu toi da 5000 key
        trimmed = list(seen)[-5000:]

        SEEN_FILE.write_text(
            json.dumps(
                trimmed,
                ensure_ascii=False
            ),
            encoding="utf-8"
        )

    except Exception as e:

        log.warning(
            "Khong ghi duoc %s: %s",
            SEEN_FILE,
            e
        )


# ============================================================
# MONITOR STATE
# ============================================================

def _load_state() -> dict:
    """
    State:

      consecutive_fail
      groups

      GENERAL RESET SUMMARY:
        window_*

      NAPAS SERVER RESET WINDOW:
        srv_window_*
    """

    default = {

        "consecutive_fail": 0,
        "alerted_down": False,

        # General 10-min summary
        "window_start_ts": None,
        "window_count": 0,
        "window_server": 0,
        "window_client": 0,
        "window_fast": 0,
        "window_long": 0,
        "window_first_time": None,
        "window_last_time": None,

        # Client groups
        "groups": {},

        # NAPAS server reset window
        "srv_window_open": False,
        "srv_window_start_ts": None,
        "srv_window_total": 0,
        "srv_window_per_server": {},
        "srv_window_first_time": None,
        "srv_window_last_time": None,
    }

    if not STATE_FILE.exists():
        return default

    try:

        loaded = json.loads(
            STATE_FILE.read_text(
                encoding="utf-8"
            )
        )

        default.update(
            loaded
        )

        return default

    except Exception:

        return default


def _save_state(
    state: dict
):

    try:

        STATE_FILE.write_text(
            json.dumps(
                state,
                ensure_ascii=False
            ),
            encoding="utf-8"
        )

    except Exception as e:

        log.warning(
            "Khong ghi duoc %s: %s",
            STATE_FILE,
            e
        )


# ============================================================
# HEARTBEAT
# ============================================================

def _send_heartbeat(
    rm_cfg: dict
):

    url = rm_cfg.get(
        "heartbeat_url"
    )

    if not url:
        return

    try:

        import urllib.request

        req = urllib.request.Request(
            url,
            method="GET"
        )

        urllib.request.urlopen(
            req,
            timeout=10
        )

        log.debug(
            "Heartbeat ping OK -> %s",
            url
        )

    except Exception as e:

        log.warning(
            "Heartbeat ping loi "
            "(bo qua): %s",
            e
        )


# ============================================================
# CLOSE NAPAS SERVER WINDOW
# ============================================================

def _close_server_reset_window(
    state: dict,
    rm_cfg: dict,
    tg_cfg: dict,
    dev_name: str,
    platform: str
):
    """
    Dong cua so NAPAS server reset.

    Gui 1 summary sau 10 phut.
    """

    total = state.get(
        "srv_window_total",
        0
    )

    per_server = state.get(
        "srv_window_per_server",
        {}
    )

    window_minutes = rm_cfg.get(
        "server_reset_window_minutes",
        10
    )

    summary_text = (
        build_alert_server_reset_summary(

            total=total,

            per_server=per_server,

            window_minutes=window_minutes,

            period_start=(
                state.get(
                    "srv_window_first_time"
                ) or "—"
            ),

            period_end=(
                state.get(
                    "srv_window_last_time"
                ) or "—"
            ),

            high_rate_per_min=(
                rm_cfg.get(
                    "server_reset_high_rate_per_min",
                    3.0
                )
            ),

            device_name=dev_name,

            platform=platform,
        )
    )

    _send_raw(
        tg_cfg["bot_token"],
        tg_cfg["chat_id"],
        summary_text
    )

    log.info(
        "Da gui NAPAS SERVER RESET SUMMARY "
        "(%d phut): %d lan, %d server bi anh huong",
        window_minutes,
        total,
        len(per_server)
    )

    # Reset window
    state["srv_window_open"] = False
    state["srv_window_start_ts"] = None
    state["srv_window_total"] = 0
    state["srv_window_per_server"] = {}
    state["srv_window_first_time"] = None
    state["srv_window_last_time"] = None


# ============================================================
# RUN ONCE
# ============================================================

def run_once(
    cfg: dict
) -> int:

    rm_cfg = cfg.get(
        "reset_monitor"
    )

    tg_cfg = cfg["telegram"]

    faz_cfg = cfg["faz"]

    devices = {
        d["name"]: d
        for d in cfg["devices"]
    }

    # --------------------------------------------------------
    # ENABLE CHECK
    # --------------------------------------------------------

    if (
        not rm_cfg
        or not rm_cfg.get("enabled")
    ):

        log.info(
            "reset_monitor dang bi tat "
            "(settings.json -> "
            "reset_monitor.enabled=false)"
        )

        return 0

    if not faz_cfg.get(
        "enabled"
    ):

        log.error(
            "FAZ dang bi tat "
            "(enabled=false) - "
            "reset_monitor bat buoc phai co FAZ"
        )

        return 0

    # --------------------------------------------------------
    # DEVICE
    # --------------------------------------------------------

    dev_name = rm_cfg[
        "device_name"
    ]

    dev = devices.get(
        dev_name
    )

    if not dev:

        log.error(
            "Khong tim thay thiet bi '%s' "
            "trong devices[]",
            dev_name
        )

        return 0

    # --------------------------------------------------------
    # FAZ
    # --------------------------------------------------------

    faz = FAZClient(

        faz_cfg["url"],

        faz_cfg["api_token"],

        faz_cfg.get(
            "adom",
            "root"
        )
    )

    # --------------------------------------------------------
    # INTERVAL
    # --------------------------------------------------------

    minutes = rm_cfg[
        "interval_minutes"
    ]

    query_minutes = rm_cfg.get(
        "query_lookback_minutes",
        minutes + 1
    )

    seen = _load_seen()

    state = _load_state()

    fail_threshold = rm_cfg.get(
        "consecutive_fail_threshold",
        3
    )

    now_ts = time.time()

    # --------------------------------------------------------
    # FAZ QUERY
    # --------------------------------------------------------

    try:

        raw_logs = (
            faz.query_traffic_resets(

                devname=dev_name,

                minutes=query_minutes,

                src_ips=rm_cfg[
                    "shb_src_ips"
                ],

                dst_ips=rm_cfg[
                    "napas_dst_ips"
                ],

                dst_ports=rm_cfg[
                    "dst_ports"
                ],

                actions=rm_cfg.get(
                    "watch_actions",
                    [
                        "server-rst",
                        "client-rst"
                    ]
                ),

                max_rows=rm_cfg.get(
                    "max_rows",
                    200
                ),
            )
        )

    except Exception as e:

        log.warning(
            "FAZ traffic query loi "
            "(device=%s): %s",
            dev_name,
            e
        )

        state[
            "consecutive_fail"
        ] = (
            state.get(
                "consecutive_fail",
                0
            ) + 1
        )

        _save_state(
            state
        )

        if (
            state["consecutive_fail"]
            >= fail_threshold
            and not state.get(
                "alerted_down"
            )
        ):

            msg = (

                f"FAZ traffic query "
                f"LỖI <b>"
                f"{state['consecutive_fail']}"
                f"</b> lần liên tiếp "

                f"(thiết bị "
                f"<code>{dev_name}</code>)."

                f"\nLỗi gần nhất: "
                f"<code>{e}</code>"

                f"\n\n⚠️ Hệ thống "
                f"<b>reset_monitor.py</b> "
                f"có thể đang "
                f"<b>KHÔNG hoạt động đúng</b>."

                f"\nKiểm tra "
                f"<code>faz_api_token</code> "
                f"hoặc kết nối mạng tới FAZ."
            )

            _send_raw(

                tg_cfg[
                    "bot_token"
                ],

                tg_cfg[
                    "chat_id"
                ],

                build_alert_system(
                    "HỆ THỐNG GIÁM SÁT GẶP SỰ CỐ",
                    msg,
                    severity="critical"
                )
            )

            state[
                "alerted_down"
            ] = True

            _save_state(
                state
            )

        return 0

    # --------------------------------------------------------
    # FAZ RECOVERED
    # --------------------------------------------------------

    if state.get(
        "consecutive_fail",
        0
    ) > 0:

        if state.get(
            "alerted_down"
        ):

            _send_raw(

                tg_cfg[
                    "bot_token"
                ],

                tg_cfg[
                    "chat_id"
                ],

                build_alert_system(

                    "HỆ THỐNG GIÁM SÁT ĐÃ PHỤC HỒI",

                    (
                        "FAZ traffic query "
                        "đã thành công trở lại "
                        f"sau "
                        f"{state['consecutive_fail']} "
                        "lần lỗi liên tiếp."
                    ),

                    severity="recovered"
                )
            )

        state[
            "consecutive_fail"
        ] = 0

        state[
            "alerted_down"
        ] = False

        _save_state(
            state
        )

    # --------------------------------------------------------
    # HEARTBEAT
    # --------------------------------------------------------

    _send_heartbeat(
        rm_cfg
    )

    num_logs = (
        len(raw_logs)
        if raw_logs
        else 0
    )

    log.info(

        "FAZ traffic device=%s "
        "(%s) -> %d phien reset "
        "trong %d phut "
        "(query lookback=%d phut)",

        dev["devid"],

        dev_name,

        num_logs,

        minutes,

        query_minutes,
    )

    total_alerts = 0

    new_seen = set(
        seen
    )

    # ========================================================
    # NORMALIZE
    # ========================================================

    all_events = [

        normalize_reset_event(
            row
        )

        for row in raw_logs
    ]

    all_events = [
        ev
        for ev in all_events
        if ev
    ]

    # ========================================================
    # DEDUP
    # ========================================================

    to_alert = []

    for ev in all_events:

        key = dedup_key(
            ev
        )

        if key in seen:
            continue

        new_seen.add(
            key
        )

        to_alert.append(
            ev
        )

    # ========================================================
    # THRESHOLD CLIENT
    # ========================================================

    threshold_matrix = rm_cfg.get(
        "threshold_matrix",
        {}
    )

    default_thresholds = {

        "warning_1m": 5,

        "warning_5m": 15,

        "critical_1m": 10,

        "critical_5m": 30,
    }

    groups = state.setdefault(
        "groups",
        {}
    )

    # ========================================================
    # SERVER RESET WINDOW CONFIG
    # ========================================================

    srv_window_minutes = rm_cfg.get(
        "server_reset_window_minutes",
        10
    )

    # ========================================================
    # XU LY EVENT
    # ========================================================

    for ev in to_alert:

        action = str(
            ev.get(
                "action",
                ""
            )
        ).lower()

        # ====================================================
        # NAPAS SERVER RESET
        # ====================================================

        if action == "server-rst":

            evt_time = (
                f"{ev.get('date')} "
                f"{ev.get('time')}"
            )

            dst_ip = ev.get(
                "dstip",
                "?"
            )

            # ------------------------------------------------
            # Mo cua so neu chua co
            # ------------------------------------------------

            if not state.get(
                "srv_window_open"
            ):

                # Alert NGAY phien dau tien.
                #
                # KHONG kiem tra duration.
                #
                # Duration 1s / 5s / 7s / 30s...
                # deu duoc alert.

                immediate_text = (
                    build_alert_server_reset_immediate(

                        ev,

                        device_name=dev_name,

                        platform=dev.get(
                            "platform",
                            "FortiGate"
                        )
                    )
                )

                ok = _send_raw(

                    tg_cfg[
                        "bot_token"
                    ],

                    tg_cfg[
                        "chat_id"
                    ],

                    immediate_text
                )

                if ok:

                    total_alerts += 1

                # Mo cua so 10 phut

                state[
                    "srv_window_open"
                ] = True

                state[
                    "srv_window_start_ts"
                ] = now_ts

                state[
                    "srv_window_total"
                ] = 0

                state[
                    "srv_window_per_server"
                ] = {}

                state[
                    "srv_window_first_time"
                ] = evt_time

                state[
                    "srv_window_last_time"
                ] = evt_time

                log.warning(

                    "NAPAS SERVER RESET "
                    "dau tien - MO cua so "
                    "%d phut (dst=%s, duration=%ss)",

                    srv_window_minutes,

                    dst_ip,

                    ev.get(
                        "duration",
                        0
                    )
                )

            # ------------------------------------------------
            # Count moi server-rst
            # ------------------------------------------------

            state[
                "srv_window_total"
            ] = (
                state.get(
                    "srv_window_total",
                    0
                ) + 1
            )

            per_server = state.setdefault(
                "srv_window_per_server",
                {}
            )

            per_server[dst_ip] = (
                per_server.get(
                    dst_ip,
                    0
                ) + 1
            )

            state[
                "srv_window_last_time"
            ] = evt_time

            log.info(

                "NAPAS SERVER RESET "
                "counted: dst=%s "
                "duration=%ss "
                "session=%s",

                dst_ip,

                ev.get(
                    "duration",
                    0
                ),

                ev.get(
                    "sessionid",
                    "?"
                )
            )

        # ====================================================
        # SHB CLIENT RESET
        # ====================================================

        elif action == "client-rst":

            category = classify_category(

                ev.get(
                    "action",
                    ""
                ),

                ev.get(
                    "reset_class",
                    ""
                )
            )

            gkey = group_key_fn(
                ev,
                category
            )

            grp = groups.setdefault(

                gkey,

                {
                    "events_ts": [],
                    "severity": "NORMAL",
                    "last_individual_alert_ts": 0,
                }
            )

            grp[
                "events_ts"
            ].append(
                now_ts
            )

            grp[
                "events_ts"
            ] = [

                t

                for t in grp[
                    "events_ts"
                ]

                if now_ts - t <= 300
            ]

            burst_1m_grp = sum(

                1

                for t in grp[
                    "events_ts"
                ]

                if now_ts - t <= 60
            )

            burst_5m_grp = len(
                grp[
                    "events_ts"
                ]
            )

            thresholds = (
                threshold_matrix.get(
                    category,
                    default_thresholds
                )
            )

            new_severity = (
                classify_group_severity(

                    burst_1m_grp,

                    burst_5m_grp,

                    thresholds
                )
            )

            old_severity = grp.get(
                "severity",
                "NORMAL"
            )

            log.info(

                "Event category=%s "
                "(CLIENT): %s %s -> %s "
                "policy=%s session=%s",

                category,

                ev.get(
                    "date"
                ),

                ev.get(
                    "time"
                ),

                ev.get(
                    "dstip"
                ),

                ev.get(
                    "policyid"
                ),

                ev.get(
                    "sessionid"
                )
            )

            if new_severity != old_severity:

                # --------------------------------------------
                # WARNING / CRITICAL
                # --------------------------------------------

                if new_severity in (
                    "WARNING",
                    "CRITICAL"
                ):

                    status_text = (
                        build_alert_group_threshold(

                            new_severity,

                            category,

                            service=ev.get(
                                "service",
                                "?"
                            ),

                            dst_ip=ev.get(
                                "dstip",
                                "?"
                            ),

                            policy=ev.get(
                                "policyid",
                                "?"
                            ),

                            burst_1m=burst_1m_grp,

                            burst_5m=burst_5m_grp,

                            thresholds=thresholds,

                            device_name=dev_name,

                            platform=dev.get(
                                "platform",
                                "FortiGate"
                            )
                        )
                    )

                    _send_raw(

                        tg_cfg[
                            "bot_token"
                        ],

                        tg_cfg[
                            "chat_id"
                        ],

                        status_text
                    )

                    log.warning(

                        "Group %s chuyen "
                        "%s -> %s "
                        "(burst_1m=%d "
                        "burst_5m=%d)",

                        gkey,

                        old_severity,

                        new_severity,

                        burst_1m_grp,

                        burst_5m_grp
                    )

                # --------------------------------------------
                # RECOVERED
                # --------------------------------------------

                elif (
                    new_severity == "NORMAL"
                    and old_severity
                    in (
                        "WARNING",
                        "CRITICAL"
                    )
                ):

                    status_text = (
                        build_alert_group_threshold(

                            "RECOVERED",

                            category,

                            service=ev.get(
                                "service",
                                "?"
                            ),

                            dst_ip=ev.get(
                                "dstip",
                                "?"
                            ),

                            policy=ev.get(
                                "policyid",
                                "?"
                            ),

                            burst_1m=burst_1m_grp,

                            burst_5m=burst_5m_grp,

                            thresholds=thresholds,

                            device_name=dev_name,

                            platform=dev.get(
                                "platform",
                                "FortiGate"
                            )
                        )
                    )

                    _send_raw(

                        tg_cfg[
                            "bot_token"
                        ],

                        tg_cfg[
                            "chat_id"
                        ],

                        status_text
                    )

                    log.info(
                        "Group %s da RECOVERED "
                        "(%s -> NORMAL)",
                        gkey,
                        old_severity
                    )

                grp[
                    "severity"
                ] = new_severity

            groups[
                gkey
            ] = grp

        # ====================================================
        # UNKNOWN ACTION
        # ====================================================

        else:

            log.debug(
                "Bo qua action khong theo doi: %s",
                action
            )

            continue

        # ====================================================
        # GENERAL RESET SUMMARY
        # ====================================================

        state[
            "window_count"
        ] = (
            state.get(
                "window_count",
                0
            ) + 1
        )

        if action == "server-rst":

            state[
                "window_server"
            ] = (
                state.get(
                    "window_server",
                    0
                ) + 1
            )

        elif action == "client-rst":

            state[
                "window_client"
            ] = (
                state.get(
                    "window_client",
                    0
                ) + 1
            )

        if ev.get(
            "reset_class"
        ) == "FAST_RESET":

            state[
                "window_fast"
            ] = (
                state.get(
                    "window_fast",
                    0
                ) + 1
            )

        elif ev.get(
            "reset_class"
        ) == "LONG_CONN_RESET":

            state[
                "window_long"
            ] = (
                state.get(
                    "window_long",
                    0
                ) + 1
            )

        evt_time2 = (
            f"{ev.get('date')} "
            f"{ev.get('time')}"
        )

        if not state.get(
            "window_first_time"
        ):

            state[
                "window_first_time"
            ] = evt_time2

        state[
            "window_last_time"
        ] = evt_time2

        if state.get(
            "window_start_ts"
        ) is None:

            state[
                "window_start_ts"
            ] = now_ts

    # ========================================================
    # SAVE DEDUP
    # ========================================================

    _save_seen(
        new_seen
    )

    # ========================================================
    # CLOSE NAPAS SERVER WINDOW
    # ========================================================

    srv_start = state.get(
        "srv_window_start_ts"
    )

    if (

        state.get(
            "srv_window_open"
        )

        and srv_start is not None

        and (
            now_ts - srv_start
        ) >= (
            srv_window_minutes * 60
        )
    ):

        _close_server_reset_window(

            state,

            rm_cfg,

            tg_cfg,

            dev_name,

            dev.get(
                "platform",
                "FortiGate"
            )
        )

    # ========================================================
    # GENERAL RESET SUMMARY
    # ========================================================

    summary_minutes = rm_cfg.get(
        "summary_interval_minutes",
        10
    )

    window_start = state.get(
        "window_start_ts"
    )

    if (

        window_start is not None

        and (
            time.time()
            - window_start
        ) >= (
            summary_minutes * 60
        )
    ):

        stats = {

            "count": state.get(
                "window_count",
                0
            ),

            "server": state.get(
                "window_server",
                0
            ),

            "client": state.get(
                "window_client",
                0
            ),

            "fast": state.get(
                "window_fast",
                0
            ),

            "long": state.get(
                "window_long",
                0
            ),

            "first_time": state.get(
                "window_first_time"
            ),

            "last_time": state.get(
                "window_last_time"
            ),
        }

        # ----------------------------------------------------
        # Severity cho general summary
        # ----------------------------------------------------

        window_crit_base = rm_cfg.get(
            "window_summary_critical_5m",
            30
        )

        window_warn_base = rm_cfg.get(
            "window_summary_warning_5m",
            15
        )

        scale = (
            summary_minutes / 5.0
        )

        window_severity = (
            classify_severity(

                stats["count"],

                critical_threshold=round(
                    window_crit_base * scale
                ),

                warning_threshold=round(
                    window_warn_base * scale
                )
            )
        )

        summary_text = (
            build_alert_window_summary(

                stats,

                summary_minutes,

                device_name=dev_name,

                platform=dev.get(
                    "platform",
                    "FortiGate"
                ),

                severity=window_severity
            )
        )

        _send_raw(

            tg_cfg[
                "bot_token"
            ],

            tg_cfg[
                "chat_id"
            ],

            summary_text
        )

        log.info(

            "Da gui TONG HOP %d phut: "
            "%d phien RESET "
            "(severity=%s)",

            summary_minutes,

            stats["count"],

            window_severity
        )

        # Reset general window

        state[
            "window_start_ts"
        ] = time.time()

        state[
            "window_count"
        ] = 0

        state[
            "window_server"
        ] = 0

        state[
            "window_client"
        ] = 0

        state[
            "window_fast"
        ] = 0

        state[
            "window_long"
        ] = 0

        state[
            "window_first_time"
        ] = None

        state[
            "window_last_time"
        ] = None

    # ========================================================
    # SAVE STATE
    # ========================================================

    _save_state(
        state
    )

    return total_alerts


# ============================================================
# MAIN
# ============================================================

def main() -> int:

    parser = argparse.ArgumentParser(

        description=(
            "SHB <-> NAPAS Connection "
            "Reset Monitor via FAZ Traffic Log"
        )
    )

    parser.add_argument(
        "--loop",
        action="store_true",
        help="Chay lap dinh ky"
    )

    parser.add_argument(
        "--test",
        action="store_true",
        help="Test Telegram + FAZ"
    )

    args = parser.parse_args()

    cfg = load_config()

    # ========================================================
    # TEST
    # ========================================================

    if args.test:

        log.info(
            "[1/2] Kiem tra Telegram..."
        )

        sample_ev = (
            normalize_reset_event({

                "action": "server-rst",

                "srcip": "10.4.38.54",

                "dstip": "10.1.249.2",

                "srcport": 57498,

                "dstport": 35789,

                "policyid": "872",

                "sessionid": "181156104",

                "duration": 7,

                "sentbyte": 60,

                "rcvdbyte": 40,

                "service": (
                    "NAPAS-PROD-ACQ_35789"
                ),

                "date": "2026-08-24",

                "time": "10:31:37",
            })
        )

        tg_ok = _send_raw(

            cfg[
                "telegram"
            ][
                "bot_token"
            ],

            cfg[
                "telegram"
            ][
                "chat_id"
            ],

            build_alert_server_reset_immediate(

                sample_ev,

                device_name=(
                    "004_DC-FW-PARTNER"
                ),

                platform=(
                    "FortiGate-501E"
                )
            )
        )

        log.info(
            "[2/2] Kiem tra FortiAnalyzer "
            "qua API Token..."
        )

        faz = FAZClient(

            cfg[
                "faz"
            ][
                "url"
            ],

            cfg[
                "faz"
            ][
                "api_token"
            ],

            cfg[
                "faz"
            ].get(
                "adom",
                "root"
            )
        )

        faz_ok = (
            faz.test_connection()
        )

        log.info(

            "==> TEST KET QUA: "
            "Telegram=%s | "
            "FAZ_API_Token=%s",

            (
                "OK"
                if tg_ok
                else "FAIL"
            ),

            (
                "OK"
                if faz_ok
                else "FAIL"
            )
        )

        return 0

    # ========================================================
    # LOOP
    # ========================================================

    if args.loop:

        rm_cfg = (
            cfg.get(
                "reset_monitor"
            )
            or {}
        )

        interval = (
            rm_cfg.get(
                "interval_minutes",
                1
            )
            * 60
        )

        log.info(

            "LOOP MODE STARTED "
            "(reset_monitor) - "
            "Quet moi %d phut.",

            rm_cfg.get(
                "interval_minutes",
                1
            )
        )

        while True:

            try:

                run_once(
                    cfg
                )

            except KeyboardInterrupt:

                log.info(
                    "Dung reset_monitor."
                )

                break

            except Exception as e:

                log.exception(
                    "Loi run_once: %s",
                    e
                )

            time.sleep(
                interval
            )

        return 0

    # ========================================================
    # ONE SHOT
    # ========================================================

    run_once(
        cfg
    )

    return 0


if __name__ == "__main__":

    sys.exit(
        main()
    )