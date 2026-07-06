"""
event_filter.py — Lọc và phân loại event log từ FortiAnalyzer (FAZ).
"""

import re
from datetime import datetime, timezone


def normalize_action(raw_action: str) -> str:
    """'Edit' / 'EDIT' / 'edit' -> 'edit'"""
    return (raw_action or "").strip().lower()


def is_config_change(log_entry: dict, watch_actions: list, watch_keywords: list) -> bool:
    """
    True nếu log entry là 1 sự kiện thay đổi config khớp filter.

    LUU Y: watch_actions trong settings.json can bao gom them "disable"
    va "enable" neu muon nhan canh bao khi rule bi tat/bat, vi du:
        "watch_actions": ["edit", "add", "delete", "move", "clone",
                           "disable", "enable"]
    Neu khong co "disable"/"enable" trong watch_actions, cac su kien nay
    se bi loc bo du normalize_faz_event() da nhan dien dung.
    """
    if (log_entry.get("type", "").lower() != "event"
            or log_entry.get("subtype", "").lower() != "system"):
        return False

    action = normalize_action(log_entry.get("action", ""))
    if action not in watch_actions:
        return False

    cfgpath = (log_entry.get("cfgpath") or "").lower()
    msg = (log_entry.get("msg") or "").lower()

    return any(kw.lower() in cfgpath or kw.lower() in msg for kw in watch_keywords)


def extract_object_id(log_entry: dict) -> str:
    """Bóc tách Policy ID hoặc Object Name từ log"""
    if log_entry.get("cfgobj"):
        return str(log_entry["cfgobj"])

    msg = log_entry.get("msg") or ""
    match = re.search(r"(?:policy|address|addrgrp|service|vip|ippool)\s+([a-zA-Z0-9\._\-]+)", msg.lower())
    if match:
        return match.group(1)
    return "—"


# change_type (do faz_client._classify_change gan vao record) -> action
# chuan de is_config_change()/telegram_notify dung duoc ma khong can sua
# logic o 2 noi do.
_CHANGE_TYPE_TO_ACTION = {
    "DISABLE_RULE": "disable",
    "ENABLE_RULE":  "enable",
    "DELETE_RULE":  "delete",
}


def normalize_faz_event(row: dict) -> dict:
    """
    Chuẩn hóa log thô từ FortiAnalyzer sang định dạng chuẩn để monitor.py xử lý.
    """
    if not row:
        return {}

    # ĐƯA TOÀN BỘ KEY VỀ CHỮ THƯỜNG & XÓA KÝ TỰ ĐẶC BIỆT ĐỂ KHÔNG BỊ TRỐNG TRƯỜNG
    # Ví dụ: "User Name" -> "username", "Date/Time" -> "datetime", "Time Stamp" -> "timestamp"
    # "change_type" (do faz_client gan) -> "changetype"
    raw = {}
    for k, v in row.items():
        clean_key = str(k).lower().replace(" ", "").replace("/", "").replace("_", "").replace("-", "")
        raw[clean_key] = v

    # 1. Lấy tin nhắn log thô từ FAZ
    msg_text = raw.get("msg") or raw.get("eventmessage") or ""

    # 2. BÓC TÁCH NGƯỜI SỬA (Đã được làm sạch key)
    user_val = raw.get("user") or raw.get("username") or raw.get("userid") or raw.get("hostowner") or "—"
    ui_val   = raw.get("ui") or raw.get("logonuserinterface") or raw.get("userinterface") or ""

    # 3. Phân tách Hành động (Action) và Đối tượng (cfgpath)
    action_val  = str(raw.get("action") or raw.get("eventaction") or "").lower()
    cfgpath_val = str(raw.get("cfgpath") or "").lower()
    cfgattr_val = str(raw.get("cfgattr") or "")

    if msg_text:
        if not action_val:
            for act in ["edit", "add", "delete", "move", "clone", "disable", "enable"]:
                if act in msg_text.lower():
                    action_val = act
                    break
        if not cfgpath_val:
            for kw in ["firewall.policy", "firewall.address", "firewall.addrgrp",
                       "firewall.service", "firewall.vip", "firewall.ippool"]:
                if kw in msg_text.lower():
                    cfgpath_val = kw
                    break
    if not cfgpath_val:
        cfgpath_val = "firewall.policy"

    # 3b. GHI ĐÈ action THEO change_type (do faz_client._classify_change tinh)
    # neu co, vi day la thong tin chinh xac nhat: phan biet duoc DISABLE
    # ngay ca khi FAZ chi ghi action = "edit" chung chung kem cfgattr
    # "status[enable->disable]". Neu khong co field nay (vi du log tu
    # nguon khac khong qua faz_client), fallback ve action_val nhu cu.
    change_type_val = raw.get("changetype")
    if change_type_val in _CHANGE_TYPE_TO_ACTION:
        action_val = _CHANGE_TYPE_TO_ACTION[change_type_val]
    elif action_val == "edit" and "status" in cfgattr_val.lower():
        # Fallback: tu doi chieu cfgattr ngay tai day, phong truong hop
        # row nay khong di qua faz_client._classify_change() (vi du duoc
        # normalize truc tiep tu nguon khac).
        low = cfgattr_val.lower()
        if "->disable" in low:
            action_val = "disable"
        elif "->enable" in low:
            action_val = "enable"

    # 4. THỜI GIAN
    date_val = raw.get("date") or ""
    time_val = raw.get("time") or ""

    dt_raw = (
        raw.get("datetime") or       # "Date/Time" -> 2026-06-17 15:09:30 (local UTC+7)
        raw.get("timestamp") or      # "Time Stamp"
        raw.get("datatimestamp") or  # "Data Timestamp" (UTC)
        raw.get("eventcreationtime") or
        raw.get("itime") or
        raw.get("logtime") or
        ""
    )

    if dt_raw and (not date_val or not time_val):
        dt_str = str(dt_raw).strip()

        # Unix timestamp thuần số
        if re.match(r"^\d{7,10}(\.\d+)?$", dt_str):
            try:
                ts = float(dt_str)
                if ts < 1_000_000_000:
                    base = datetime(2000, 1, 1, tzinfo=timezone.utc)
                    dt_obj = datetime.fromtimestamp(base.timestamp() + ts, tz=timezone.utc)
                else:
                    dt_obj = datetime.fromtimestamp(ts, tz=timezone.utc)
                date_val = dt_obj.strftime("%Y-%m-%d")
                time_val = dt_obj.strftime("%H:%M:%S")
            except Exception:
                pass

        # YYYY-MM-DD HH:MM:SS
        if not date_val or not time_val:
            match_dt = re.search(
                r"(\d{4}[-/]\d{2}[-/]\d{2})[T\s]+(\d{2}:\d{2}:\d{2})",
                dt_str
            )
            if match_dt:
                date_val = match_dt.group(1).replace("/", "-")
                time_val = match_dt.group(2)

        if not date_val or not time_val:
            parts = [p for p in dt_str.split() if p]
            if len(parts) >= 2:
                date_val = parts[0].replace("/", "-")
                time_val = parts[1]

    # Fallback tìm trong msg
    if (not date_val or not time_val) and msg_text:
        match_msg = re.search(
            r"(\d{4}[-/]\d{2}[-/]\d{2})[T\s]+(\d{2}:\d{2}:\d{2})",
            msg_text
        )
        if match_msg:
            date_val = match_msg.group(1).replace("/", "-")
            time_val = match_msg.group(2)

    # 5. cfgobj
    cfgobj_val = raw.get("cfgobj") or raw.get("policyid") or ""
    if not cfgobj_val and msg_text:
        match_bracket = re.search(
            r"\((?:edit|add|delete|move|clone)\s+[\w\.]+\s+([a-zA-Z0-9\._\-]+)\)",
            msg_text.lower()
        )
        if match_bracket:
            cfgobj_val = match_bracket.group(1)
        else:
            match_obj = re.search(
                r"(?:policy|address|addrgrp|service|vip|ippool)\s+([a-zA-Z0-9\._\-]+)",
                msg_text.lower()
            )
            if match_obj:
                cfgobj_val = match_obj.group(1)

        if cfgobj_val and cfgobj_val != "—":
            start_idx = msg_text.lower().find(cfgobj_val)
            if start_idx != -1:
                cfgobj_val = msg_text[start_idx:start_idx + len(cfgobj_val)].replace(")", "").strip()

    if not cfgobj_val:
        cfgobj_val = "—"

    return {
        "date":    date_val,
        "time":    time_val,
        "type":    "event",
        "subtype": "system",
        "action":  action_val,
        "cfgpath": cfgpath_val,
        "cfgobj":  cfgobj_val,
        "cfgattr": cfgattr_val,
        "user":    user_val,
        "ui":      ui_val,
        "msg":     msg_text,
    }