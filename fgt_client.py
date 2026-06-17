"""
fgt_client.py — FortiGate REST API client (kết nối TRỰC TIẾP, không qua FAZ)
==============================================================================
Lấy 2 loại dữ liệu trực tiếp từ FortiGate:

1. EVENT LOG (audit log nội bộ trên FGT) — phát hiện thay đổi policy:
     GET /api/v2/log/memory/event?filter=...
   FortiGate tự ghi log mỗi khi admin add/edit/delete/move/clone policy,
   lưu trong memory log (mặc định) hoặc disk log (nếu có ổ cứng).
   Đây là nguồn dữ liệu thay thế hoàn toàn cho FAZ.

2. POLICY DETAIL — chi tiết source/destination/service/status:
     GET /api/v2/cmdb/firewall/policy/{id}?vdom={vdom}
   Dùng để enrich event log với thông tin rule đầy đủ.

XỬ LÝ "DELETE":
  Khi rule bị xóa, /cmdb/firewall/policy/{id} không còn trả data.
  Module duy trì SNAPSHOT toàn bộ policy (lưu local JSON), cập nhật mỗi
  lần chạy. Khi phát hiện delete, tra trong snapshot CŨ (trước update)
  để lấy lại source/dest/service của rule vừa bị xóa.

YÊU CẦU TRÊN FORTIGATE:
  - Tạo REST API Admin (System > Administrators > Create New > REST API Admin)
  - Quyền tối thiểu: Read trên Log & Report, Read trên Firewall Policy
  - Trusted host: IP máy chạy script này
  - Token được FGT hiển thị 1 lần duy nhất lúc tạo — lưu vào secrets.json

Python stdlib only.
"""

import json
import logging
import ssl
import urllib.request
import urllib.error
import urllib.parse
from pathlib import Path

log = logging.getLogger("fgt")

_SSL = ssl.create_default_context()
_SSL.check_hostname = False
_SSL.verify_mode    = ssl.CERT_NONE

_SNAPSHOT_DIR = Path(__file__).resolve().parent / "logs" / "snapshots"


class FGTError(Exception):
    """Lỗi kết nối/API FortiGate."""
    pass


# =============================================================================
# Low-level HTTP
# =============================================================================

def _get(fgt_url: str, token: str, path: str, params: dict | None = None) -> dict:
    """
    GET FortiGate REST API.

    Raises:
        FGTError nếu HTTP lỗi hoặc network lỗi.
    """
    qs  = f"?{urllib.parse.urlencode(params)}" if params else ""
    url = f"{fgt_url.rstrip('/')}{path}{qs}"

    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept":        "application/json",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, context=_SSL, timeout=20) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")[:300]
        raise FGTError(f"HTTP {e.code} {path}: {body}") from e
    except urllib.error.URLError as e:
        raise FGTError(f"Không kết nối được {fgt_url}: {e.reason}") from e
    except json.JSONDecodeError as e:
        raise FGTError(f"FGT trả về non-JSON ({path}): {e}") from e


# =============================================================================
# 1. EVENT LOG — phát hiện thay đổi policy
# =============================================================================

def fetch_event_logs(fgt_url: str, token: str, minutes: int, max_rows: int = 200) -> list:
    """
    Lấy log event "Object attribute configured" trực tiếp từ FortiGate
    (System Event log), trong N phút gần nhất.

    Endpoint: GET /api/v2/log/memory/event
    Filter:   subtype==system, type==event

    Returns:
        list[dict] — mỗi dict là 1 log entry (raw JSON từ FGT), tối thiểu
        có các field: action, logdesc, msg, cfgpath, cfgobj, cfgattr,
        date, time, user, ui.

    Raises:
        FGTError nếu kết nối/API lỗi (caller nên catch và bỏ qua thiết bị
        đó cho lần chạy này, không crash toàn bộ).
    """
    # Thứ tự ưu tiên: thử lần lượt 4 endpoint (v7.x, v6.4.x, disk fallback)
    candidates = [
        ("/api/v2/log/memory/event",        {"rows": str(max_rows), "filter": "subtype==system"}),
        ("/api/v2/log/memory/event/system", {"rows": str(max_rows)}),
        ("/api/v2/log/disk/event",          {"rows": str(max_rows), "filter": "subtype==system"}),
        ("/api/v2/log/disk/event/system",   {"rows": str(max_rows)}),
    ]

    last_error = None
    for path, params in candidates:
        try:
            resp = _get(fgt_url, token, path, params)
            results = resp.get("results")
            if results is None:
                raise FGTError(f"Response khong co 'results': {json.dumps(resp)[:200]}")
            log.info("FGT log endpoint hoat dong: %s (%d logs)", path, len(results))
            return results
        except FGTError as e:
            last_error = e
            log.debug("Thu endpoint %s that bai: %s", path, e)
            continue

    raise FGTError(f"Tat ca log endpoint deu that bai. Loi cuoi: {last_error}")


# =============================================================================
# 2. POLICY DETAIL — source/destination/service/status
# =============================================================================

def _names(obj_list: list, max_items: int = 4) -> str:
    """Rút gọn list address/service object FortiGate thành chuỗi tên."""
    if not obj_list:
        return "—"
    names = [o.get("name", str(o)) for o in obj_list if isinstance(o, dict)]
    if not names:
        names = [str(x) for x in obj_list]
    if len(names) <= max_items:
        return ", ".join(names)
    return ", ".join(names[:max_items]) + f" (+{len(names)-max_items})"


def _normalize_policy(p: dict) -> dict:
    """Chuẩn hoá 1 policy object từ FortiGate API thành dict gọn."""
    return {
        "policyid":   str(p.get("policyid", "")),
        "name":       p.get("name", ""),
        "status":     p.get("status", ""),          # enable / disable
        "action":     p.get("action", ""),           # accept / deny / ipsec
        "srcintf":    _names(p.get("srcintf",  [])),
        "dstintf":    _names(p.get("dstintf",  [])),
        "srcaddr":    _names(p.get("srcaddr",  [])),
        "dstaddr":    _names(p.get("dstaddr",  [])),
        "srcaddr6":   _names(p.get("srcaddr6", [])),
        "dstaddr6":   _names(p.get("dstaddr6", [])),
        "service":    _names(p.get("service",  [])),
        "schedule":   p.get("schedule", "always"),
        "nat":        "ON" if p.get("nat") == "enable" else "OFF",
        "logtraffic": p.get("logtraffic", ""),
        "comments":   p.get("comments", ""),
    }


def fetch_all_policies(fgt_url: str, token: str, vdom: str) -> dict[str, dict]:
    """
    Lấy TOÀN BỘ firewall policy hiện tại, trả về {policyid: detail}.

    Raises:
        FGTError nếu kết nối/API lỗi.
    """
    resp = _get(fgt_url, token, "/api/v2/cmdb/firewall/policy", {"vdom": vdom})
    results = resp.get("results")
    if results is None:
        raise FGTError(f"Response không có 'results': {json.dumps(resp)[:200]}")

    return {str(p.get("policyid", "")): _normalize_policy(p) for p in results}


# cfgpath -> (API endpoint, type mô tả cho hiển thị)
_OBJECT_ENDPOINTS = {
    "firewall.address":        ("/api/v2/cmdb/firewall/address",        "Address"),
    "firewall.addrgrp":        ("/api/v2/cmdb/firewall/addrgrp",         "Address Group"),
    "firewall.vip":            ("/api/v2/cmdb/firewall/vip",             "Virtual IP"),
    "firewall.ippool":         ("/api/v2/cmdb/firewall/ippool",          "IP Pool"),
    "firewall.service.custom": ("/api/v2/cmdb/firewall.service/custom",  "Service"),
    "firewall.service.group":  ("/api/v2/cmdb/firewall.service/group",   "Service Group"),
}


def _normalize_named_object(p: dict, obj_type: str) -> dict:
    """
    Chuẩn hoá 1 named object (address/vip/service/...) thành dict
    cùng "shape" với _normalize_policy() để telegram_notify dùng chung.
    Field nào không áp dụng để "—".
    """
    detail = {
        "policyid":   p.get("name", ""),
        "name":       p.get("name", ""),
        "status":     "",
        "action":     "",
        "srcintf":    "—",
        "dstintf":    "—",
        "srcaddr":    "—",
        "dstaddr":    "—",
        "srcaddr6":   "—",
        "dstaddr6":   "—",
        "service":    "—",
        "schedule":   "—",
        "nat":        "—",
        "logtraffic": "",
        "comments":   p.get("comment", "") or p.get("comments", ""),
        "_object_type": obj_type,
    }

    if obj_type == "Address":
        subnet = p.get("subnet", "")
        ftype  = p.get("type", "")
        detail["srcaddr"] = f"{ftype}: {subnet}".strip(": ") or "—"
    elif obj_type == "Virtual IP":
        detail["srcaddr"] = f"ext: {p.get('extip','—')}"
        detail["dstaddr"] = f"map: {p.get('mappedip','—')}"
        detail["service"] = (
            f"{p.get('extintf','—')} : "
            f"{p.get('extport','') or p.get('mappedport','')}"
        ).strip(": ")
    elif obj_type == "Address Group":
        detail["srcaddr"] = _names(p.get("member", []))
    elif obj_type in ("Service", "Service Group"):
        if obj_type == "Service":
            tcp = p.get("tcp-portrange", "")
            udp = p.get("udp-portrange", "")
            ports = ", ".join(x for x in [f"TCP:{tcp}" if tcp else "", f"UDP:{udp}" if udp else ""] if x)
            detail["service"] = ports or "—"
        else:
            detail["service"] = _names(p.get("member", []))
    elif obj_type == "IP Pool":
        detail["srcaddr"] = f"{p.get('startip','—')} - {p.get('endip','—')}"

    return detail


def fetch_named_object(fgt_url: str, token: str, vdom: str,
                        cfgpath: str, name: str) -> dict | None:
    """
    Lấy chi tiết 1 named object (address/vip/service/addrgrp/...).
    Dùng khi event log có cfgpath khác "firewall.policy" (object_id là tên,
    không phải số).

    Returns:
        dict đã normalize (cùng shape với policy detail) hoặc None nếu
        không tồn tại / cfgpath không được hỗ trợ.
    """
    endpoint_info = _OBJECT_ENDPOINTS.get(cfgpath.lower())
    if not endpoint_info:
        return None
    endpoint, obj_type = endpoint_info

    try:
        resp = _get(fgt_url, token, f"{endpoint}/{urllib.parse.quote(name, safe='')}",
                    {"vdom": vdom})
    except FGTError:
        return None

    results = resp.get("results")
    if not results:
        return None

    p = results[0] if isinstance(results, list) else results
    return _normalize_named_object(p, obj_type)


# =============================================================================
# 3. SNAPSHOT — lưu/đọc toàn bộ policy của 1 thiết bị (cho case delete)
# =============================================================================

def _snapshot_path(device_name: str) -> Path:
    _SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    safe_name = device_name.replace("/", "_")
    return _SNAPSHOT_DIR / f"{safe_name}.json"


def load_snapshot(device_name: str) -> dict[str, dict]:
    """Đọc snapshot cũ. Trả về {} nếu chưa có."""
    p = _snapshot_path(device_name)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        log.warning("Đọc snapshot %s lỗi: %s", device_name, e)
        return {}


def save_snapshot(device_name: str, policies_by_id: dict[str, dict]):
    """Ghi snapshot mới (toàn bộ policy hiện tại)."""
    p = _snapshot_path(device_name)
    try:
        p.write_text(json.dumps(policies_by_id, ensure_ascii=False), encoding="utf-8")
    except OSError as e:
        log.warning("Ghi snapshot %s lỗi: %s", device_name, e)


def get_policy_detail(
    cfgpath: str,
    object_id: str,
    action: str,
    fgt_url: str,
    token: str,
    vdom: str,
    current_policies: dict[str, dict] | None,
    old_snapshot: dict[str, dict],
) -> tuple[dict | None, str]:
    """
    Lấy chi tiết object cho 1 sự kiện thay đổi — dispatch theo cfgpath:

      - cfgpath == firewall.policy/policy6 (object_id là SỐ):
          add/edit/move/clone -> tra trong current_policies (source="live")
          delete              -> tra trong old_snapshot      (source="snapshot")

      - cfgpath khác (address/vip/service/addrgrp/... — object_id là TÊN):
          add/edit/move/clone -> gọi fetch_named_object() trực tiếp (source="live")
          delete              -> named object không nằm trong snapshot policy
                                 -> "unavailable" (xem README để biết cách mở rộng)

    Returns:
        (policy_detail | None, source)
        source: "live" | "snapshot" | "unavailable"
    """
    is_policy = cfgpath.lower() in ("firewall.policy", "firewall.policy6")

    if is_policy:
        if action == "delete":
            old = old_snapshot.get(object_id)
            return (old, "snapshot") if old else (None, "unavailable")
        if current_policies is None:
            return None, "unavailable"
        detail = current_policies.get(object_id)
        return (detail, "live") if detail else (None, "unavailable")

    # Named object (address/vip/service/...)
    if action == "delete":
        # Snapshot hiện chỉ lưu policy, không lưu named objects riêng lẻ.
        return None, "unavailable"

    detail = fetch_named_object(fgt_url, token, vdom, cfgpath, object_id)
    return (detail, "live") if detail else (None, "unavailable")


# =============================================================================
# 4. CONNECTIVITY TEST
# =============================================================================

def diagnose(fgt_url: str, token: str, vdom: str) -> str:
    """
    Chẩn đoán kết nối tới 1 FortiGate — gọi 3 endpoint chính, in RAW
    response (status code, headers, body không cắt) để xác định lỗi
    thật khi gặp 403/404/HTML error page.

    Dùng cho `python monitor.py --diagnose <device_name>`.
    Không dùng trong vận hành thường ngày.

    Returns:
        Báo cáo dạng text, in trực tiếp ra terminal.
    """
    out = []
    out.append(f"FGT URL : {fgt_url}")
    out.append(f"VDOM    : {vdom}")
    out.append(f"Token   : {token[:6]}...{token[-4:]}" if len(token) > 10 else "Token   : (qua ngan)")
    out.append("")

    endpoints = [
        ("system/status",      "/api/v2/monitor/system/status", None),
        ("firewall/policy",    "/api/v2/cmdb/firewall/policy",  {"vdom": vdom}),
        ("log/memory/event",        "/api/v2/log/memory/event",        {"rows": "3", "filter": "subtype==system"}),
        ("log/memory/event/system",  "/api/v2/log/memory/event/system",  {"rows": "3"}),
        ("log/disk/event",           "/api/v2/log/disk/event",           {"rows": "3", "filter": "subtype==system"}),
        ("log/disk/event/system",    "/api/v2/log/disk/event/system",    {"rows": "3"}),
    ]

    for label, path, params in endpoints:
        out.append(f"--- {label} ({path}) ---")
        qs  = f"?{urllib.parse.urlencode(params)}" if params else ""
        url = f"{fgt_url.rstrip('/')}{path}{qs}"
        req = urllib.request.Request(
            url,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, context=_SSL, timeout=20) as r:
                body = r.read().decode("utf-8", errors="replace")
                out.append(f"HTTP {r.status}")
                out.append(f"Content-Type: {r.headers.get('Content-Type','')}")
                out.append(f"Server      : {r.headers.get('Server','')}")
                out.append(body[:2000])
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            out.append(f"HTTP {e.code} {e.reason}")
            out.append(f"Content-Type: {e.headers.get('Content-Type','')}")
            out.append(f"Server      : {e.headers.get('Server','')}")
            out.append(body[:2000])
        except urllib.error.URLError as e:
            out.append(f"URLError: {e.reason}")
        out.append("")

    return "\n".join(out)


def test_connection(fgt_url: str, token: str, vdom: str) -> dict:
    """
    Kiểm tra kết nối tới 1 FortiGate.

    Returns:
        {
          "ok": bool,
          "system_status": dict | None,
          "policy_count": int | None,
          "event_log_count": int | None,
          "error": str | None,
        }
    """
    result = {"ok": False, "system_status": None, "policy_count": None,
              "event_log_count": None, "error": None}

    try:
        status = _get(fgt_url, token, "/api/v2/monitor/system/status")
        result["system_status"] = status.get("results")
    except FGTError as e:
        result["error"] = f"system/status: {e}"
        return result

    try:
        policies = fetch_all_policies(fgt_url, token, vdom)
        result["policy_count"] = len(policies)
    except FGTError as e:
        result["error"] = f"cmdb/firewall/policy: {e}"
        return result

    try:
        logs = fetch_event_logs(fgt_url, token, minutes=1440, max_rows=10)
        result["event_log_count"] = len(logs)
    except FGTError as e:
        result["error"] = f"log/memory/event: {e}"
        return result

    result["ok"] = True
    return result
