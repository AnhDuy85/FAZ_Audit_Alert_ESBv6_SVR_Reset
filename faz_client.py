"""
faz_client.py — FortiAnalyzer Log View REST API client
==============================================================================
Dung lam NGUON DU PHONG cho event log, song song voi ket noi truc tiep
FortiGate (fgt_client.py).

Ly do ket hop:
  - FortiGate forward log len FAZ qua "config log fortianalyzer setting",
    cau hinh NAY DOC LAP voi "config log memory/disk setting" tren tung FGT.
  - Neu local log tren 1 FGT bi tat/sai cau hinh (nhu da gap voi
    003_DC-FW-INT: "log memory setting status disable"), FAZ van co the
    da ghi nhan event do qua forward log -> khong bi mat alert.
  - FAZ KHONG cung cap source/destination/port -> van can fgt_client.py
    de enrich chi tiet policy.

Da verify hoat dong tren FAZ v7.6.3-build3492.

API:
  /jsonrpc  method "get"  url /dvmdb/adom/{adom}/device        -> test connection
  /jsonrpc  method "add"  url /logview/adom/{adom}/logsearch   -> tao search task,
                                                                    tra {"tid": N}
  /jsonrpc  method "get"  url /logview/adom/{adom}/logsearch/{tid}
                                                                -> poll ket qua,
                                                                    tra {"data": [...],
                                                                    "percentage": 100}

Auth: Bearer API Token qua header Authorization (KHONG can username/password,
KHONG can login Web UI/cookie session).

GHI CHU QUAN TRONG (da debug thuc te tren FAZ v7.6.3-build3492):
  - Method phai la "add" (tao task) / "get" (doc ket qua), KHONG PHAI "exec".
    Dung "exec" cho module logview se luon tra ve -32600 Invalid Request.
  - Payload JSON-RPC top-level BAT BUOC phai co du "jsonrpc": "2.0" va
    "session": None, du dang dung Bearer token (khong dang nhap session
    that). Thieu 2 field nay cung gay -32600 Invalid Request, ngay ca khi
    method/url/params dung het.
  - "device" phai la list cac dict dang [{"devid": "..."}], KHONG PHAI
    chuoi/list chuoi tran.
  - "time-range" dung dang {"start": "YYYY-MM-DDTHH:MM:SS", "end": "..."},
    KHONG PHAI {"last": seconds}.
  - "filter" dung dau "=" don va noi bang "or" viet thuong, gia tri bo
    trong dau nhay kep, vi du:
    'action = "edit" or action = "add" or action = "delete"'.

Da verify hoat dong tren FAZ v7.6.3-build3492.

Python stdlib only.
"""

import json
import logging
import ssl
import time
import http.cookiejar
import urllib.request
import urllib.error
import requests  # type: ignore # <--- BỔ SUNG DÒNG NÀY Ở ĐẦU FILE

from datetime import datetime, timedelta

log = logging.getLogger("faz")

_SSL = ssl.create_default_context()
_SSL.check_hostname = False
_SSL.verify_mode    = ssl.CERT_NONE

_LOGVIEW_REFERER_PATH = "/ui/logview/logs/logview_all/31/26"
_FETCH_MAX_RETRIES = 20
_FETCH_POLL_DELAY  = 0.5

class FAZError(Exception):
    """Loi nghiep vu FAZ: login fail, API loi, network loi, response sai format."""
    pass


def _classify_change(record: dict) -> str:
    """
    Xac dinh loai thay doi cu the tu 1 record log, uu tien nhan dien
    DISABLE/ENABLE ngay ca khi action ghi la "edit" chung chung.

    GIA DINH VE FIELD (dua tren cau truc audit log pho bien cua
    FortiGate/FAZ - can doi chieu lai voi log thuc te neu ten field
    tren thiet bi cua ban khac):
      - action:  "edit" | "add" | "delete" | "move" | "clone" | ...
      - cfgattr: chuoi mo ta thuoc tinh da doi, vi du
                 'status[enable->disable]' khi tat 1 rule.
    Neu cfgattr khong co hoac khong dung format nay, ham se fallback
    ve action goc, KHONG suy doan sai.
    """
    action = str(record.get("action", "")).lower()
    cfgattr = str(record.get("cfgattr", "")).lower()

    if action == "disable":
        return "DISABLE_RULE"
    if action == "enable":
        return "ENABLE_RULE"
    if action == "delete":
        return "DELETE_RULE"

    if action == "edit" and "status" in cfgattr:
        if "->disable" in cfgattr:
            return "DISABLE_RULE"
        if "->enable" in cfgattr:
            return "ENABLE_RULE"

    return action.upper() or "UNKNOWN"

class FAZClient:
    def __init__(self, url: str, api_token: str, adom: str = "root"):
        self.base_url = url.rstrip('/')
        self.url = f"{self.base_url}/jsonrpc"
        self.api_token = api_token
        self.adom = adom
        # Bọc Header chuẩn xác theo cơ chế REST API Auth của Fortinet
        self.headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_token}", # Thử phương thức Bearer token nếu hệ thống đi qua gateway
            "APIToken": f"{self.api_token}"
        }

    def _post(self, payload: dict) -> dict:
        try:
            res = requests.post(self.url, json=payload, headers=self.headers, verify=False, timeout=30)
            res.raise_for_status()
            res_json = res.json()
            
            if "result" in res_json:
                result_data = res_json["result"]
                
                if isinstance(result_data, list) and len(result_data) > 0:
                    first_res = result_data[0]
                    status = first_res.get("status", {})
                    # SỬA TẠI ĐÂY: Nếu code khác 0 -> Ép ném lỗi ra ngoài ngay lập tức
                    if status.get("code", 0) != 0: 
                        raise Exception(f"FAZ Error [{status.get('code')}]: {status.get('message')}")
                    return first_res
                    
                elif isinstance(result_data, dict):
                    status = result_data.get("status", {})
                    if status.get("code", 0) != 0:
                        raise Exception(f"FAZ Error [{status.get('code')}]: {status.get('message')}")
                    return result_data
            return res_json
        except requests.RequestException as e:
            raise Exception(f"HTTP Error: {e}")

    def test_connection(self) -> bool:
        """
        Kiểm tra Token bằng cách lấy danh sách thiết bị (Device Manager).
        Đây là URL an toàn nhất, không bị lỗi chặn phân quyền -11 của LogView database.
        """
        payload = {
            "method": "get",
            "params": [
                {
                    "url": f"/dvmdb/adom/{self.adom}/device"
                }
            ],
            "id": 1
        }
        try:
            self._post(payload)
            return True
        except Exception:
            return False

    def query_device_events(self, devid: str, minutes: int, max_rows: int = 500) -> list:
        """
        Lay danh sach log thay doi cau hinh qua /logview/adom/{adom}/logsearch,
        dung API Token qua /jsonrpc (KHONG can username/password).
        Chi tiet cac rang buoc format bat buoc: xem ghi chu dau file.
        """
        search_url = f"/logview/adom/{self.adom}/logsearch"

        now = datetime.now()
        start_time = now - timedelta(minutes=minutes)
        time_fmt = "%Y-%m-%dT%H:%M:%S"

        # CÚ PHÁP FILTER CHUẨN: dấu "=" đơn, nối bằng "or" viết thường,
        # giá trị bọc trong dấu nháy kép (theo đúng tài liệu Fortinet).
        # Thêm "disable"/"enable" phòng truong hop FAZ ghi rieng 2 action
        # nay (khong gop chung vao "edit") khi rule bi tat/bat.
        filter_str = (
            'action = "edit" or action = "add" or action = "delete" '
            'or action = "move" or action = "clone" '
            'or action = "disable" or action = "enable"'
        )

        add_payload = {
            "jsonrpc": "2.0",
            "session": None,
            "method": "add",
            "params": [
                {
                    "apiver": 3,
                    "case-sensitive": False,
                    "device": [{"devid": devid}],
                    "logtype": "event",
                    "subtype": "system",
                    "filter": filter_str,
                    "time-order": "desc",
                    "time-range": {
                        "start": start_time.strftime(time_fmt),
                        "end": now.strftime(time_fmt),
                    },
                    "url": search_url,
                }
            ],
            "id": 2
        }

        log.debug("FAZ REQUEST (add): %s", json.dumps(add_payload))

        add_res = self._post(add_payload)

        tid = add_res.get("tid")
        if tid is None:
            raise FAZError(f"logsearch (add) khong tra ve tid: {add_res}")

        fetch_payload = {
            "jsonrpc": "2.0",
            "session": None,
            "method": "get",
            "params": [
                {
                    "apiver": 3,
                    "offset": 0,
                    "limit": max_rows,
                    "url": f"{search_url}/{tid}",
                }
            ],
            "id": 2
        }

        collected = []
        for attempt in range(_FETCH_MAX_RETRIES):
            fetch_res = self._post(fetch_payload)

            log.debug("FAZ RESPONSE (fetch tid=%s): %s", tid, json.dumps(fetch_res))

            batch = fetch_res.get("data", [])
            if isinstance(batch, list) and batch:
                collected = batch

            percentage = fetch_res.get("percentage", 100)
            if percentage >= 100 or len(collected) >= max_rows:
                break

            time.sleep(_FETCH_POLL_DELAY)
        else:
            log.warning("FAZ logsearch tid=%s chua hoan tat sau %s lan poll", tid, _FETCH_MAX_RETRIES)

        # Gan nhan change_type cho tung record (vi du DISABLE_RULE) de
        # code goi ham (monitor.py) de phan biet muc do nghiem trong,
        # khong can tu doi chieu action/cfgattr o tang tren nua.
        for record in collected:
            if isinstance(record, dict):
                record["change_type"] = _classify_change(record)

        return collected[:max_rows]