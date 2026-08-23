"""
faz_client.py — FortiAnalyzer Log View REST API client

Duy nhat 1 chuc nang: query_traffic_resets() - truy van LOG TRAFFIC tren
FAZ de bat cac phien bi RESET (Firewall Action = server-rst / client-rst)
giua dai IP SHB (ESB) va dai IP NAPAS, tren cong 35787/35789. Dung boi
reset_monitor.py.

Auth: Bearer API Token qua header Authorization (settings.json/secrets.json
-> faz_api_token). Khong can username/password, khong can login Web UI.

API dung:
  /jsonrpc  method "add"  url /logview/adom/{adom}/logsearch
            -> tao search task, tra {"tid": N}
  /jsonrpc  method "get"  url /logview/adom/{adom}/logsearch/{tid}
            -> poll ket qua, tra {"data": [...], "percentage": 100}

GHI CHU QUAN TRONG (da debug thuc te tren FAZ v7.6.3-build3492):
  - Method phai la "add" (tao task) / "get" (doc ket qua), KHONG PHAI "exec".
  - Payload JSON-RPC top-level BAT BUOC phai co du "jsonrpc": "2.0" va
    "session": None, du dang dung Bearer token.
  - "time-range" dung dang {"start": "YYYY-MM-DDTHH:MM:SS", "end": "..."}.
  - "filter" dung dau "=" don, noi bang "and"/"or" viet thuong, gia tri
    IP/chuoi bo trong dau nhay kep, so (port) khong can nhay kep.
  - **KHONG the loc log TRAFFIC theo `device: [{"devid": "..."}]`** du
    dung dung devid that - FAZ nay tra ve total-count=0 bat ke dieu kien.
    Ly do: devid ghi trong tung dong log TRAFFIC khong trung voi devid
    quan ly trong Device Manager/settings.json.
  - **Cach dung dung (da verify)**: dung `device: [{"devid": "All_Device"}]`,
    roi dua dieu kien `devname = "004_DC-FW-PARTNER"` VAO TRONG chuoi
    filter cung voi srcip/dstip/dstport/action. Xem query_traffic_resets()
    ben duoi.

Raw log traffic thuc te tren FAZ (Log View > Logs, filter
Source IP=10.4.38.* AND Firewall Action=server-rst):

  date=2026-08-20 time=09:58:23 itime=2026-08-20 09:58:24 ...
  type=traffic subtype=forward level=notice action=server-rst
  policyid=872 sessionid=181156104 srcip=10.4.38.54 dstip=10.1.249.2
  transip=10.253.196.24 srcport=57498 dstport=35789 transport=57498
  trandisp=snat duration=5 proto=6 sentbyte=60 rcvdbyte=40 sentpkt=1
  rcvdpkt=1 logid=0000000013 service=NAPAS-PROD-ACQ_35789
  app=NAPAS-PROD-ACQ_35789

Python stdlib + `requests`.
"""

import json
import logging
import ssl
import time

import requests  # type: ignore

from datetime import datetime, timedelta

log = logging.getLogger("faz")

_FETCH_MAX_RETRIES = 20
_FETCH_POLL_DELAY  = 0.5

class FAZError(Exception):
    """Loi nghiep vu FAZ: login fail, API loi, network loi, response sai format."""
    pass


def _build_ip_or_filter(field: str, ip_list: list) -> str:
    """'srcip', ['10.4.38.21','10.4.38.22'] -> '(srcip = "10.4.38.21" or srcip = "10.4.38.22")'"""
    parts = [f'{field} = "{ip}"' for ip in ip_list]
    return "(" + " or ".join(parts) + ")"


def _build_port_or_filter(field: str, ports: list) -> str:
    """'dstport', [35787, 35789] -> '(dstport = 35787 or dstport = 35789)'"""
    parts = [f"{field} = {p}" for p in ports]
    return "(" + " or ".join(parts) + ")"


def _build_action_or_filter(actions: list) -> str:
    parts = [f'action = "{a}"' for a in actions]
    return "(" + " or ".join(parts) + ")"


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

    def query_traffic_resets(self, devname: str, minutes: int, src_ips: list,
                              dst_ips: list, dst_ports: list,
                              actions: list = None, max_rows: int = 200) -> list:
        """
        Truy van LOG TRAFFIC tren FAZ, loc theo srcip/dstip/dstport/action,
        dung de bat RESET (server-rst / client-rst) giua SHB (ESB) va NAPAS.

        QUAN TRONG - da debug thuc te (xem README):
          - Tham so "device" cap tren (vi du [{"devid": "..."}]) KHONG loc
            duoc log TRAFFIC tren FAZ nay - du dung dung devid that, van
            tra ve total-count=0.
          - Ly do: devid thuc te ghi trong tung dong log TRAFFIC (vi du
            "FG5H1E5819905057") KHONG TRUNG voi devid cua thiet bi trong
            Device Manager / settings.json (vi du "FG5H1ETB19908551") -
            co the do FAZ ghi devid theo serial goc tai thoi diem log,
            khac voi devid hien dang quan ly. => KHONG THE dung devid de
            loc traffic log duoc.
          - Cach lam dung (da verify): dung device=[{"devid": "All_Device"}]
            (khong loc theo device o tang API), roi dua dieu kien
            'devname = "<ten thiet bi>"' VAO TRONG chuoi filter cung voi
            srcip/dstip/dstport/action. devname MATCH dung va tra ve dung
            ket qua.

        actions mac dinh = ["server-rst", "client-rst"] (ca 2 chieu reset:
        server tuc NAPAS gui RST, hoac client tuc SHB gui RST).

        Tra ve list dict = cac dong log traffic tho tu FAZ (chua qua
        normalize) - dung reset_filter.normalize_reset_event() de chuan hoa
        truoc khi gui alert.
        """
        if actions is None:
            actions = ["server-rst", "client-rst"]

        search_url = f"/logview/adom/{self.adom}/logsearch"

        now = datetime.now()
        start_time = now - timedelta(minutes=minutes)
        time_fmt = "%Y-%m-%dT%H:%M:%S"

        filter_str = " and ".join([
            f'devname = "{devname}"',
            _build_ip_or_filter("srcip", src_ips),
            _build_ip_or_filter("dstip", dst_ips),
            _build_port_or_filter("dstport", dst_ports),
            _build_action_or_filter(actions),
        ])

        add_payload = {
            "jsonrpc": "2.0",
            "session": None,
            "method": "add",
            "params": [
                {
                    "apiver": 3,
                    "case-sensitive": False,
                    "device": [{"devid": "All_Device"}],
                    "logtype": "traffic",
                    "subtype": "forward",
                    "filter": filter_str,
                    "time-order": "desc",
                    "time-range": {
                        "start": start_time.strftime(time_fmt),
                        "end": now.strftime(time_fmt),
                    },
                    "url": search_url,
                }
            ],
            "id": 3,
        }

        log.debug("FAZ REQUEST traffic (add): %s", json.dumps(add_payload))

        add_res = self._post(add_payload)
        tid = add_res.get("tid")
        if tid is None:
            raise FAZError(f"logsearch traffic (add) khong tra ve tid: {add_res}")

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
            "id": 3,
        }

        collected = []
        for _ in range(_FETCH_MAX_RETRIES):
            fetch_res = self._post(fetch_payload)

            log.debug("FAZ RESPONSE traffic (fetch tid=%s): %s", tid, json.dumps(fetch_res))

            batch = fetch_res.get("data", [])
            if isinstance(batch, list) and batch:
                collected = batch

            percentage = fetch_res.get("percentage", 100)
            if percentage >= 100 or len(collected) >= max_rows:
                break

            time.sleep(_FETCH_POLL_DELAY)
        else:
            log.warning("FAZ logsearch traffic tid=%s chua hoan tat sau %s lan poll", tid, _FETCH_MAX_RETRIES)

        return collected[:max_rows]