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
  /jsonrpc /sys/login/user                  -> JSONRPC session (logout)
  /cgi-bin/module/flatui_auth               -> Web UI login, set cookie
                                                CURRENT_SESSION + HTTP_CSRF_TOKEN
  /p/logview/logsearch/run/                 -> tao search task, tra {"tid": N}
  /p/logview/logsearch/fetch/               -> poll {"tid","limit","offset",
                                                "isLocalEvent": false}
                                                tra {"data": [...], "percentage": 100}

GHI CHU: /jsonrpc KHONG expose module /logview/* (luon -32600 Invalid
Request). API dung la /p/logview/logsearch/... - xac dinh bang DevTools.

Python stdlib only.
"""

import json
import logging
import ssl
import time
import http.cookiejar
import urllib.request
import urllib.error
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


class FAZClient:

    def __init__(self, url: str, username: str, password: str,
                 adom: str = "root", timeout: int = 30):
        self._base     = url.rstrip("/")
        self._username = username
        self._password = password
        self._adom     = adom
        self._timeout  = timeout
        self._id       = 0

        self._jsonrpc_session = None
        self._csrf            = None

        self._cj = http.cookiejar.CookieJar()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self._cj),
            urllib.request.HTTPSHandler(context=_SSL),
        )

    # -- low level ---------------------------------------------------------------

    def _rid(self) -> int:
        self._id += 1
        return self._id

    def _get_cookie(self, name: str):
        for c in self._cj:
            if c.name == name:
                return c.value
        return None

    def _request(self, path: str, body: dict) -> dict:
        raw = json.dumps(body).encode()
        headers = {
            "Content-Type":     "application/json",
            "Accept":           "application/json, text/plain, */*",
            "Referer":          f"{self._base}{_LOGVIEW_REFERER_PATH}",
            "Origin":           self._base,
            "X-Requested-With": "XMLHttpRequest",
        }
        if self._csrf:
            headers["xsrf-token"] = self._csrf

        req = urllib.request.Request(
            f"{self._base}{path}", data=raw, headers=headers, method="POST",
        )
        try:
            with self._opener.open(req, timeout=self._timeout) as r:
                text = r.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            raise FAZError(f"HTTP {e.code} {path}: {err_body[:300]}") from e
        except urllib.error.URLError as e:
            raise FAZError(f"FAZ unreachable ({path}): {e.reason}") from e

        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            raise FAZError(f"FAZ tra ve non-JSON ({path}): {text[:300]}") from e

    # -- login / logout ----------------------------------------------------------

    def login(self):
        resp = self._request("/jsonrpc", {
            "id":     self._rid(),
            "method": "exec",
            "params": [{
                "url":  "/sys/login/user",
                "data": {"user": self._username, "passwd": self._password},
            }],
        })
        if "result" not in resp or resp["result"][0]["status"]["code"] != 0:
            msg = resp.get("result", [{}])[0].get("status", {}).get("message", str(resp))
            raise FAZError(f"FAZ login failed (jsonrpc): {msg}")
        self._jsonrpc_session = resp.get("session")

        ui_resp = self._request("/cgi-bin/module/flatui_auth", {
            "url":    "/gui/userauth",
            "method": "login",
            "params": {
                "username":  self._username,
                "secretkey": self._password,
                "logintype": 0,
            },
        })

        self._csrf = (
            self._get_cookie("HTTP_CSRF_TOKEN")
            or self._get_cookie("csrftoken")
            or self._get_cookie("XSRF-TOKEN")
        )
        has_session = bool(self._get_cookie("CURRENT_SESSION"))

        if not has_session:
            cookie_names = [c.name for c in self._cj]
            raise FAZError(
                f"Web UI login khong set cookie CURRENT_SESSION.\n"
                f"  Cookies nhan duoc: {cookie_names}\n"
                f"  Response flatui_auth: {json.dumps(ui_resp, ensure_ascii=False)[:300]}"
            )

        log.info("FAZ login OK  (csrf=%s, current_session=yes)",
                "yes" if self._csrf else "NO")

    def logout(self):
        if not self._jsonrpc_session:
            return
        try:
            self._request("/jsonrpc", {
                "id":      self._rid(),
                "method":  "exec",
                "session": self._jsonrpc_session,
                "params":  [{"url": "/sys/logout"}],
            })
        except Exception as e:
            log.debug("FAZ logout loi (bo qua): %s", e)
        finally:
            self._jsonrpc_session = None
            log.info("FAZ logout OK")

    def __enter__(self):
        self.login()
        return self

    def __exit__(self, *_):
        self.logout()

    # -- log search ----------------------------------------------------------------

    def query_device_events(self, devid: str, minutes: int, max_rows: int = 200) -> list:
        """
        Query Log View > Logs > Event: System cho 1 thiet bi (theo Data
        Source ID), N phut gan nhat. Chi lay log "Object attribute
        configured(...)" qua server-side filter.

        Args:
            devid: Data Source ID tren FAZ (vd "FG6H1FTB22903740") - xem
                   cot "Data Source ID" trong Log View > Logs tren FAZ UI.

        Returns:
            list[dict] - moi dict co data_sourceid, devname, event_message,
            itime, user (neu co), ...

        Raises:
            FAZError neu run/ khong tra tid hoac fetch/ tra status loi.
        """
        now   = datetime.now()
        start = (now - timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")
        end   = now.strftime("%Y-%m-%d %H:%M:%S")

        run_body = {
            "osType":        31,
            "logtype":       26,
            "timeOrder":     "desc",
            "caseSensitive": False,
            "device":        [{"devid": "All_Device"}],
            "filter": (
                f" data_sourceid={devid}"
                ' event_message="Object attribute configured*"'
            ),
            "isLocalEvent":  False,
            "limit":         max_rows,
            "serverTime":    {"start": start, "end": end},
        }

        resp = self._request("/p/logview/logsearch/run/", run_body)
        tid = resp.get("tid")
        if tid is None:
            raise FAZError(f"logsearch/run khong tra ve tid: {json.dumps(resp)[:300]}")

        rows = []
        for _ in range(_FETCH_MAX_RETRIES):
            r = self._request("/p/logview/logsearch/fetch/", {
                "tid":          tid,
                "limit":        max_rows,
                "offset":       0,
                "isLocalEvent": False,
            })
            status = r.get("status", {})
            if status.get("code") != 0:
                raise FAZError(f"logsearch/fetch loi: {status}")

            rows = r.get("data") or []
            if r.get("percentage", 100) >= 100:
                break
            time.sleep(_FETCH_POLL_DELAY)

        log.info("FAZ device=%s -> %d log(s)  [%s ~ %s]", devid, len(rows), start, end)
        return rows
