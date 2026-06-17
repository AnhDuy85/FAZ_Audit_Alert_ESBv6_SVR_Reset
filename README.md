# FortiGate Rule Change Monitor (Production)
KET HOP: FortiGate truc tiep (nguon chinh) + FortiAnalyzer (nguon du phong)

Canh bao Telegram day du chi tiet khi co thay doi firewall rule (them /
sua / xoa / di chuyen vi tri / enable-disable / nhan ban) tren cac
FortiGate, bao gom:

- Source, Destination, Service/Port
- Trang thai (Enable/Disable), Action (Accept/Deny/IPsec), NAT
- Policy ID / ten object bi thay doi
- User thuc thi + giao dien (GUI/SSH/API)
- Thoi gian thay doi

| Device              | FortiGate IP        | Platform        |
|---------------------|---------------------|-----------------|
| 004_DC-FW-DMZ       | 10.4.30.30          | FortiGate-601F  |
| 004_DC-FW-PARTNER   | 10.4.30.38          | FortiGate-501E  |

## Kien truc - vi sao ket hop FAZ + FGT truc tiep

**FGT truc tiep (nguon chinh)**:
- GET /api/v2/log/memory(or disk)/event[/system] -> event log (audit log)
  -> action, cfgpath, object id, user, thoi gian
- GET /api/v2/cmdb/firewall/policy -> chi tiet source/dest/service/status
  (FAZ KHONG co thong tin nay)

**FAZ (nguon du phong)**:
- FortiGate forward log len FAZ qua "config log fortianalyzer setting" -
  cau hinh nay DOC LAP voi "config log memory/disk setting" tren tung FGT.
- Neu local log tren 1 FGT bi tat/sai (da gap thuc te: 003_DC-FW-INT co
  "log memory setting status disable"), event do se KHONG xuat hien qua
  FGT truc tiep - nhung FAZ van co the da ghi nhan qua forward log.
- monitor.py merge 2 nguon, loai trung lap theo
  (cfgpath, object_id, action, date, time). Event chi co tu FAZ duoc
  danh dau "Phat hien qua FAZ" trong alert - dau hieu local log can kiem tra.

**Ket qua**: alert co day du source/dest/port (tu FGT API) VA khong bi mat
event do FGT local log gap su co (nho FAZ).

## Cau truc file

```
monitor.py            entry point - merge FGT + FAZ, gui alert
fgt_client.py          FortiGate REST API - event log + policy detail + snapshot
faz_client.py           FortiAnalyzer Log View REST API - event log du phong
event_filter.py         loc/parse/merge/dedup event tu 2 nguon
telegram_notify.py       gui canh bao Telegram
settings.json           cau hinh (commit duoc)
secrets.json.example    template (commit)
secrets.json            token/password that (gitignore)
logs/monitor.log        tu sinh
logs/snapshots/         snapshot policy moi thiet bi (cho case delete)
```

Yeu cau: Python 3.9+, stdlib only.

## API su dung

### FortiGate (bat buoc)

```
GET /api/v2/log/memory/event           (v7.x, filter subtype==system)
GET /api/v2/log/memory/event/system    (v6.4.x, subtype trong path)
GET /api/v2/log/disk/event[/system]    (fallback neu memory log disable)
GET /api/v2/cmdb/firewall/policy       -> toan bo policy hien tai
GET /api/v2/cmdb/firewall/{address|vip|addrgrp|...}/{name}  -> named object
```
fgt_client.fetch_event_logs() tu dong thu ca 4 endpoint theo thu tu, dung
endpoint dau tien thanh cong - hoat dong voi ca v6.4.x va v7.x.

### FortiAnalyzer (tuy chon - faz.enabled trong settings.json)

```
/jsonrpc /sys/login/user                  -> JSONRPC session
/cgi-bin/module/flatui_auth               -> set cookie CURRENT_SESSION + CSRF
POST /p/logview/logsearch/run/            -> {"tid": N}
POST /p/logview/logsearch/fetch/          -> {"data":[...], "percentage":100}
```
GHI CHU: /jsonrpc KHONG expose /logview/* (-32600 Invalid Request).
API dung la /p/logview/logsearch/... - xac dinh bang DevTools.

## Cau hinh FortiGate - tao REST API Admin

Tren MOI FortiGate can giam sat, CLI:

```
config system api-user
    edit "monitor-readonly"
        set accprofile "super_admin"
        set vdom "root"
        config trusthost
            edit 1
                set ipv4-trusthost <IP_MAY_CHAY_SCRIPT>/32
            next
        end
    next
end
```

Sau khi tao qua CLI, vao GUI System > Administrators > REST API Administrator,
click vao user moi tao -> Generate de lay token (hien 1 lan duy nhat).

Neu "REST API Admin" bi an trong menu Create New: dang nhap bang account
Super_Admin, hoac tao truoc qua CLI nhu tren roi generate token qua GUI.

## Cau hinh FAZ - lay Data Source ID (faz_devid)

Tren FAZ: Log View > Logs > Logs, tim cot "Data Source ID" cho thiet bi
tuong ung (vd FG6H1FTB22903740). Day la gia tri dien vao
`devices[].faz_devid` trong settings.json.

Tai khoan FAZ can quyen doc Log View cho ADOM tuong ung.

## Cau hinh script

```bash
cp secrets.json.example secrets.json
```

secrets.json:
```json
{
  "telegram_bot_token": "<token tu BotFather>",
  "faz_password": "<mat khau user FAZ - bo qua neu faz.enabled=false>",
  "fgt_api_tokens": {
    "004_DC-FW-DMZ":     "<token tu 004_DC-FW-DMZ>",
    "004_DC-FW-PARTNER": "<token tu 004_DC-FW-PARTNER>"
  }
}
```

settings.json - dien telegram.chat_id. Neu KHONG dung FAZ, dat
`"faz": {"enabled": false}` - khi do khong can faz_password/faz_devid.

### Them thiet bi moi

1. Them block vao `devices[]` trong settings.json:
   ```json
   {
     "name":      "003_DC-FW-INT",
     "fgt_url":   "https://10.20.2.64:10443",
     "platform":  "FortiGate-401F",
     "vdom":      "root",
     "faz_devid": "FG4H1FT924905795"
   }
   ```
   `faz_devid` co the bo qua neu khong dung FAZ cho thiet bi nay.
2. Them token vao `fgt_api_tokens` trong secrets.json voi KEY TRUNG KHOP
   chinh xac voi `name` o tren.
3. Chay `python monitor.py --test` de tao snapshot ban dau cho thiet bi moi.

## Test

```bash
python monitor.py --test
```

Test se:
- Ket noi toi tat ca thiet bi FGT (system/status, cmdb/firewall/policy,
  log event) + TAO SNAPSHOT BAN DAU (quan trong - xem "Luu y ve DELETE")
- Ket noi FAZ (neu enabled) - login + query 24h cho tung faz_devid
- Gui tin nhan test Telegram

### Chan doan loi ket noi FGT (--diagnose)

```bash
python monitor.py --diagnose 003_DC-FW-INT
```

In RAW response (khong cat) cua 4 endpoint FGT - dung khi --test bao loi
403/404/HTML kho hieu. Phan biet loi tu FortiGate (JSON) vs loi tu
proxy/web server phia truoc (HTML error page).

## Chay

```bash
python monitor.py          # 1 lan - dung cho cron / AWX
python monitor.py --loop   # lap moi interval_minutes (settings.json)
```

### Cron (Linux), moi 10 phut
```cron
*/10 * * * * cd /opt/FW_AUDIT && /usr/bin/python3 monitor.py >> logs/cron.log 2>&1
```

### systemd (chay --loop lien tuc)

/etc/systemd/system/fgt-monitor.service:
```ini
[Unit]
Description=FortiGate Rule Change Monitor
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/FW_AUDIT
ExecStart=/usr/bin/python3 monitor.py --loop
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now fgt-monitor
journalctl -u fgt-monitor -f
```

## Logic chi tiet

1. (Neu FAZ enabled) Login FAZ 1 lan, query event log theo faz_devid cho
   tung thiet bi, chuan hoa ve cung format voi log FGT.
2. Voi moi thiet bi:
   - FGT: lay event log, loc type=event/subtype=system/action trong
     watch_actions/cfgpath chua watch_keywords, trong N phut gan nhat
   - Merge voi event FAZ tuong ung (dedup theo cfgpath+object_id+action+
     date+time) - event chi co tu FAZ duoc danh dau "_source=FAZ"
3. Xac dinh object_id:
   - firewall.policy/policy6: SO (vd "859")
   - firewall.address/vip/service/addrgrp/...: TEN (vd "VETC-AWS_172.16.x")
4. Voi thiet bi co event:
   - GET /api/v2/cmdb/firewall/policy -> toan bo policy hien tai
   - So voi snapshot cu (logs/snapshots/{device}.json), luu snapshot moi
5. Lay chi tiet cho tung event:
   - policy + add/edit/move/clone -> tra trong policy hien tai (live)
   - policy + delete -> tra trong snapshot CU (snapshot)
   - named object + add/edit -> goi API rieng (live)
   - named object + delete -> "unavailable" (han che, xem duoi)
6. Gui Telegram:
   - 1 su kien -> 1 tin chi tiet day du
   - >1 su kien -> 1 tin tong hop + tung tin chi tiet
   - Event tu FAZ duoc ghi chu rieng de canh bao local log co van de

## Mau sac / icon theo action

| Action | Y nghia |
|--------|---------|
| add (xanh)        | Them rule moi |
| edit (vang)       | Sua rule (bao gom enable/disable) |
| delete (do)       | Xoa rule |
| move (xanh duong) | Di chuyen vi tri rule |
| clone (tim)       | Nhan ban rule |

Trang thai rule: Enable / Disable. Action policy: ACCEPT / DENY / IPSEC.

## Luu y ve DELETE va snapshot

- **firewall.policy/policy6**: khi bi xoa, script tra source/dest/service
  tu SNAPSHOT cua lan chay TRUOC. LAN CHAY DAU TIEN (hoac sau khi xoa
  logs/snapshots/) se khong co du lieu cho rule bi xoa trong chinh lan
  chay do - chay `python monitor.py --test` truoc de tao snapshot ban dau.

- **Named object (address/vip/service/addrgrp/ippool) khi bi XOA**: hien
  tai tra "unavailable" vi snapshot chi luu firewall.policy.

## Exit codes

| Code | Y nghia |
|------|---------|
| 0 | OK |
| 1 | Loi cau hinh (thieu file / chua dien secrets) |

## Troubleshooting

| Van de | Nguyen nhan |
|--------|-------------|
| `--test` FAIL system/status | Sai token FGT, hoac IP may chay script chua trong trusthost |
| FAIL cmdb/firewall/policy | Token FGT thieu quyen Read Firewall Policy |
| FAIL log event (ca 4 endpoint) | Kiem tra `show log memory setting` / `show log disk setting` / `show log eventfilter` tren FGT - "set status disable" la nguyen nhan thuong gap |
| Loi HTML (`<!DOCTYPE HTML...`) thay vi JSON | Trang loi web server/proxy, KHONG phai FortiGate API. Chay `--diagnose`, kiem tra dung admin-sport |
| FAZ login FAIL | Sai faz.url/username/faz_password; kiem tra quyen ADOM cua user FAZ |
| FAZ query khong tra du lieu | Sai faz_devid - phai khop cot "Data Source ID" tren FAZ Log View |
| Alert lien tuc co dong "Phat hien qua FAZ" | Local log tren FGT co van de - kiem tra log memory/disk setting va eventfilter |
| Alert thieu source/dest cho rule da xoa | Chua co snapshot (lan chay dau) - chay --test truoc |
| Telegram FAIL | Sai bot_token/chat_id |

## Push GitHub

```bash
git init && git add .
git commit -m "feat: FortiGate rule change monitor - FGT direct + FAZ failover"
git push origin main
```

secrets.json nam trong .gitignore - chi secrets.json.example duoc commit.
