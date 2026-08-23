# FAZ Reset Alert Monitor (SHB <-> NAPAS)

Canh bao Telegram khi ket noi giua SHB (cac may chu ESB) va NAPAS (DC1/DC2)
bi **RESET** (Firewall Action = `server-rst` hoac `client-rst`), doc du
lieu tu **FortiAnalyzer LOG TRAFFIC** cua thiet bi `004_DC-FW-PARTNER`.

> **GHI CHU**: He thong nay CHI CON DUY NHAT 1 chuc nang - canh bao RESET
> ket noi SHB<->NAPAS qua `reset_monitor.py`. Toan bo code khong con lien
> quan (monitor.py, event_filter.py, fgt_client.py, debug_faz.py,
> debug_reset_filters*.py) da bi XOA HOAN TOAN khoi repo - khong con ton
> tai duoi bat ky dang nao (kho phai chi "khong dung toi" nhu truoc).

## Nguon du lieu

- Log **TRAFFIC** tren FortiAnalyzer (khong phai log event/system).
- Thiet bi: `004_DC-FW-PARTNER` (co dinh - khong quet cac FortiGate
  khac dan du chung van khai bao trong `devices[]` cua settings.json).
- Dieu kien loc: `srcip` thuoc dai IP SHB, `dstip` thuoc dai IP NAPAS,
  `dstport` trong danh sach cong da khai bao, `action` = `server-rst`
  hoac `client-rst`.

### Dai IP / cong dang giam sat (settings.json -> reset_monitor)

**Nguon (SHB/ESB)**:
```
10.18.38.21   (DR-ESB6)
10.4.38.21    (ESB6-PRO01)
10.4.38.22    (ESB6-PRO02)
10.4.38.23    (ESB6-PRO03)
10.4.38.24    (ESB6-PRO04)
10.4.38.43    (ESB6-PRO05)
10.4.38.44    (ESB6-PRO06)
10.4.38.51-56 (ESBv6.1)
```

**Dich (NAPAS)**:
```
10.1.153.2  (NAPAS-PROD-DC1)
10.1.249.2  (NAPAS-PROD-DC2)
```

**Cong**: `35787`, `35789`

## Cau truc file

```
reset_monitor.py         entry point - quet FAZ log traffic, gui alert Telegram
faz_client.py             FortiAnalyzer Log View REST API client (chi con query_traffic_resets())
reset_filter.py           chuan hoa/phan loai log traffic RST (FAST_RESET / LONG_CONN_RESET)
telegram_notify.py        gui canh bao Telegram (alert ca nhan + tong hop dinh ky + canh bao he thong)
debug_reset.py            tra cuu thu cong 1 khoang thoi gian tuy chinh (khong gui Telegram)
settings.json             cau hinh (commit duoc)
secrets.json.example      template (commit)
secrets.json              token that (gitignore)
logs/reset_monitor.log    tu sinh
logs/reset_seen.json      dedup giua cac lan chay (tranh spam khi interval overlap)
logs/monitor_state.json   dem loi lien tiep + tich luy cua so tong hop dinh ky
```

Yeu cau: Python 3.9+, xem `requirements.txt` (`requests`, `urllib3`).

## API FortiAnalyzer su dung

```
/jsonrpc  method "add"  url /logview/adom/{adom}/logsearch   -> tao search task, tra {"tid": N}
/jsonrpc  method "get"  url /logview/adom/{adom}/logsearch/{tid} -> poll ket qua
```

Auth: Bearer API Token (`secrets.json -> faz_api_token`), khong can
username/password hay dang nhap Web UI.

### GHI CHU QUAN TRONG DA DEBUG THUC TE (logtype "traffic")

- **KHONG the loc log traffic theo `device: [{"devid": "..."}]`** du dung
  dung devid that - FAZ nay tra ve `total-count=0` bat ke dieu kien.
  Ly do: `devid` ghi trong tung dong log TRAFFIC khong trung voi `devid`
  quan ly trong Device Manager/settings.json.
- **Cach dung dung (da verify)**: dung `device: [{"devid": "All_Device"}]`,
  roi dua dieu kien `devname = "004_DC-FW-PARTNER"` **vao trong chuoi
  filter** cung voi `srcip`/`dstip`/`dstport`/`action`. Xem
  `faz_client.py -> query_traffic_resets()` de biet chi tiet.
- Filter dung dau "=" don, noi bang "and"/"or" viet thuong, gia tri IP/
  chuoi bo trong dau nhay kep, so (port) khong can nhay kep.

## Cau hinh script

```bash
cp secrets.json.example secrets.json
```

secrets.json:
```json
{
  "telegram_bot_token": "<token tu BotFather>",
  "faz_api_token": "<API token cua user FAZ, quyen doc Log View ADOM root>"
}
```

settings.json -> dien `telegram.chat_id`. Phan `reset_monitor` da co san
cau hinh mac dinh (xem tren) - chi can sua neu doi dai IP/port/thiet bi.

## Phan loai muc do (Telegram alert)

Moi phien RST duoc phan loai theo `duration` (xem
`reset_filter.classify_reset_duration()`):

| Nhan               | Dieu kien       | Y nghia |
|--------------------|-----------------|---------|
| ⚡ RESET NHANH      | `duration <= 5s`| Bi tu choi/reset gan nhu ngay lap tuc sau khi ket noi - dang chu y hon |
| ⏳ RESET SAU KET NOI KEO DAI | `duration > 5s` | Da truyen du lieu mot thoi gian roi moi bi reset |

Nguong `5s` chinh o **dong 39 file `reset_filter.py`**:
```python
return "FAST_RESET" if duration <= 5 else "LONG_CONN_RESET"
```

## Cau hinh nang cao (do vá cho muc do "dich vu cap 3")

```jsonc
"reset_monitor": {
  ...
  "interval_minutes": 1,             // khop lich AWX quet moi 1 phut
  "query_lookback_minutes": 2,       // quet RONG hon interval de khong bo sot khi job chay tre
  "summary_interval_minutes": 5,     // moi X phut gui 1 tin TONG HOP dem so lan RESET
  "consecutive_fail_threshold": 3,   // FAZ query loi lien tiep bao nhieu lan thi gui canh bao he thong
  "heartbeat_url": ""                // (tuy chon) URL ping healthchecks.io/Cronitor - xem duoi
}
```

### 1. MOI phien RESET duoc alert NGAY LAP TUC + tong hop dinh ky

Hanh vi hien tai:
- **Moi phien RESET moi phat hien** (server-rst hoac client-rst) duoc
  gui alert Telegram **ngay lap tuc**, khong gop/giu lai - dung 1 tin
  cho 1 phien.
- **THEM VAO DO** (khong thay the), moi `summary_interval_minutes` phut
  (mac dinh 5), he thong gui **1 tin TONG HOP** dem tong so phien RESET
  xay ra trong khoang do (breakdown server-rst/client-rst, FAST/LONG
  reset, khoang thoi gian dau-cuoi).

Co che tong hop nay dung **state file** (`logs/monitor_state.json`) de
**cong don qua nhieu lan chay** - bat buoc phai lam vay vi
`interval_minutes=1` nghia la 1 lan quet chi co ~1-2 phut du lieu,
khong du de tong hop dung 5 phut trong 1 lan quet don le.

### 2. Lich quet 1 phut/lan tren AWX

`interval_minutes=1` + `query_lookback_minutes=2` nghia la: **lich AWX
Schedule can dat `*/1 * * * *`** (moi 1 phut), va moi lan quet se query
FAZ trong 2 phut gan nhat (co du 1 phut de tranh bo sot neu job chay
tre) - dedup theo sessionid tu dong loai bo cac phien da alert trong
lan quet truoc do bi trung do overlap.

**Luu y hieu nang**: chay moi 1 phut = ~1440 lan query FAZ/ngay (gap
~10 lan so voi truoc day quet moi 10 phut). Nen theo doi FAZ trong vai
ngay dau de dam bao khong anh huong hieu nang chung cua FAZ (dac biet
neu nhieu nguoi/he thong khac cung dang dung chung FAZ Log View).

`playbook.yml` da chinh `timeout: 45` (bat buoc phai NHO HON 60s de
khong bi 2 job AWX chay chong lan nhau khi lich la 1 phut).

### 3. Canh bao khi HE THONG GIAM SAT gap su co (khong phai canh bao RESET)

Neu FAZ query loi **lien tiep** >= `consecutive_fail_threshold` lan (vi
du token het han, mat mang toi FAZ), `reset_monitor.py` gui **1 tin
Telegram rieng** dang "🆘 HỆ THỐNG GIÁM SÁT GẶP SỰ CỐ" - chi gui 1 lan
duy nhat (khong spam moi lan loi), va gui tiep 1 tin "✅ ĐÃ PHỤC HỒI"
khi query thanh cong tro lai.

**GIOI HAN QUAN TRONG**: co che nay chi phat hien duoc khi script **VAN
DANG CHAY** nhung FAZ tra loi loi. Neu script **NGUNG CHAY HOAN TOAN**
(AWX job bi xoa, cron bi tat, server sap) thi **KHONG co gi tu bao**
duoc - can dich vu heartbeat ben ngoai (xem muc 3).

### 4. (Da bo) Gop tin khi co "burst" nhieu RESET cung luc

Truoc day co co che gop nhieu alert thanh 1 tin khi vuot nguong - **da
BO HOAN TOAN** ca code lan cau hinh, theo yeu cau moi nhat ("co canh bao
thi canh bao luon"). Khong con `build_alert_burst_summary()` hay
`burst_alert_threshold` trong he thong nua.

### 5. Heartbeat / dead-man switch (KHUYEN NGHI cho dich vu cap 3)

`reset_monitor.py` co the ping 1 URL ben ngoai (vi du
[healthchecks.io](https://healthchecks.io) - mien phi cho da so nhu
cau) sau MOI lan chay thanh cong. Dich vu do se **tu canh bao** neu
KHONG nhan duoc ping dung han - day la cach DUY NHAT phat hien truong
hop script ngung chay hoan toan (khong phai chi loi FAZ).

Thiet lap:
1. Tao 1 "check" tren healthchecks.io (hoac tuong tu), lay URL ping.
2. Dien vao `settings.json -> reset_monitor.heartbeat_url`.
3. Cau hinh "Period" tren healthchecks.io = 10 phut (khop
   `interval_minutes`), "Grace Time" = vai phut du de chiu duoc 1-2 lan
   cham tre truoc khi bao dong.
4. healthchecks.io se tu gui email/Telegram/Slack rieng cua ho khi mat
   heartbeat - **doc lap hoan toan** voi bot Telegram cua reset_monitor.py
   (dung neu bot/token cua chinh he thong nay cung bi loi).

### 6. GHI CHU VE DEDUP TREN AWX (chua giai quyet trietde, CANG QUAN TRONG voi lich 1 phut)

`logs/reset_seen.json` va `logs/monitor_state.json` chi ton tai trong
**workspace cua 1 lan chay AWX** - neu AWX KHONG co persistent volume
mount vao `project_dir`, 2 file nay se **mat sau moi job**, dan toi:
- Dedup khong hoat dong qua cac lan chay (co the gui trung alert neu co
  overlap giua 2 lan quet lien tiep - hiem, vi da dung sessionid lam
  khoa dedup va sessionid khong lap lai).
- Bo dem loi lien tiep bi reset ve 0 moi lan chay (giam do nhay cua
  co che #1 tren AWX, vi tung lan chay deu "bat dau lai tu 0").

**Neu dung AWX**: kiem tra Project co mount persistent volume vao
`/runner/project` khong. Neu KHONG, can:
- Cau hinh AWX Execution Environment mount 1 volume ben ngoai vao
  `project_dir/logs/`, HOAC
- Doi dedup/state sang luu ngoai (Redis, database, hoac 1 file tren
  host qua AWX Container Group volume mount) - lien he neu can trien
  khai phan nay.

**QUAN TRONG THEM voi lich 1 phut**: neu `logs/monitor_state.json`
KHONG persistent, co che **TONG HOP DINH KY (muc 1)** se **KHONG BAO
GIO** gui duoc tin tong hop dung nghia - vi moi lan chay se coi
`window_start_ts` la `None` (state moi tinh), dan den cua so "tong hop"
luon bi reset ve 0 truoc khi kip tich luy du 5 phut. Neu gap tinh huong
nay, se thay dong log "Da gui TONG HOP..." KHONG BAO GIO xuat hien
trong `logs/reset_monitor.log` du da chay rat lau - day la dau hieu ro
rang AWX dang khong persistent workspace giua cac lan chay.

## Test

```bash
python reset_monitor.py --test
```

Gui tin nhan Telegram mau (theo dung format alert that) + kiem tra ket
noi FAZ API Token.

## Tra cuu thu cong (khong gui Telegram)

```bash
python debug_reset.py --start "2026-08-20 09:50:00"
```

Them `--raw` de in ra request/response tho gui/nhan tu FAZ khi can debug.

## Chay

```bash
python reset_monitor.py          # 1 lan - dung cho cron / AWX
python reset_monitor.py --loop   # lap moi interval_minutes (settings.json)
```

### Cron (Linux), moi 10 phut
```cron
*/10 * * * * cd /opt/FAZ_RESET_ALERT && /usr/bin/python3 reset_monitor.py >> logs/cron.log 2>&1
```

### systemd (chay --loop lien tuc)

/etc/systemd/system/faz-reset-monitor.service:
```ini
[Unit]
Description=FAZ Reset Alert Monitor (SHB <-> NAPAS)
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/FAZ_RESET_ALERT
ExecStart=/usr/bin/python3 reset_monitor.py --loop
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now faz-reset-monitor
journalctl -u faz-reset-monitor -f
```

### AWX / Ansible

`playbook.yml` da duoc cap nhat de chay `reset_monitor.py` (thay vi
`monitor.py` cu).

## Exit codes

| Code | Y nghia |
|------|---------|
| 0 | OK |
| 1 | Loi cau hinh (thieu file / chua dien secrets) |

## Troubleshooting

| Van de | Nguyen nhan |
|--------|-------------|
| `--test` FAIL FAZ_API_Token | Sai `faz_api_token`, hoac user FAZ thieu quyen Log View ADOM root |
| Query ra 0 ket qua du data co that | Kiem tra dung dang dung `devname` (khong phai `devid`) trong filter - xem phan "GHI CHU QUAN TRONG" o tren |
| Alert bi trung lap giua cac lan chay | Xoa `logs/reset_seen.json` neu muon reset lai dedup, hoac kiem tra `interval_minutes` co bi qua ngan/chong lap khong |
| Telegram FAIL | Sai `bot_token`/`chat_id` |
| Muon giam sat them dai IP/cong/thiet bi khac | Sua `settings.json -> reset_monitor` (`shb_src_ips`, `napas_dst_ips`, `dst_ports`, `device_name`) |

## Push GitHub

```bash
git init && git add .
git commit -m "feat: FAZ reset alert monitor SHB<->NAPAS (remove rule-change monitor)"
git push origin main
```

secrets.json nam trong .gitignore - chi secrets.json.example duoc commit.