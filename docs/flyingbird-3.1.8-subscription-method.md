# FlyingBird 3.1.8：Android 與 Windows 訂閱取得、headers 與解密方法

查證日期：2026-10-11。本文只適用於下列已驗證程式版本。本文不包含個人帳號、密碼、登入憑證、訂閱 token、節點 UUID 或節點入口；共用 AES-GCM key 及完整相容 UA 經明確授權保留。

## 1. 已驗證結果與平台差異

兩平台的主要流程都是「API 登入 → getSubscribe → 解析下載網址 → GET 訂閱 → 解壓 → Base64 / AES-GCM 解密 → YAML 解析」。AES key 與磁碟 XOR 材料相同，但實際 User-Agent 不同。

| 項目 | Android 3.1.8 | Windows 3.1.8 |
| --- | --- | --- |
| API UA | `Mozilla/5.0 (dart:io) SuperAccelerator Env/generic` | `Mozilla/5.0 (dart:io) SuperAccelerator` |
| 訂閱下載 UA | `securitynet/v3.1.8 clash-verge Platform/android Env/generic` | `securitynet/v3.1.8 clash-verge Platform/windows` |
| 下載 Accept-Encoding | `gzip` | `gzip` |
| 下載 Host | 下載 URL 的 authority | 下載 URL 的 authority |
| 下載 Authorization | 沒有 | 沒有 |
| 下載 Cookie / x-auth-token / x-app-package-name / x-client-platform | 實際擷取的請求未出現 | 實際擷取的請求未出現 |
| 訂閱加密 | AES-256-GCM / Base64 | AES-256-GCM / Base64 |
| 此次直接下載解析 | 74 個 VLESS 節點 | 74 個 VLESS 節點 |

`securitynet` 的大小寫必須按實際下載 UA 保留。Android 相容標記是 APK 內建值，並非遠端設定的 `Authentication` 值；Windows 實際請求沒有該後綴。HTTP header 名稱的大小寫無關，但 header 值不可任意改寫。

使用同一有效訂閱 token，依兩平台實際下載 UA 重放後，兩者均 HTTP 200、74 個相同名稱的節點，但 `server` 與 `servername` 各有 74 處差異，其餘欄位一致。因此不能假設改變平台 UA 後會得到完全相同的節點內容。

## 2. 確認程式版本

Android：package `com.fbclient.app`，Activity `com.follow.clash.MainActivity`，版本 3.1.8 / versionCode 2026071612。

| 檔案 | SHA256 |
| --- | --- |
| Android APK | `29184f00db786b028d9cfda8d26a2f1c4a493a6a06ead4043bac5a33034cf420` |
| APK lib/arm64-v8a/libapp.so | `cb8d621e2d2db1edbf4e657d1a91ec524cd91e145aae8b738e5d8d5a69f57008` |
| APK lib/arm64-v8a/libclash.so | `d7dbf2b55e464d8e6d9370cebffeb69f0ba3d8de6d89f6cc1ab2259b3f10a2b3` |
| Windows data/app.so | `9e0813ea10d386e018b4a8acb15fdba61a1652a793eb6402cd9e139eec255e72` |
| Windows 原始 Go 核心 | `97df8e74ec0ad25f557ee2fce3bb9bc59c54d424f59144514bb0fae0836b00a9` |

Windows 安裝包經 Inno Setup 解包後，前端為 `FlyingBird.exe`，Flutter AOT 為 `data/app.so`，原始核心為 `FlyingBirdCore.exe`。若曾使用 IPC 擷取 wrapper，原始核心可能改名為 `real_FlyingBirdCore.exe`；須核對雜湊，不能把 wrapper 當原始核心。

不要把根目錄舊版 3.0.3 APK 當成 3.1.8。新版可能修改 UA、key、offset 或 API 契約，不能直接沿用本文固定值。

## 3. API 流程

程式已內建 `SERVER_ADDRESS = 'https://fbesa.apiv2.a047.com'`，不需要命令列 server 參數。以下 HTTP 範例仍用 `https://api.service.invalid` 作通用佔位示例。API base 為 `/api/v1`，組合時只保留一次此 prefix。

### 3.0 server 地址從哪裡取得

server 是 API origin，不是訂閱 URL，也不是節點 server。查找優先順序是「App 遠端 bootstrap 的 hosts → 本機已驗證 api_base_url → 實際 API / 訂閱請求 Host」。

已確認的 bootstrap 格式為 Base64 編碼 JSON，2026-10-11 重新讀取下列來源得到 HTTP 200：

`https://cdno01.llguanglisf.com/saos/fb_news.json`

此時 `hosts` 包含：

1. `https://fbesa.apiv2.a047.com`（本程式固定採用）。
2. `https://fbesa.web.ak005.com`（原版 App 動態擷取曾使用的另一 origin）。

APK 靜態分析另有三個候選來源：`https://apisa.cnossfile.com/saos/fb_news.json`、`https://tcdn.getxlx.com/saos/saos/fb_news.json`、`https://ocdn01.llguangli25o.com:59991/saos/fb_news.json`。這些是候選鏡像，本文不宣稱本次逐一驗證全部可用。原始來源由常數整數陣列逐 byte XOR `0x1e` 還原；已驗證 APK 解碼呼叫鏈包含 `0x4ba6e8`、`0x4ba71c`、`0x4ba788`。不同 build 不可盲用固定 offset。

安全讀取 hosts 的範例，只輸出一般 server 設定，不輸出 bootstrap 的 Authentication 或其他欄位：

```python
import base64
import json
import urllib.request
from urllib.parse import urlsplit

request = urllib.request.Request(
    "https://cdno01.llguanglisf.com/saos/fb_news.json",
    headers={"User-Agent": "Mozilla/5.0 (dart:io) SuperAccelerator"},
)
with urllib.request.urlopen(request, timeout=30) as response:
    config = json.loads(base64.b64decode(response.read()))
hosts = [value for value in config.get("hosts", [])
         if isinstance(value, str) and urlsplit(value).scheme == "https"
         and urlsplit(value).hostname and not urlsplit(value).username
         and not urlsplit(value).password]
print(json.dumps({"hosts": hosts}))
```

發現 hosts 不代表登入與訂閱可用：還要用對應平台 API UA 驗證 `/guest/comm/config`，再走本人授權帳號的登入、getSubscribe 與訂閱下載。程式現在刻意採固定地址，不在每次執行時自動更新 hosts；服務換域名時重新走上述查證，更新 `get_subscribe.py` 的 `SERVER_ADDRESS`。

本機來源可交叉核對：Windows `%APPDATA%/FlyingBird/FlyingBird/shared_preferences.json` 的 `flutter.api_base_url`，Android App 私有 shared preferences 的同名 key。若值有 `enc1:`，依第 6 節在記憶體內解密，只輸出經 URL 解析後的 API origin。SQLite `profiles.url` 含訂閱 token，只讀取 host/path 用於核對，不能把完整值當普通 server 設定貼出。原版 App 可切換備援 host，因此固定地址與某次擷取 Host 不同不一定代表錯誤。

### 3.1 驗證面板

```http
GET /api/v1/guest/comm/config HTTP/1.1
Host: api.service.invalid
User-Agent: <該平台 API UA>
Content-Type: application/json
Accept: application/json
Accept-Encoding: gzip
```

以上完整 API header 集合由 Windows 實際序列化請求確認；Android API UA 及登入流程已驗證，本文未宣稱所有 Android API 請求的 header 順序及集合均逐一重抓。header 順序不構成功能契約。

### 3.2 登入

```http
POST /api/v1/passport/auth/login HTTP/1.1
Host: api.service.invalid
User-Agent: <該平台 API UA>
Content-Type: application/json
Accept: application/json
Accept-Encoding: gzip

{"email":"ACCOUNT_EMAIL","password":"ACCOUNT_PASSWORD","cf_token":""}
```

這是可實作的登入格式；本次 Windows 動態擷取使用已登入的狀態，沒有重新捕捉原版 Windows 的登入 POST，不能把上述 POST 描述成此次捕捉證據。Content-Length 由 HTTP library 根據 UTF-8 body 自動設定。

登入回應 `data.auth_data` 優先，其次 `data.token`、`data.access_token`。保留伺服器提供的完整認證字串：有 `Bearer ` 就保留，沒有就不要自行補。

### 3.3 取得訂閱資訊

```http
GET /api/v1/user/getSubscribe HTTP/1.1
Host: api.service.invalid
User-Agent: <該平台 API UA>
Accept: application/json
Accept-Encoding: gzip
Authorization: <登入回傳的完整認證字串>
Content-Type: application/json
```

Windows 此 GET 的 UA 與上述 headers 已重新動態擷取確認。API 回應中的 `subscribe_url` 是訂閱來源；其 token 與登入 Authorization 是兩種不同用途的材料。

### 3.4 处理佔位 host

觀察到回應含 `https://api.example.com/api/v1/client/subscribe?token=SUBSCRIPTION_TOKEN`。原版 App 的有效 profile URL 改用目前 API host，保留 path、query 與訂閱 token。

規則：

1. 優先使用回應中的有效非佔位 HTTPS 訂閱 URL。
2. 只有確認為 example.com 佔位 host、path 為 `/api/v1/client/subscribe`、query 含有效 token 時，才換成當前已驗證 API origin 的 authority。
3. 不把登入 token 拼成訂閱 URL；不任意加 `type=clash`；不把登入 Authorization 帶到訂閱 host。
4. 對登入/API redirect 禁止自動跳轉，可避免認證資料被送到其他 host。

## 4. 下載訂閱：實際請求

Windows 重新啟動原版前端及核心，從程序中 TLS 加密前的 HTTP 序列化緩衝擷取到：

```http
GET /api/v1/client/subscribe?token=SUBSCRIPTION_TOKEN HTTP/1.1
user-agent: securitynet/v3.1.8 clash-verge Platform/windows
accept-encoding: gzip
host: api.service.invalid
```

Android 原版 APK 的模擬器動態擷取結果：

```http
GET /api/v1/client/subscribe?token=SUBSCRIPTION_TOKEN HTTP/1.1
user-agent: securitynet/v3.1.8 clash-verge Platform/android Env/generic
accept-encoding: gzip
host: api.service.invalid
```

兩平台下載請求沒有 Authorization，也未觀察到額外 x-* 認證 headers。實際重放 Windows 原始 header 集合後 HTTP 200，回應 `Content-Encoding: gzip`，解密後可解析為 Mihomo YAML。

若 HTTP library 自動解 gzip，不要再解一次。若自行處理 bytes，按 Content-Encoding 解壓，再處理 Base64。限制下載與解壓後大小，現有腳本上限 16 MiB。

## 5. AES-GCM key 與資料封裝

此版本共用 AES-256-GCM key（32 bytes，hex）：

```text
77fc1541d4552bf8879d0597f5ecb6547b0a1b25e33d24dc696e8964fdfe74c0
```

此 key 不由 email、密碼或登入 token 推導。Windows 原始核心包含相同三組混淆材料，且 Android 還原出的 key 實際通過 Windows 訂閱快取及 profile 的 GCM 驗證。

HTTP 回應解壓後：

```text
Base64(nonce[12] || ciphertext || authentication_tag[16])
```

支援標準及 URL-safe Base64。AES-GCM 不使用額外 AAD（Python `None`）。tag 驗證失敗應停止，不能把未驗證 bytes 當 YAML。每份密文的 nonce 在封裝中，不是 key，也不是固定值。

最小解密函式：

```python
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_HEX = "77fc1541d4552bf8879d0597f5ecb6547b0a1b25e33d24dc696e8964fdfe74c0"

def decrypt_download(body: bytes) -> bytes:
    envelope = base64.b64decode(
        b"".join(body.split()), altchars=b"-_", validate=True
    )
    if len(envelope) < 12 + 16:
        raise ValueError("Incomplete AES-GCM envelope")
    return AESGCM(bytes.fromhex(KEY_HEX)).decrypt(
        envelope[:12], envelope[12:], None
    )
```

### 5.1 從 APK 還原 key，便於核對固定值

只有原生程式庫 SHA256 符合第 2 節才使用固定 offset。以 ELF PT_LOAD 將虛擬位址映射到檔案 offset，並套用 `R_AARCH64_RELATIVE` relocation，讀取 Go slice 的 pointer / length。

- 三組 slice header 位址：`0x384e4a0`、`0x384e4c0`、`0x384e4e0`。
- 第 1 組：`a[i] XOR ((i + 0xc3) & 255) XOR 0x5a`。
- 第 2 組：`(b[i] - i - 0x3c) & 255`。
- 第 3 組：先 `c[i] XOR 0xa7`，再向右循環旋轉 `i % 5 + 1` bit。
- 最終 key：`SHA256(part1 || part2 || part3)`。
- Android UA 相容標記：已驗證 `libapp.so` 檔案 offset `0x84967`，長度 11 bytes。

實作在 `tools/flyingbird_subscription_codec.py`；預設直接使用內建 key 的實作在 `get_subscribe.py`。

## 6. 磁碟 profile 與 prefs：不能混用 HTTP 解碼路徑

原版已儲存 `profiles/999999.yaml` 雖有 YAML 副檔名，實際內容需要先移除磁碟 XOR 層：

```text
disk bytes → repeated-key XOR → Base64 → AES-GCM → YAML
```

磁碟 key：從 `libclash.so` Go slice header `0x384e500` 取得 bytes，每 byte XOR `0xa7`。還原後以 index modulo key length 循環 XOR 文件 bytes。HTTP body 沒有這一層。

部分 shared preferences 值以 `enc1:` 開頭：移除 prefix → URL-safe Base64 → nonce/ciphertext/tag → 同一 key AES-GCM 解密。不要把所有 prefs 值當作密文；例如普通 JSON 設定需先判斷 prefix。早期使用標準 Base64 直接解析 URL-safe 快取所產生的錯誤，不是兩平台 key 不同的證據。

常用資料位置只以通用形式表示：

- Android：App 私有資料內的 shared_prefs、files/database.sqlite、files/profiles。
- Windows：`%APPDATA%/FlyingBird/FlyingBird/` 下的 shared_preferences.json、database.sqlite、profiles。
- SQLite profiles.url 保存可下載 URL；讀取時使用 read-only 模式，輸出不得包含 query 中的 token。

## 7. 使用現有 Python 工具

從專案根目錄安裝依賴，再執行。密碼使用隱藏 prompt，不能放在命令列參數：

```powershell
python -m pip install -r requirements-subscribe.txt
python get_subscribe.py account@example.invalid
python get_subscribe.py account@example.invalid --platform windows
python get_subscribe.py account@example.invalid --platform android --compare PATH_TO_PRIOR_NODES_JSON
python -m unittest tools.test_get_subscribe -v
```

`get_subscribe.py` 預設使用 Android 已驗證 UA / key；`--platform windows` 同時切換 API 與下載 UA。預設即下載、解密與解析，`--verify` 僅保留為相容參數。`--apk PATH` 可選，Android 從已驗證 APK 重新還原材料；Windows 用它核對 APK 版本，仍使用 Windows UA。`--show-url` 明確開啟後會輸出含 token 的 URL，正常診斷不需要它。預設只回報摘要；明確指定 `--output PATH` 才寫入解密訂閱，且不覆寫既有檔案。完整操作見 [程式使用文件](get-subscribe-usage.md)。

重放 Windows 下載時，可沿用同一解密器，替換下載 UA：

```python
import get_subscribe as client

windows_codec = client.EmbeddedSubscriptionCodec("windows")

# subscription_url 必須來自本人已授權帳號的 getSubscribe 及上述 URL 規則。
# 它含秘密 token，不要輸出或寫入文件。
result = client.verify_subscription(subscription_url, codec=windows_codec)
```

若在 Python 中重放完整 Windows API 流程，每次呼叫 `client.api` 時傳入 `user_agent=windows_codec.api_user_agent`；避免修改全域 UA，防止兩平台混用。CLI 的 `--platform windows` 已將這些步驟整合。

## 8. 動態驗證方法與證據標準

Android：

常用命令（裝置 serial 及檔案位置自行替換）：

```powershell
adb devices
adb -s EMULATOR_SERIAL install -r PATH_TO_VERIFIED_APK
adb -s EMULATOR_SERIAL root
adb -s EMULATOR_SERIAL push PATH_TO_MATCHING_FRIDA_SERVER /data/local/tmp/frida-server
adb -s EMULATOR_SERIAL shell chmod 755 /data/local/tmp/frida-server
adb -s EMULATOR_SERIAL shell "nohup /data/local/tmp/frida-server >/dev/null 2>&1 </dev/null &"
adb -s EMULATOR_SERIAL shell am start -n com.fbclient.app/com.follow.clash.MainActivity
frida-ps -D EMULATOR_SERIAL -ai
```

僅在可拋棄的 rooted 測試模擬器執行 root / server 命令，Frida server 版本需與 host 套件相符。本次使用 Frida 17.12.0。Android 15 模擬器的 native bridge 已支援 ARM64；APK 沒有完整 x86_64 Flutter/core，不能僅因裝置是 x86_64 就略過 ARM 翻譯需求。

1. 使用隔離 Android 15 / API 35 x86_64 Google APIs 模擬器，以 ARM native bridge 執行原版 ARM64 APK。
2. 驗證 APK 版本及雜湊，安裝後以授權帳號登入，觸發訂閱刷新。
3. 透過 Frida 對程序 rw 記憶體內 HTTP 序列化資料擷取 method、path 與 headers。完整 token 只留在可信任程序記憶體，輸出前移除 query 值、Authorization 值及登入 body。
4. 重放實際下載 UA，確認 HTTP status、解壓、GCM tag 驗證及 YAML 節點解析。另解密 App 已儲存 profile 作交叉核對。

Windows：

1. 解包原版 3.1.8，核對前端 app.so 與原始核心雜湊。用測試副本，不使用擷取 wrapper 作下載核心。
2. 建立測試資料副本，在測試設定關閉 autoRun、systemProxy、VPN、系統 DNS 自動設定及更新。單純設 APPDATA 或只改 CreateFileW 不保證隔離所有 Windows 寫入。
3. 在前端 resume 前，以 Frida 導向測試資料路徑；檔案建立、讀取、rename / replace / delete 都要涵蓋，SQLite 亦須留意實際 API。只擷取指定測試程序及其原始核心。
4. 捕捉 API 與 `/api/v1/client/subscribe` 的 TLS 前 HTTP headers；保留 UA，遮蔽認證 header，去掉 token query 值。捕捉腳本不得落地原始記憶體或登入 body。
5. 使用真正訂閱 URL 在可信任程序內重放捕捉到的 headers，驗證 HTTP 200、gzip、GCM 完整性與 74 節點解析，再比較兩平台的完整 node 內容，而非只比較数量。
6. 停止指定測試程序。對原始 prefs / database 記錄測試前後 metadata 或 hash，必要 baseline 僅暫存於記憶體。首次測試發現原子寫入繞過 CreateFileW 隔離；已還原受影響設定，後續加入 rename / replace 導向及原始 prefs baseline 回復。

Windows 本次實際捕捉的 API endpoints：guest/comm/config、user/info、user/getStat、user/notice/fetch、user/getSubscribe；另捕捉 client/subscribe 下載。登入 POST 未在此次 Windows capture 中出現，詳見第 3 節限制。

Windows 可使用 `frida.get_local_device().spawn(...)` 暫停啟動前端，attach 後先安裝隔離 hooks，再 resume；列舉測試 child core PID 後 attach。HTTP 擷取的核心邏輯如下，適用測試前端或核心程序；這段只回傳必要 headers，避免輸出 GET token 或登入 body：

```javascript
rpc.exports.snapshot = function () {
  const output = [];
  const seen = new Set();
  for (const range of Process.enumerateRanges({protection: 'rw-', coalesce: true})) {
    if (range.size > 300000000) continue;
    try {
      for (const match of Memory.scanSync(range.base, range.size, '47 45 54 20 2f').slice(0, 100)) {
        try {
          const bytes = new Uint8Array(match.address.readByteArray(4096));
          const text = String.fromCharCode(...bytes);
          const first = text.match(/^GET ([^\r\n ]+) HTTP\/1\.[01]\r\n/);
          const end = text.indexOf('\r\n\r\n');
          if (!first || end < 0) continue;
          const path = first[1].split('?')[0];
          if (!path.startsWith('/api/v1/')) continue;
          const headers = {};
          for (const line of text.slice(0, end).split('\r\n').slice(1)) {
            const colon = line.indexOf(':');
            if (colon < 1) continue;
            const name = line.slice(0, colon).toLowerCase();
            // UA 經授權保留；Host 用一般佔位名稱；其他只保留安全已知欄位。
            if (name === 'host') headers[name] = '<API_HOST>';
            else if (['user-agent', 'accept', 'accept-encoding', 'content-type'].includes(name)) {
              headers[name] = line.slice(colon + 1).trim();
            } else headers[name] = '<redacted>';
          }
          const item = {method: 'GET', path, headers};
          const signature = JSON.stringify(item);
          if (!seen.has(signature)) { seen.add(signature); output.push(item); }
        } catch (_) {}
      }
    } catch (_) {}
  }
  return output;
};
```

這是對 TLS 前序列化請求的動態證據，並非封包擷取；掃描未找到不代表請求未送出。需在觸發下載後及時讀取，並以實際重放結果交叉驗證。不能將「將 TLS 端口打開」或「HTTP header 字串靜態存在」等同於實際下載成功。

成功標準是整條下載、解密、解析路徑；登入成功或 HTTP 200 不能單獨代表成功。此次未驗證所有節點的 VLESS / Vision 代理流量。

## 9. 常見失敗與排查順序

| 症狀 | 優先核對 |
| --- | --- |
| API 403 | API UA、有效 API origin、路由與防護回應，不先亂加 Origin / Referer |
| 訂閱 401 / 403 | 是否用了 API UA；securitynet 大小寫；平台值；Android 相容後綴；是否誤用登入 token |
| example.com URL 無法下載 | getSubscribe 佔位 host 替換規則，不直接照抄、不猜 token |
| HTTP 200 但不是 YAML | gzip、Base64、AES-GCM 解密順序 |
| GCM tag 驗證失敗 | key 對應版本、Base64 類型、nonce 前 12 bytes、資料有無被截斷或多解一次 |
| 磁碟 yaml 解密失敗 | 先移除 disk XOR；HTTP 不做 disk XOR |
| 74 節點但與舊檔不同 | 比較 name / server / servername / UUID 等欄位；平台 UA 可得到不同結果 |
| Android emulator 崩潰 | Android 11 ARM bridge 在此環境不穩；成功證據來自 Android 15，不將 emulator 崩潰當成 API 失敗 |

原有 `subscription_pipeline_process.md` 描述其他舊版下載及明文 fallback 路徑；對本文已驗證的 3.1.8 AES-GCM 訂閱應使用本文，不能直接沿用舊版 x-* headers 或「HTTP body 已是 YAML」的假設。
