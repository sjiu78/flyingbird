# get_subscribe.py 使用文件

## 交付內容

- `get_subscribe.py`：固定 server，支援 Android / Windows API 與下載 UA，內建已授權的 3.1.8 共用 GCM key。
- `requirements-subscribe.txt`：必要 Python dependencies。
- `tools/fetch_flyingbird_nodes.py`：訂閱解析器，主程式有引用，不可單獨移除。
- `tools/flyingbird_subscription_codec.py`：可選的 APK 材料重新還原與版本核對。
- `tools/test_get_subscribe.py`：離線回歸測試。
- [Android 與 Windows 訂閱取得方法](flyingbird-3.1.8-subscription-method.md)：實際 UA / headers、GCM key、解密、server 查找及動態驗證方法。

使用 Python 3.10 或更新版本。實際驗證環境為 Windows / Python 3.14；其他作業系統未在本次執行驗證。保留以上相對目錄結構，在交付包根目錄執行。

## 安裝與最短用法

```powershell
python -m pip install -r requirements-subscribe.txt
python get_subscribe.py account@example.invalid
```

只需指定 email，接著在 `密碼:` 提示中輸入密碼，輸入內容不顯示。程式已內建 `https://fbesa.apiv2.a047.com`，不需要 server 參數、不需要啟動 App、不需要 APK。

預設使用 Android 取法。若要 Windows 取法：

```powershell
python get_subscribe.py account@example.invalid --platform windows
```

平台是請求相容模式，不是執行程式的作業系統。在 Windows 電腦上同樣可使用 `--platform android`。兩平台的 GCM key 相同；API UA 與下載 UA 不同，伺服器回傳的節點入口也可能不同。

每次執行會完成：驗證 server → 登入 → 取得訂閱 URL → 下載 → gzip / AES-GCM 解密 → YAML 解析。預設輸出一般摘要，不顯示密碼、登入 token、完整訂閱 URL 或節點連線資料：

```json
{"format":"mihomo-yaml","node_count":74,"node_types":{"vless":74},"decode_layers":0,"encryption":"aes-gcm-base64","platform":"windows"}
```

74 是本次驗證結果，不是程式固定預期的數量；不同帳號方案或服務變更可能回傳不同數量。

## 保存可匯入的解密訂閱

```powershell
python get_subscribe.py account@example.invalid --platform windows --output subscription-windows.yaml
python get_subscribe.py account@example.invalid --platform android --output subscription-android.yaml
```

`--output` 明確要求保存解密內容，輸出檔含節點連線資料，勿公開或加入版本控制。父目錄須已存在；檔案已存在時程式會在登入前停止，請另指定新檔名。寫入階段仍以 exclusive create 防止覆蓋競態。未指定 `--output` 時不保存解密內容。

## 自動化：email 參數 + 密碼 stdin

```powershell
python get_subscribe.py account@example.invalid --platform windows --password-stdin
```

`--password-stdin` 讀取 stdin 第一行並去掉行尾，不使用命令列密碼參數或永久環境變數。直接在 terminal 使用此模式可能由 shell 回顯輸入；手動操作請使用預設隱藏 prompt，自動化由可信任父程序 pipe 注入。

Python 父程序範例，不在命令列或檔案保存密碼：

```python
import getpass
import subprocess
import sys

email = input("Email: ").strip()
password = getpass.getpass("Password: ")
try:
    result = subprocess.run(
        [sys.executable, "get_subscribe.py", email,
         "--platform", "windows", "--password-stdin"],
        input=password + "\n", text=True, check=False,
    )
finally:
    password = None
sys.exit(result.returncode)
```

Python 無法保證立即清除不可變字串的所有記憶體副本；此範例只避免命令列、日誌及檔案持久化。

## 參數表

| 參數 | 行為 |
| --- | --- |
| `email` | 唯一必要的命令列位置參數 |
| `--platform android` | 預設，API / 下載 UA 帶 Android 相容標記 |
| `--platform windows` | 使用 Windows 實際 UA，不帶 Android 相容後綴 |
| `--password-stdin` | 從 stdin 第一行讀取密碼，供可信任程序 pipe 使用 |
| `--output PATH` | 保存解密訂閱到新檔案，不覆寫 |
| `--compare PATH` | 比對既有 nodes JSON，不把敏感差異值印出 |
| `--show-url` | 明確輸出含 token 的訂閱 URL，輸出即具有存取能力 |
| `--apk PATH` | 可選，要求已驗證的 3.1.8 APK；Android 重讀材料，Windows 核對 APK 版本 |
| `--verify` | 相容舊版；現在預設即下載驗證 |
| `--help` | 顯示用法 |

舊用法 `get_subscribe.py SERVER EMAIL` 已取消，會被 argparse 拒絕。程式不接受位置密碼參數。

## 舊檔比較與測試

比對檔支援節點 list，或 `{"nodes": [...]}` JSON：

```powershell
python get_subscribe.py account@example.invalid --platform windows --compare previous-nodes.json
python -m unittest tools.test_get_subscribe -v
```

`identical` 是完整節點內容比較；`added` / `removed` 也是完整內容集合差異。若 74 個相同名称的節點全部更換入口，會顯示 added=74、removed=74、common_names=74，不能解讀成新增 74 個名稱。

離線測試涵蓋平台 UA、固定 server、只傳 email 的 CLI 預設下載、gzip API 回應、佔位 host 替換、不猜 token、下載不帶 Authorization、GCM 完整性與不覆寫輸出。提供 `FLYINGBIRD_TEST_APK`（非秘密檔案路徑）可多驗證內建材料與原版 APK 一致；未提供時該項會 skip。

## server 更新與限制

server 是一般設定，固定在程式 `SERVER_ADDRESS`。目前遠端 bootstrap `hosts` 已重新確認仍包含這個地址。程式不自動改寫 server，不在 API 失敗時無限重試或自行改用其他 origin。

若服務換址，依 [server 取得方法](flyingbird-3.1.8-subscription-method.md#30-server-地址從哪裡取得) 讀 bootstrap 的 hosts，或在記憶體內解密 App 的 api_base_url，再驗證 config、登入和下載，才修改常數。不要使用 example.com 佔位 URL、訂閱 token 或節點 server 作 API server。

成功 exit code 為 0；缺少有效認證、下載失敗、GCM 驗證失敗或輸出寫入失敗為 1；參數錯誤由 argparse 回傳 2。只下載解析訂閱，不啟用系統代理，也不驗證所有節點的實際代理流量。
