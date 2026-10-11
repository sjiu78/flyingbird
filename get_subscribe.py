#!/usr/bin/env python3
"""
直接下載並解密 FlyingBird-Lite 訂閱
複刻 App 內部的 V2Board API 流程，不需開啟 App。

用法:
    python get_subscribe.py <email> [--platform android|windows] [--password-stdin]

    已內建驗證過的 server，預設 Android 取法。
    密碼預設隱藏輸入，不再接受命令列密碼。
    已內建 3.1.8 的相容 UA 與訂閱 key，不需 APK。
    --apk PATH 可選，改從已驗證的 3.1.8 APK 讀取材料。
    預設下載並解析訂閱；--compare PATH 比對既有 nodes JSON。
    --output PATH 將解密訂閱寫入新檔案（不覆寫既有檔案）。
    --show-url 明確輸出含秘密的訂閱網址，預設隱藏。
"""
import json
import argparse
import getpass
import gzip
import io
import base64
from pathlib import Path
import sys
import urllib.request
import urllib.error
import urllib.parse

# 使用者於 2026-10-11 明確授權將 3.1.8 共用材料直接寫入此程式。
# 適用已驗證的 3.1.8；新版 App 可能更換材料。
SUBSCRIPTION_KEY = bytes.fromhex('77fc1541d4552bf8879d0597f5ecb6547b0a1b25e33d24dc696e8964fdfe74c0')
APP_COMPATIBILITY_MARKER = 'Env/generic'
USER_AGENT = 'Mozilla/5.0 (dart:io) SuperAccelerator ' + APP_COMPATIBILITY_MARKER
SERVER_ADDRESS = 'https://fbesa.apiv2.a047.com'
API_UA_PREFIX = 'Mozilla/5.0 (dart:io) SuperAccelerator'


class EmbeddedSubscriptionCodec:
    api_user_agent = USER_AGENT
    subscription_user_agent = (
        'securitynet/v3.1.8 clash-verge Platform/android ' + APP_COMPATIBILITY_MARKER)

    def __init__(self, platform='android'):
        if platform not in ('android', 'windows'):
            raise ValueError('platform 必須是 android 或 windows')
        self.api_user_agent = API_UA_PREFIX
        self.subscription_user_agent = f'securitynet/v3.1.8 clash-verge Platform/{platform}'
        if platform == 'android':
            self.api_user_agent += ' ' + APP_COMPATIBILITY_MARKER
            self.subscription_user_agent += ' ' + APP_COMPATIBILITY_MARKER

    def decode_download(self, content):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        try:
            data = base64.b64decode(b''.join(content.split()), altchars=b'-_', validate=True)
            return AESGCM(SUBSCRIPTION_KEY).decrypt(data[:12], data[12:], None)
        except Exception:
            raise RuntimeError('訂閱 AES-GCM 解密／完整性驗證失敗') from None

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def normalize_base(base):
    base = base.strip().rstrip('/')
    if '://' not in base:
        base = 'https://' + base
    p = urllib.parse.urlsplit(base)
    if p.scheme != 'https' or not p.hostname or p.username or p.password or p.query or p.fragment:
        raise ValueError('API 地址必須為不含帳密與 query 的 HTTPS URL')
    return base if base.endswith('/api/v1') else base + '/api/v1'

def api(base, path, token=None, data=None, user_agent=None):
    url = normalize_base(base) + '/' + path.lstrip('/')
    headers = {
        'User-Agent': user_agent or USER_AGENT,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Accept-Encoding': 'gzip',
    }
    if token:
        headers['Authorization'] = token
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=headers,
                                 method='POST' if data else 'GET')
    try:
        with urllib.request.build_opener(NoRedirect()).open(req, timeout=30) as r:
            raw = r.read()
            if getattr(r, 'headers', {}).get('Content-Encoding', '').lower() == 'gzip':
                with gzip.GzipFile(fileobj=io.BytesIO(raw)) as compressed:
                    raw = compressed.read(16 * 1024 * 1024 + 1)
            if len(raw) > 16 * 1024 * 1024:
                raise RuntimeError('API 回應超過 16 MiB 限制')
            return json.loads(raw)
    except urllib.error.HTTPError as e:
        print(f'[!] {path} -> HTTP {e.code}')
        return None

def select_authorization(login):
    data = (login or {}).get('data')
    if isinstance(data, dict):
        for key in ('auth_data', 'token', 'access_token'):
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    raise RuntimeError('登入回應缺少有效認證字串')

def select_subscription_url(sub, base=None):
    data = (sub or {}).get('data')
    if not isinstance(data, dict):
        raise RuntimeError('訂閱回應缺少 data')
    placeholder = False
    fallback = None
    for key in ('subscribe_url', 'subscription_url', 'subscribeUrl', 'url'):
        value = data.get(key)
        if not isinstance(value, str) or not value.strip():
            continue
        url = value.strip()
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
            continue
        if parsed.hostname == 'example.com' or parsed.hostname.endswith('.example.com'):
            placeholder = True
            if (base and parsed.path == '/api/v1/client/subscribe'
                    and urllib.parse.parse_qs(parsed.query).get('token')):
                # 原版 APK 動態驗證：保留訂閱 token/path，改用目前 API 的 host。
                origin = urllib.parse.urlsplit(normalize_base(base))
                fallback = urllib.parse.urlunsplit(parsed._replace(netloc=origin.netloc))
            continue
        return url
    if fallback:
        return fallback
    if placeholder:
        raise RuntimeError('登入成功，但 API 回傳 example.com 佔位訂閱網址；尚未取得可下載的訂閱')
    raise RuntimeError('API 未回傳有效 HTTPS 訂閱地址，不以登入 token 猜測網址')

def verify_subscription(url, compare=None, codec=None, output=None):
    from collections import Counter
    from tools.fetch_flyingbird_nodes import decode_subscription
    p = urllib.parse.urlsplit(url)
    if p.scheme != 'https' or not p.hostname or p.username or p.password:
        raise RuntimeError('訂閱 URL 必須為 HTTPS 且不含帳密')
    if codec is None:
        codec = EmbeddedSubscriptionCodec()
    req = urllib.request.Request(url, headers={
        'User-Agent': codec.subscription_user_agent, 'Accept-Encoding': 'gzip'})
    # 訂閱下載不帶登入 Authorization，避免洩漏至其他 host。
    with urllib.request.urlopen(req, timeout=30) as response:
        raw = response.read(16 * 1024 * 1024 + 1)
        if len(raw) > 16 * 1024 * 1024:
            raise RuntimeError('訂閱超過 16 MiB 限制')
        if response.headers.get('Content-Encoding', '').lower() == 'gzip':
            with gzip.GzipFile(fileobj=io.BytesIO(raw)) as compressed:
                raw = compressed.read(16 * 1024 * 1024 + 1)
    if len(raw) > 16 * 1024 * 1024:
        raise RuntimeError('訂閱超過 16 MiB 限制')
    try:
        decoded = decode_subscription(raw)
        encryption = 'none'
    except Exception:
        decoded = decode_subscription(codec.decode_download(raw))
        encryption = 'aes-gcm-base64'
    result = {'format': decoded.format, 'node_count': len(decoded.nodes),
              'node_types': decoded.node_types, 'decode_layers': decoded.decode_layers,
              'encryption': encryption}
    if compare:
        previous = json.loads(Path(compare).read_text(encoding='utf-8-sig'))
        old_nodes = previous.get('nodes') if isinstance(previous, dict) else previous
        if not isinstance(old_nodes, list):
            raise RuntimeError('比對檔案缺少 nodes list')
        def signature(nodes):
            return Counter(json.dumps(n, sort_keys=True, ensure_ascii=False) for n in nodes)
        old, new = signature(old_nodes), signature(decoded.nodes)
        result.update(previous_node_count=len(old_nodes), identical=old == new,
                      added=sum((new - old).values()), removed=sum((old - new).values()))
        previous = {n['name']: n for n in old_nodes if 'name' in n}
        current = {n['name']: n for n in decoded.nodes if 'name' in n}
        common = previous.keys() & current.keys()
        changed = Counter(key for name in common
                          for key in previous[name].keys() | current[name].keys()
                          if previous[name].get(key) != current[name].get(key))
        result.update(common_names=len(common), changed_fields=dict(changed))
    if output:
        try:
            with Path(output).open('x', encoding='utf-8', newline='\n') as target:
                target.write(decoded.text.rstrip() + '\n')
        except FileExistsError:
            raise RuntimeError('輸出檔案已存在，請指定另一個 --output 路徑') from None
        result['output_written'] = True
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('email')
    parser.add_argument('--platform', choices=('android', 'windows'), default='android')
    parser.add_argument('--password-stdin', action='store_true')
    parser.add_argument('--show-url', action='store_true')
    parser.add_argument('--verify', action='store_true', help='相容舊版參數；現在預設即下載驗證')
    parser.add_argument('--compare', type=Path)
    parser.add_argument('--apk', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.output and args.output.exists():
        raise RuntimeError('輸出檔案已存在，請指定另一個 --output 路徑')
    codec = EmbeddedSubscriptionCodec(args.platform)
    if args.apk:
        from tools.flyingbird_subscription_codec import ApkSubscriptionCodec
        apk_codec = ApkSubscriptionCodec(args.apk)
        if args.platform == 'android':
            codec = apk_codec
    email = args.email
    password = (sys.stdin.readline().rstrip('\r\n') if args.password_stdin
                else getpass.getpass('密碼: '))
    if not password:
        raise RuntimeError('密碼不可為空')
    base = normalize_base(SERVER_ADDRESS)

    # 1. 驗證伺服器（App 輸入地址時做的同一件事）
    print('[1] 驗證伺服器...')
    cfg = api(base, '/guest/comm/config', user_agent=codec.api_user_agent)
    if cfg is None:
        print('[!] 伺服器無回應或不是 V2Board 面板，檢查地址是否正確')
        sys.exit(1)
    print('    OK，面板名稱:', cfg.get('data', {}).get('site_name', '(未知)'))

    # 2. 登入
    print('[2] 登入...')
    login = api(base, '/passport/auth/login',
                data={'email': email, 'password': password, 'cf_token': ''},
                user_agent=codec.api_user_agent)
    password = None
    token = select_authorization(login)
    print('    登入成功，取得 token')

    # 3. 拿訂閱地址
    print('[3] 獲取訂閱地址...')
    sub = api(base, '/user/getSubscribe', token=token, user_agent=codec.api_user_agent)
    url = select_subscription_url(sub, base=base)
    print('    已依 App 規則取得下載地址（預設隱藏）')
    result = verify_subscription(url, args.compare, codec, args.output)
    result['platform'] = args.platform
    print(json.dumps(result, ensure_ascii=False))
    if args.show_url:
        print(url)

if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        message = str(exc) if type(exc) is RuntimeError else type(exc).__name__
        print('[!] ' + message, file=sys.stderr)
        sys.exit(1)
