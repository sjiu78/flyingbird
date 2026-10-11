"""Offline subscription regressions; optional verified APK enables crypto checks."""
import base64
import gzip
import io
import os
import unittest
import contextlib
import tempfile
from pathlib import Path
from unittest.mock import patch

import get_subscribe as subscription
from tools.flyingbird_subscription_codec import ApkSubscriptionCodec


class SubscriptionTests(unittest.TestCase):
    def test_platform_contracts(self):
        windows = subscription.EmbeddedSubscriptionCodec('windows')
        android = subscription.EmbeddedSubscriptionCodec('android')
        self.assertEqual(windows.api_user_agent, 'Mozilla/5.0 (dart:io) SuperAccelerator')
        self.assertEqual(windows.subscription_user_agent, 'securitynet/v3.1.8 clash-verge Platform/windows')
        self.assertTrue(android.subscription_user_agent.endswith(' ' + subscription.APP_COMPATIBILITY_MARKER))
        self.assertTrue(android.api_user_agent.endswith(' ' + subscription.APP_COMPATIBILITY_MARKER))

    def test_email_only_cli_downloads_both_platforms_with_fixed_server(self):
        for platform in ('android', 'windows'):
            with self.subTest(platform=platform):
                arguments = ['get_subscribe.py', 'account@example.invalid', '--password-stdin']
                if platform == 'windows':
                    arguments += ['--platform', 'windows']
                output = io.StringIO()
                with patch.object(subscription.sys, 'argv', arguments), \
                     patch.object(subscription.sys, 'stdin', io.StringIO('dummy-password\n')), \
                     patch.object(subscription, 'api', side_effect=[{'data': {}},
                         {'data': {'auth_data': 'dummy-auth'}},
                         {'data': {'subscribe_url': 'https://api.example.com/api/v1/client/subscribe?token=dummy-sub'}}]) as api, \
                     patch.object(subscription, 'verify_subscription', return_value={'node_count': 1}) as verify, \
                     contextlib.redirect_stdout(output):
                    subscription.main()
                codec = subscription.EmbeddedSubscriptionCodec(platform)
                for call in api.call_args_list:
                    self.assertEqual(call.args[0], subscription.normalize_base(subscription.SERVER_ADDRESS))
                    self.assertEqual(call.kwargs['user_agent'], codec.api_user_agent)
                self.assertEqual(verify.call_count, 1)
                self.assertEqual(verify.call_args.args[2].subscription_user_agent, codec.subscription_user_agent)
                self.assertNotIn('dummy-password', output.getvalue())
                self.assertNotIn('dummy-auth', output.getvalue())
                self.assertNotIn('dummy-sub', output.getvalue())

    def test_windows_api_headers_and_gzip_response(self):
        response = io.BytesIO(gzip.compress(b'{"data": {"ok": true}}'))
        response.headers = {'Content-Encoding': 'gzip'}
        with patch.object(subscription.urllib.request, 'build_opener') as builder:
            builder.return_value.open.return_value = response
            result = subscription.api(subscription.SERVER_ADDRESS, '/guest/comm/config',
                                      user_agent=subscription.EmbeddedSubscriptionCodec('windows').api_user_agent)
        request = builder.return_value.open.call_args.args[0]
        self.assertTrue(result['data']['ok'])
        self.assertEqual(request.get_header('User-agent'), 'Mozilla/5.0 (dart:io) SuperAccelerator')
        self.assertEqual(request.get_header('Accept'), 'application/json')
        self.assertEqual(request.get_header('Accept-encoding'), 'gzip')

    def test_subscription_output_does_not_overwrite(self):
        plain = b'proxies:\n  - {name: test, type: vless, server: node.invalid, port: 443, uuid: "00000000-0000-0000-0000-000000000001"}\n'
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'subscription.yaml'
            for attempt in range(2):
                response = io.BytesIO(plain)
                response.headers = {}
                with patch.object(subscription.urllib.request, 'urlopen', return_value=response):
                    if attempt == 0:
                        result = subscription.verify_subscription('https://subscription.invalid/sub', output=output)
                        self.assertTrue(result['output_written'])
                    else:
                        with self.assertRaisesRegex(RuntimeError, '已存在'):
                            subscription.verify_subscription('https://subscription.invalid/sub', output=output)
            self.assertEqual(output.read_bytes(), plain)

    def test_placeholder_keeps_subscription_token_and_query(self):
        result = subscription.select_subscription_url({'data': {
            'subscribe_url': 'https://api.example.com/api/v1/client/subscribe?token=dummy&type=clash'}},
            base='https://api.invalid/api/v1')
        self.assertEqual(result, 'https://api.invalid/api/v1/client/subscribe?token=dummy&type=clash')

    def test_missing_subscription_token_is_not_guessed(self):
        with self.assertRaises(RuntimeError):
            subscription.select_subscription_url({'data': {
                'subscribe_url': 'https://api.example.com/api/v1/client/subscribe',
                'token': 'login-token'}}, base='https://api.invalid')

    def test_valid_alternate_precedes_placeholder_fallback(self):
        self.assertEqual(subscription.select_subscription_url({'data': {
            'subscribe_url': 'https://api.example.com/api/v1/client/subscribe?token=dummy',
            'subscription_url': 'https://subscription.invalid/sub'}}, base='https://api.invalid'),
            'https://subscription.invalid/sub')

    def test_gzip_encrypted_download_has_no_login_authorization(self):
        plain = b'proxies:\n  - {name: test, type: vless, server: node.invalid, port: 443, uuid: "00000000-0000-0000-0000-000000000001"}\n'
        response = io.BytesIO(gzip.compress(b'encrypted-test-envelope'))
        response.headers = {'Content-Encoding': 'gzip'}
        class Codec:
            subscription_user_agent = 'securitynet/v3.1.8 test-marker'
            def decode_download(self, content):
                assert content == b'encrypted-test-envelope'
                return plain
        with patch.object(subscription.urllib.request, 'urlopen', return_value=response) as opening:
            result = subscription.verify_subscription('https://subscription.invalid/sub?token=dummy', codec=Codec())
        request = opening.call_args.args[0]
        self.assertEqual(request.get_header('User-agent'), Codec.subscription_user_agent)
        self.assertIsNone(request.get_header('Authorization'))
        self.assertEqual(result['node_count'], 1)
        self.assertEqual(result['encryption'], 'aes-gcm-base64')

    @unittest.skipUnless(os.environ.get('FLYINGBIRD_TEST_APK'), 'Set FLYINGBIRD_TEST_APK to verified 3.1.8 APK')
    def test_apk_codec_accepts_base64_and_rejects_tampering(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        codec = ApkSubscriptionCodec(os.environ['FLYINGBIRD_TEST_APK'])
        self.assertTrue(codec._key == subscription.SUBSCRIPTION_KEY, 'Embedded key differs from verified APK')
        self.assertTrue(codec.subscription_user_agent == subscription.EmbeddedSubscriptionCodec.subscription_user_agent,
                        'Embedded UA differs from verified APK')
        self.assertTrue(codec.subscription_user_agent.startswith('securitynet/v3.1.8 '))
        nonce = bytes(range(12))
        envelope = nonce + AESGCM(codec._key).encrypt(nonce, b'synthetic subscription', None)
        for encode in (base64.b64encode, base64.urlsafe_b64encode):
            self.assertEqual(codec.decode_download(encode(envelope)), b'synthetic subscription')
        tampered = envelope[:-1] + bytes([envelope[-1] ^ 1])
        with self.assertRaisesRegex(RuntimeError, '完整性'):
            codec.decode_download(base64.b64encode(tampered))

    def test_download_decrypts_without_apk(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        plain = b'proxies:\n  - {name: test, type: vless, server: node.invalid, port: 443, uuid: "00000000-0000-0000-0000-000000000001"}\n'
        nonce = bytes(range(12))
        envelope = nonce + AESGCM(subscription.SUBSCRIPTION_KEY).encrypt(nonce, plain, None)
        response = io.BytesIO(base64.urlsafe_b64encode(envelope))
        response.headers = {}
        with patch.object(subscription.urllib.request, 'urlopen', return_value=response):
            result = subscription.verify_subscription('https://subscription.invalid/sub?token=dummy')
        self.assertEqual(result['node_count'], 1)
        self.assertEqual(result['encryption'], 'aes-gcm-base64')
        tampered = envelope[:-1] + bytes([envelope[-1] ^ 1])
        with self.assertRaisesRegex(RuntimeError, '完整性'):
            subscription.EmbeddedSubscriptionCodec().decode_download(base64.b64encode(tampered))


if __name__ == '__main__':
    unittest.main()
