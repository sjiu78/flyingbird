"""Read the verified 3.1.8 APK's subscription material without storing secrets."""
import base64
import hashlib
import struct
import zipfile


class ApkSubscriptionCodec:
    def __init__(self, path):
        with zipfile.ZipFile(path) as apk:
            app = apk.read('lib/arm64-v8a/libapp.so')
            core = apk.read('lib/arm64-v8a/libclash.so')
        if (hashlib.sha256(app).hexdigest() !=
                'cb8d621e2d2db1edbf4e657d1a91ec524cd91e145aae8b738e5d8d5a69f57008'
                or hashlib.sha256(core).hexdigest() !=
                'd7dbf2b55e464d8e6d9370cebffeb69f0ba3d8de6d89f6cc1ab2259b3f10a2b3'):
            raise RuntimeError('APK 原生程式庫不符合已驗證的 3.1.8 版本')
        self._marker = app[0x84967:0x84967 + 11].decode('ascii')
        self.api_user_agent = 'Mozilla/5.0 (dart:io) SuperAccelerator ' + self._marker
        self.subscription_user_agent = (
            'securitynet/v3.1.8 clash-verge Platform/android ' + self._marker)
        self._core = core
        phoff = struct.unpack_from('<Q', core, 0x20)[0]
        phsize, phcount = struct.unpack_from('<HH', core, 0x36)
        self._segments = [struct.unpack_from('<IIQQQQQQ', core, phoff + i * phsize)
                          for i in range(phcount)]
        shoff = struct.unpack_from('<Q', core, 0x28)[0]
        shsize, shcount = struct.unpack_from('<HH', core, 0x3a)
        self._relocations = {}
        for i in range(shcount):
            section = struct.unpack_from('<IIQQQQIIQQ', core, shoff + i * shsize)
            if section[1] == 4:  # SHT_RELA
                for off in range(section[4], section[4] + section[5], section[9]):
                    address, info, addend = struct.unpack_from('<QQq', core, off)
                    if info & 0xffffffff == 1027:  # R_AARCH64_RELATIVE
                        self._relocations[address] = addend
        a, b, c = (self._slice(addr) for addr in (0x384e4a0, 0x384e4c0, 0x384e4e0))
        first = bytes(v ^ ((i + 0xc3) & 255) ^ 0x5a for i, v in enumerate(a))
        second = bytes((v - i - 0x3c) & 255 for i, v in enumerate(b))
        third = []
        for i, v in enumerate(c):
            v ^= 0xa7
            shift = i % 5 + 1
            third.append(((v >> shift) | (v << (8 - shift))) & 255)
        self._key = hashlib.sha256(first + second + bytes(third)).digest()
        self._disk_key = bytes(v ^ 0xa7 for v in self._slice(0x384e500))

    def _read(self, address, size):
        for seg in self._segments:
            if seg[0] == 1 and seg[3] <= address and address + size <= seg[3] + seg[5]:
                offset = seg[2] + address - seg[3]
                return self._core[offset:offset + size]
        raise RuntimeError('APK 原生資料位址無效')

    def _slice(self, address):
        pointer, size = struct.unpack('<QQ', self._read(address, 16))
        pointer = self._relocations.get(address, pointer)
        if not 0 < size <= 512:
            raise RuntimeError('APK 原生資料長度無效')
        return self._read(pointer, size)

    def decode_download(self, content):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        try:
            data = base64.b64decode(b''.join(content.split()), altchars=b'-_', validate=True)
            return AESGCM(self._key).decrypt(data[:12], data[12:], None)
        except Exception:
            raise RuntimeError('訂閱 AES-GCM 解密／完整性驗證失敗') from None

    def decode_disk(self, content):
        """APK's saved profile has an additional XOR layer; HTTP content does not."""
        data = bytes(v ^ self._disk_key[i % len(self._disk_key)]
                     for i, v in enumerate(content))
        return self.decode_download(data)
