#!/usr/bin/env python
#
# Copyright 2026 shadowsocks contributors
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

# Shadowsocks 2022 Edition (SIP022), single user
# https://github.com/Shadowsocks-NET/shadowsocks-specs
#
# The "password" is a base64 encoded pre-shared key (PSK) of exactly the
# cipher's key length, e.g. `openssl rand -base64 32`.
#
# TCP request:   salt
#                AEAD(type=0, timestamp, length of the first chunk)
#                AEAD(socks address, padding length, padding, payload)
#                [AEAD(length), AEAD(payload)]...
# TCP response:  salt
#                AEAD(type=1, timestamp, request salt, length of 1st chunk)
#                AEAD(payload)
#                [AEAD(length), AEAD(payload)]...
#   session key = BLAKE3-derive_key("shadowsocks 2022 session subkey",
#                                   PSK + salt), nonce is a LE counter
#
# UDP (AES):     AES-ECB(PSK, session id + packet id)
#                AEAD(session key(PSK + session id),
#                     nonce = last 12 bytes of the plain separate header,
#                     body)
# UDP (ChaCha):  24 byte nonce
#                XChaCha20-Poly1305(PSK, session id + packet id + body)
#
# client body:   type=0, timestamp, padding length, padding, address, payload
# server body:   type=1, timestamp, client session id, padding length,
#                padding, address, payload

from __future__ import absolute_import, division, print_function, \
    with_statement

import base64
import binascii
import os
import random
import struct
import time

from ctypes import c_char_p, c_int, c_void_p, byref, create_string_buffer

from shadowsocks import common
from shadowsocks.crypto import aead, openssl
from shadowsocks.crypto.aead import AeadError, TAG_LEN, nonce_increment
from shadowsocks.crypto.blake3_kdf import derive_key

__all__ = ['ciphers', 'is_aead2022']

SUBKEY_CONTEXT = b'shadowsocks 2022 session subkey'
MAX_CHUNK_SIZE = 0xFFFF
MAX_PADDING_SIZE = 900
MAX_TIME_DIFF = 30
SALT_TTL = 60

TYPE_CLIENT = 0
TYPE_SERVER = 1

# method: (key_len, AEAD cipher used for the payload)
ciphers = {
    '2022-blake3-aes-128-gcm': (16, 'aes-128-gcm'),
    '2022-blake3-aes-256-gcm': (32, 'aes-256-gcm'),
    '2022-blake3-chacha20-poly1305': (32, 'chacha20-ietf-poly1305'),
}


def is_aead2022(method):
    return (method or '').lower() in ciphers


def decode_psk(password, method):
    key_len = ciphers[method][0]
    password = common.to_bytes(password).strip()
    key = None
    for decode in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            key = decode(password + b'=' * (-len(password) % 4))
            break
        except (TypeError, ValueError, binascii.Error):
            pass
    if key is None or len(key) != key_len:
        raise ValueError('%s needs a base64 encoded %d byte key as password, '
                         'generate one with: openssl rand -base64 %d' %
                         (method, key_len, key_len))
    return key


def now():
    return int(time.time())


def check_timestamp(ts):
    if abs(now() - ts) > MAX_TIME_DIFF:
        raise AeadError('timestamp %d is off by %d seconds, check the clock '
                        'on both sides' % (ts, ts - now()))


def _new_aead(method, key, op):
    name = ciphers[method][1]
    backend = aead.ciphers[name][3]
    return backend(common.to_bytes(name), key, 12, op)


class TimedSaltFilter(object):
    """Remembers salts for at least SALT_TTL seconds.

    Together with the timestamp check this rejects every replay.
    """

    def __init__(self, ttl=SALT_TTL):
        self._ttl = ttl
        self._current = set()
        self._previous = set()
        self._rotated = time.time()

    def check_and_add(self, salt):
        t = time.time()
        if t - self._rotated >= self._ttl:
            self._previous = self._current
            self._current = set()
            self._rotated = t
        if salt in self._current or salt in self._previous:
            return False
        self._current.add(salt)
        return True


salt_filter = TimedSaltFilter()


class SessionCipher(object):
    def __init__(self, method, psk, salt, op):
        key_len = ciphers[method][0]
        subkey = derive_key(SUBKEY_CONTEXT, psk + salt, key_len)
        self._crypto = _new_aead(method, subkey, op)
        self._nonce = bytearray(12)

    def encrypt(self, data):
        r = self._crypto.encrypt(self._nonce, data)
        nonce_increment(self._nonce)
        return r

    def decrypt(self, data):
        r = self._crypto.decrypt(self._nonce, data)
        nonce_increment(self._nonce)
        return r


def _addr_len(data):
    header = common.parse_header(data)
    if header is None:
        raise AeadError('invalid address in request header')
    return header[3]


class Aead2022Encryptor(object):
    """TCP stream codec for one connection.

    sslocal (is_server=False) encrypts the request and decrypts the response;
    ssserver (is_server=True) decrypts the request and encrypts the response.
    The first plaintext sslocal encrypts must start with the socks address;
    ssserver gets the address followed by the payload, without the padding.
    """

    def __init__(self, password, method, is_server):
        self._method = method = method.lower()
        self._psk = decode_psk(password, method)
        self._salt_len = ciphers[method][0]
        self._is_server = is_server
        self._salt = None
        self._request_salt = None
        self._cipher = None
        self._decipher = None
        self._buf = b''
        self._chunk_len = None
        self._first_chunk = True

    def encrypt(self, buf):
        if len(buf) == 0:
            return buf
        result = []
        if self._cipher is None:
            self._salt = os.urandom(self._salt_len)
            self._cipher = SessionCipher(self._method, self._psk, self._salt,
                                         1)
            result.append(self._salt)
            if self._is_server:
                if self._request_salt is None:
                    raise AeadError('response before request')
                header = struct.pack('>BQ', TYPE_SERVER, now()) + \
                    self._request_salt
            else:
                header = struct.pack('>BQ', TYPE_CLIENT, now())
                addr_len = _addr_len(buf)
                padding = 0
                if len(buf) == addr_len:
                    # no initial payload: pad to hide the request size
                    padding = random.randint(1, MAX_PADDING_SIZE)
                buf = buf[:addr_len] + struct.pack('>H', padding) + \
                    b'\x00' * padding + buf[addr_len:]
            first, buf = buf[:MAX_CHUNK_SIZE], buf[MAX_CHUNK_SIZE:]
            header += struct.pack('>H', len(first))
            result.append(self._cipher.encrypt(header))
            result.append(self._cipher.encrypt(first))
        cipher = self._cipher
        for i in range(0, len(buf), MAX_CHUNK_SIZE):
            chunk = buf[i:i + MAX_CHUNK_SIZE]
            result.append(cipher.encrypt(struct.pack('>H', len(chunk))))
            result.append(cipher.encrypt(chunk))
        return b''.join(result)

    def _read_header(self, buf):
        # returns the remaining buffer, or None if more data is needed
        salt_len = self._salt_len
        if self._is_server:
            header_len = 1 + 8 + 2
        else:
            header_len = 1 + 8 + salt_len + 2
        if len(buf) < salt_len + header_len + TAG_LEN:
            return None
        salt = buf[:salt_len]
        decipher = SessionCipher(self._method, self._psk, salt, 0)
        header = decipher.decrypt(buf[salt_len:salt_len + header_len +
                                      TAG_LEN])
        stream_type, ts = struct.unpack('>BQ', header[:9])
        expected = TYPE_CLIENT if self._is_server else TYPE_SERVER
        if stream_type != expected:
            raise AeadError('unexpected stream type %d' % stream_type)
        check_timestamp(ts)
        if self._is_server:
            if not salt_filter.check_and_add(salt):
                raise AeadError('repeated salt detected, possible replay '
                                'attack')
            self._request_salt = salt
        elif header[9:9 + salt_len] != self._salt:
            raise AeadError('response does not match our request')
        self._chunk_len = struct.unpack('>H', header[-2:])[0]
        self._decipher = decipher
        return buf[salt_len + header_len + TAG_LEN:]

    def decrypt(self, buf):
        if self._buf:
            buf = self._buf + buf
        if self._decipher is None:
            rest = self._read_header(buf)
            if rest is None:
                self._buf = buf
                return b''
            buf = rest
        decipher = self._decipher
        result = []
        pos = 0
        l = len(buf)
        while True:
            if self._chunk_len is None:
                if l - pos < 2 + TAG_LEN:
                    break
                self._chunk_len = struct.unpack(
                    '>H', decipher.decrypt(buf[pos:pos + 2 + TAG_LEN]))[0]
                pos += 2 + TAG_LEN
            n = self._chunk_len + TAG_LEN
            if l - pos < n:
                break
            data = decipher.decrypt(buf[pos:pos + n])
            self._chunk_len = None
            pos += n
            if self._first_chunk and self._is_server:
                data = self._strip_padding(data)
            self._first_chunk = False
            result.append(data)
        self._buf = buf[pos:]
        return b''.join(result)

    @staticmethod
    def _strip_padding(data):
        addr_len = _addr_len(data)
        if len(data) < addr_len + 2:
            raise AeadError('request header too short')
        padding = struct.unpack('>H', data[addr_len:addr_len + 2])[0]
        if padding > MAX_PADDING_SIZE or \
                len(data) < addr_len + 2 + padding:
            raise AeadError('invalid padding')
        return data[:addr_len] + data[addr_len + 2 + padding:]


# UDP

class _AesEcb(object):
    """Single block AES-ECB for the UDP separate header."""

    def __init__(self, key):
        if not openssl.loaded:
            openssl.load_openssl()
        lib = self._lib = openssl.libcrypto
        lib.EVP_CIPHER_CTX_set_padding.argtypes = (c_void_p, c_int)
        lib.EVP_CipherInit_ex.restype = c_int
        name = b'aes-%d-ecb' % (len(key) * 8)
        cipher = openssl.get_cipher(name)
        if not cipher:
            raise Exception('cipher %s not found in libcrypto' % name)
        self._ctx = [None, None]
        for op in (0, 1):
            ctx = lib.EVP_CIPHER_CTX_new()
            if not ctx:
                raise Exception('can not create cipher context')
            self._ctx[op] = ctx
            if not lib.EVP_CipherInit_ex(ctx, cipher, None, c_char_p(key),
                                         None, c_int(op)):
                raise Exception('can not initialize cipher context')
            lib.EVP_CIPHER_CTX_set_padding(ctx, 0)
        self._out = create_string_buffer(32)
        self._out_len = c_int(0)

    def _update(self, op, block):
        self._lib.EVP_CipherUpdate(self._ctx[op], self._out,
                                   byref(self._out_len), c_char_p(block), 16)
        return self._out.raw[:16]

    def encrypt(self, block):
        return self._update(1, block)

    def decrypt(self, block):
        return self._update(0, block)

    def __del__(self):
        for ctx in getattr(self, '_ctx', ()):
            if ctx:
                self._lib.EVP_CIPHER_CTX_free(ctx)


class PacketWindow(object):
    """Sliding window replay filter for UDP packet ids."""

    SIZE = 2048

    def __init__(self):
        self._max = -1
        self._bits = 0

    def check_and_set(self, packet_id):
        if packet_id > self._max:
            shift = packet_id - self._max
            if shift >= self.SIZE:
                self._bits = 1
            else:
                self._bits = ((self._bits << shift) | 1) & \
                    ((1 << self.SIZE) - 1)
            self._max = packet_id
            return True
        offset = self._max - packet_id
        if offset >= self.SIZE or (self._bits >> offset) & 1:
            return False
        self._bits |= 1 << offset
        return True


class _ExpiringDict(object):
    def __init__(self, ttl=300, limit=10000):
        self._ttl = ttl
        self._limit = limit
        self._items = {}

    def get(self, key):
        item = self._items.get(key)
        if item is None:
            return None
        item[0] = time.time()
        return item[1]

    def set(self, key, value):
        if len(self._items) >= self._limit:
            self._expire()
        self._items[key] = [time.time(), value]

    def _expire(self):
        deadline = time.time() - self._ttl
        for k in [k for k, v in self._items.items() if v[0] < deadline]:
            del self._items[k]
        if len(self._items) >= self._limit:
            # still full: drop the oldest half
            items = sorted(self._items.items(), key=lambda kv: kv[1][0])
            for k, _ in items[:len(items) // 2]:
                del self._items[k]


class _UdpPacketCodec(object):
    def __init__(self, password, method):
        self._method = method = method.lower()
        self._psk = decode_psk(password, method)
        self._chacha = method == '2022-blake3-chacha20-poly1305'
        if self._chacha:
            self._xchacha = aead.SodiumAeadCrypto('xchacha20-ietf-poly1305',
                                                  self._psk, 24, 1)
        else:
            self._ecb = _AesEcb(self._psk)
            self._body_ciphers = _ExpiringDict(ttl=60, limit=10000)

    def _body_cipher(self, session_id, op):
        c = self._body_ciphers.get((session_id, op))
        if c is None:
            subkey = derive_key(SUBKEY_CONTEXT,
                                self._psk + struct.pack('>Q', session_id),
                                ciphers[self._method][0])
            c = _new_aead(self._method, subkey, op)
            self._body_ciphers.set((session_id, op), c)
        return c

    def encode_packet(self, session_id, packet_id, body):
        header = struct.pack('>QQ', session_id, packet_id)
        if self._chacha:
            nonce = os.urandom(24)
            return nonce + self._xchacha.encrypt(nonce, header + body)
        body = self._body_cipher(session_id, 1).encrypt(header[4:], body)
        return self._ecb.encrypt(header) + body

    def decode_packet(self, data):
        if self._chacha:
            if len(data) < 24 + 16 + TAG_LEN:
                raise AeadError('packet too short')
            plain = self._xchacha.decrypt(data[:24], data[24:])
            session_id, packet_id = struct.unpack('>QQ', plain[:16])
            return session_id, packet_id, plain[16:]
        if len(data) < 16 + TAG_LEN:
            raise AeadError('packet too short')
        header = self._ecb.decrypt(data[:16])
        session_id, packet_id = struct.unpack('>QQ', header)
        decipher = self._body_cipher(session_id, 0)
        body = decipher.decrypt(header[4:], data[16:])
        return session_id, packet_id, body


def _skip_padding(body, pos):
    if len(body) < pos + 2:
        raise AeadError('packet too short')
    padding = struct.unpack('>H', body[pos:pos + 2])[0]
    pos += 2 + padding
    if len(body) < pos:
        raise AeadError('invalid padding')
    return body[pos:]


class _ServerSession(object):
    def __init__(self):
        self.session_id = struct.unpack('>Q', os.urandom(8))[0]
        self.packet_id = 0
        self.window = PacketWindow()


class UdpServerCodec(_UdpPacketCodec):
    def __init__(self, password, method, timeout=300):
        super(UdpServerCodec, self).__init__(password, method)
        self._sessions = _ExpiringDict(ttl=max(timeout, 60))

    def decode(self, data):
        """Returns (client session id, address + payload)."""
        session_id, packet_id, body = self.decode_packet(data)
        if len(body) < 1 + 8:
            raise AeadError('packet too short')
        packet_type, ts = struct.unpack('>BQ', body[:9])
        if packet_type != TYPE_CLIENT:
            raise AeadError('unexpected packet type %d' % packet_type)
        check_timestamp(ts)
        session = self._sessions.get(session_id)
        if session is None:
            session = _ServerSession()
            self._sessions.set(session_id, session)
        if not session.window.check_and_set(packet_id):
            raise AeadError('repeated packet id, possible replay attack')
        return session_id, _skip_padding(body, 9)

    def encode(self, client_session_id, data):
        session = self._sessions.get(client_session_id)
        if session is None:
            session = _ServerSession()
            self._sessions.set(client_session_id, session)
        session.packet_id += 1
        body = struct.pack('>BQQH', TYPE_SERVER, now(), client_session_id,
                           0) + data
        return self.encode_packet(session.session_id, session.packet_id, body)


class UdpClientCodec(_UdpPacketCodec):
    def __init__(self, password, method):
        super(UdpClientCodec, self).__init__(password, method)
        self._session_id = struct.unpack('>Q', os.urandom(8))[0]
        self._packet_id = 0
        self._server_session_id = None
        self._window = None

    def encode(self, data):
        self._packet_id += 1
        body = struct.pack('>BQH', TYPE_CLIENT, now(), 0) + data
        return self.encode_packet(self._session_id, self._packet_id, body)

    def decode(self, data):
        """Returns address + payload."""
        session_id, packet_id, body = self.decode_packet(data)
        if len(body) < 1 + 8 + 8:
            raise AeadError('packet too short')
        packet_type, ts, client_session_id = struct.unpack('>BQQ', body[:17])
        if packet_type != TYPE_SERVER:
            raise AeadError('unexpected packet type %d' % packet_type)
        check_timestamp(ts)
        if client_session_id != self._session_id:
            raise AeadError('packet is not for this session')
        if session_id != self._server_session_id:
            # first packet, or the server restarted
            self._server_session_id = session_id
            self._window = PacketWindow()
        if not self._window.check_and_set(packet_id):
            raise AeadError('repeated packet id, possible replay attack')
        return _skip_padding(body, 17)


def test_tcp():
    for method, (key_len, _) in sorted(ciphers.items()):
        psk = base64.b64encode(os.urandom(key_len))
        client = Aead2022Encryptor(psk, method, False)
        server = Aead2022Encryptor(psk, method, True)
        addr = b'\x03\x0bexample.com\x00\x50'
        # request without payload gets padding, which the server strips
        req = client.encrypt(addr)
        assert len(req) > key_len + 11 + 16 + len(addr) + 2 + 16
        assert server.decrypt(req[:10]) == b''
        assert server.decrypt(req[10:]) == addr
        big = os.urandom(200000)
        data = client.encrypt(big)
        out = b''.join(server.decrypt(data[i:i + 999])
                       for i in range(0, len(data), 999))
        assert out == big
        resp = server.encrypt(big)
        assert client.decrypt(resp) == big
        # replay of the same request is rejected
        try:
            Aead2022Encryptor(psk, method, True).decrypt(req)
        except AeadError:
            pass
        else:
            raise AssertionError('replay accepted')


def test_tcp_initial_payload():
    psk = base64.b64encode(os.urandom(32))
    client = Aead2022Encryptor(psk, '2022-blake3-aes-256-gcm', False)
    server = Aead2022Encryptor(psk, '2022-blake3-aes-256-gcm', True)
    req = b'\x01\x7f\x00\x00\x01\x00\x50GET / HTTP/1.0\r\n\r\n'
    assert server.decrypt(client.encrypt(req)) == req


def test_wrong_key():
    method = '2022-blake3-aes-128-gcm'
    client = Aead2022Encryptor(base64.b64encode(os.urandom(16)), method,
                               False)
    server = Aead2022Encryptor(base64.b64encode(os.urandom(16)), method,
                               True)
    try:
        server.decrypt(client.encrypt(b'\x01\x7f\x00\x00\x01\x00\x50'))
    except AeadError:
        return
    raise AssertionError('wrong key accepted')


def test_timestamp():
    global now
    psk = base64.b64encode(os.urandom(32))
    method = '2022-blake3-aes-256-gcm'
    real_now = now
    now = lambda: real_now() - 100
    try:
        req = Aead2022Encryptor(psk, method, False).encrypt(
            b'\x01\x7f\x00\x00\x01\x00\x50')
    finally:
        now = real_now
    try:
        Aead2022Encryptor(psk, method, True).decrypt(req)
    except AeadError:
        return
    raise AssertionError('stale request accepted')


def test_bad_psk():
    try:
        decode_psk(b'not a base64 key', '2022-blake3-aes-256-gcm')
    except ValueError:
        return
    raise AssertionError('bad psk accepted')


def test_packet_window():
    w = PacketWindow()
    assert w.check_and_set(1)
    assert not w.check_and_set(1)
    assert w.check_and_set(5)
    assert w.check_and_set(3)
    assert not w.check_and_set(3)
    assert w.check_and_set(5000)
    assert not w.check_and_set(5)


def test_udp():
    for method, (key_len, _) in sorted(ciphers.items()):
        psk = base64.b64encode(os.urandom(key_len))
        client = UdpClientCodec(psk, method)
        server = UdpServerCodec(psk, method)
        pkt = client.encode(b'\x01\x08\x08\x08\x08\x00\x35hello')
        sid, data = server.decode(pkt)
        assert data == b'\x01\x08\x08\x08\x08\x00\x35hello'
        try:
            server.decode(pkt)
        except AeadError:
            pass
        else:
            raise AssertionError('replayed packet accepted')
        resp = server.encode(sid, b'\x01\x08\x08\x08\x08\x00\x35world')
        assert client.decode(resp) == b'\x01\x08\x08\x08\x08\x00\x35world'


if __name__ == '__main__':
    test_tcp()
    test_tcp_initial_payload()
    test_wrong_key()
    test_timestamp()
    test_bad_psk()
    test_packet_window()
    test_udp()
    print('ok')
