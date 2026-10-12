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

# AEAD ciphers as specified by SIP004 / SIP007
# https://shadowsocks.org/doc/aead.html
#
# TCP stream:  [salt][encrypted length][length tag][encrypted payload][tag]...
# UDP packet:  [salt][encrypted payload][tag]
#
# subkey = HKDF-SHA1(key=master key, salt=salt, info=b'ss-subkey')
# nonce  = 12 (or 24 for xchacha) byte little-endian counter starting at 0,
#          incremented after every encrypt / decrypt operation

from __future__ import absolute_import, division, print_function, \
    with_statement

import hashlib
import hmac
import os
import struct

from ctypes import c_char_p, c_int, c_ulonglong, c_void_p, byref, \
    create_string_buffer

from shadowsocks import common
from shadowsocks.crypto import openssl, util

__all__ = ['ciphers', 'AeadError']

TAG_LEN = 16
CHUNK_SIZE_LEN = 2
CHUNK_SIZE_MASK = 0x3FFF
SUBKEY_INFO = b'ss-subkey'

EVP_CTRL_AEAD_SET_IVLEN = 0x9
EVP_CTRL_AEAD_GET_TAG = 0x10
EVP_CTRL_AEAD_SET_TAG = 0x11


class AeadError(Exception):
    pass


def hkdf_sha1(key, salt, info, length):
    prk = hmac.new(salt, key, hashlib.sha1).digest()
    okm = b''
    t = b''
    i = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + struct.pack('B', i),
                     hashlib.sha1).digest()
        okm += t
        i += 1
    return okm[:length]


def nonce_increment(nonce):
    # little-endian increment of a bytearray, in place
    for i in range(len(nonce)):
        nonce[i] = (nonce[i] + 1) & 0xFF
        if nonce[i] != 0:
            break


_openssl_aead_ready = False


def _load_openssl_aead():
    global _openssl_aead_ready
    if not openssl.loaded:
        openssl.load_openssl()
    libcrypto = openssl.libcrypto
    libcrypto.EVP_CIPHER_CTX_ctrl.argtypes = (c_void_p, c_int, c_int,
                                              c_void_p)
    libcrypto.EVP_CIPHER_CTX_ctrl.restype = c_int
    libcrypto.EVP_CipherFinal_ex.argtypes = (c_void_p, c_void_p, c_void_p)
    libcrypto.EVP_CipherFinal_ex.restype = c_int
    libcrypto.EVP_CipherInit_ex.restype = c_int
    libcrypto.EVP_CipherUpdate.restype = c_int
    _openssl_aead_ready = True


class OpenSSLAeadCrypto(object):
    """One AEAD key; every call takes an explicit nonce."""

    def __init__(self, cipher_name, key, nonce_len, op):
        self._ctx = None
        if not _openssl_aead_ready:
            _load_openssl_aead()
        self._lib = libcrypto = openssl.libcrypto
        cipher = openssl.get_cipher(cipher_name)
        if not cipher:
            raise Exception('cipher %s not found in libcrypto' % cipher_name)
        self._op = op
        self._ctx = libcrypto.EVP_CIPHER_CTX_new()
        if not self._ctx:
            raise Exception('can not create cipher context')
        if not libcrypto.EVP_CipherInit_ex(self._ctx, cipher, None, None,
                                           None, c_int(op)):
            self.clean()
            raise Exception('can not initialize cipher context')
        libcrypto.EVP_CIPHER_CTX_ctrl(self._ctx, EVP_CTRL_AEAD_SET_IVLEN,
                                      nonce_len, None)
        if not libcrypto.EVP_CipherInit_ex(self._ctx, None, None,
                                           c_char_p(key), None, c_int(op)):
            self.clean()
            raise Exception('can not set cipher key')
        self._out_len = c_int(0)

    def _init_nonce(self, nonce):
        if not self._lib.EVP_CipherInit_ex(self._ctx, None, None, None,
                                           c_char_p(bytes(nonce)), c_int(-1)):
            raise AeadError('can not set nonce')

    def encrypt(self, nonce, data):
        lib = self._lib
        self._init_nonce(nonce)
        l = len(data)
        out = create_string_buffer(l + TAG_LEN)
        out_len = self._out_len
        lib.EVP_CipherUpdate(self._ctx, out, byref(out_len),
                             c_char_p(data), l)
        n = out_len.value
        tmp = create_string_buffer(TAG_LEN)
        lib.EVP_CipherFinal_ex(self._ctx, tmp, byref(out_len))
        tag = create_string_buffer(TAG_LEN)
        if not lib.EVP_CIPHER_CTX_ctrl(self._ctx, EVP_CTRL_AEAD_GET_TAG,
                                       TAG_LEN, tag):
            raise AeadError('can not get tag')
        return out.raw[:n] + tag.raw

    def decrypt(self, nonce, data):
        lib = self._lib
        l = len(data) - TAG_LEN
        if l < 0:
            raise AeadError('data too short')
        self._init_nonce(nonce)
        out = create_string_buffer(l + TAG_LEN)
        out_len = self._out_len
        lib.EVP_CipherUpdate(self._ctx, out, byref(out_len),
                             c_char_p(data[:l]), l)
        n = out_len.value
        tag = create_string_buffer(data[l:], TAG_LEN)
        if not lib.EVP_CIPHER_CTX_ctrl(self._ctx, EVP_CTRL_AEAD_SET_TAG,
                                       TAG_LEN, tag):
            raise AeadError('can not set tag')
        tmp = create_string_buffer(TAG_LEN)
        if lib.EVP_CipherFinal_ex(self._ctx, tmp, byref(out_len)) <= 0:
            raise AeadError('authentication failed')
        return out.raw[:n]

    def __del__(self):
        self.clean()

    def clean(self):
        if self._ctx:
            self._lib.EVP_CIPHER_CTX_free(self._ctx)
            self._ctx = None


libsodium = None


def _load_libsodium():
    global libsodium
    lib = util.find_library('sodium',
                            'crypto_aead_chacha20poly1305_ietf_encrypt',
                            'libsodium')
    if lib is None:
        raise Exception('libsodium not found')
    for prefix in ('crypto_aead_chacha20poly1305_ietf',
                   'crypto_aead_xchacha20poly1305_ietf'):
        enc = getattr(lib, prefix + '_encrypt', None)
        dec = getattr(lib, prefix + '_decrypt', None)
        if enc is None or dec is None:
            continue
        enc.restype = c_int
        enc.argtypes = (c_void_p, c_void_p, c_char_p, c_ulonglong,
                        c_char_p, c_ulonglong, c_char_p, c_char_p, c_char_p)
        dec.restype = c_int
        dec.argtypes = (c_void_p, c_void_p, c_char_p, c_char_p, c_ulonglong,
                        c_char_p, c_ulonglong, c_char_p, c_char_p)
    libsodium = lib


class SodiumAeadCrypto(object):
    def __init__(self, cipher_name, key, nonce_len, op):
        if libsodium is None:
            _load_libsodium()
        cipher_name = common.to_str(cipher_name)
        if cipher_name == 'chacha20-ietf-poly1305':
            prefix = 'crypto_aead_chacha20poly1305_ietf'
        elif cipher_name == 'xchacha20-ietf-poly1305':
            prefix = 'crypto_aead_xchacha20poly1305_ietf'
        else:
            raise Exception('unknown cipher %s' % cipher_name)
        self._enc = getattr(libsodium, prefix + '_encrypt', None)
        self._dec = getattr(libsodium, prefix + '_decrypt', None)
        if self._enc is None or self._dec is None:
            raise Exception('cipher %s not found in libsodium' % cipher_name)
        self._key = key
        self._out_len = c_ulonglong(0)

    def encrypt(self, nonce, data):
        l = len(data)
        out = create_string_buffer(l + TAG_LEN)
        self._enc(out, byref(self._out_len), data, l, None, 0, None,
                  bytes(nonce), self._key)
        return out.raw[:self._out_len.value]

    def decrypt(self, nonce, data):
        l = len(data)
        if l < TAG_LEN:
            raise AeadError('data too short')
        out = create_string_buffer(l)
        r = self._dec(out, byref(self._out_len), None, data, l, None, 0,
                      bytes(nonce), self._key)
        if r != 0:
            raise AeadError('authentication failed')
        return out.raw[:self._out_len.value]


def _chacha_backend(cipher_name, key, nonce_len, op):
    # prefer OpenSSL (1.1.0+), fall back to libsodium
    try:
        return OpenSSLAeadCrypto(b'chacha20-poly1305', key, nonce_len, op)
    except Exception:
        return SodiumAeadCrypto(cipher_name, key, nonce_len, op)


def _openssl_backend(cipher_name, key, nonce_len, op):
    return OpenSSLAeadCrypto(cipher_name, key, nonce_len, op)


def _sodium_backend(cipher_name, key, nonce_len, op):
    return SodiumAeadCrypto(cipher_name, key, nonce_len, op)


# method: (key_len, salt_len, nonce_len, backend)
ciphers = {
    'aes-128-gcm': (16, 16, 12, _openssl_backend),
    'aes-192-gcm': (24, 24, 12, _openssl_backend),
    'aes-256-gcm': (32, 32, 12, _openssl_backend),
    'chacha20-ietf-poly1305': (32, 32, 12, _chacha_backend),
    'xchacha20-ietf-poly1305': (32, 32, 24, _sodium_backend),
}


def is_aead(method):
    return method in ciphers


class AeadCipher(object):
    """A key derived from (master key, salt) plus its running nonce."""

    def __init__(self, method, master_key, salt, op):
        key_len, salt_len, nonce_len, backend = ciphers[method]
        subkey = hkdf_sha1(master_key, salt, SUBKEY_INFO, key_len)
        self._crypto = backend(common.to_bytes(method), subkey, nonce_len, op)
        self._nonce = bytearray(nonce_len)

    def encrypt(self, data):
        r = self._crypto.encrypt(self._nonce, data)
        nonce_increment(self._nonce)
        return r

    def decrypt(self, data):
        r = self._crypto.decrypt(self._nonce, data)
        nonce_increment(self._nonce)
        return r


class AeadEncryptor(object):
    """Stream (TCP) encryptor/decryptor pair for one connection.

    on_salt, if given, is called with every salt received from the peer and
    every salt generated locally; it may raise to reject the connection
    (used for replay protection on the server side).
    """

    def __init__(self, master_key, method, on_salt=None):
        self._method = method
        self._master_key = master_key
        self._key_len, self._salt_len, _, _ = ciphers[method]
        self._on_salt = on_salt
        self._cipher = None
        self._decipher = None
        self._buf = b''
        self._chunk_len = None

    def encrypt(self, buf):
        if len(buf) == 0:
            return buf
        result = []
        if self._cipher is None:
            salt = os.urandom(self._salt_len)
            if self._on_salt:
                self._on_salt(salt, False)
            self._cipher = AeadCipher(self._method, self._master_key, salt, 1)
            result.append(salt)
        cipher = self._cipher
        for i in range(0, len(buf), CHUNK_SIZE_MASK):
            chunk = buf[i:i + CHUNK_SIZE_MASK]
            result.append(cipher.encrypt(struct.pack('>H', len(chunk))))
            result.append(cipher.encrypt(chunk))
        return b''.join(result)

    def decrypt(self, buf):
        if self._buf:
            buf = self._buf + buf
        if self._decipher is None:
            if len(buf) < self._salt_len:
                self._buf = buf
                return b''
            salt = buf[:self._salt_len]
            buf = buf[self._salt_len:]
            if self._on_salt:
                self._on_salt(salt, True)
            self._decipher = AeadCipher(self._method, self._master_key, salt,
                                        0)
        decipher = self._decipher
        result = []
        pos = 0
        l = len(buf)
        while True:
            if self._chunk_len is None:
                if l - pos < CHUNK_SIZE_LEN + TAG_LEN:
                    break
                chunk_len = decipher.decrypt(
                    buf[pos:pos + CHUNK_SIZE_LEN + TAG_LEN])
                chunk_len = struct.unpack('>H', chunk_len)[0] & CHUNK_SIZE_MASK
                if chunk_len == 0:
                    raise AeadError('invalid chunk length')
                self._chunk_len = chunk_len
                pos += CHUNK_SIZE_LEN + TAG_LEN
            n = self._chunk_len + TAG_LEN
            if l - pos < n:
                break
            result.append(decipher.decrypt(buf[pos:pos + n]))
            self._chunk_len = None
            pos += n
        self._buf = buf[pos:]
        return b''.join(result)


def encrypt_all(master_key, method, op, data):
    """Encrypt/decrypt one UDP packet. Raises AeadError on bad data."""
    salt_len = ciphers[method][1]
    if op:
        salt = os.urandom(salt_len)
        return salt + AeadCipher(method, master_key, salt, 1).encrypt(data)
    if len(data) < salt_len + TAG_LEN:
        raise AeadError('packet too short')
    salt = data[:salt_len]
    return AeadCipher(method, master_key, salt, 0).decrypt(data[salt_len:])


def _run_stream(method):
    key = os.urandom(ciphers[method][0])
    plain = os.urandom(100000)
    enc = AeadEncryptor(key, method)
    dec = AeadEncryptor(key, method)
    data = enc.encrypt(plain[:30000]) + enc.encrypt(plain[30000:])
    out = []
    pos = 0
    # feed in odd-sized pieces to exercise buffering
    while pos < len(data):
        out.append(dec.decrypt(data[pos:pos + 1337]))
        pos += 1337
    assert b''.join(out) == plain


def test_hkdf_sha1():
    # RFC 5869 test case 4
    ikm = b'\x0b' * 11
    salt = bytes(bytearray(range(0x0d)))
    info = bytes(bytearray(range(0xf0, 0xfa)))
    okm = hkdf_sha1(ikm, salt, info, 42)
    assert okm == bytes(bytearray.fromhex(
        '085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2'
        'c22e422478d305f3f896'))


def test_aead_stream():
    for method in sorted(ciphers.keys()):
        _run_stream(method)


def test_aead_tamper():
    key = os.urandom(32)
    enc = AeadEncryptor(key, 'aes-256-gcm')
    data = bytearray(enc.encrypt(b'hello world'))
    data[-1] ^= 1
    dec = AeadEncryptor(key, 'aes-256-gcm')
    try:
        dec.decrypt(bytes(data))
    except AeadError:
        return
    raise AssertionError('tampered data was accepted')


def test_aead_udp():
    for method in sorted(ciphers.keys()):
        key = os.urandom(ciphers[method][0])
        data = encrypt_all(key, method, 1, b'udp packet')
        assert encrypt_all(key, method, 0, data) == b'udp packet'


if __name__ == '__main__':
    test_hkdf_sha1()
    test_aead_stream()
    test_aead_tamper()
    test_aead_udp()
    print('ok')
