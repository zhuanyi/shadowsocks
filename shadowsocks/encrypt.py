#!/usr/bin/env python
#
# Copyright 2012-2015 clowwindy
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

from __future__ import absolute_import, division, print_function, \
    with_statement

import os
import sys
import hashlib
import logging

from shadowsocks import common
from shadowsocks.crypto import rc4_md5, openssl, sodium, table, aead, \
    aead2022


# legacy stream ciphers: method: (key_len, iv_len, class)
method_supported = {}
method_supported.update(rc4_md5.ciphers)
method_supported.update(openssl.ciphers)
method_supported.update(sodium.ciphers)
method_supported.update(table.ciphers)

# AEAD ciphers (recommended): method: (key_len, salt_len, nonce_len, backend)
aead_method_supported = aead.ciphers


def is_aead(method):
    return (method or '').lower() in aead_method_supported


# Shadowsocks 2022 ciphers: method: (key_len, payload cipher)
aead2022_method_supported = aead2022.ciphers
is_aead2022 = aead2022.is_aead2022


class SaltFilter(object):
    """Remembers recently seen AEAD salts to reject replayed connections.

    Two generations are kept; when the current one is full the older one is
    dropped, so memory stays bounded at 2 * capacity salts.
    """

    def __init__(self, capacity=100000):
        self._capacity = capacity
        self._current = set()
        self._previous = set()

    def check_and_add(self, salt):
        if salt in self._current or salt in self._previous:
            return False
        if len(self._current) >= self._capacity:
            self._previous = self._current
            self._current = set()
        self._current.add(salt)
        return True


salt_filter = SaltFilter()


def check_salt(salt, from_peer):
    # salts we generate ourselves are recorded too, so that our own responses
    # can't be reflected back to us as new requests
    if not salt_filter.check_and_add(salt) and from_peer:
        raise aead.AeadError('repeated salt detected, possible replay attack')


def random_string(length):
    return os.urandom(length)


cached_keys = {}


def try_cipher(key, method=None):
    if is_aead2022(method):
        aead2022.decode_psk(key, method.lower())
        aead2022.Aead2022Encryptor(key, method, False).encrypt(
            b'\x01\x00\x00\x00\x00\x00\x00')
    elif is_aead(method):
        AeadEncryptor(key, method).encrypt(b'test')
    else:
        Encryptor(key, method)


def EVP_BytesToKey(password, key_len, iv_len):
    # equivalent to OpenSSL's EVP_BytesToKey() with count 1
    # so that we make the same key and iv as nodejs version
    cached_key = '%s-%d-%d' % (password, key_len, iv_len)
    r = cached_keys.get(cached_key, None)
    if r:
        return r
    m = []
    i = 0
    while len(b''.join(m)) < (key_len + iv_len):
        md5 = hashlib.md5()
        data = password
        if i > 0:
            data = m[i - 1] + password
        md5.update(data)
        m.append(md5.digest())
        i += 1
    ms = b''.join(m)
    key = ms[:key_len]
    iv = ms[key_len:key_len + iv_len]
    cached_keys[cached_key] = (key, iv)
    return key, iv


class Encryptor(object):
    def __init__(self, key, method):
        self.key = key
        self.method = method
        self.iv = None
        self.iv_sent = False
        self.cipher_iv = b''
        self.decipher = None
        method = method.lower()
        self._method_info = self.get_method_info(method)
        if self._method_info:
            self.cipher = self.get_cipher(key, method, 1,
                                          random_string(self._method_info[1]))
        else:
            logging.error('method %s not supported' % method)
            sys.exit(1)

    def get_method_info(self, method):
        method = method.lower()
        m = method_supported.get(method)
        return m

    def iv_len(self):
        return len(self.cipher_iv)

    def get_cipher(self, password, method, op, iv):
        password = common.to_bytes(password)
        m = self._method_info
        if m[0] > 0:
            key, iv_ = EVP_BytesToKey(password, m[0], m[1])
        else:
            # key_length == 0 indicates we should use the key directly
            key, iv = password, b''

        iv = iv[:m[1]]
        if op == 1:
            # this iv is for cipher not decipher
            self.cipher_iv = iv[:m[1]]
        return m[2](method, key, iv, op)

    def encrypt(self, buf):
        if len(buf) == 0:
            return buf
        if self.iv_sent:
            return self.cipher.update(buf)
        else:
            self.iv_sent = True
            return self.cipher_iv + self.cipher.update(buf)

    def decrypt(self, buf):
        if len(buf) == 0:
            return buf
        if self.decipher is None:
            decipher_iv_len = self._method_info[1]
            decipher_iv = buf[:decipher_iv_len]
            self.decipher = self.get_cipher(self.key, self.method, 0,
                                            iv=decipher_iv)
            buf = buf[decipher_iv_len:]
            if len(buf) == 0:
                return buf
        return self.decipher.update(buf)


class AeadEncryptor(aead.AeadEncryptor):
    def __init__(self, password, method, replay_protection=False):
        method = method.lower()
        key_len = aead_method_supported[method][0]
        key, _ = EVP_BytesToKey(common.to_bytes(password), key_len, 0)
        on_salt = check_salt if replay_protection else None
        super(AeadEncryptor, self).__init__(key, method, on_salt)


def new_encryptor(password, method, replay_protection=False):
    """replay_protection is True for ssserver, False for sslocal"""
    if is_aead2022(method):
        return aead2022.Aead2022Encryptor(password, method, replay_protection)
    if is_aead(method):
        return AeadEncryptor(password, method, replay_protection)
    return Encryptor(password, method)


def encrypt_all(password, method, op, data):
    result = []
    method = method.lower()
    if method in aead_method_supported:
        key_len = aead_method_supported[method][0]
        key, _ = EVP_BytesToKey(common.to_bytes(password), key_len, 0)
        return aead.encrypt_all(key, method, op, data)
    (key_len, iv_len, m) = method_supported[method]
    if key_len > 0:
        key, _ = EVP_BytesToKey(password, key_len, iv_len)
    else:
        key = password
    if op:
        iv = random_string(iv_len)
        result.append(iv)
    else:
        iv = data[:iv_len]
        data = data[iv_len:]
    cipher = m(method, key, iv, op)
    result.append(cipher.update(data))
    return b''.join(result)


CIPHERS_TO_TEST = [
    'aes-128-gcm',
    'aes-256-gcm',
    'chacha20-ietf-poly1305',
    'aes-128-cfb',
    'aes-256-cfb',
    'rc4-md5',
    'salsa20',
    'chacha20',
    'table',
]


def test_encryptor():
    from os import urandom
    plain = urandom(10240)
    for method in CIPHERS_TO_TEST:
        logging.warning(method)
        encryptor = new_encryptor(b'key', method)
        decryptor = new_encryptor(b'key', method)
        cipher = encryptor.encrypt(plain)
        plain2 = decryptor.decrypt(cipher)
        assert plain == plain2


def test_encrypt_all():
    from os import urandom
    plain = urandom(10240)
    for method in CIPHERS_TO_TEST:
        logging.warning(method)
        cipher = encrypt_all(b'key', method, 1, plain)
        plain2 = encrypt_all(b'key', method, 0, cipher)
        assert plain == plain2


def test_replay_protection():
    plain = b'x' * 100
    data = new_encryptor(b'key', 'aes-256-gcm').encrypt(plain)
    assert new_encryptor(b'key', 'aes-256-gcm', True).decrypt(data) == plain
    try:
        new_encryptor(b'key', 'aes-256-gcm', True).decrypt(data)
    except aead.AeadError:
        return
    raise AssertionError('replayed data was accepted')


if __name__ == '__main__':
    test_encrypt_all()
    test_encryptor()
    test_replay_protection()
