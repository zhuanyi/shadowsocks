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

# BLAKE3 key derivation, as used by the Shadowsocks 2022 ciphers.
#
# Uses the `blake3` package when it is installed. Otherwise falls back to a
# small pure-Python implementation that only supports what Shadowsocks needs:
# inputs of at most one chunk (1024 bytes) and outputs of at most 64 bytes.

from __future__ import absolute_import, division, print_function, \
    with_statement

import struct

__all__ = ['derive_key']

CHUNK_LEN = 1024
BLOCK_LEN = 64

CHUNK_START = 1
CHUNK_END = 2
ROOT = 8
DERIVE_KEY_CONTEXT = 32
DERIVE_KEY_MATERIAL = 64

IV = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
      0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)

MSG_PERMUTATION = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)

MASK = 0xFFFFFFFF


def _g(s, a, b, c, d, x, y):
    s[a] = (s[a] + s[b] + x) & MASK
    t = s[d] ^ s[a]
    s[d] = ((t >> 16) | (t << 16)) & MASK
    s[c] = (s[c] + s[d]) & MASK
    t = s[b] ^ s[c]
    s[b] = ((t >> 12) | (t << 20)) & MASK
    s[a] = (s[a] + s[b] + y) & MASK
    t = s[d] ^ s[a]
    s[d] = ((t >> 8) | (t << 24)) & MASK
    s[c] = (s[c] + s[d]) & MASK
    t = s[b] ^ s[c]
    s[b] = ((t >> 7) | (t << 25)) & MASK


def _compress(cv, block_words, counter, block_len, flags):
    s = list(cv) + list(IV[:4]) + [counter & MASK, (counter >> 32) & MASK,
                                   block_len, flags]
    m = list(block_words)
    for r in range(7):
        _g(s, 0, 4, 8, 12, m[0], m[1])
        _g(s, 1, 5, 9, 13, m[2], m[3])
        _g(s, 2, 6, 10, 14, m[4], m[5])
        _g(s, 3, 7, 11, 15, m[6], m[7])
        _g(s, 0, 5, 10, 15, m[8], m[9])
        _g(s, 1, 6, 11, 12, m[10], m[11])
        _g(s, 2, 7, 8, 13, m[12], m[13])
        _g(s, 3, 4, 9, 14, m[14], m[15])
        if r < 6:
            m = [m[i] for i in MSG_PERMUTATION]
    for i in range(8):
        s[i] ^= s[i + 8]
        s[i + 8] ^= cv[i]
    return s


def _hash_one_chunk(key_words, data, flags, out_len):
    if len(data) > CHUNK_LEN or out_len > BLOCK_LEN:
        raise ValueError('input or output too long for the built-in BLAKE3')
    cv = list(key_words)
    blocks = [data[i:i + BLOCK_LEN] for i in range(0, len(data), BLOCK_LEN)]
    if not blocks:
        blocks = [b'']
    for i, block in enumerate(blocks):
        block_flags = flags
        if i == 0:
            block_flags |= CHUNK_START
        words = struct.unpack('<16I', block.ljust(BLOCK_LEN, b'\x00'))
        if i == len(blocks) - 1:
            block_flags |= CHUNK_END | ROOT
            out = _compress(cv, words, 0, len(block), block_flags)
            return struct.pack('<16I', *out)[:out_len]
        cv = _compress(cv, words, 0, BLOCK_LEN, block_flags)[:8]


def _derive_key_builtin(context, key_material, length):
    context_key = _hash_one_chunk(IV, context, DERIVE_KEY_CONTEXT, 32)
    key_words = struct.unpack('<8I', context_key)
    return _hash_one_chunk(key_words, key_material, DERIVE_KEY_MATERIAL,
                           length)


try:
    import blake3 as _blake3_module

    def derive_key(context, key_material, length=32):
        if not isinstance(context, str):
            context = context.decode('utf-8')
        h = _blake3_module.blake3(key_material, derive_key_context=context)
        return h.digest(length)
except ImportError:
    def derive_key(context, key_material, length=32):
        if not isinstance(context, bytes):
            context = context.encode('utf-8')
        return _derive_key_builtin(context, key_material, length)


def test_derive_key():
    # official test vector (input = 0, 1, 2, ..., 250, 0, 1, ...)
    context = b'BLAKE3 2019-12-27 16:29:52 test vectors context'
    data = bytes(bytearray(i % 251 for i in range(1024)))
    assert _derive_key_builtin(context, data[:0], 32) == bytes(
        bytearray.fromhex('2cc39783c223154fea8dfb7c1b1660f2'
                          'ac2dcbd1c1de8277b0b0dd39b7e50d7d'))
    assert _derive_key_builtin(context, data[:1], 32) == bytes(
        bytearray.fromhex('b3e2e340a117a499c6cf2398a19ee0d2'
                          '9cca2bb7404c73063382693bf66cb06c'))
    assert _derive_key_builtin(context, data[:1023], 32) == bytes(
        bytearray.fromhex('74a16c1c3d44368a86e1ca6df64be6a2'
                          'f64cce8f09220787450722d85725dea5'))
    assert _derive_key_builtin(context, data[:1024], 32) == bytes(
        bytearray.fromhex('7356cd7720d5b66b6d0697eb3177d9f8'
                          'd73a4a5c5e968896eb6a689684302706'))
    assert derive_key(context, data[:64], 32) == \
        _derive_key_builtin(context, data[:64], 32)


if __name__ == '__main__':
    test_derive_key()
    print('ok')
