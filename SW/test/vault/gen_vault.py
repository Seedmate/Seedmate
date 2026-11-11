#!/usr/bin/env python3
"""Reference vectors for the Seedmate vault (../../docs/vault.md).

An independent implementation of the vault key (BIP85 HEX) and of the record
and header formats, using Python's hashlib/hmac and AES-256-GCM: the
'cryptography' package when it is installed, otherwise a pure Python one
(FIPS 197, SP 800-38D), checked here against a record that 'cryptography'
made. Writes vault_vectors.h for test_vault.c; it is also the reference for
the VAULT section of the offline HTML recovery page.

Record nonce: since 2026-11-11 the first 12 bytes of HMAC-SHA256(vault key,
counter || plain header || plaintext), so a counter used twice (a header put
back by someone who had the card) never gives the same nonce to another text.
Records written before used counter || sector; the nonce is stored in every
record, so both kinds open the same way.

Usage: python gen_vault.py
"""
import hashlib
import hmac
import os
import zlib

# --- AES-256-GCM ---------------------------------------------------------------
def _sbox():
    s, p, q = [0x63] * 256, 1, 1
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ (q << 1 | q >> 7) & 0xFF ^ (q << 2 | q >> 6) & 0xFF ^ (q << 3 | q >> 5) & 0xFF ^ (q << 4 | q >> 4) & 0xFF
        s[p] = (x ^ 0x63) & 0xFF
        if p == 1:
            return s


S = _sbox()


def _xt(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1


def _expand(key):
    w = [list(key[i:i + 4]) for i in range(0, 32, 4)]
    rcon = 1
    for i in range(8, 60):
        t = list(w[i - 1])
        if i % 8 == 0:
            t = [S[t[1]] ^ rcon, S[t[2]], S[t[3]], S[t[0]]]
            rcon = _xt(rcon)
        elif i % 8 == 4:
            t = [S[b] for b in t]
        w.append([w[i - 8][j] ^ t[j] for j in range(4)])
    return [sum(w[i:i + 4], []) for i in range(0, 60, 4)]


def _aes(rk, block):
    s = [block[i] ^ rk[0][i] for i in range(16)]
    for r in range(1, 15):
        s = [S[b] for b in s]
        s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]
        if r != 14:
            m = []
            for c in range(0, 16, 4):
                a = s[c:c + 4]
                m += [_xt(a[0]) ^ _xt(a[1]) ^ a[1] ^ a[2] ^ a[3], a[0] ^ _xt(a[1]) ^ _xt(a[2]) ^ a[2] ^ a[3],
                      a[0] ^ a[1] ^ _xt(a[2]) ^ _xt(a[3]) ^ a[3], _xt(a[0]) ^ a[0] ^ a[1] ^ a[2] ^ _xt(a[3])]
            s = m
        s = [s[i] ^ rk[r][i] for i in range(16)]
    return bytes(s)


def _gf_mul(x, y):
    z, v = 0, y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        v = (v >> 1) ^ (0xE1 << 120) if v & 1 else v >> 1
    return z


def aesgcm_encrypt(key, nonce, data, aad):
    """ciphertext || 16 byte tag, as cryptography's AESGCM(key).encrypt()"""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM(key).encrypt(nonce, data, aad)
    except ImportError:
        pass
    rk = _expand(key)
    h = int.from_bytes(_aes(rk, bytes(16)), 'big')
    ct = bytearray()
    for i in range(0, len(data), 16):
        ks = _aes(rk, nonce + (2 + i // 16).to_bytes(4, 'big'))
        ct += bytes(a ^ b for a, b in zip(data[i:i + 16], ks))
    y = 0
    for part in (aad, bytes(ct)):
        padded = part + bytes(-len(part) % 16)
        for i in range(0, len(padded), 16):
            y = _gf_mul(y ^ int.from_bytes(padded[i:i + 16], 'big'), h)
    y = _gf_mul(y ^ ((len(aad) * 8) << 64 | len(ct) * 8), h)
    tag = bytes(a ^ b for a, b in zip(y.to_bytes(16, 'big'), _aes(rk, nonce + (1).to_bytes(4, 'big'))))
    return bytes(ct) + tag


# FIPS 197 appendix C.3
assert _aes(_expand(bytes(range(32))), bytes.fromhex('00112233445566778899aabbccddeeff')).hex() == \
    '8ea2b7ca516745bfeafc49904b496089'
# The legacy record below, as 'cryptography' made it before this file had its own AES-GCM
LEGACY_SHA256 = 'c83de7c6f5f4cf4be969b266adc634852fa4735df61f1cfb9d36a990a01466fc'

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
H = 0x80000000
B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

# BIP85 test master key (from the BIP85 specification)
XPRV = ('xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmb'
        'aLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb')


def b58decode_check(s):
    n = 0
    for ch in s:
        n = n * 58 + B58.index(ch)
    raw = n.to_bytes(82, 'big')
    data, chk = raw[:-4], raw[-4:]
    assert hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4] == chk
    return data


def master_from_xprv(xprv):
    d = b58decode_check(xprv)
    return d[46:78], d[13:45]           # private key (after 0x00), chain code


def bip85(k, c, path):
    for i in path:
        I = hmac.new(c, b'\x00' + k + i.to_bytes(4, 'big'), hashlib.sha512).digest()
        k = ((int.from_bytes(I[:32], 'big') + int.from_bytes(k, 'big')) % N).to_bytes(32, 'big')
        c = I[32:]
    return hmac.new(b'bip-entropy-from-k', k, hashlib.sha512).digest()


def vault_key(k, c):
    return bip85(k, c, [H | 83696968, H | 128169, H | 32, H | 8377])[:32]


def header(vault_id):
    s = bytearray(512)
    s[0:8] = b'SMVAULT\x00'
    s[8] = 1
    s[24:32] = vault_id
    s[508:512] = zlib.crc32(bytes(s[:508])).to_bytes(4, 'big')
    return bytes(s)


def record(key, sector_no, counter, part, rtype, title, body, legacy=False):
    pt = bytearray(476)
    pt[0] = rtype
    pt[1] = len(title)
    pt[2:2 + len(title)] = title
    pt[22:24] = len(body).to_bytes(2, 'big')
    pt[24:24 + len(body)] = body
    hdr = b'VR' + bytes([1, part]) + sector_no.to_bytes(4, 'big')
    if legacy:                                                # Records written before 2026-11-11
        nonce = counter.to_bytes(8, 'big') + sector_no.to_bytes(4, 'big')
    else:
        nonce = hmac.new(key, counter.to_bytes(8, 'big') + hdr + bytes(pt), hashlib.sha256).digest()[:12]
    ct = aesgcm_encrypt(key, nonce, bytes(pt), hdr)          # ciphertext || tag
    return hdr + nonce + ct, bytes(pt)


def c_array(name, data):
    out = 'static const uint8_t %s[%d] = {' % (name, len(data))
    for i, b in enumerate(data):
        out += ('\n    ' if i % 16 == 0 else ' ') + '0x%02x,' % b
    return out + '\n};\n'


k, c = master_from_xprv(XPRV)
# BIP85 specification vectors (checked here, then again in C)
assert bip85(k, c, [H | 83696968, H | 0, H | 0]).hex().startswith('efecfbccffea313214232d29e71563d9')
assert bip85(k, c, [H | 83696968, H | 39, H | 0, H | 12, H | 0])[:16].hex() == '6250b68daf746d12a24d58b4787a714b'
assert bip85(k, c, [H | 83696968, H | 128169, H | 64, H | 0]).hex().startswith('492db4698cf3b73a5a24998aa3e9d7fa')

vkey = vault_key(k, c)
vid = bytes(range(1, 9))
rec, pt = record(vkey, 502, 1, 0x11, 1, b'TEST NOTE', b'hello vault\nsecond line')
rec2, _ = record(vkey, 2046, 0x0102030405060708, 0x12, 16, b'MULTISIG', bytes(range(200)))
legacy, _ = record(vkey, 502, 1, 0x11, 1, b'TEST NOTE', b'hello vault\nsecond line', legacy=True)
assert hashlib.sha256(legacy).hexdigest() == LEGACY_SHA256, 'AES-GCM reference'
# The same counter and sector with another text: another nonce
other, _ = record(vkey, 502, 1, 0x11, 1, b'TEST NOTE', b'another text', legacy=False)
assert other[8:20] != record(vkey, 502, 1, 0x11, 1, b'TEST NOTE', b'hello vault\nsecond line')[0][8:20]

out = ['// Generated by gen_vault.py - do not edit\n#include <stdint.h>\n']
out.append(c_array('vec_master_k', k))
out.append(c_array('vec_master_c', c))
out.append(c_array('vec_bip85_hex64', bip85(k, c, [H | 83696968, H | 128169, H | 64, H | 0])))
out.append(c_array('vec_bip85_bip39_12', bip85(k, c, [H | 83696968, H | 39, H | 0, H | 12, H | 0])[:16]))
out.append(c_array('vec_vault_key', vkey))
out.append(c_array('vec_vault_id', vid))
out.append(c_array('vec_header', header(vid)))
out.append(c_array('vec_record_plain', pt))
out.append(c_array('vec_record', rec))
out.append(c_array('vec_record2', rec2))
out.append(c_array('vec_record_legacy', legacy))
path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vault_vectors.h')
with open(path, 'w', newline='\n') as f:
    f.write('\n'.join(out))
print('wrote', path)
print('vault key', vkey.hex())
