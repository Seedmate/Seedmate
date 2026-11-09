#!/usr/bin/env python3
"""Reference for the KEF code of Seedmate, independent from ../../src/kef.c.

Pure Python AES-256, CTR, GCM and base43, written from the specifications
(FIPS 197, NIST SP 800-38D), and hashlib for PBKDF2 and SHA-256. It first
checks itself against the vectors of Krux v26.09.0 (tests/test_encryption.py and
tests/pages/test_encryption_ui.py, MIT), then writes kef_vectors.h.
Only test seeds: "abandon x11 about" and the entropies of the Krux tests.
"""
import hashlib

# --- AES-256 ------------------------------------------------------------------
SBOX = []
p = q = 1
while True:
    p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
    q ^= q << 1
    q ^= q << 2
    q ^= q << 4
    q &= 0xFF
    if q & 0x80:
        q ^= 0x09
    x = q ^ (q << 1 | q >> 7) & 0xFF ^ (q << 2 | q >> 6) & 0xFF ^ (q << 3 | q >> 5) & 0xFF ^ (q << 4 | q >> 4) & 0xFF
    SBOX.append((p, (x ^ 0x63) & 0xFF))
    if p == 1:
        break
S = [0x63] * 256
for a, b in SBOX:
    S[a] = b
assert S[0x53] == 0xED and S[0] == 0x63

def xt(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1

def expand(key):
    w = [list(key[i:i + 4]) for i in range(0, 32, 4)]
    rcon = 1
    for i in range(8, 60):
        t = list(w[i - 1])
        if i % 8 == 0:
            t = [S[t[1]] ^ rcon, S[t[2]], S[t[3]], S[t[0]]]
            rcon = xt(rcon)
        elif i % 8 == 4:
            t = [S[b] for b in t]
        w.append([w[i - 8][j] ^ t[j] for j in range(4)])
    return [sum(w[i:i + 4], []) for i in range(0, 60, 4)]

def aes(rk, block):
    s = [block[i] ^ rk[0][i] for i in range(16)]
    for r in range(1, 15):
        s = [S[b] for b in s]
        s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]
        if r != 14:
            m = []
            for c in range(0, 16, 4):
                a = s[c:c + 4]
                m += [xt(a[0]) ^ xt(a[1]) ^ a[1] ^ a[2] ^ a[3],
                      a[0] ^ xt(a[1]) ^ xt(a[2]) ^ a[2] ^ a[3],
                      a[0] ^ a[1] ^ xt(a[2]) ^ xt(a[3]) ^ a[3],
                      xt(a[0]) ^ a[0] ^ a[1] ^ a[2] ^ xt(a[3])]
            s = m
        s = [s[i] ^ rk[r][i] for i in range(16)]
    return bytes(s)

# FIPS 197 appendix C.3
assert aes(expand(bytes(range(32))), bytes.fromhex('00112233445566778899aabbccddeeff')).hex() == '8ea2b7ca516745bfeafc49904b496089'

def ctr(key, nonce, data, first=0):
    rk = expand(key)
    out = bytearray()
    for i in range(0, len(data), 16):
        block = aes(rk, nonce + (first + i // 16).to_bytes(4, 'big'))
        out += bytes(a ^ b for a, b in zip(data[i:i + 16], block))
    return bytes(out)

def gf_mul(x, y):
    z, v = 0, y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        v = (v >> 1) ^ (0xE1 << 120) if v & 1 else v >> 1
    return z

def gcm(key, iv, data, decrypt=False):
    """Returns (output, 16 byte tag). No additional data, 12 byte iv."""
    rk = expand(key)
    h = int.from_bytes(aes(rk, bytes(16)), 'big')
    output = ctr(key, iv, data, first=2)
    ct = data if decrypt else output
    y = 0
    padded = ct + bytes(-len(ct) % 16)
    for i in range(0, len(padded), 16):
        y = gf_mul(y ^ int.from_bytes(padded[i:i + 16], 'big'), h)
    y = gf_mul(y ^ (len(ct) * 8), h)
    tag = bytes(a ^ b for a, b in zip(y.to_bytes(16, 'big'), aes(rk, iv + (1).to_bytes(4, 'big'))))
    return output, tag

# NIST GCM test case 15 style check: AES-256, empty key material replaced by case 14
assert gcm(bytes(32), bytes(12), bytes(16))[1].hex() == 'd0d1c8a799996bf0265b98b5d48ab919'

# --- Base43 and the envelope -----------------------------------------------------
B43 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$*+-./:'

def b43_encode(b):
    n = int.from_bytes(b, 'big')
    s = ''
    while n:
        n, r = divmod(n, 43)
        s = B43[r] + s
    return '0' * (len(b) - len(b.lstrip(b'\x00'))) + s

def b43_decode(s):
    n = 0
    for c in s:
        n = n * 43 + B43.index(c)
    body = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes(len(s) - len(s.lstrip('0'))) + body

def derive(secret, salt, iterations):
    return hashlib.pbkdf2_hmac('sha256', secret, salt, iterations, 32)

def stored(iterations):
    return iterations // 10000 if iterations % 10000 == 0 else iterations

def wrap_v20(secret, id_, iterations, iv, plain):
    ct, tag = gcm(derive(secret, id_, iterations), iv, plain)
    return bytes([len(id_)]) + id_ + bytes([20]) + stored(iterations).to_bytes(3, 'big') + iv + ct + tag[:4]

# --- Krux vectors: the reference must reproduce them -----------------------------
KEY = b'test key'
ID = b'test ID'
IV = bytes.fromhex('4f52a1936c3e3271209e9d64')
GCM_KEF = bytes.fromhex('07746573742049441400000a4f52a1936c3e3271209e9d64bfb7766f5d5d8a4f908e86e738344c025d8fed54')
GCM_PLAIN_OF_KRUX = bytes.fromhex('350e7b31a36727c5f2fc76b58304668c')   # TEST_WORDS_ENTROPY of Krux
CTR_KEF = bytes.fromhex('07746573742049440f00000a4f52a1936c3e3271209e9d64f49120c7a26d12de7b0ff0268c9691e689b02494f0af52c21c295b57b5347e9a86ee2a40')
CTR_ENTROPY = bytes.fromhex('ec54ea346caa1ed06cb35c96c4ef23228a26a2e0996c71d0608ec2ba49ce2316')
CBC_B43 = 'VBRRAN4/CZD0I$4DYJWT8SU8R2+VAKKV*IKVFAXL0CIALR2AKM:.LUBEBS1CIT0DTX5VBE*HR7D3S8GY8D.H57$J3527$OP'

k = derive(KEY, ID, 100000)
body = GCM_KEF[1 + 7 + 4 + 12:]
plain, tag = gcm(k, IV, body[:-4], decrypt=True)
assert tag[:4] == body[-4:], 'GCM vector'
assert plain == GCM_PLAIN_OF_KRUX
assert wrap_v20(KEY, ID, 100000, IV, plain) == GCM_KEF

k = derive(KEY, ID, 100000)
body = CTR_KEF[1 + 7 + 4 + 12:]
out = ctr(k, IV, body)
assert out[:32] == CTR_ENTROPY and out[32:] == hashlib.sha256(CTR_ENTROPY).digest()[:4], 'CTR vector'

assert b43_encode(b43_decode(CBC_B43)) == CBC_B43
assert b43_decode(CBC_B43)[:10] == b'353175d8' + bytes([10])   # Its envelope, in the Krux test

# --- Vectors for the C test ---------------------------------------------------------
def arr(name, b):
    return 'static const uint8_t %s[%d] = {%s};\n' % (name, len(b), ','.join('0x%02x' % x for x in b))

def text(name, s):
    return 'static const char %s[] = "%s";\n' % (name, s)

ABANDON_ID = b'73c5da0a'
SEAL_IV = hashlib.sha256(b'seedmate kef test iv').digest()[:12]
seal = {
    's12': (bytes(16), 100000),
    's24': (bytes(32), 123456),
}
kdf_cases = [
    (b'short', b'salt', 10000),
    (b'k' * 64, b'salt', 10001),
    (b'k' * 65, b'a longer salt than usual', 12345),
    (b'x' * 200, b'', 10000),
]

with open('kef_vectors.h', 'w', newline='\n') as f:
    f.write('// Generated by gen_kef.py. Do not edit.\n')
    f.write('#define KEY_TEXT "test key"\n#define ID_TEXT "test ID"\n')
    f.write(arr('krux_gcm', GCM_KEF) + arr('krux_gcm_plain', GCM_PLAIN_OF_KRUX))
    f.write(arr('krux_ctr', CTR_KEF) + arr('krux_ctr_plain', CTR_ENTROPY))
    f.write(text('krux_b43', CBC_B43) + arr('krux_b43_bytes', b43_decode(CBC_B43)))
    f.write(arr('seal_iv', SEAL_IV))
    for name, (plain, iters) in seal.items():
        env = wrap_v20(KEY, ABANDON_ID, iters, SEAL_IV, plain)
        f.write(arr(name + '_plain', plain) + arr(name + '_env', env))
        f.write('#define %s_ITER %du\n' % (name.upper(), iters))
        f.write(text(name + '_b43', b43_encode(env)))
    f.write('static const struct { const char *secret; uint32_t secret_len; const char *salt; uint32_t iter; uint8_t key[32]; } kdf_cases[] = {\n')
    for s, salt, it in kdf_cases:
        k = derive(s, salt, it)
        f.write('    {"%s", %d, "%s", %d, {%s}},\n' % (s.decode(), len(s), salt.decode(), it, ','.join('0x%02x' % x for x in k)))
    f.write('};\n')
print('kef_vectors.h written; Krux GCM, CTR and base43 vectors reproduced')
