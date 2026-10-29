"""Signs ABANDON.PSB on the PC with the "abandon x11 about" seed.

Independent from the firmware: pure Python secp256k1, BIP32, BIP143 and
RFC6979 ECDSA. Every building block is checked against published test
vectors before signing. Outputs:
  ABANDON_SIGNED.PSB             signed PSBT (binary)
  abandon_signed.psbt.txt        same, base64
  ur_test_psbt.h                 C arrays for the host tests (signed PSBT and test key)
"""
import base64, hashlib, hmac, struct

# --- secp256k1 -------------------------------------------------------------
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

def point_add(a, b):
    if a is None: return b
    if b is None: return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0: return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return (x, (lam * (a[0] - x) - a[1]) % P)

def point_mul(k, pt=G):
    r = None
    while k:
        if k & 1: r = point_add(r, pt)
        pt = point_add(pt, pt)
        k >>= 1
    return r

def ser_pub(pt):
    return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, 'big')

def sha256(b): return hashlib.sha256(b).digest()
def dsha(b): return sha256(sha256(b))
def hash160(b): return hashlib.new('ripemd160', sha256(b)).digest()

# --- BIP32 -----------------------------------------------------------------
H = 0x80000000

def master_key(seed):
    i = hmac.new(b'Bitcoin seed', seed, hashlib.sha512).digest()
    return int.from_bytes(i[:32], 'big'), i[32:]

def ckd_priv(k, c, index):
    if index & H:
        data = b'\x00' + k.to_bytes(32, 'big') + struct.pack('>I', index)
    else:
        data = ser_pub(point_mul(k)) + struct.pack('>I', index)
    i = hmac.new(c, data, hashlib.sha512).digest()
    return (int.from_bytes(i[:32], 'big') + k) % N, i[32:]

def derive(seed, path):
    k, c = master_key(seed)
    for index in path:
        k, c = ckd_priv(k, c, index)
    return k

# --- Base58check (only to compare with the BIP84 WIF vector) ---------------
B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def b58check(payload):
    data = payload + dsha(payload)[:4]
    n = int.from_bytes(data, 'big')
    s = ''
    while n:
        n, r = divmod(n, 58)
        s = B58[r] + s
    return '1' * (len(data) - len(data.lstrip(b'\x00'))) + s

# --- ECDSA with RFC6979 nonces and low S -----------------------------------
def rfc6979_k(priv, h, extra=b''):
    """RFC6979 nonce as libsecp256k1 builds it: key || (hash mod n) || extra."""
    x = priv.to_bytes(32, 'big')
    h = (int.from_bytes(h, 'big') % N).to_bytes(32, 'big')     # bits2octets
    v, k = b'\x01' * 32, b'\x00' * 32
    k = hmac.new(k, v + b'\x00' + x + h + extra, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b'\x01' + x + h + extra, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        t = int.from_bytes(v, 'big')
        if 1 <= t < N: return t
        k = hmac.new(k, v + b'\x00', hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()

def sign(priv, h, grind_out=None):
    """Bitcoin Core / libsecp256k1 / embit signing: RFC6979, low S, and low R
    grinding (retry with a 32-byte little-endian counter as extra entropy)."""
    counter = 0
    while True:
        extra = struct.pack('<I', counter) + bytes(28) if counter else b''
        k = rfc6979_k(priv, h, extra)
        r = point_mul(k)[0] % N
        s = pow(k, -1, N) * (int.from_bytes(h, 'big') + r * priv) % N
        if s > N // 2: s = N - s        # Low S (BIP146)
        if r < 2**255:                  # Low R: DER r without the 0x00 pad
            if grind_out is not None: grind_out.append(counter)
            return r, s
        counter += 1

def verify(pub_pt, h, r, s):
    w = pow(s, -1, N)
    pt = point_add(point_mul(int.from_bytes(h, 'big') * w % N), point_mul(r * w % N, pub_pt))
    return pt is not None and pt[0] % N == r

def der(r, s):
    def enc(v):
        b = v.to_bytes(32, 'big').lstrip(b'\x00')
        if b[0] & 0x80: b = b'\x00' + b
        return b'\x02' + bytes([len(b)]) + b
    body = enc(r) + enc(s)
    return b'\x30' + bytes([len(body)]) + body

# --- Transaction / PSBT helpers ---------------------------------------------
def read_varint(b, i):
    v = b[i]
    if v < 0xFD: return v, i + 1
    if v == 0xFD: return struct.unpack_from('<H', b, i + 1)[0], i + 3
    return struct.unpack_from('<I', b, i + 1)[0], i + 5

def varint(n):
    if n < 0xFD: return bytes([n])
    if n <= 0xFFFF: return b'\xfd' + struct.pack('<H', n)
    return b'\xfe' + struct.pack('<I', n)

def parse_tx(tx):
    """Legacy-serialized unsigned tx -> (version, inputs, outputs, locktime)."""
    i = 4
    n_in, i = read_varint(tx, i)
    ins = []
    for _ in range(n_in):
        outpoint = tx[i:i + 36]; i += 36
        sl, i = read_varint(tx, i); i += sl
        seq = tx[i:i + 4]; i += 4
        ins.append((outpoint, seq))
    n_out, i = read_varint(tx, i)
    outs_start = i
    for _ in range(n_out):
        i += 8
        sl, i = read_varint(tx, i); i += sl
    return tx[:4], ins, tx[outs_start:i], tx[i:i + 4]

def bip143_sighash(tx, index, script_code, amount, sighash=1):
    version, ins, outs, locktime = parse_tx(tx)
    hash_prevouts = dsha(b''.join(o for o, _ in ins))
    hash_sequence = dsha(b''.join(s for _, s in ins))
    hash_outputs = dsha(outs)
    outpoint, seq = ins[index]
    pre = (version + hash_prevouts + hash_sequence + outpoint + script_code +
           struct.pack('<Q', amount) + seq + hash_outputs + locktime + struct.pack('<I', sighash))
    return dsha(pre), (hash_prevouts, hash_sequence, hash_outputs)

def read_maps(psbt):
    """Splits a PSBT into its key/value maps (list of lists of (key, value))."""
    assert psbt[:5] == b'psbt\xff'
    i, maps, cur = 5, [], []
    while i < len(psbt):
        kl, i = read_varint(psbt, i)
        if kl == 0:
            maps.append(cur); cur = []
            continue
        key = psbt[i:i + kl]; i += kl
        vl, i = read_varint(psbt, i)
        cur.append((key, psbt[i:i + vl])); i += vl
    return maps

def write_maps(maps):
    out = b'psbt\xff'
    for m in maps:
        for k, v in m:
            out += varint(len(k)) + k + varint(len(v)) + v
        out += b'\x00'
    return out

# --- Self-checks against published vectors ----------------------------------
# BIP143 native P2WPKH example (second input, 6 BTC)
t = bytes.fromhex(
    '0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffff'
    'ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206'
    '000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42db'
    'ee7e4dbe6a21b2d50ce2f0167faa815988ac11000000')
sh, (hp, hs, ho) = bip143_sighash(t, 1, bytes.fromhex('1976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac'), 600000000)
assert hp.hex() == '96b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd37'
assert hs.hex() == '52b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3b'
assert ho.hex() == '863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e5'
assert sh.hex() == 'c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670'

# BIP84 vector: "abandon x11 about", m/84'/0'/0'/0/0
MNEMONIC = ' '.join(['abandon'] * 11 + ['about'])
seed = hashlib.pbkdf2_hmac('sha512', MNEMONIC.encode(), b'mnemonic', 2048)
master_priv, _ = master_key(seed)
assert hash160(ser_pub(point_mul(master_priv)))[:4].hex() == '73c5da0a'
priv = derive(seed, [84 | H, H, H, 0, 0])
pub = ser_pub(point_mul(priv))
assert pub.hex() == '0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c'
assert b58check(b'\x80' + priv.to_bytes(32, 'big') + b'\x01') == 'KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d'

# --- Sign input 0 of ABANDON.PSB ---------------------------------------------
psbt = open('ABANDON.PSB', 'rb').read()
maps = read_maps(psbt)
unsigned_tx = dict(maps[0])[b'\x00']
in0 = maps[1]
wutxo = dict(in0)[b'\x01']
amount = struct.unpack_from('<Q', wutxo)[0]
spk = wutxo[9:]
assert spk == b'\x00\x14' + hash160(pub), 'input 0 does not pay to m/84h/0h/0h/0/0'

script_code = b'\x19\x76\xa9\x14' + spk[2:] + b'\x88\xac'
sighash, _ = bip143_sighash(unsigned_tx, 0, script_code, amount)
r, s = sign(priv, sighash)
assert verify(point_mul(priv), sighash, r, s) and s <= N // 2
sig = der(r, s) + b'\x01'                   # SIGHASH_ALL

in0.append((b'\x02' + pub, sig))             # PSBT_IN_PARTIAL_SIG
signed = write_maps(maps)
assert read_maps(signed)[1][-1] == (b'\x02' + pub, sig)

open('ABANDON_SIGNED.PSB', 'wb').write(signed)
open('abandon_signed.psbt.txt', 'w').write(base64.b64encode(signed).decode() + '\n')
print('sighash   ', sighash.hex())
print('signature ', sig.hex())
print('signed PSBT', len(signed), 'bytes')

# --- 2-of-3 P2WSH multisig (sortedmulti), our key at m/48h/0h/0h/2h ----------
# Cosigners B and C use the test keys 1 and 2 (public keys G and 2G).
def kv(key, val):
    return varint(len(key)) + key + varint(len(val)) + val

def keypath(fp, *elems):
    return fp + b''.join(struct.pack('<I', e) for e in elems)

def sortedmulti(m, keys):
    keys = sorted(keys)
    return bytes([0x50 + m]) + b''.join(b'\x21' + k for k in keys) + bytes([0x50 + len(keys), 0xAE])

FP_ME = hash160(ser_pub(point_mul(master_priv)))[:4]
FP_B, FP_C = bytes.fromhex('b0b0b0b0'), bytes.fromhex('c0c0c0c0')
MS = [48 | H, H, H, 2 | H]
priv_ms_in = derive(seed, MS + [0, 0])
priv_ms_change = derive(seed, MS + [1, 0])
pub_me_in, pub_me_change = ser_pub(point_mul(priv_ms_in)), ser_pub(point_mul(priv_ms_change))
pub_b, pub_c = ser_pub(point_mul(1)), ser_pub(point_mul(2))

ws_in = sortedmulti(2, [pub_me_in, pub_b, pub_c])
ws_change = sortedmulti(2, [pub_me_change, pub_b, pub_c])
p2wsh = lambda ws: b'\x00\x20' + sha256(ws)
EXTERNAL = bytes.fromhex('0014751e76e8199196d454941c45d1b3a323f1433bd6')

tx_ms = (struct.pack('<I', 2) + b'\x01' + sha256(b'ms') + struct.pack('<I', 1) + b'\x00' +
         struct.pack('<I', 0xfffffffd) + b'\x02' +
         struct.pack('<Q', 60000) + varint(len(EXTERNAL)) + EXTERNAL +
         struct.pack('<Q', 39000) + varint(34) + p2wsh(ws_change) + struct.pack('<I', 850000))
in_ms = (kv(b'\x01', struct.pack('<Q', 100000) + varint(34) + p2wsh(ws_in)) + kv(b'\x05', ws_in) +
         kv(b'\x06' + pub_me_in, keypath(FP_ME, *MS, 0, 0)) +
         kv(b'\x06' + pub_b, keypath(FP_B, *MS, 0, 0)) +
         kv(b'\x06' + pub_c, keypath(FP_C, *MS, 0, 0)))
out_change = (kv(b'\x01', ws_change) +
              kv(b'\x02' + pub_me_change, keypath(FP_ME, *MS, 1, 0)) +
              kv(b'\x02' + pub_b, keypath(FP_B, *MS, 1, 0)) +
              kv(b'\x02' + pub_c, keypath(FP_C, *MS, 1, 0)))
ms_psbt = b'psbt\xff' + kv(b'\x00', tx_ms) + b'\x00' + in_ms + b'\x00' + b'\x00' + out_change + b'\x00'

ms_sighash, _ = bip143_sighash(tx_ms, 0, varint(len(ws_in)) + ws_in, 100000)
r, s = sign(priv_ms_in, ms_sighash)
assert verify(point_mul(priv_ms_in), ms_sighash, r, s) and s <= N // 2
ms_sig = der(r, s) + b'\x01'
ms_maps = read_maps(ms_psbt)
assert write_maps(ms_maps) == ms_psbt
ms_maps[1].append((b'\x02' + pub_me_in, ms_sig))
ms_signed = write_maps(ms_maps)

open('ABANDON_MS.PSB', 'wb').write(ms_psbt)
open('ABANDON_MS_SIGNED.PSB', 'wb').write(ms_signed)
print('multisig sighash', ms_sighash.hex())
print('multisig PSBT', len(ms_psbt), 'bytes, signed', len(ms_signed), 'bytes')

# --- C header for the host tests ----------------------------------------------
def c_array(f, name, data):
    f.write('static const uint8_t %s[%d] = {\n' % (name, len(data)))
    for i in range(0, len(data), 16):
        f.write('    ' + ', '.join('0x%02x' % b for b in data[i:i + 16]) + ',\n')
    f.write('};\n\n')

with open('ur_test_psbt.h', 'w', newline='\r\n') as f:
    f.write('// Generated by test/psbt/sign_abandon.py - test data only, not a secret.\n')
    f.write('// "abandon x11 about" PSBTs signed by the independent Python signer.\n')
    f.write('#ifndef UR_TEST_PSBT_H\n#define UR_TEST_PSBT_H\n\n#include <stdint.h>\n\n')
    f.write('// Single sig: input 0 signed with m/84h/0h/0h/0/0\n')
    c_array(f, 'ur_test_signed_psbt', signed)
    c_array(f, 'ur_test_priv_0_0', priv.to_bytes(32, 'big'))
    f.write('// 2-of-3 P2WSH: unsigned, and input 0 signed with m/48h/0h/0h/2h/0/0\n')
    c_array(f, 'ur_test_ms_psbt', ms_psbt)
    c_array(f, 'ur_test_ms_signed_psbt', ms_signed)
    c_array(f, 'ur_test_ms_priv_0_0', priv_ms_in.to_bytes(32, 'big'))

    # Low R grinding: digests whose first nonce gives a high R need retries
    f.write('// Signatures by m/84h/0h/0h/0/0 of SHA256("grind" || i), with the number of\n')
    f.write('// low R retries each needed (0 = plain RFC6979)\n')
    f.write('#define UR_TEST_GRIND_COUNT 12\n')
    digests, sigs, grinds = [], [], []
    for i in range(12):
        h = sha256(b'grind' + bytes([i]))
        g_out = []
        r, s = sign(priv, h, g_out)
        assert verify(point_mul(priv), h, r, s)
        digests.append(h); sigs.append(der(r, s)); grinds.append(g_out[0])
    assert max(grinds) >= 2, 'want a case with at least two retries'
    f.write('static const uint8_t ur_test_grind_digest[UR_TEST_GRIND_COUNT][32] = {\n')
    for h in digests: f.write('    {' + ', '.join('0x%02x' % b for b in h) + '},\n')
    f.write('};\n')
    f.write('static const uint8_t ur_test_grind_sig[UR_TEST_GRIND_COUNT][72] = {\n')
    for d in sigs: f.write('    {' + ', '.join('0x%02x' % b for b in d) + '},\n')
    f.write('};\n')
    f.write('static const uint8_t ur_test_grind_sig_len[UR_TEST_GRIND_COUNT] = {%s};\n' % ', '.join(str(len(d)) for d in sigs))
    f.write('static const uint8_t ur_test_grind_retries[UR_TEST_GRIND_COUNT] = {%s};\n\n' % ', '.join(str(g) for g in grinds))
    f.write('#endif // UR_TEST_PSBT_H\n')
print('grind retries per digest', grinds)
