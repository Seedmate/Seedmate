"""Taproot single sig (BIP86 key path) test data for the "abandon x11 about" seed.

Independent from the firmware: BIP32 and secp256k1 come from sign_abandon.py;
BIP340 Schnorr, the BIP341 signature hash, the BIP86 tweak and bech32m are
written here from the specifications. Each is checked first against the
official vectors, read from the BIP repository files given as arguments:
  python gen_taproot.py bip-0340/test-vectors.csv bip-0341/wallet-test-vectors.json
(https://github.com/bitcoin/bips, files bip-0340/test-vectors.csv and
bip-0341/wallet-test-vectors.json). Writes:
  abandon taproot.psbt - unsigned PSBT for the device, as Sparrow makes them
                         (BIP371 fields, WITNESS_UTXO only): two inputs at
                         m/86'/0'/0'/0/0 and 0/1, a send to an external bc1q
                         address and change at m/86'/0'/0'/1/0
  taproot_vectors.h    - that PSBT and the same signed by this signer (the
                         firmware must sign byte-identically), and the BIP340
                         and BIP341 vectors the C code is checked with
Signatures use 32 zero bytes of auxiliary randomness, as the firmware does.
"""
import csv, json, runpy, struct, sys, base64

g = runpy.run_path('sign_abandon.py')
H, seed, derive, master_key, ckd_priv = g['H'], g['seed'], g['derive'], g['master_key'], g['ckd_priv']
point_mul, point_add, ser_pub, hash160, sha256 = g['point_mul'], g['point_add'], g['ser_pub'], g['hash160'], g['sha256']
b58check, varint, kv, keypath, N, P, G = g['b58check'], g['varint'], g['kv'], g['keypath'], g['N'], g['P'], g['G']
read_maps, write_maps, read_varint = g['read_maps'], g['write_maps'], g['read_varint']

# --- BIP340 ----------------------------------------------------------------
def tagged(tag, data):
    t = sha256(tag.encode())
    return sha256(t + t + data)

def lift_x(x):
    if x >= P: return None
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if pow(y, 2, P) != y_sq: return None
    return (x, y if y % 2 == 0 else P - y)

def bip340_sign(sk, msg, aux):
    d0 = int.from_bytes(sk, 'big')
    assert 0 < d0 < N
    Pt = point_mul(d0)
    d = d0 if Pt[1] % 2 == 0 else N - d0
    t = (d ^ int.from_bytes(tagged('BIP0340/aux', aux), 'big')).to_bytes(32, 'big')
    k0 = int.from_bytes(tagged('BIP0340/nonce', t + Pt[0].to_bytes(32, 'big') + msg), 'big') % N
    assert k0 != 0
    R = point_mul(k0)
    k = k0 if R[1] % 2 == 0 else N - k0
    e = int.from_bytes(tagged('BIP0340/challenge', R[0].to_bytes(32, 'big') + Pt[0].to_bytes(32, 'big') + msg), 'big') % N
    sig = R[0].to_bytes(32, 'big') + ((k + e * d) % N).to_bytes(32, 'big')
    assert bip340_verify(Pt[0].to_bytes(32, 'big'), msg, sig)
    return sig

def bip340_verify(px, msg, sig):
    Pt = lift_x(int.from_bytes(px, 'big'))
    r, s = int.from_bytes(sig[:32], 'big'), int.from_bytes(sig[32:], 'big')
    if Pt is None or r >= P or s >= N: return False
    e = int.from_bytes(tagged('BIP0340/challenge', sig[:32] + px + msg), 'big') % N
    R = point_add(point_mul(s), point_mul(N - e, Pt))
    return R is not None and R[1] % 2 == 0 and R[0] == r

def check_bip340(path):
    signed = 0
    for row in csv.DictReader(open(path)):
        pk, msg, sig = bytes.fromhex(row['public key']), bytes.fromhex(row['message']), bytes.fromhex(row['signature'])
        if row['secret key']:
            assert bip340_sign(bytes.fromhex(row['secret key']), msg, bytes.fromhex(row['aux_rand'])) == sig, row['index']
            signed += 1
        assert bip340_verify(pk, msg, sig) == (row['verification result'] == 'TRUE'), row['index']
    return signed

# --- BIP341 key path signature hash (SIGHASH_DEFAULT and SIGHASH_ALL only) --
def parse_unsigned(tx):
    """version, [(outpoint36, sequence)], serialized outputs (without their count), count, locktime"""
    i = 4
    n, i = read_varint(tx, i)
    ins = []
    for _ in range(n):
        outpoint = tx[i:i + 36]
        i += 36
        sl, i = read_varint(tx, i)
        assert sl == 0
        i += sl
        ins.append((outpoint, tx[i:i + 4]))
        i += 4
    n_out, i = read_varint(tx, i)
    start = i
    for _ in range(n_out):
        i += 8
        sl, i = read_varint(tx, i)
        i += sl
    return tx[:4], ins, tx[start:i], n_out, tx[i:i + 4]

def taproot_sighash(tx, index, utxos, hash_type):
    """utxos: [(amount, scriptPubKey)] of every input"""
    assert hash_type in (0, 1)
    version, ins, outputs, _, locktime = parse_unsigned(tx)
    msg = bytes([0, hash_type]) + version + locktime
    msg += sha256(b''.join(o for o, _ in ins))
    msg += sha256(b''.join(struct.pack('<Q', a) for a, _ in utxos))
    msg += sha256(b''.join(varint(len(s)) + s for _, s in utxos))
    msg += sha256(b''.join(q for _, q in ins))
    msg += sha256(outputs)
    msg += b'\x00' + struct.pack('<I', index)
    return tagged('TapSighash', msg)

def check_bip341(path):
    d = json.load(open(path))
    k = d['keyPathSpending'][0]
    tx = bytes.fromhex(k['given']['rawUnsignedTx'])
    utxos = [(u['amountSats'], bytes.fromhex(u['scriptPubKey'])) for u in k['given']['utxosSpent']]
    cases = []
    for s in k['inputSpending']:
        ht = s['given']['hashType']
        if ht not in (0, 1): continue
        idx = s['given']['txinIndex']
        sh = taproot_sighash(tx, idx, utxos, ht)
        assert sh.hex() == s['intermediary']['sigHash'], idx
        tweaked = bytes.fromhex(s['intermediary']['tweakedPrivkey'])
        sig = bip340_sign(tweaked, sh, bytes(32))
        expected = bytes.fromhex(s['expected']['witness'][0])
        assert sig + (bytes([ht]) if ht else b'') == expected, idx
        cases.append((idx, ht, sh, tweaked, expected))
    # A PSBT of that transaction, every input with its WITNESS_UTXO
    psbt = b'psbt\xff' + kv(b'\x00', tx) + b'\x00'
    for a, s in utxos:
        psbt += kv(b'\x01', struct.pack('<Q', a) + varint(len(s)) + s) + b'\x00'
    psbt += b'\x00' * parse_unsigned(tx)[3]
    return psbt, cases

# --- BIP86 -------------------------------------------------------------------
def taproot_output_key(pub33):
    Pt = lift_x(int.from_bytes(pub33[1:], 'big'))
    t = int.from_bytes(tagged('TapTweak', pub33[1:]), 'big')
    assert t < N
    return point_add(Pt, point_mul(t))

def taproot_tweaked_priv(priv):
    Pt = point_mul(priv)
    d = priv if Pt[1] % 2 == 0 else N - priv
    t = int.from_bytes(tagged('TapTweak', Pt[0].to_bytes(32, 'big')), 'big')
    d = (d + t) % N
    return d.to_bytes(32, 'big')

# bech32m (BIP350), for the published addresses
CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
def bech32_polymod(values):
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk

def segwit_address(witver, prog):
    data, acc, bits = [witver], 0, 0
    for b in prog:
        acc = (acc << 8) | b
        bits += 8
        while bits >= 5:
            bits -= 5
            data.append((acc >> bits) & 31)
    if bits: data.append((acc << (5 - bits)) & 31)
    const = 0x2bc830a3 if witver else 1
    hrp = 'bc'
    values = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp] + data
    pm = bech32_polymod(values + [0] * 6) ^ const
    return hrp + '1' + ''.join(CHARSET[d] for d in data + [(pm >> 5 * (5 - i)) & 31 for i in range(6)])

if len(sys.argv) != 3:
    sys.exit(__doc__)
n_signed = check_bip340(sys.argv[1])
bip341_psbt, bip341_cases = check_bip341(sys.argv[2])
assert len(bip341_cases) == 2

ACC = [86 | H, H, H]
master_priv, _ = master_key(seed)
FP = hash160(ser_pub(point_mul(master_priv)))[:4]
assert FP.hex() == '73c5da0a'

def tr_key(chain, index):
    priv = derive(seed, ACC + [chain, index])
    pub = ser_pub(point_mul(priv))
    Q = taproot_output_key(pub)
    spk = b'\x51\x20' + Q[0].to_bytes(32, 'big')
    return priv, pub, spk

# Published BIP86 vectors of this seed
priv_r0, pub_r0, spk_r0 = tr_key(0, 0)
assert pub_r0[1:].hex() == 'cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115'
assert segwit_address(1, spk_r0[2:]) == 'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr'
priv_c0, pub_c0, spk_c0 = tr_key(1, 0)
assert segwit_address(1, spk_c0[2:]) == 'bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7'
priv_r1, pub_r1, spk_r1 = tr_key(0, 1)

k, c = master_key(seed)
for idx in ACC[:2]:
    k, c = ckd_priv(k, c, idx)
parent_fp = hash160(ser_pub(point_mul(k)))[:4]
k, c = ckd_priv(k, c, ACC[2])
xpub = b58check(struct.pack('>I', 0x0488B21E) + bytes([3]) + parent_fp + struct.pack('>I', ACC[2]) +
                c + ser_pub(point_mul(k)))
assert xpub == 'xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ'

# Two coins received at receive 0 and 1, spent to an external address with change
AMOUNTS = [120000, 80000]
prev_txids = [sha256(b'taproot prev 0'), sha256(b'taproot prev 1')]
EXTERNAL = bytes.fromhex('0014751e76e8199196d454941c45d1b3a323f1433bd6')   # bc1q of m/84'/0'/0'/1/0
SEND, CHANGE = 150000, 48000                                                 # Fee 2,000 sats
tx = (struct.pack('<I', 2) + b'\x02' +
      prev_txids[0] + struct.pack('<I', 1) + b'\x00' + struct.pack('<I', 0xfffffffd) +
      prev_txids[1] + struct.pack('<I', 0) + b'\x00' + struct.pack('<I', 0xfffffffd) +
      b'\x02' +
      struct.pack('<Q', SEND) + varint(len(EXTERNAL)) + EXTERNAL +
      struct.pack('<Q', CHANGE) + varint(len(spk_c0)) + spk_c0 + struct.pack('<I', 870000))

def tap_keypath(chain, index):
    return b'\x00' + keypath(FP, *ACC, chain, index)     # No leaf hashes: key path only

ins = [(pub_r0, spk_r0, 0, 0), (pub_r1, spk_r1, 0, 1)]
psbt = b'psbt\xff' + kv(b'\x00', tx) + b'\x00'
for (pub, spk, ch, ix), amount in zip(ins, AMOUNTS):
    psbt += (kv(b'\x01', struct.pack('<Q', amount) + varint(len(spk)) + spk) +
             kv(b'\x16' + pub[1:], tap_keypath(ch, ix)) +
             kv(b'\x17', pub[1:]) + b'\x00')
psbt += b'\x00'                                                            # External output
psbt += kv(b'\x05', pub_c0[1:]) + kv(b'\x07' + pub_c0[1:], tap_keypath(1, 0)) + b'\x00'
maps = read_maps(psbt)
assert write_maps(maps) == psbt

utxos = [(a, s) for (_, s, _, _), a in zip(ins, AMOUNTS)]
sighashes = []
for i, priv in enumerate([priv_r0, priv_r1]):
    sh = taproot_sighash(tx, i, utxos, 0)
    sig = bip340_sign(taproot_tweaked_priv(priv), sh, bytes(32))
    assert bip340_verify(utxos[i][1][2:], sh, sig)
    maps[1 + i].append((b'\x13', sig))                  # TAP_KEY_SIG, appended at the end of the map
    sighashes.append(sh)
signed = write_maps(maps)

open('abandon taproot.psbt', 'wb').write(psbt)

def c_array(f, name, data):
    f.write('static const uint8_t %s[%d] = {\n' % (name, len(data)))
    for i in range(0, len(data), 16):
        f.write('    ' + ', '.join('0x%02x' % b for b in data[i:i + 16]) + ',\n')
    f.write('};\n\n')

rows = [r for r in csv.DictReader(open(sys.argv[1]))]
with open('taproot_vectors.h', 'w', newline='\r\n') as f:
    f.write('// Generated by test/psbt/gen_taproot.py - test data only, not a secret.\n')
    f.write('// "abandon x11 about" P2TR (BIP86 key path) PSBT signed by the independent Python\n')
    f.write('// signer, and the official BIP340 and BIP341 vectors.\n')
    f.write('#ifndef TAPROOT_VECTORS_H\n#define TAPROOT_VECTORS_H\n\n#include <stdint.h>\n\n')
    f.write('// Unsigned, and both inputs signed (m/86h/0h/0h/0/0 and 0/1, SIGHASH_DEFAULT)\n')
    c_array(f, 'taproot_psbt', psbt)
    c_array(f, 'taproot_signed_psbt', signed)
    c_array(f, 'taproot_priv_0_0', priv_r0.to_bytes(32, 'big'))
    c_array(f, 'taproot_pub_0_0', pub_r0)
    c_array(f, 'taproot_priv_0_1', priv_r1.to_bytes(32, 'big'))
    c_array(f, 'taproot_pub_0_1', pub_r1)
    c_array(f, 'taproot_spk_0_0', spk_r0)
    c_array(f, 'taproot_sighash_0', sighashes[0])
    f.write('// BIP340 test-vectors.csv: secret key (empty: verification only), public key,\n')
    f.write('// aux_rand, message, signature, expected verification result\n')
    f.write('typedef struct { const char *sk, *pk, *aux, *msg, *sig; int valid; } bip340_vector_t;\n')
    f.write('static const bip340_vector_t bip340_vectors[] = {\n')
    for r in rows:
        if len(r['message']) != 64: continue           # The C code signs 32 byte messages only
        f.write('    {"%s", "%s", "%s", "%s", "%s", %d},\n' % (r['secret key'], r['public key'], r['aux_rand'],
                r['message'], r['signature'], 1 if r['verification result'] == 'TRUE' else 0))
    f.write('};\n\n')
    f.write('// BIP341 wallet-test-vectors.json keyPathSpending: the transaction as a PSBT\n')
    f.write('// (WITNESS_UTXO on every input) and the inputs with hash type 0 or 1\n')
    c_array(f, 'bip341_psbt', bip341_psbt)
    f.write('typedef struct { uint32_t index; uint8_t hash_type; const char *sighash, *tweaked, *sig; } bip341_case_t;\n')
    f.write('static const bip341_case_t bip341_cases[] = {\n')
    for idx, ht, sh, tw, sig in bip341_cases:
        f.write('    {%d, %d, "%s", "%s", "%s"},\n' % (idx, ht, sh.hex(), tw.hex(), sig.hex()))
    f.write('};\n\n')
    f.write('#endif // TAPROOT_VECTORS_H\n')

print('BIP340: %d signing vectors and every verification vector agree' % n_signed)
print('BIP341: sighash and signature of inputs', [c[0] for c in bip341_cases], 'agree')
print('receive 0 ', segwit_address(1, spk_r0[2:]))
print('receive 1 ', segwit_address(1, spk_r1[2:]))
print('change 0  ', segwit_address(1, spk_c0[2:]))
print('xpub      ', xpub)
print('PSBT', len(psbt), 'bytes, signed', len(signed), 'bytes')
print('base64    ', base64.b64encode(psbt).decode())
