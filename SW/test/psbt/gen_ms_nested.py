"""Nested multisig (P2SH-P2WSH, BIP48 script type 1') test data, independent
from descriptor.c and the firmware.

The same three cosigners as gen_descriptor.py (A = "abandon x11 about", B, C,
and the attacker X), at m/48'/0'/0'/1'. Writes:
  MSNDESC.TXT                    - sh(wsh(sortedmulti())) descriptor file
  MSNCOLD.TXT                    - the same wallet as a Coldcard file (Ypub keys)
  abandon nested multisig.psbt   - 2 inputs of the wallet (receive 0, change 0)
                                   with their previous transactions, a send and
                                   change 1/3, for the device
  MSNATTACK.PSB                  - 1 input; the "change" has X's key instead of B
  ms_nested_vectors.h            - texts, CBOR, keys, change script, and the
                                   review PSBT unsigned and signed by A on
                                   input 0 (test_descriptor.c, test_sign.c)
"""
import runpy, struct, hashlib

g = runpy.run_path('gen_descriptor.py')
H, master_key, ckd_priv = g['H'], g['master_key'], g['ckd_priv']
point_mul, ser_pub, hash160, sha256, dsha = g['point_mul'], g['ser_pub'], g['hash160'], g['sha256'], g['dsha']
b58check, varint, kv, keypath = g['b58check'], g['varint'], g['kv'], g['keypath']
descsum_create, multisig_script, cbor, Tag = g['descsum_create'], g['multisig_script'], g['cbor'], g['Tag']
seed_a, EXTERNAL = g['seed_a'], g['EXTERNAL']
s = runpy.run_path('sign_abandon.py')
bip143_sighash, sign, verify, der, N = s['bip143_sighash'], s['sign'], s['verify'], s['der'], s['N']
read_maps, write_maps = s['read_maps'], s['write_maps']

MS1 = [48 | H, 0 | H, 0 | H, 1 | H]

class Cosigner:
    def __init__(self, seed):
        k, c = master_key(seed)
        self.fp = hash160(ser_pub(point_mul(k)))[:4]
        parent = None
        for idx in MS1:
            parent = hash160(ser_pub(point_mul(k)))[:4]
            k, c = ckd_priv(k, c, idx)
        self.k, self.c, self.pub, self.parent = k, c, ser_pub(point_mul(k)), parent
        payload = bytes([len(MS1)]) + parent + struct.pack('>I', MS1[-1]) + c + self.pub
        self.xpub = b58check(bytes.fromhex('0488b21e') + payload)
        self.Ypub = b58check(bytes.fromhex('0295b43f') + payload)     # SLIP-0132 P2SH-P2WSH multisig

    def child(self, change, index):
        k, c = ckd_priv(self.k, self.c, change)
        k, c = ckd_priv(k, c, index)
        return k, ser_pub(point_mul(k))

A = Cosigner(seed_a)
B = Cosigner(hashlib.sha512(b'seedmate test cosigner B').digest())
C = Cosigner(hashlib.sha512(b'seedmate test cosigner C').digest())
X = Cosigner(hashlib.sha512(b'seedmate test attacker').digest())
cosigners = [A, B, C]
assert A.fp.hex() == '73c5da0a'

def key_expr(co):
    return '[%s/48h/0h/0h/1h]%s/<0;1>/*' % (co.fp.hex(), co.xpub)

desc = descsum_create('sh(wsh(sortedmulti(2,%s)))' % ','.join(key_expr(co) for co in cosigners))
desc_text = '# Receive and change descriptor (BIP389), nested segwit multisig:\n' + desc + '\n'
cold_text = ('# Coldcard Multisig setup file (test)\n#\nName: Seedmate nested\nPolicy: 2 of 3\nFormat: P2SH-P2WSH\n\n' +
             ''.join("Derivation: m/48'/0'/0'/1'\n%s: %s\n\n" % (co.fp.hex().upper(), co.Ypub) for co in cosigners))

def p2sh_p2wsh(ws):
    """redeem script OP_0 <sha256(ws)> and the P2SH output paying to it"""
    redeem = b'\x00\x20' + sha256(ws)
    return redeem, b'\xa9\x14' + hash160(redeem) + b'\x87'

def ws_at(cos, change, index):
    return multisig_script(2, [co.child(change, index)[1] for co in cos], True)

CHANGE, INDEX = 1, 3
ws_change = ws_at(cosigners, CHANGE, INDEX)
_, spk_change = p2sh_p2wsh(ws_change)
receive0 = b58check(b'\x05' + p2sh_p2wsh(ws_at(cosigners, 0, 0))[1][2:22])

# UR crypto-output: sh(wsh(sortedmulti())), tags 400, 401, 407
keys = []
for co in cosigners:
    origin = Tag(304, {1: [48, True, 0, True, 0, True, 1, True], 2: int.from_bytes(co.fp, 'big'), 3: 4})
    keys.append(Tag(303, {2: False, 3: co.pub, 4: co.c, 5: Tag(305, {1: 0, 2: 0}), 6: origin,
                          8: int.from_bytes(co.parent, 'big')}))
output_cbor = cbor(Tag(400, Tag(401, Tag(407, {1: 2, 2: keys}))))

def input_map(ch, ix, amount, n):
    ws = ws_at(cosigners, ch, ix)
    redeem, spk = p2sh_p2wsh(ws)
    prev = (struct.pack('<I', 2) + b'\x01' + sha256(b'ms nested funding %d' % n) + struct.pack('<I', 0) +
            b'\x00' + struct.pack('<I', 0xffffffff) + b'\x01' +
            struct.pack('<Q', amount) + varint(len(spk)) + spk + struct.pack('<I', 0))
    m = (kv(b'\x00', prev) + kv(b'\x01', struct.pack('<Q', amount) + varint(len(spk)) + spk) +
         kv(b'\x04', redeem) + kv(b'\x05', ws))
    for co in cosigners:
        m += kv(b'\x06' + co.child(ch, ix)[1], keypath(co.fp, *MS1, ch, ix))
    return dsha(prev), m, ws, amount

def change_map(change_cos):
    ws = ws_at(change_cos, CHANGE, INDEX)
    redeem, spk = p2sh_p2wsh(ws)
    m = kv(b'\x00', redeem) + kv(b'\x01', ws)
    # The attacker keeps B's fingerprint and path, so only the key differs
    for co, real in zip(change_cos, cosigners):
        m += kv(b'\x02' + co.child(CHANGE, INDEX)[1], keypath(real.fp, *MS1, CHANGE, INDEX))
    return spk, m

def build(spends, change_cos, send, change_amount):
    ins, maps, wss = b'', b'', []
    for n, ((ch, ix), amount) in enumerate(spends):
        txid, m, ws, _ = input_map(ch, ix, amount, n)
        ins += txid + struct.pack('<I', 0) + b'\x00' + struct.pack('<I', 0xfffffffd)
        maps += m + b'\x00'
        wss.append((ws, amount))
    spk, cmap = change_map(change_cos)
    outs = [(EXTERNAL, send), (spk, change_amount)]
    tx = (struct.pack('<I', 2) + varint(len(spends)) + ins + varint(len(outs)) +
          b''.join(struct.pack('<Q', a) + varint(len(sc)) + sc for sc, a in outs) + struct.pack('<I', 0))
    psbt = b'psbt\xff' + kv(b'\x00', tx) + b'\x00' + maps + b'\x00' + cmap + b'\x00'
    assert write_maps(read_maps(psbt)) == psbt
    return psbt, tx, wss

# Review PSBT: 300,000 + 120,000 in, 250,000 sent, 168,000 change, fee 2,000
review, review_tx, review_ws = build([((0, 0), 300000), ((1, 0), 120000)], cosigners, 250000, 168000)
attack, _, _ = build([((0, 0), 300000)], [A, X, C], 150000, 148000)

# A signs input 0 of the review PSBT: BIP143 with the witness script as scriptCode
ws0, amount0 = review_ws[0]
priv_a0, pub_a0 = A.child(0, 0)
sighash, _ = bip143_sighash(review_tx, 0, varint(len(ws0)) + ws0, amount0)
r, s_ = sign(priv_a0, sighash)
assert verify(point_mul(priv_a0), sighash, r, s_) and s_ <= N // 2
maps = read_maps(review)
maps[1].append((b'\x02' + pub_a0, der(r, s_) + b'\x01'))
review_signed = write_maps(maps)

open('MSNDESC.TXT', 'w', newline='\n').write(desc_text)
open('MSNCOLD.TXT', 'w', newline='\n').write(cold_text)
open('abandon nested multisig.psbt', 'wb').write(review)
open('MSNATTACK.PSB', 'wb').write(attack)

def c_str(t):
    return '"' + t.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n') + '"'

def arr(data):
    return '{' + ', '.join('0x%02x' % b for b in data) + '}'

# Addresses of both wallets (WALLET > ADDRESSES in multisig): receive and
# change 0..4, native P2WSH (the cosigners of gen_descriptor.py at /2') and
# nested P2SH-P2WSH (/1'), with a bech32 encoder written from BIP173
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

def p2wsh_address(ws):
    data, acc, bits = [0], 0, 0
    for byte in sha256(ws):
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            data.append((acc >> bits) & 31)
    if bits: data.append((acc << (5 - bits)) & 31)
    values = [ord(x) >> 5 for x in 'bc'] + [0] + [ord(x) & 31 for x in 'bc'] + data
    pm = bech32_polymod(values + [0] * 6) ^ 1
    return 'bc1' + ''.join(CHARSET[d] for d in data + [(pm >> 5 * (5 - i)) & 31 for i in range(6)])

native_cos = g['cosigners']
ADDR_N = 5
native_addr = [[p2wsh_address(multisig_script(2, [co.child(ch, i)[1] for co in native_cos], True))
                for i in range(ADDR_N)] for ch in (0, 1)]
nested_addr = [[b58check(b'\x05' + p2sh_p2wsh(ws_at(cosigners, ch, i))[1][2:22])
                for i in range(ADDR_N)] for ch in (0, 1)]
assert nested_addr[0][0] == receive0

with open('ms_nested_vectors.h', 'w', newline='\r\n') as f:
    f.write('// Generated by gen_ms_nested.py - public test data only (P2SH-P2WSH, m/48h/0h/0h/1h)\n')
    f.write('#include <stdint.h>\n\n')
    f.write('static const char msn_desc_text[] = %s;\n' % c_str(desc_text))
    f.write('static const char msn_cold_text[] = %s;\n' % c_str(cold_text))
    f.write('static const uint8_t msn_output_cbor[%d] = %s;\n\n' % (len(output_cbor), arr(output_cbor)))
    f.write('static const uint8_t msn_fp[3][4] = {%s};\n' % ', '.join(arr(co.fp) for co in cosigners))
    f.write('static const uint8_t msn_chain[3][32] = {%s};\n' % ', '.join(arr(co.c) for co in cosigners))
    f.write('static const uint8_t msn_pub[3][33] = {%s};\n' % ', '.join(arr(co.pub) for co in cosigners))
    f.write('#define MSN_CHANGE %d\n#define MSN_INDEX %d\n' % (CHANGE, INDEX))
    f.write('static const uint8_t msn_change_ws[%d] = %s;\n' % (len(ws_change), arr(ws_change)))
    f.write('static const uint8_t msn_change_spk[%d] = %s;\n\n' % (len(spk_change), arr(spk_change)))
    f.write('// Review PSBT, unsigned and signed by A (m/48h/0h/0h/1h/0/0) on input 0\n')
    f.write('static const uint8_t msn_psbt[%d] = %s;\n' % (len(review), arr(review)))
    f.write('static const uint8_t msn_signed_psbt[%d] = %s;\n' % (len(review_signed), arr(review_signed)))
    f.write('static const uint8_t msn_priv_a0[32] = %s;\n' % arr(priv_a0.to_bytes(32, 'big')))
    f.write('static const uint8_t msn_pub_a0[33] = %s;\n' % arr(pub_a0))
    f.write('\n// Receive and change 0..%d of the native (/2h) and nested (/1h) wallets\n' % (ADDR_N - 1))
    f.write('#define MSA_N %d\n' % ADDR_N)
    f.write('static const char msa_native_desc[] = %s;\n' % c_str(g['desc_sorted']))
    for name, table in (('msa_native_addr', native_addr), ('msa_nested_addr', nested_addr)):
        f.write('static const char *const %s[2][MSA_N] = {\n' % name)
        for row in table:
            f.write('    {%s},\n' % ', '.join(c_str(x) for x in row))
        f.write('};\n')

print('descriptor ', desc)
print('receive 0  ', receive0)
print('Ypub A     ', A.Ypub)
print('review PSBT', len(review), 'bytes, signed', len(review_signed), '; attack', len(attack))
