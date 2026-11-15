"""Legacy (BIP44, P2PKH) test data for the "abandon x11 about" seed.

Independent from the firmware: the BIP32, secp256k1 and RFC6979 code is the
Python of sign_abandon.py, the legacy signature hash is written here from the
original algorithm (the unsigned tx with the spent scriptPubKey as the
scriptSig of the input signed, empty scriptSigs elsewhere, then the hash
type). Writes:
  abandon legacy.psbt  - unsigned PSBT for the device: two inputs at
                         m/44'/0'/0'/0/0 and 0/1 with their previous
                         transactions (NON_WITNESS_UTXO only, as BIP174 asks
                         for non-SegWit inputs), a send to an external bc1q
                         address and change at m/44'/0'/0'/1/0
  legacy_vectors.h     - that PSBT, the same signed on both inputs by this
                         signer, and the keys, for test_sign.c (the firmware
                         must sign byte-identically)
Also checks the published address of m/44'/0'/0'/0/0 and the account xpub.
"""
import runpy, struct, base64

g = runpy.run_path('sign_abandon.py')
H, seed, derive, master_key, ckd_priv = g['H'], g['seed'], g['derive'], g['master_key'], g['ckd_priv']
point_mul, ser_pub, hash160, sha256, dsha = g['point_mul'], g['ser_pub'], g['hash160'], g['sha256'], g['dsha']
b58check, varint, read_varint, kv, keypath = g['b58check'], g['varint'], g['read_varint'], g['kv'], g['keypath']
sign, verify, der, N = g['sign'], g['verify'], g['der'], g['N']
read_maps, write_maps = g['read_maps'], g['write_maps']

ACC = [44 | H, H, H]
master_priv, _ = master_key(seed)
FP = hash160(ser_pub(point_mul(master_priv)))[:4]
assert FP.hex() == '73c5da0a'


def p2pkh(pub):
    return b'\x76\xa9\x14' + hash160(pub) + b'\x88\xac'


def p2pkh_address(spk):
    return b58check(b'\x00' + spk[3:23])


keys = [derive(seed, ACC + [0, i]) for i in (0, 1)]
pubs = [ser_pub(point_mul(k)) for k in keys]
spks = [p2pkh(p) for p in pubs]
# Published address of this seed at m/44'/0'/0'/0/0 (Electrum / Sparrow / iancoleman)
assert p2pkh_address(spks[0]) == '1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA', p2pkh_address(spks[0])

priv_change = derive(seed, ACC + [1, 0])
pub_change = ser_pub(point_mul(priv_change))
spk_change = p2pkh(pub_change)

# Account xpub, parent = m/44'/0'
k, c = master_key(seed)
for idx in ACC[:2]:
    k, c = ckd_priv(k, c, idx)
parent_fp = hash160(ser_pub(point_mul(k)))[:4]
k, c = ckd_priv(k, c, ACC[2])
xpub = b58check(struct.pack('>I', 0x0488B21E) + bytes([3]) + parent_fp + struct.pack('>I', ACC[2]) +
                c + ser_pub(point_mul(k)))
# Published BIP44 account xpub of this seed
assert xpub == ('xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj'), xpub

# Previous transactions, one per input: version 1, two outputs, ours second
AMOUNTS = [120000, 75000]
prev = []
for i, (amount, spk) in enumerate(zip(AMOUNTS, spks)):
    other = bytes.fromhex('76a914') + sha256(b'legacy other %d' % i)[:20] + bytes.fromhex('88ac')
    tx = (struct.pack('<I', 1) + b'\x01' + sha256(b'legacy prev %d' % i) + struct.pack('<I', 1) +
          b'\x00' + struct.pack('<I', 0xffffffff) + b'\x02' +
          struct.pack('<Q', 5000) + varint(len(other)) + other +
          struct.pack('<Q', amount) + varint(len(spk)) + spk + struct.pack('<I', 0))
    prev.append(tx)
prev_txids = [dsha(t) for t in prev]

EXTERNAL = bytes.fromhex('0014751e76e8199196d454941c45d1b3a323f1433bd6')   # bc1q of m/84'/0'/0'/1/0
SEND, CHANGE = 150000, 41000                                                 # Fee 4,000 sats
tx = (struct.pack('<I', 2) + b'\x02' +
      prev_txids[0] + struct.pack('<I', 1) + b'\x00' + struct.pack('<I', 0xfffffffd) +
      prev_txids[1] + struct.pack('<I', 1) + b'\x00' + struct.pack('<I', 0xfffffffd) +
      b'\x02' +
      struct.pack('<Q', SEND) + varint(len(EXTERNAL)) + EXTERNAL +
      struct.pack('<Q', CHANGE) + varint(len(spk_change)) + spk_change + struct.pack('<I', 870000))


def legacy_sighash(tx, index, script_code, hash_type=1):
    """Serializes tx again with script_code as the scriptSig of input 'index'"""
    i = 4
    n_in, i = read_varint(tx, i)
    out = tx[:4] + varint(n_in)
    for j in range(n_in):
        outpoint = tx[i:i + 36]; i += 36
        sl, i = read_varint(tx, i); i += sl
        seq = tx[i:i + 4]; i += 4
        out += outpoint + (varint(len(script_code)) + script_code if j == index else b'\x00') + seq
    out += tx[i:]                       # Output count, outputs, locktime
    return dsha(out + struct.pack('<I', hash_type))


ins = b''.join(kv(b'\x00', prev[i]) + kv(b'\x06' + pubs[i], keypath(FP, *ACC, 0, i)) + b'\x00' for i in (0, 1))
out_change = kv(b'\x02' + pub_change, keypath(FP, *ACC, 1, 0))
psbt = b'psbt\xff' + kv(b'\x00', tx) + b'\x00' + ins + b'\x00' + out_change + b'\x00'
maps = read_maps(psbt)
assert write_maps(maps) == psbt

sighashes = []
for i in (0, 1):
    h = legacy_sighash(tx, i, spks[i])
    r, s = sign(keys[i], h)
    assert verify(point_mul(keys[i]), h, r, s) and s <= N // 2
    maps[1 + i].append((b'\x02' + pubs[i], der(r, s) + b'\x01'))
    sighashes.append(h)
signed = write_maps(maps)

open('abandon legacy.psbt', 'wb').write(psbt)


def c_array(f, name, data):
    f.write('static const uint8_t %s[%d] = {\n' % (name, len(data)))
    for i in range(0, len(data), 16):
        f.write('    ' + ', '.join('0x%02x' % b for b in data[i:i + 16]) + ',\n')
    f.write('};\n\n')


with open('legacy_vectors.h', 'w', newline='\r\n') as f:
    f.write('// Generated by test/psbt/gen_legacy.py - test data only, not a secret.\n')
    f.write('// "abandon x11 about" P2PKH (BIP44) PSBT, signed by the independent Python signer.\n')
    f.write('#ifndef LEGACY_VECTORS_H\n#define LEGACY_VECTORS_H\n\n#include <stdint.h>\n\n')
    f.write('// Unsigned, and both inputs signed (m/44h/0h/0h/0/0 and 0/1)\n')
    c_array(f, 'legacy_psbt', psbt)
    c_array(f, 'legacy_signed_psbt', signed)
    c_array(f, 'legacy_priv', keys[0].to_bytes(32, 'big') + keys[1].to_bytes(32, 'big'))
    c_array(f, 'legacy_pub', pubs[0] + pubs[1])
    c_array(f, 'legacy_sighash', sighashes[0] + sighashes[1])
    f.write('#endif // LEGACY_VECTORS_H\n')

print('receive 0 ', p2pkh_address(spks[0]))
print('receive 1 ', p2pkh_address(spks[1]))
print('change 0  ', p2pkh_address(spk_change))
print('xpub      ', xpub)
print('PSBT', len(psbt), 'bytes, signed', len(signed), 'bytes')
print('base64    ', base64.b64encode(psbt).decode())
