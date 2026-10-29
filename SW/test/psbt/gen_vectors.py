"""Builds BIP174 test PSBTs and writes them as C arrays to test_vectors.h."""
import struct, hashlib, sys, base64

def varint(n):
    if n < 0xFD: return bytes([n])
    if n <= 0xFFFF: return b'\xfd' + struct.pack('<H', n)
    return b'\xfe' + struct.pack('<I', n)

def kv(key, val):
    return varint(len(key)) + key + varint(len(val)) + val

def tx(version, ins, outs, locktime=0, segwit=False):
    s = struct.pack('<I', version)
    if segwit: s += b'\x00\x01'
    s += varint(len(ins))
    for txid, vout, script_sig, seq in ins:
        s += txid + struct.pack('<I', vout) + varint(len(script_sig)) + script_sig + struct.pack('<I', seq)
    s += varint(len(outs))
    for amount, spk in outs:
        s += struct.pack('<Q', amount) + varint(len(spk)) + spk
    if segwit:
        for _ in ins: s += b'\x00'          # empty witness stacks
    return s + struct.pack('<I', locktime)

def psbt(unsigned_tx, in_maps, out_maps, extra_global=b''):
    s = b'psbt\xff' + kv(b'\x00', unsigned_tx) + extra_global + b'\x00'
    for m in in_maps: s += m + b'\x00'
    for m in out_maps: s += m + b'\x00'
    return s

def witness_utxo(amount, spk):
    return kv(b'\x01', struct.pack('<Q', amount) + varint(len(spk)) + spk)

# BIP173 / BIP350 scripts with known mainnet addresses
P2WPKH = bytes.fromhex('0014751e76e8199196d454941c45d1b3a323f1433bd6')
P2WSH = bytes.fromhex('00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262')
P2TR = bytes.fromhex('512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
P2PKH = bytes.fromhex('76a914' + '11' * 20 + '88ac')
P2SH = bytes.fromhex('a914' + '22' * 20 + '87')

txid_a = bytes(range(32))                 # display order is reversed
txid_b = hashlib.sha256(b'b').digest()

# 1) Two witness_utxo inputs, two outputs, fee 1000 sats
t1 = tx(2, [(txid_a, 1, b'', 0xfffffffd), (txid_b, 0, b'', 0xfffffffd)],
        [(120000, P2WPKH), (29000, P2TR)], locktime=850000)
v1 = psbt(t1, [witness_utxo(100000, P2WPKH), witness_utxo(50000, P2WSH)],
          [b'', kv(b'\x02' + b'\x03' * 33, b'\x00' * 8)])   # output map with a dummy key

# 1b) Same PSBT wrapped in a CBOR byte string (ur:crypto-psbt payload)
v1_cbor = b'\x59' + struct.pack('>H', len(v1)) + v1

# 2) non_witness_utxo input (SegWit-serialized prev tx, spending vout 2)
prev = tx(1, [(hashlib.sha256(b'p').digest(), 0, b'', 0xffffffff)],
          [(1, P2PKH), (2, P2SH), (777777, P2WPKH)], segwit=True)
prev_txid = hashlib.sha256(hashlib.sha256(prev).digest()).digest()
t2 = tx(2, [(prev_txid, 2, b'', 0xffffffff)], [(700000, P2PKH), (70000, P2SH), (0, b'\x6a\x04test')])
v2 = psbt(t2, [kv(b'\x00', prev)], [b'', b'', b''])

# 3) Input without UTXO data -> fee unknown
v3 = psbt(t2, [b''], [b'', b'', b''])

# 4) Errors
bad_magic = b'psbx\xff' + v1[5:]
truncated = v1[:-1]
v2_global = psbt(t1, [witness_utxo(100000, P2WPKH), witness_utxo(50000, P2WSH)], [b'', b''],
                 extra_global=kv(b'\xfb', struct.pack('<I', 2)))
t_sig = tx(2, [(txid_a, 0, b'\x01\x02', 0)], [(1, P2WPKH)])
script_sig = psbt(t_sig, [b''], [b''])
missing_maps = b'psbt\xff' + kv(b'\x00', t1) + b'\x00' + witness_utxo(1, P2WPKH)  # no separators

# --- Key metadata: BIP32 derivations, sighash, partial sigs, multisig ---
# BIP84 test vector keys for "abandon abandon ... about" (master fp 73c5da0a)
FP_TEST = bytes.fromhex('73c5da0a')
PUB_0_0 = bytes.fromhex('0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c')
ADDR_0_0 = 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu'
PUB_1_0 = bytes.fromhex('03025324888e429ab8e3dbaf1f7802648b9cd01e9b418485c5fa4c1b9b5700e1a6')
ADDR_1_0 = 'bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el'
PUB_G = bytes.fromhex('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
PUB_2G = bytes.fromhex('02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5')
H = 0x80000000

def bech32_program(addr):
    charset = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
    data = [charset.index(c) for c in addr[addr.rfind('1') + 1:-6]]
    acc = bits = 0; out = []
    for v in data[1:]:
        acc = (acc << 5) | v; bits += 5
        while bits >= 8:
            bits -= 8; out.append((acc >> bits) & 0xFF)
    return bytes(out)

def p2wpkh(addr):
    return b'\x00\x14' + bech32_program(addr)

def path_bytes(fp, *elems):
    return fp + b''.join(struct.pack('<I', e) for e in elems)

def multisig(m, keys):
    return bytes([0x50 + m]) + b''.join(b'\x21' + k for k in keys) + bytes([0x50 + len(keys), 0xAE])

ms_script = multisig(2, [PUB_0_0, PUB_G, PUB_2G])
P2WSH_MS = b'\x00\x20' + hashlib.sha256(ms_script).digest()
xpub_dummy = bytes.fromhex('0488b21e') + bytes(74)     # 78-byte serialized xpub
ms_derivs = (kv(b'\x06' + PUB_0_0, path_bytes(FP_TEST, 48 | H, H, H, 2 | H, 0, 0)) +
             kv(b'\x06' + PUB_G, path_bytes(bytes.fromhex('11111111'), 48 | H, H, H, 2 | H, 0, 0)) +
             kv(b'\x06' + PUB_2G, path_bytes(bytes.fromhex('22222222'), 48 | H, H, H, 2 | H, 0, 0)))

t4 = tx(2, [(txid_a, 0, b'', 0xfffffffd), (txid_b, 1, b'', 0xffffffff), (txid_a, 2, b'', 0xffffffff)],
        [(50000, P2WPKH), (40000, p2wpkh(ADDR_1_0)), (30000, P2WSH_MS)], locktime=850000)
# 4) Input 0: own P2WPKH with explicit SIGHASH_ALL. Input 1: 2-of-3 P2WSH with
#    one partial signature and SIGHASH_NONE|ANYONECANPAY. Input 2: finalized.
#    Outputs: external, own change, 2-of-3 multisig change. One global xpub.
out2 = kv(b'\x01', ms_script) + b''.join(
    kv(b'\x02' + k, path_bytes(fp, 48 | H, H, H, 2 | H, 1, 0))
    for k, fp in [(PUB_0_0, FP_TEST), (PUB_G, bytes.fromhex('11111111')), (PUB_2G, bytes.fromhex('22222222'))])
v4 = psbt(t4,
          [witness_utxo(60000, p2wpkh(ADDR_0_0)) + kv(b'\x03', struct.pack('<I', 1)) +
               kv(b'\x06' + PUB_0_0, path_bytes(FP_TEST, 84 | H, H, H, 0, 0)),
           witness_utxo(50000, P2WSH_MS) + kv(b'\x05', ms_script) + ms_derivs +
               kv(b'\x02' + PUB_G, bytes(71)) + kv(b'\x03', struct.pack('<I', 0x82)),
           witness_utxo(20000, P2WPKH) + kv(b'\x08', b'\x02' + b'\x47' + bytes(71) + b'\x21' + PUB_G)],
          [b'', kv(b'\x02' + PUB_1_0, path_bytes(FP_TEST, 84 | H, H, H, 1, 0)), out2],
          extra_global=kv(b'\x01' + xpub_dummy, path_bytes(FP_TEST, 84 | H, H, H)))

# Clean single-sig PSBT for the device: load "abandon x11 about" and expect
# input 1 = MINE m/84'/0'/0'/0/0 and output 2 = CHANGE m/84'/0'/0'/1/0
abandon = psbt(tx(2, [(txid_a, 0, b'', 0xfffffffd)], [(70000, P2WPKH), (29000, p2wpkh(ADDR_1_0))], locktime=850000),
               [witness_utxo(100000, p2wpkh(ADDR_0_0)) + kv(b'\x06' + PUB_0_0, path_bytes(FP_TEST, 84 | H, H, H, 0, 0))],
               [b'', kv(b'\x02' + PUB_1_0, path_bytes(FP_TEST, 84 | H, H, H, 1, 0))])

# --- Signing support ---------------------------------------------------------
# BIP143 native P2WPKH example as a PSBT (empty input maps): the sighash of
# input 1 must be c37af311...cb670
bip143_tx = bytes.fromhex(
    '0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffff'
    'ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206'
    '000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42db'
    'ee7e4dbe6a21b2d50ce2f0167faa815988ac11000000')
bip143_psbt = psbt(bip143_tx, [b'', b''], [b'', b''])

# NON_WITNESS_UTXO whose prev_txid is the real txid (legacy serialization,
# without the SegWit marker and witnesses). v2 above hashes the SegWit
# serialization instead, so its prev_txid must NOT match.
prev_legacy = tx(1, [(hashlib.sha256(b'p').digest(), 0, b'', 0xffffffff)],
                 [(1, P2PKH), (2, P2SH), (777777, P2WPKH)])
txid_ok = hashlib.sha256(hashlib.sha256(prev_legacy).digest()).digest()
t5 = tx(2, [(txid_ok, 2, b'', 0xffffffff)], [(700000, P2PKH)])
prev_ok = psbt(t5, [kv(b'\x00', prev)], [b''])                 # SegWit-serialized prev tx
prev_ok_legacy = psbt(t5, [kv(b'\x00', prev_legacy)], [b''])  # Same tx, legacy form
tampered = prev.replace(struct.pack('<Q', 777777), struct.pack('<Q', 9777777))
prev_bad = psbt(t5, [kv(b'\x00', tampered)], [b''])            # Amount changed

vectors = [
    ('v1', v1), ('v1_cbor', v1_cbor), ('v2', v2), ('v3', v3),
    ('bad_magic', bad_magic), ('truncated', truncated), ('v2_global', v2_global),
    ('script_sig', script_sig), ('missing_maps', missing_maps),
    ('v4', v4), ('abandon', abandon),
    ('bip143_psbt', bip143_psbt), ('prev_ok', prev_ok), ('prev_ok_legacy', prev_ok_legacy), ('prev_bad', prev_bad),
]

with open(sys.argv[1], 'w') as f:
    f.write('// Generated by gen_vectors.py\n#include <stdint.h>\n')
    for name, data in vectors:
        f.write('static const uint8_t %s[%d] = {%s};\n' % (name, len(data), ','.join(str(b) for b in data)))
    f.write('static const char *expected_txid_v1_in0 = "%s";\n' % txid_a[::-1].hex())
    # Base64 text as a wallet would save it: wrapped at 64 chars with CRLF
    b64 = base64.b64encode(abandon).decode()
    wrapped = '\\r\\n'.join(b64[i:i + 64] for i in range(0, len(b64), 64))
    f.write('static const char abandon_b64[] = "%s\\r\\n";\n' % wrapped)

# Device test files: base64 text (.TXT) and binary (.PSB, as Sparrow saves it)
with open('abandon_bip84.psbt.txt', 'w') as f:
    f.write(base64.b64encode(abandon).decode() + '\n')
with open('ABANDON.PSB', 'wb') as f:
    f.write(abandon)
print('ok')
