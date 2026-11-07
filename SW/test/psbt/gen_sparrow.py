"""Device test PSBTs for the "abandon x11 about" seed, built the way Sparrow
saves a BIP84 single sig wallet's transaction (PSBT v0):
  - global: unsigned tx (version 2, RBF sequence 0xfffffffd, locktime = a
    block height) and the account xpub with its origin (PSBT_GLOBAL_XPUB)
  - input: NON_WITNESS_UTXO (the whole previous tx), WITNESS_UTXO and the
    BIP32 derivation of the key
  - change output: BIP32 derivation; outputs to others: nothing
Test keys only (rule 5). The previous transactions are made up, so these
PSBTs can be signed but never broadcast.

Writes test/psbt/sparrow/ with long file names, as Sparrow saves them (on the
card they show up as 8.3 aliases such as "ABANDO~1.PSB"):
  abandon send.psbt          1 input, one payment + change
  abandon send 3 inputs.psbt 3 inputs (one from the change chain), 2 payments + change
  abandon sweep.psbt         2 inputs, everything to one address, no change
  abandon account 1.psbt     account 1 (m/84'/0'/1'): needs WALLET > CONFIG > ACCOUNT 1
  abandon big.psbt           12 inputs, to try a file of several sectors
  abandon send.txt           the first one as base64 text
    python gen_sparrow.py
"""
import base64, hashlib, hmac, os, struct

# --- secp256k1 and BIP32 (independent of the firmware) ----------------------
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
H = 0x80000000

def point_add(a, b):
    if a is None: return b
    if b is None: return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0: return None
    if a == b: l = 3 * a[0] * a[0] * pow(2 * a[1], P - 2, P) % P
    else: l = (b[1] - a[1]) * pow(b[0] - a[0], P - 2, P) % P
    x = (l * l - a[0] - b[0]) % P
    return (x, (l * (a[0] - x) - a[1]) % P)

def point_mul(k, pt=G):
    r = None
    while k:
        if k & 1: r = point_add(r, pt)
        pt = point_add(pt, pt)
        k >>= 1
    return r

def ser_pub(pt): return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, 'big')
def sha256(b): return hashlib.sha256(b).digest()
def dsha(b): return sha256(sha256(b))
def hash160(b): return hashlib.new('ripemd160', sha256(b)).digest()

def ckd(k, c, i):
    data = (b'\x00' + k.to_bytes(32, 'big') if i & H else ser_pub(point_mul(k))) + struct.pack('>I', i)
    d = hmac.new(c, data, hashlib.sha512).digest()
    return (int.from_bytes(d[:32], 'big') + k) % N, d[32:]

seed = hashlib.pbkdf2_hmac('sha512', ' '.join(['abandon'] * 11 + ['about']).encode(), b'mnemonic', 2048)
d = hmac.new(b'Bitcoin seed', seed, hashlib.sha512).digest()
MK, MC = int.from_bytes(d[:32], 'big'), d[32:]
FP = hash160(ser_pub(point_mul(MK)))[:4]
assert FP.hex() == '73c5da0a'

def derive(path):
    k, c = MK, MC
    for i in path: k, c = ckd(k, c, i)
    return k, c

def account_xpub(account):
    k1, _ = derive([84 | H, H])
    k, c = derive([84 | H, H, account | H])
    return (bytes.fromhex('0488b21e') + b'\x03' + hash160(ser_pub(point_mul(k1)))[:4] +
            struct.pack('>I', account | H) + c + ser_pub(point_mul(k)))

def key(account, chain, index):
    path = [84 | H, H, account | H, chain, index]
    k, _ = derive(path)
    pub = ser_pub(point_mul(k))
    return pub, path, b'\x00\x14' + hash160(pub)

assert key(0, 0, 0)[0].hex() == '0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c'   # BIP84 vector

# --- Serialization -----------------------------------------------------------
def varint(n):
    if n < 0xFD: return bytes([n])
    if n <= 0xFFFF: return b'\xfd' + struct.pack('<H', n)
    return b'\xfe' + struct.pack('<I', n)

def kv(k, v): return varint(len(k)) + k + varint(len(v)) + v
def keypath(path): return FP + b''.join(struct.pack('<I', e) for e in path)

def tx(ins, outs, locktime, segwit=False):
    s = struct.pack('<I', 2) + (b'\x00\x01' if segwit else b'') + varint(len(ins))
    for txid, vout, seq in ins:
        s += txid + struct.pack('<I', vout) + b'\x00' + struct.pack('<I', seq)
    s += varint(len(outs))
    for amount, spk in outs:
        s += struct.pack('<Q', amount) + varint(len(spk)) + spk
    if segwit:
        s += (b'\x02\x47' + bytes(71) + b'\x21' + bytes(33)) * len(ins)  # A plausible witness per input
    return s + struct.pack('<I', locktime)

def txid_of(ins, outs, locktime):
    return dsha(tx(ins, outs, locktime))           # Legacy serialization: the real txid

# Addresses of other people (BIP173 / BIP350 examples and fixed test keys)
EXTERNAL_WPKH = bytes.fromhex('0014751e76e8199196d454941c45d1b3a323f1433bd6')     # bc1qw508d6qe...
EXTERNAL_TR = bytes.fromhex('5120' + '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
EXTERNAL_WSH = bytes.fromhex('00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262')

LOCKTIME = 870120

def sparrow_psbt(account, coins, payments, change=None, label=''):
    """coins: (chain, index, amount) of ours; payments: (amount, script);
    change: (index, amount) on chain 1 or None."""
    ins, in_maps = [], []
    for n, (chain, index, amount) in enumerate(coins):
        pub, path, spk = key(account, chain, index)
        # A made-up previous transaction that paid this address (and someone else)
        p_ins = [(sha256(b'prev' + label.encode() + bytes([n])), n, 0xfffffffd)]
        p_outs = [(amount, spk), (123456 + n, EXTERNAL_WPKH)]
        p_tx = tx(p_ins, p_outs, LOCKTIME - 50 - n, segwit=True)
        prev_txid = txid_of(p_ins, p_outs, LOCKTIME - 50 - n)
        ins.append((prev_txid, 0, 0xfffffffd))
        in_maps.append(kv(b'\x00', p_tx) +
                       kv(b'\x01', struct.pack('<Q', amount) + varint(len(spk)) + spk) +
                       kv(b'\x06' + pub, keypath(path)))
    outs, out_maps = [], []
    for amount, spk in payments:
        outs.append((amount, spk))
        out_maps.append(b'')
    if change:
        pub, path, spk = key(account, 1, change[0])
        outs.insert(len(outs) // 2, (change[1], spk))           # Sparrow mixes the change in
        out_maps.insert(len(out_maps) // 2, kv(b'\x02' + pub, keypath(path)))
    unsigned = tx(ins, outs, LOCKTIME)
    fee = sum(c[2] for c in coins) - sum(o[0] for o in outs)
    assert fee > 0
    s = b'psbt\xff' + kv(b'\x00', unsigned) + kv(b'\x01' + account_xpub(account), keypath([84 | H, H, account | H])) + b'\x00'
    for m in in_maps: s += m + b'\x00'
    for m in out_maps: s += m + b'\x00'
    return s, fee

cases = [
    ('abandon send.psbt', 0, [(0, 0, 100000)], [(60000, EXTERNAL_WPKH)], (0, 39720)),
    ('abandon send 3 inputs.psbt', 0, [(0, 1, 250000), (0, 2, 80000), (1, 0, 41000)],
     [(200000, EXTERNAL_WPKH), (120000, EXTERNAL_TR)], (1, 49900)),
    ('abandon sweep.psbt', 0, [(0, 3, 54321), (0, 4, 12345)], [(66300, EXTERNAL_WSH)], None),
    ('abandon account 1.psbt', 1, [(0, 0, 500000)], [(150000, EXTERNAL_WPKH)], (0, 349800)),
    ('abandon big.psbt', 0, [(0, 10 + i, 20000 + 1000 * i) for i in range(12)], [(250000, EXTERNAL_WPKH)], (2, 47500)),
]

out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sparrow')
os.makedirs(out_dir, exist_ok=True)
for name, account, coins, payments, change in cases:
    data, fee = sparrow_psbt(account, coins, payments, change, name)
    open(os.path.join(out_dir, name), 'wb').write(data)
    print('%-28s %5d bytes, %d in, fee %d sats' % (name, len(data), len(coins), fee))
first = open(os.path.join(out_dir, cases[0][0]), 'rb').read()
open(os.path.join(out_dir, 'abandon send.txt'), 'w').write(base64.b64encode(first).decode() + '\n')
print('ok')
