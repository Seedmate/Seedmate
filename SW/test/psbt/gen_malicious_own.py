"""Seedmate's own vectors for the warnings the psbt_faker corpus does not reach
(its OP_RETURN burns stop earlier, at FEE UNKNOWN).

Writes malicious/OWN-*.psbt for "abandon x11 about": one P2WPKH input at
m/84'/0'/0'/0/0, witness UTXO only, optional change at m/84'/0'/0'/1/0.
Run from this folder; test_malicious.c reads them through malicious_truth.txt.
"""
import contextlib, io, runpy, struct

with contextlib.redirect_stdout(io.StringIO()):
    g = runpy.run_path('sign_abandon.py')
H, seed, derive = g['H'], g['seed'], g['derive']
point_mul, ser_pub, hash160, sha256 = g['point_mul'], g['ser_pub'], g['hash160'], g['sha256']
varint, kv, keypath = g['varint'], g['kv'], g['keypath']

FP = bytes.fromhex('73c5da0a')
ACCOUNT = [84 | H, 0 | H, 0 | H]
EXTERNAL = bytes.fromhex('0014751e76e8199196d454941c45d1b3a323f1433bd6')
OP_RETURN = b'\x6a\x04test'

def key(chain, index):
    return ser_pub(point_mul(derive(seed, ACCOUNT + [chain, index])))

def p2wpkh(pub):
    return b'\x00\x14' + hash160(pub)

def psbt(amount_in, outs, change=None, change_index=0):
    """outs: list of (script, amount); change: amount of an output of ours"""
    pub_in, pub_ch = key(0, 0), key(1, change_index)
    all_outs = list(outs) + ([(p2wpkh(pub_ch), change)] if change is not None else [])
    tx = (struct.pack('<I', 2) + b'\x01' + sha256(b'own vector') + struct.pack('<I', 0) + b'\x00' +
          struct.pack('<I', 0xfffffffd) + varint(len(all_outs)) +
          b''.join(struct.pack('<Q', a) + varint(len(s)) + s for s, a in all_outs) + struct.pack('<I', 0))
    spk = p2wpkh(pub_in)
    inp = kv(b'\x01', struct.pack('<Q', amount_in) + varint(len(spk)) + spk)
    inp += kv(b'\x06' + pub_in, keypath(FP, *ACCOUNT, 0, 0))
    maps = b''
    for i in range(len(outs)):
        maps += b'\x00'
    if change is not None:
        maps += kv(b'\x02' + pub_ch, keypath(FP, *ACCOUNT, 1, change_index)) + b'\x00'
    return b'psbt\xff' + kv(b'\x00', tx) + b'\x00' + inp + b'\x00' + maps

def legacy_witness_only():
    """A P2PKH input at m/44'/0'/0'/0/0 with only a witness UTXO: a legacy
    signature does not commit to the amount, so without the previous tx the
    amount (and the fee) is a claim; the legacy mode must refuse it"""
    acc = [44 | H, 0 | H, 0 | H]
    pub = ser_pub(point_mul(derive(seed, acc + [0, 0])))
    spk = b'\x76\xa9\x14' + hash160(pub) + b'\x88\xac'
    tx = (struct.pack('<I', 2) + b'\x01' + sha256(b'own legacy') + struct.pack('<I', 0) + b'\x00' +
          struct.pack('<I', 0xfffffffd) + b'\x01' +
          struct.pack('<Q', 199000) + varint(len(EXTERNAL)) + EXTERNAL + struct.pack('<I', 0))
    inp = kv(b'\x01', struct.pack('<Q', 200000) + varint(len(spk)) + spk)
    inp += kv(b'\x06' + pub, keypath(FP, *acc, 0, 0))
    return b'psbt\xff' + kv(b'\x00', tx) + b'\x00' + inp + b'\x00' + b'\x00'

def legacy_prev_tx_bad_vout():
    """Audit R1: a P2PKH input whose previous tx is there and hashes to the
    outpoint, but has no output at that index, so the amount and the script
    come from a WITNESS_UTXO, which can claim any amount. Such an
    outpoint does not exist on chain; the device must still not call the
    amount verified, and the legacy mode must refuse it"""
    acc = [44 | H, 0 | H, 0 | H]
    pub = ser_pub(point_mul(derive(seed, acc + [0, 0])))
    spk = b'\x76\xa9\x14' + hash160(pub) + b'\x88\xac'
    prev = (struct.pack('<I', 2) + b'\x01' + sha256(b'own legacy funding') + struct.pack('<I', 0) + b'\x00' +
            struct.pack('<I', 0xffffffff) + b'\x01' +
            struct.pack('<Q', 5000000) + varint(len(spk)) + spk + struct.pack('<I', 0))
    txid = sha256(sha256(prev))
    tx = (struct.pack('<I', 2) + b'\x01' + txid + struct.pack('<I', 5) + b'\x00' +       # vout 5: not there
          struct.pack('<I', 0xfffffffd) + b'\x01' +
          struct.pack('<Q', 199000) + varint(len(EXTERNAL)) + EXTERNAL + struct.pack('<I', 0))
    inp = kv(b'\x00', prev)
    inp += kv(b'\x01', struct.pack('<Q', 200000) + varint(len(spk)) + spk)
    inp += kv(b'\x06' + pub, keypath(FP, *acc, 0, 0))
    return b'psbt\xff' + kv(b'\x00', tx) + b'\x00' + inp + b'\x00' + b'\x00'

# --- Taproot (BIP86 key path), for the rules the corpus has no vector for ---
point_add, N, P = g['point_add'], g['N'], g['P']
TR_ACC = [86 | H, 0 | H, 0 | H]

def tagged(tag, data):
    t = sha256(tag.encode())
    return sha256(t + t + data)

def tr_script(pub33, merkle_root=b''):
    """P2TR of the key tweaked as BIP341: with no merkle root it is the BIP86
    output key, the only one the device signs for"""
    x = int.from_bytes(pub33[1:], 'big')
    y = pow((pow(x, 3, P) + 7) % P, (P + 1) // 4, P)
    if y % 2: y = P - y
    t = int.from_bytes(tagged('TapTweak', pub33[1:] + merkle_root), 'big')
    assert t < N
    return b'\x51\x20' + point_add((x, y), point_mul(t))[0].to_bytes(32, 'big')

def taproot(in_leaves=0, in_root=b'', change_root=b'', sighash=None, key_sig=False, plain_derivation=False):
    """One P2TR input at m/86'/0'/0'/0/0 (200,000 sats), 100,000 out and
    99,000 of change at m/86'/0'/0'/1/0, each with one thing wrong"""
    pub_in = ser_pub(point_mul(derive(seed, TR_ACC + [0, 0])))
    pub_ch = ser_pub(point_mul(derive(seed, TR_ACC + [1, 0])))
    spk_in, spk_ch = tr_script(pub_in, in_root), tr_script(pub_ch, change_root)
    outs = [(EXTERNAL, 100000), (spk_ch, 99000)]
    tx = (struct.pack('<I', 2) + b'\x01' + sha256(b'own taproot') + struct.pack('<I', 0) + b'\x00' +
          struct.pack('<I', 0xfffffffd) + varint(len(outs)) +
          b''.join(struct.pack('<Q', a) + varint(len(s)) + s for s, a in outs) + struct.pack('<I', 0))
    inp = kv(b'\x01', struct.pack('<Q', 200000) + varint(len(spk_in)) + spk_in)
    if sighash is not None: inp += kv(b'\x03', struct.pack('<I', sighash))
    if plain_derivation:
        inp += kv(b'\x06' + pub_in, keypath(FP, *TR_ACC, 0, 0))             # As a segwit v0 wallet would
    else:
        leaves = varint(in_leaves) + b''.join(sha256(b'leaf %d' % i) for i in range(in_leaves))
        inp += kv(b'\x16' + pub_in[1:], leaves + keypath(FP, *TR_ACC, 0, 0))
    if key_sig: inp += kv(b'\x13', bytes(64))
    inp += kv(b'\x17', pub_in[1:])
    if in_root: inp += kv(b'\x18', in_root)
    out = kv(b'\x05', pub_ch[1:]) + kv(b'\x07' + pub_ch[1:], b'\x00' + keypath(FP, *TR_ACC, 1, 0))
    return b'psbt\xff' + kv(b'\x00', tx) + b'\x00' + inp + b'\x00' + b'\x00' + out + b'\x00'

ROOT = sha256(b'a script tree')

VECTORS = {
    # An amount in an OP_RETURN is burned; an empty one is only data
    'OWN-op_return_burn': psbt(200000, [(OP_RETURN, 50000), (EXTERNAL, 149000)]),
    'OWN-op_return_zero': psbt(200000, [(OP_RETURN, 0), (EXTERNAL, 199000)]),
    # 1/4 of what is sent: the limit does not warn, one sat more does
    'OWN-fee_quarter_limit': psbt(1000000, [(EXTERNAL, 100000)], change=875000),
    'OWN-fee_quarter_over': psbt(1000000, [(EXTERNAL, 100000)], change=874999),
    # All back to us: 1/10 of the inputs warns, one sat less does not
    'OWN-fee_tenth_limit': psbt(1000000, [], change=900000),
    'OWN-fee_tenth_under': psbt(1000000, [], change=900001),
    # The input is at index 0: change up to 100 is normal, 101 is flagged
    'OWN-change_index_limit': psbt(1000000, [(EXTERNAL, 500000)], change=499000, change_index=100),
    'OWN-change_index_over': psbt(1000000, [(EXTERNAL, 500000)], change=499000, change_index=101),
    # Legacy input without its previous tx: refused in the legacy mode
    'OWN-legacy_no_prev_tx': legacy_witness_only(),
    # ...nor with a previous tx that has no such output (audit R1)
    'OWN-legacy_prev_tx_bad_vout': legacy_prev_tx_bad_vout(),
    # Taproot: the control signs; a key used in script leaves, an input or a
    # change whose output key commits to a script tree, another sighash type,
    # a signature already there and a derivation of the segwit v0 form do not
    'OWN-taproot_key_path': taproot(),
    'OWN-taproot_leaf_hash': taproot(in_leaves=1),
    'OWN-taproot_input_script_tree': taproot(in_root=ROOT),
    'OWN-taproot_change_script_tree': taproot(change_root=ROOT),
    'OWN-taproot_sighash_none': taproot(sighash=0x02),
    'OWN-taproot_sighash_acp': taproot(sighash=0x81),
    'OWN-taproot_sighash_all': taproot(sighash=0x01),
    'OWN-taproot_key_sig_present': taproot(key_sig=True),
    'OWN-taproot_plain_derivation': taproot(plain_derivation=True),
}

for name, data in VECTORS.items():
    open('malicious/%s.psbt' % name, 'wb').write(data)
print(len(VECTORS), 'vectors written')
