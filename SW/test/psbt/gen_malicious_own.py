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
}

for name, data in VECTORS.items():
    open('malicious/%s.psbt' % name, 'wb').write(data)
print(len(VECTORS), 'vectors written')
