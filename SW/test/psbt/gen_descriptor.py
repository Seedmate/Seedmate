"""Multisig descriptor test data, independent from descriptor.c.

Writes:
  descriptor_vectors.h  - texts and expected keys/scripts for test_descriptor.c
  MSDESC.TXT            - output descriptor file (Sparrow style) for the device
  MSCOLD.TXT            - the same wallet as a Coldcard multisig setup file
  MSWALLET.PSB          - 2-of-3 PSBT whose input and change belong to that wallet
  MSATTACK.PSB          - the same, but the "change" has a foreign key instead of B

Wallet: 2-of-3 P2WSH sortedmulti at m/48'/0'/0'/2'. Cosigner A is the
"abandon x11 about" seed (so the device can sign with it), B and C are test
seeds. Keys come from private derivation with the BIP32 code of
sign_abandon.py; the device derives them from the xpubs (public derivation),
so the test also checks psbt_public_ckd(). The checksum follows the BIP380
reference code.
"""
import hashlib, runpy, struct

g = runpy.run_path('sign_abandon.py')
H, seed_a, master_key, ckd_priv = g['H'], g['seed'], g['master_key'], g['ckd_priv']
point_mul, ser_pub, hash160, sha256 = g['point_mul'], g['ser_pub'], g['hash160'], g['sha256']
b58check, varint, kv, keypath = g['b58check'], g['varint'], g['kv'], g['keypath']

# --- BIP380 checksum (reference code from the BIP) ----------------------------
INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
GENERATOR = [0xf5dee51989, 0xa9fdca3312, 0x1bab10e32d, 0x3706b1677a, 0x644d626ffd]

def descsum_polymod(symbols):
    chk = 1
    for value in symbols:
        top = chk >> 35
        chk = (chk & 0x7ffffffff) << 5 ^ value
        for i in range(5):
            chk ^= GENERATOR[i] if ((top >> i) & 1) else 0
    return chk

def descsum_expand(s):
    groups, symbols = [], []
    for c in s:
        v = INPUT_CHARSET.find(c)
        symbols.append(v & 31)
        groups.append(v >> 5)
        if len(groups) == 3:
            symbols.append(groups[0] * 9 + groups[1] * 3 + groups[2])
            groups = []
    if len(groups) == 1: symbols.append(groups[0])
    elif len(groups) == 2: symbols.append(groups[0] * 3 + groups[1])
    return symbols

def descsum_create(s):
    c = descsum_polymod(descsum_expand(s) + [0] * 8) ^ 1
    return s + '#' + ''.join(CHECKSUM_CHARSET[(c >> (5 * (7 - i))) & 31] for i in range(8))

assert descsum_create('raw(deadbeef)') == 'raw(deadbeef)#89f8spxm'     # BIP380 example

# --- Cosigners -------------------------------------------------------------------
MS = [48 | H, 0 | H, 0 | H, 2 | H]

class Cosigner:
    def __init__(self, seed):
        k, c = master_key(seed)
        self.fp = hash160(ser_pub(point_mul(k)))[:4]
        parent = None
        for idx in MS:
            parent = hash160(ser_pub(point_mul(k)))[:4]
            k, c = ckd_priv(k, c, idx)
        self.k, self.c, self.pub = k, c, ser_pub(point_mul(k))
        payload = bytes.fromhex('0488b21e') + bytes([len(MS)]) + parent + struct.pack('>I', MS[-1]) + c + self.pub
        self.xpub = b58check(payload)
        self.zpub = b58check(bytes.fromhex('02aa7ed3') + payload[4:])
        self.tpub = b58check(bytes.fromhex('043587cf') + payload[4:])

    def child(self, change, index):
        k, c = ckd_priv(self.k, self.c, change)
        k, c = ckd_priv(k, c, index)
        return k, ser_pub(point_mul(k))

A = Cosigner(seed_a)
B = Cosigner(hashlib.sha512(b'seedmate test cosigner B').digest())
C = Cosigner(hashlib.sha512(b'seedmate test cosigner C').digest())
X = Cosigner(hashlib.sha512(b'seedmate test attacker').digest())
cosigners = [A, B, C]

def key_expr(co, xpub=None, suffix='/<0;1>/*'):
    return '[%s/48h/0h/0h/2h]%s%s' % (co.fp.hex(), xpub or co.xpub, suffix)

def descriptor(kind='sortedmulti', m=2, keys=None):
    keys = keys or [key_expr(co) for co in cosigners]
    return descsum_create('wsh(%s(%d,%s))' % (kind, m, ','.join(keys)))

def multisig_script(m, pubs, sort):
    pubs = sorted(pubs) if sort else pubs
    return bytes([0x50 + m]) + b''.join(b'\x21' + p for p in pubs) + bytes([0x50 + len(pubs), 0xAE])

desc_sorted = descriptor()
desc_text = ('# Receive and change descriptor (BIP389):\n' + desc_sorted + '\n\n'
             '# Receive descriptor (Bitcoin Core):\n' +
             descriptor(keys=[key_expr(co, suffix='/0/*') for co in cosigners]) + '\n')
desc_multi = descriptor('multi', 2, [key_expr(co, suffix='/0/*') for co in [C, A, B]])
cold_text = ('# Coldcard Multisig setup file (test)\n#\nName: Seedmate test\nPolicy: 2 of 3\nFormat: P2WSH\n\n' +
             ''.join("Derivation: m/48'/0'/0'/2'\n%s: %s\n\n" % (co.fp.hex().upper(), co.zpub) for co in cosigners))

CHANGE, INDEX = 1, 3
script_sorted = multisig_script(2, [co.child(CHANGE, INDEX)[1] for co in cosigners], True)
script_multi = multisig_script(2, [co.child(CHANGE, INDEX)[1] for co in [C, A, B]], False)

def bad(text):
    return text
neg = [
    (desc_sorted[:-1] + ('q' if desc_sorted[-1] != 'q' else 'p'), 'DESC_ERR_CHECKSUM'),
    (descriptor(keys=[key_expr(co, co.tpub) for co in cosigners]), 'DESC_ERR_NETWORK'),
    (descsum_create('sh(wsh(sortedmulti(2,%s)))' % ','.join(key_expr(co) for co in cosigners)), 'DESC_ERR_SCRIPT'),
    (descsum_create('wpkh(%s)' % key_expr(A)), 'DESC_ERR_SCRIPT'),
    (descriptor(m=4), 'DESC_ERR_THRESHOLD'),
    (descriptor(m=0), 'DESC_ERR_THRESHOLD'),
    (descriptor(keys=[key_expr(A), key_expr(B), key_expr(A)]), 'DESC_ERR_DUPLICATE'),
    (descriptor(keys=[key_expr(co, suffix='/2/*') for co in cosigners]), 'DESC_ERR_PATH'),
    (descriptor(keys=[key_expr(co, co.xpub[:-1] + ('1' if co.xpub[-1] != '1' else '2')) for co in cosigners]), 'DESC_ERR_KEY'),
    (descriptor(m=2, keys=[key_expr(co) for co in [A, B, C, X, A, B, C, X]]), 'DESC_ERR_TOO_MANY'),
    (cold_text.replace('Format: P2WSH\n', ''), 'DESC_ERR_SCRIPT'),
    (cold_text.replace('Policy: 2 of 3', 'Policy: 2 of 4'), 'DESC_ERR_THRESHOLD'),
    ('hello world\n', 'DESC_ERR_FORMAT'),
    ('raw(deadbeef)#89f8spxm', 'DESC_ERR_SCRIPT'),       # Valid BIP380 checksum, not multisig
    ('raw(deadbeef)#89f8spxx', 'DESC_ERR_CHECKSUM'),
]

# --- PSBTs for the device ---------------------------------------------------------
EXTERNAL = bytes.fromhex('0014751e76e8199196d454941c45d1b3a323f1433bd6')
p2wsh = lambda ws: b'\x00\x20' + sha256(ws)
ws_in = multisig_script(2, [co.child(0, 0)[1] for co in cosigners], True)

def ms_psbt(change_cosigners):
    ws_change = multisig_script(2, [co.child(CHANGE, INDEX)[1] for co in change_cosigners], True)
    tx = (struct.pack('<I', 2) + b'\x01' + sha256(b'ms wallet') + struct.pack('<I', 0) + b'\x00' +
          struct.pack('<I', 0xfffffffd) + b'\x02' +
          struct.pack('<Q', 50000) + varint(len(EXTERNAL)) + EXTERNAL +
          struct.pack('<Q', 49000) + varint(34) + p2wsh(ws_change) + struct.pack('<I', 0))
    inp = kv(b'\x01', struct.pack('<Q', 100000) + varint(34) + p2wsh(ws_in)) + kv(b'\x05', ws_in)
    for co in cosigners:
        inp += kv(b'\x06' + co.child(0, 0)[1], keypath(co.fp, *MS, 0, 0))
    out = kv(b'\x01', ws_change)
    # The attacker keeps B's fingerprint and path, so only the key differs
    for co, real in zip(change_cosigners, cosigners):
        out += kv(b'\x02' + co.child(CHANGE, INDEX)[1], keypath(real.fp, *MS, CHANGE, INDEX))
    return b'psbt\xff' + kv(b'\x00', tx) + b'\x00' + inp + b'\x00' + b'\x00' + out + b'\x00'

open('MSWALLET.PSB', 'wb').write(ms_psbt([A, B, C]))
open('MSATTACK.PSB', 'wb').write(ms_psbt([A, X, C]))
open('MSDESC.TXT', 'w', newline='\n').write(desc_text)
open('MSCOLD.TXT', 'w', newline='\n').write(cold_text)

# --- C header -----------------------------------------------------------------------
def c_str(s):
    return '"' + s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n') + '"'

def arr(data):
    return '{' + ', '.join('0x%02x' % b for b in data) + '}'

with open('descriptor_vectors.h', 'w', newline='\r\n') as f:
    f.write('// Generated by gen_descriptor.py - public test data only\n')
    f.write('#include <stdint.h>\n\n')
    f.write('static const char desc_text[] = %s;\n' % c_str(desc_text))
    f.write('static const char desc_multi[] = %s;\n' % c_str(desc_multi))
    f.write('static const char cold_text[] = %s;\n\n' % c_str(cold_text))
    f.write('// Keys in descriptor order (A, B, C); desc_multi lists C, A, B\n')
    f.write('static const uint8_t vec_fp[3][4] = {%s};\n' % ', '.join(arr(co.fp) for co in cosigners))
    f.write('static const uint8_t vec_chain[3][32] = {%s};\n' % ', '.join(arr(co.c) for co in cosigners))
    f.write('static const uint8_t vec_pub[3][33] = {%s};\n\n' % ', '.join(arr(co.pub) for co in cosigners))
    f.write('#define VEC_CHANGE %d\n#define VEC_INDEX %d\n' % (CHANGE, INDEX))
    f.write('static const uint8_t vec_script_sorted[%d] = %s;\n' % (len(script_sorted), arr(script_sorted)))
    f.write('static const uint8_t vec_script_multi[%d] = %s;\n\n' % (len(script_multi), arr(script_multi)))
    f.write('typedef struct { const char *text; desc_result_t expected; } desc_neg_t;\n')
    f.write('static const desc_neg_t desc_neg[] = {\n')
    for text, err in neg:
        f.write('    {%s, %s},\n' % (c_str(text), err))
    f.write('};\n')

print('descriptor', desc_sorted)
print('fingerprints', ' '.join(co.fp.hex() for co in cosigners))
