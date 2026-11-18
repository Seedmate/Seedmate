"""Testnet (coin type 1') test data for the "abandon x11 about" seed.

Independent from the firmware: BIP32 and secp256k1 are the Python of
sign_abandon.py, bech32 / bech32m and the BIP380 checksum are the reference
code of the BIPs. Writes:
  abandon testnet.psbt - unsigned PSBT for the device in TESTNET, NATIVE SEGWIT:
                         one input at m/84'/1'/0'/0/0 with its previous
                         transaction, a send to an external tb1q address and
                         change at m/84'/1'/0'/1/0
  MSTDESC.TXT          - a testnet 2-of-3 wsh(sortedmulti()) wallet: this seed at
                         m/48'/1'/0'/2' and the cosigners B and C of
                         gen_descriptor.py at the same path, tpub keys
  MSTNDESC.TXT         - the same cosigners as a nested sh(wsh()) wallet at m/48'/1'/0'/1'
  MSTCOLD.TXT, MSTNCOLD.TXT - both wallets as Coldcard setup files (Vpub, Upub)
  testnet_vectors.h    - that wallet and its receive / change addresses 0 and 1,
                         for the firmware's ms_wallet_address() in test_malicious.c
Prints what the device must show in TESTNET (addresses 0 of every script type,
the account keys, the multisig receive address 0) for the validation page.
"""
import contextlib, hashlib, io, runpy, struct, base64

with contextlib.redirect_stdout(io.StringIO()):
    g = runpy.run_path('sign_abandon.py')
H, seed, master_key, ckd_priv, derive = g['H'], g['seed'], g['master_key'], g['ckd_priv'], g['derive']
point_mul, point_add, ser_pub, hash160, sha256 = g['point_mul'], g['point_add'], g['ser_pub'], g['hash160'], g['sha256']
b58check, varint, kv, keypath, dsha, N, P = g['b58check'], g['varint'], g['kv'], g['keypath'], g['dsha'], g['N'], g['P']

# --- bech32 / bech32m (BIP173, BIP350 reference code) ----------------------------
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

def segwit_address(hrp, version, program):
    data, acc, bits = [version], 0, 0
    for b in program:
        acc = (acc << 8) | b
        bits += 8
        while bits >= 5:
            bits -= 5
            data.append((acc >> bits) & 31)
    if bits: data.append((acc << (5 - bits)) & 31)
    const = 0x2bc830a3 if version else 1
    values = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp] + data
    pm = bech32_polymod(values + [0] * 6) ^ const
    return hrp + '1' + ''.join(CHARSET[d] for d in data + [(pm >> 5 * (5 - i)) & 31 for i in range(6)])

assert segwit_address('bc', 0, bytes.fromhex('751e76e8199196d454941c45d1b3a323f1433bd6')) == \
    'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'                                   # BIP173 example

# --- BIP380 checksum (reference code from the BIP) --------------------------------
INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
GENERATOR = [0xf5dee51989, 0xa9fdca3312, 0x1bab10e32d, 0x3706b1677a, 0x644d626ffd]

def descsum_create(s):
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
    chk = 1
    for value in symbols + [0] * 8:
        top = chk >> 35
        chk = (chk & 0x7ffffffff) << 5 ^ value
        for i in range(5):
            chk ^= GENERATOR[i] if ((top >> i) & 1) else 0
    chk ^= 1
    return s + '#' + ''.join(CHARSET[(chk >> (5 * (7 - i))) & 31] for i in range(8))

assert descsum_create('raw(deadbeef)') == 'raw(deadbeef)#89f8spxm'                 # BIP380 example

# --- Keys -------------------------------------------------------------------------
def account(seed_bytes, path):
    """(master fingerprint, parent fingerprint, chain code, public key) of path"""
    k, c = master_key(seed_bytes)
    master_fp = hash160(ser_pub(point_mul(k)))[:4]
    parent = master_fp
    for idx in path:
        parent = hash160(ser_pub(point_mul(k)))[:4]
        k, c = ckd_priv(k, c, idx)
    return master_fp, parent, c, ser_pub(point_mul(k))

def ext_key(version, path, acc):
    _, parent, c, pub = acc
    return b58check(struct.pack('>I', version) + bytes([len(path)]) + parent + struct.pack('>I', path[-1]) + c + pub)

TPUB, UPUB, VPUB = 0x043587CF, 0x044A5262, 0x045F1CF6

def tagged(tag, data):
    t = sha256(tag.encode())
    return sha256(t + t + data)

def bip86_output_key(pub33):
    x = int.from_bytes(pub33[1:], 'big')
    y = pow((pow(x, 3, P) + 7) % P, (P + 1) // 4, P)
    if y % 2: y = P - y
    t = int.from_bytes(tagged('TapTweak', pub33[1:]), 'big')
    return point_add((x, y), point_mul(t))[0].to_bytes(32, 'big')

def pub_at(path):
    return ser_pub(point_mul(derive(seed, path)))

FP = account(seed, [])[0]
assert FP.hex() == '73c5da0a'

# Address 0 of every script type, as the device shows it in TESTNET
shown = {}
for name, purpose in (('LEGACY', 44), ('NESTED SEGWIT', 49), ('NATIVE SEGWIT', 84), ('TAPROOT', 86)):
    acc_path = [purpose | H, 1 | H, 0 | H]
    pub = pub_at(acc_path + [0, 0])
    if purpose == 44:
        addr = b58check(b'\x6f' + hash160(pub))
    elif purpose == 49:
        addr = b58check(b'\xc4' + hash160(b'\x00\x14' + hash160(pub)))
    elif purpose == 84:
        addr = segwit_address('tb', 0, hash160(pub))
    else:
        addr = segwit_address('tb', 1, bip86_output_key(pub))
    acc = account(seed, acc_path)
    keys = [ext_key(TPUB, acc_path, acc)]
    if purpose == 49: keys.append(ext_key(UPUB, acc_path, acc))
    if purpose == 84: keys.append(ext_key(VPUB, acc_path, acc))
    shown[name] = (addr, keys)

# Published values of this seed on testnet (BIP84 / BIP86 test wallets, iancoleman)
assert shown['NATIVE SEGWIT'][0] == 'tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl', shown['NATIVE SEGWIT'][0]

# --- abandon testnet.psbt ---------------------------------------------------------
ACC = [84 | H, 1 | H, 0 | H]
pub_in, pub_change = pub_at(ACC + [0, 0]), pub_at(ACC + [1, 0])
spk_in, spk_change = b'\x00\x14' + hash160(pub_in), b'\x00\x14' + hash160(pub_change)
AMOUNT = 300000
prev_tx = (struct.pack('<I', 2) + b'\x01' + sha256(b'testnet prev') + struct.pack('<I', 0) + b'\x00' +
           struct.pack('<I', 0xffffffff) + b'\x01' +
           struct.pack('<Q', AMOUNT) + varint(len(spk_in)) + spk_in + struct.pack('<I', 0))
EXTERNAL = b'\x00\x14' + hash160(b'seedmate testnet external')
SEND, CHANGE = 120000, 178500                                                   # Fee 1,500 sats
tx = (struct.pack('<I', 2) + b'\x01' + dsha(prev_tx) + struct.pack('<I', 0) + b'\x00' +
      struct.pack('<I', 0xfffffffd) + b'\x02' +
      struct.pack('<Q', SEND) + varint(len(EXTERNAL)) + EXTERNAL +
      struct.pack('<Q', CHANGE) + varint(len(spk_change)) + spk_change + struct.pack('<I', 0))
in0 = (kv(b'\x00', prev_tx) +
       kv(b'\x01', struct.pack('<Q', AMOUNT) + varint(len(spk_in)) + spk_in) +
       kv(b'\x06' + pub_in, keypath(FP, *ACC, 0, 0)))
out_change = kv(b'\x02' + pub_change, keypath(FP, *ACC, 1, 0))
psbt = b'psbt\xff' + kv(b'\x00', tx) + b'\x00' + in0 + b'\x00' + b'\x00' + out_change + b'\x00'
open('abandon testnet.psbt', 'wb').write(psbt)

# --- MSTDESC.TXT ------------------------------------------------------------------
MS = [48 | H, 1 | H, 0 | H, 2 | H]
cosigner_seeds = [seed, hashlib.sha512(b'seedmate test cosigner B').digest(),
                  hashlib.sha512(b'seedmate test cosigner C').digest()]
keys = []
for s in cosigner_seeds:
    acc = account(s, MS)
    keys.append((acc, '[%s/48h/1h/0h/2h]%s/<0;1>/*' % (acc[0].hex(), ext_key(TPUB, MS, acc))))
desc = descsum_create('wsh(sortedmulti(2,%s))' % ','.join(k[1] for k in keys))
open('MSTDESC.TXT', 'w', newline='\n').write('# Testnet 2-of-3 test wallet (Seedmate gen_testnet.py)\n' + desc + '\n')

# The same cosigners as a nested (P2SH-P2WSH, m/48'/1'/0'/1') wallet, and both
# wallets as Coldcard multisig setup files (Vpub / Upub keys)
UPUB_MS, VPUB_MS = 0x024289EF, 0x02575483
MSN = [48 | H, 1 | H, 0 | H, 1 | H]
nkeys = [(account(s, MSN)) for s in cosigner_seeds]
ndesc = descsum_create('sh(wsh(sortedmulti(2,%s)))' % ','.join(
    '[%s/48h/1h/0h/1h]%s/<0;1>/*' % (a[0].hex(), ext_key(TPUB, MSN, a)) for a in nkeys))
open('MSTNDESC.TXT', 'w', newline='\n').write('# Testnet 2-of-3 nested segwit test wallet (Seedmate gen_testnet.py)\n' + ndesc + '\n')

def coldcard(name, fmt, deriv, version, path, accs):
    text = '# Coldcard Multisig setup file (testnet test)\n#\nName: %s\nPolicy: 2 of 3\nFormat: %s\n\n' % (name, fmt)
    for a in accs:
        text += 'Derivation: %s\n%s: %s\n\n' % (deriv, a[0].hex().upper(), ext_key(version, path, a))
    return text

open('MSTCOLD.TXT', 'w', newline='\n').write(
    coldcard('Seedmate testnet', 'P2WSH', "m/48'/1'/0'/2'", VPUB_MS, MS, [k[0] for k in keys]))
open('MSTNCOLD.TXT', 'w', newline='\n').write(
    coldcard('Seedmate testnet nested', 'P2SH-P2WSH', "m/48'/1'/0'/1'", UPUB_MS, MSN, nkeys))

def msn_address(change, index):
    pubs = [ser_pub(point_mul(derive(s, MSN + [change, index]))) for s in cosigner_seeds]
    ws = bytes([0x52]) + b''.join(b'\x21' + p for p in sorted(pubs)) + bytes([0x53, 0xAE])
    return b58check(b'\xc4' + hash160(b'\x00\x20' + sha256(ws)))

def ms_address(change, index):
    pubs = [ser_pub(point_mul(derive(s, MS + [change, index]))) for s in cosigner_seeds]
    ws = bytes([0x52]) + b''.join(b'\x21' + p for p in sorted(pubs)) + bytes([0x53, 0xAE])
    return segwit_address('tb', 0, sha256(ws))

ms_addr0 = ms_address(0, 0)
with open('testnet_vectors.h', 'w', newline='\r\n') as f:
    f.write('// Generated by test/psbt/gen_testnet.py - test data only (public keys).\n')
    f.write('// The testnet 2-of-3 wallet of MSTDESC.TXT and its addresses, for test_malicious.c\n')
    f.write('static const char mst_desc[] = "%s";\n' % desc)
    f.write('static const char *const mst_addr[2][2] = {\n')
    for ch in (0, 1):
        f.write('    {"%s", "%s"},\n' % (ms_address(ch, 0), ms_address(ch, 1)))
    f.write('};\n')

print('TESTNET values of "abandon x11 about" (fingerprint %s)' % FP.hex())
for name, (addr, ks) in shown.items():
    print('%-14s receive 0  %s' % (name, addr))
    for k in ks:
        print('%-14s key        %s' % ('', k))
print('MULTISIG       2 of 3 receive 0  %s' % ms_addr0)
print('MULTISIG SH    2 of 3 receive 0  %s' % msn_address(0, 0))
print('fingerprints   %s' % ' '.join(k[0][0].hex() for k in keys))
print('wrote abandon testnet.psbt (%d bytes), MSTDESC.TXT, MSTNDESC.TXT, MSTCOLD.TXT and MSTNCOLD.TXT' % len(psbt))
print('base64 ', base64.b64encode(psbt).decode())
