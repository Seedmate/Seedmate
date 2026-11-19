"""An implementation of the backup formats written only from SPECIFICATION.md (the
"Build your own" tab of the backup tool page), in another language than the page,
run on seedmate_test_vectors.json: it shows the specification is enough to pass
every vector, as a user's own tool must.

    python check_spec.py [folder build-your-own of the page]
"""
import hashlib
import json
import os
import sys

folder = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), '../../../../HTMLbackup/build-your-own')
V = json.load(open(os.path.join(folder, 'seedmate_test_vectors.json'), encoding='utf-8'))
html = open(os.path.join(folder, '../index.html'), encoding='utf-8').read()
WORDS = json.loads(html.split('var WORDS = ', 1)[1].split(';', 1)[0])
assert hashlib.sha256(('\n'.join(WORDS) + '\n').encode()).hexdigest() == \
    '2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda'

# 1. BIP39 -------------------------------------------------------------------
def bits_of(b):
    return ''.join(format(x, '08b') for x in b)

def bytes_of(bits):
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))

def to_words(e):
    bits = bits_of(e) + bits_of(hashlib.sha256(e).digest())[:len(e) * 8 // 32]
    return ' '.join(WORDS[int(bits[i:i + 11], 2)] for i in range(0, len(bits), 11))

def from_words(text):
    w = text.split()
    assert len(w) in (12, 24)
    bits = ''.join(format(WORDS.index(x), '011b') for x in w)
    n = len(w) * 11 * 32 // 33
    e = bytes_of(bits[:n])
    assert bits[n:] == bits_of(hashlib.sha256(e).digest())[:n // 32], 'checksum'
    return e

# 2. Shamir over GF(2^8), 0x11B ------------------------------------------------
def gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11B
        b >>= 1
    return r

def ginv(a):
    return next(x for x in range(1, 256) if gmul(a, x) == 1)

def split(secret, k, n, coeffs):
    shares = []
    for x in range(1, n + 1):
        y = bytearray()
        for i, s in enumerate(secret):
            v, p = s, 1
            for c in coeffs:
                p = gmul(p, x)
                v ^= gmul(c[i], p)
            y.append(v)
        shares.append(bytes(y))
    return shares

def merge(shares):
    out = bytearray(len(shares[0][1]))
    for i in range(len(out)):
        s = 0
        for j, (xj, yj) in enumerate(shares):
            t = yj[i]
            for m, (xm, _) in enumerate(shares):
                if m != j:
                    t = gmul(t, gmul(xm, ginv(xj ^ xm)))
            s ^= t
        out[i] = s
    return bytes(out)

# 3. Obfuscation ----------------------------------------------------------------
def obfuscate(e, method, item):
    b = bits_of(e)
    L = len(b)
    if method in ('shift_left', 'shift_right'):
        n = item['bits'] % L
        if method == 'shift_right':
            n = (L - n) % L
        r = ''.join(b[(i + n) % L] for i in range(L))
    elif method == 'not':
        r = ''.join('1' if c == '0' else '0' for c in b)
    elif method in ('add', 'sub'):
        v = item['value'] if method == 'add' else -item['value']
        g = L // 11
        r = ''.join(format((int(b[i * 11:i * 11 + 11], 2) + v) % 2048, '011b') for i in range(g)) + b[g * 11:]
    elif method == 'word_xor':
        w = item['word_index']
        r = ''.join(str(int(b[i]) ^ ((w >> (10 - i % 11)) & 1)) for i in range(L))
    elif method == 'byte_swap':
        x = bytearray(e)
        for i in range(0, len(x) - 1, 2):
            x[i], x[i + 1] = x[i + 1], x[i]
        return bytes(x)
    return bytes_of(r)

UNDO = {'shift_left': 'shift_right', 'shift_right': 'shift_left', 'add': 'sub', 'sub': 'add'}

# 5. Cards ------------------------------------------------------------------------
RANKS, SUITS = 'A23456789TJQK', 'CDHS'

def card(name):
    return SUITS.index(name[1]) * 13 + RANKS.index(name[0])

def card_bits(c):
    return format(c, '05b') if c < 32 else format(c - 32, '04b') if c < 48 else format(c - 48, '02b')

def cards_encode(e):
    b, L = bits_of(e), len(e) * 8
    paths = [(0, (0,) * 52, (), 0, 0)]          # offset, usage, sequence, highest, score
    while any(p[0] != L for p in paths):
        new = []
        def insert(p):
            if len(new) < 8 or p[4] < new[-1][4]:
                pos = len(new)
                while pos > 0 and p[4] < new[pos - 1][4]:
                    pos -= 1
                new.insert(pos, p)
                del new[8:]
        for p in paths:
            off, usage, seq, hi, _ = p
            if off == L:
                insert(p)
                continue
            rem = L - off
            for ln in (5, 4, 2):
                if rem >= ln and rem - ln not in (1, 3):
                    v = int(b[off:off + ln], 2)
                    c = v if ln == 5 else 32 + v if ln == 4 else 48 + v
                    u = list(usage)
                    u[c] += 1
                    h = max(hi, u[c])
                    insert((off + ln, tuple(u), seq + (c,), h, h * 256 + len(seq) + 1))
        paths = new
    return paths[0][2], paths[0][3]

def take(bits, words):
    L = 128 if words == 12 else 256
    assert len(bits) >= L
    return bytes_of(bits[:L])

DICE = {'1': '01', '2': '10', '3': '11', '4': '0', '5': '1', '6': '00'}

# ------------------------------------------------------------------------------
fails = checks = 0
def eq(got, want, what):
    global fails, checks
    checks += 1
    if got != want:
        fails += 1
        print('FAIL', what, '\n  got ', got, '\n  want', want)

for v in V['bip39']:
    eq(to_words(bytes.fromhex(v['entropy'])), v['mnemonic'], 'bip39')
    eq(from_words(v['mnemonic']).hex(), v['entropy'], 'bip39 back')
for v in V['coins']:
    eq(to_words(bytes_of(v['tosses'])), v['mnemonic'], 'coins')
for v in V['dice']:
    eq(to_words(take(''.join(DICE[f] for f in v['rolls']), v['words'])), v['mnemonic'], 'dice')
for v in V['dice_hash']:
    t = v['rolls'].replace('6', '0') if v['mode'] == '0-5' else v['rolls']
    eq(to_words(hashlib.sha256(t.encode()).digest()[:16 if v['words'] == 12 else 32]), v['mnemonic'], 'dice hash')
for v in V['poker_cards']:
    eq(to_words(take(''.join(card_bits(card(c)) for c in v['cards'].split()), v['words'])), v['mnemonic'], 'poker')
for v in V['obfuscation']:
    e = from_words(v['mnemonic'])
    r = obfuscate(e, v['method'], v)
    eq(to_words(r), v['result'], 'obfuscation ' + v['method'])
    eq(to_words(obfuscate(r, UNDO.get(v['method'], v['method']), v)), v['mnemonic'], 'undo ' + v['method'])
    if v['method'] == 'word_xor':
        eq(WORDS[v['word_index']], v['word'], 'word of the XOR')
for v in V['xor']:
    es = [from_words(m) for m in v['inputs']]
    eq(to_words(bytes(a for a in [__import__('functools').reduce(lambda x, y: x ^ y, t) for t in zip(*es)])), v['result'], 'xor')
for v in V['shamir']:
    secret = from_words(v['secret'])
    coeffs = [bytes.fromhex(c) for c in v['coefficients_hex']]
    shares = split(secret, v['k'], v['n'], coeffs)
    eq([to_words(s) for s in shares], [s['mnemonic'] for s in v['shares']], 'Shamir split %d of %d' % (v['k'], v['n']))
    given = [(s['id'], from_words(s['mnemonic'])) for s in v['shares']]
    for start in range(v['n'] - v['k'] + 1):
        eq(to_words(merge(given[start:start + v['k']])), v['secret'], 'Shamir merge')
    eq(to_words(merge(given[-v['k']:][::-1])), v['secret'], 'Shamir merge, shares in another order')
for v in V['cards']:
    e = from_words(v['mnemonic'])
    seq, decks = cards_encode(e)
    eq(' '.join(RANKS[c % 13] + SUITS[c // 13] for c in seq), v['cards'], 'card order')
    eq(decks, v['decks'], 'decks')
    eq(to_words(bytes_of(''.join(card_bits(card(c)) for c in v['cards'].split()))), v['mnemonic'], 'cards back')

print('%d checks, %d failed (implementation from the specification)' % (checks, fails))
sys.exit(1 if fails else 0)
