"""Packs a word list in the format of src/wordpack.h."""
import os

BLOCK = 128

def code(ch):
    return 27 if ch == '-' else ord(ch) - ord('a') + 1

def pack(words):
    """Returns (bytes with a spare last byte, list of restart bit offsets)."""
    bits, restart, prev = [], [], ''
    def put(value, n):
        bits.extend((value >> (n - 1 - i)) & 1 for i in range(n))
    for i, w in enumerate(words):
        if i % BLOCK == 0:
            restart.append(len(bits))
            shared = 0
        else:
            shared = min(3, len(os.path.commonprefix([prev, w])))
        put(shared, 2)
        for ch in w[shared:]:
            put(code(ch), 5)
        put(0, 5)
        prev = w
    assert len(bits) < 65536, 'restart offsets are 16 bits'
    bits += [0] * (-len(bits) % 8)
    data = bytes(int(''.join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8))
    return data + b'\x00', restart

def c_tables(name, data, restart):
    """C source of the two tables, named <name>_bits and <name>_restart."""
    out = ['static const uint8_t %s_bits[%d] = {' % (name, len(data))]
    for i in range(0, len(data), 20):
        out.append('    ' + ','.join(str(b) for b in data[i:i + 20]) + ',')
    out.append('};')
    out.append('static const uint16_t %s_restart[%d] = {' % (name, len(restart)))
    for i in range(0, len(restart), 12):
        out.append('    ' + ','.join(str(b) for b in restart[i:i + 12]) + ',')
    out.append('};')
    return '\n'.join(out) + '\n'
