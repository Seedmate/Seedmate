"""Checks the ui_hash() formatting of src/main.c against Python (host harness)."""
import hashlib, os, subprocess

os.chdir(os.path.dirname(os.path.abspath(__file__)))
NL = chr(92) + 'n'          # the two characters backslash + n, for the C source
src = open('../src/main.c', encoding='latin-1').read()
fn = src[src.index('static void ui_hash('):src.index('// A complete record')]
code = ('#include <stdio.h>\n#include <stdint.h>\n'
        'static void ui_text(int y, const char *t, uint16_t c) { (void)c; printf("%d|%s' + NL + '", y, t); }\n'
        + fn +
        'int main(int argc, char **argv) {\n    uint8_t h[32]; (void)argc;\n'
        '    for (int i = 0; i < 32; i++) { unsigned v; sscanf(argv[1] + 2 * i, "%2x", &v); h[i] = (uint8_t)v; }\n'
        '    ui_hash(40, h, 0);\n    return 0;\n}\n')
open('hash_fmt.c', 'w').write(code)
subprocess.check_call(['gcc', '-std=c99', '-Wall', '-O1', 'hash_fmt.c', '-o', 'hash_fmt.exe'])
d = hashlib.sha256(b'seedmate').hexdigest()
out = subprocess.check_output(['./hash_fmt.exe', d]).decode().replace('\r', '').split('\n')[:4]
want = ['%d|%s %s' % (40 + 10 * l, d[l * 16:l * 16 + 8].upper(), d[l * 16 + 8:l * 16 + 16].upper()) for l in range(4)]
os.remove('hash_fmt.c')
os.remove('hash_fmt.exe')
print('ui_hash format ok' if out == want else 'MISMATCH %r %r' % (out, want))
