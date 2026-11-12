# Builds the firmware in a scratch folder with other compiler options and
# prints the flash and RAM totals. Never touches the project's build folders.
#
# Usage, from BIP39_MCC.X (see docs/flash-savings.md):
#   make -n -B -f nbproject/Makefile-v2.mk SUBPROJECTS= .build-conf | grep xc32-gcc > cmds.txt
#   python ../test/size/flagtest.py cmds.txt base "-O1|-mmemcpy -G 1024"
# A variant is a name of the table below, "opt|flags", or "opt|flags|flags of
# the speed critical files". Output goes to the system temp folder.
import os, re, subprocess, sys, shutil, tempfile
from concurrent.futures import ThreadPoolExecutor

PROJ = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'BIP39_MCC.X'))
SCR = os.path.join(tempfile.gettempdir(), 'seedmate_flagtest')
cmds = [l.strip() for l in open(sys.argv[1], errors='replace') if 'xc32-gcc' in l]

def run(tag, opt, extra, per_file=None, link_extra=''):
    out = os.path.join(SCR, tag)
    shutil.rmtree(out, ignore_errors=True)
    built = []
    for c in cmds:
        c = c.replace('build/v2/production', out.replace('\\', '/') + '/build').replace('dist/v2/production', out.replace('\\', '/') + '/dist')
        c = c.replace('-Werror ', '')
        if ' -c ' in c:
            c = c.replace(' -O1 ', ' %s %s ' % (opt, extra))
            if per_file:
                for pat, fl in per_file.items():
                    if pat in c.split(' -o ')[1]:
                        c = c.replace(' %s %s ' % (opt, extra), ' %s ' % fl)
        else:
            c = c.replace(' -o ', ' %s %s %s -o ' % (opt if 'lto' in extra else '', extra if 'lto' in extra or '-G' in extra else '', link_extra), 1)
        for m in re.findall(r'-o (\S+)|-MF "([^"]+)"|-Map="([^"]+)"|--memorysummary,(\S+)', c):
            for p in m:
                if p:
                    os.makedirs(os.path.dirname(p.rstrip(',')), exist_ok=True)
        built.append(c)
    comp = [c for c in built if ' -c ' in c]
    link = [c for c in built if ' -c ' not in c]
    def one(c):
        r = subprocess.run(c, cwd=PROJ, capture_output=True, text=True)
        return r.returncode, (r.stdout + r.stderr).strip()
    with ThreadPoolExecutor(8) as ex:
        res = list(ex.map(one, comp))
    bad = [o for rc, o in res if rc != 0]
    notes = set()
    for rc, o in res:
        for l in o.splitlines():
            if 'license' in l.lower() or 'not supported' in l.lower() or 'unrecognized' in l.lower():
                notes.add(l.strip()[:150])
    if bad:
        print('%-28s COMPILE FAILED: %s' % (tag, bad[0][:300].replace('\n', ' | ')))
        return
    for c in link:
        rc, o = one(c)
        if rc != 0:
            print('%-28s LINK FAILED: %s' % (tag, o[-400:].replace('\n', ' | ')))
            return
    mp = open(os.path.join(out, 'dist', 'BIP39_MCC.X.production.map'), errors='replace').read()
    fl = int(re.search(r'Total kseg0_program_mem used\s*:\s*\S+\s+(\d+)', mp).group(1))
    ram = int(re.search(r'Total Data Memory used\s*:\s*\S+\s+(\d+)', mp).group(1))
    print('%-28s flash %7d  ram %6d  %s' % (tag, fl, ram, ' ; '.join(sorted(notes))[:300]))
    sys.stdout.flush()
    return fl

# Kept with the project options in the per-file variants: cryptography and
# anything that runs for long (hashes, PBKDF2, curve, AES, UR decoding, QR
# encoding, FAT, display and SPI drivers)
HOT_FILES = ('sha256.o', 'sha512.o', 'kdf.o', 'kef.o', 'bignum.o', 'ecdsa.o', 'secp256k1.o', 'bip32.o',
             'ripemd160.o', 'aescrypt.o', 'aeskey.o', 'aestab.o', 'aesgcm.o', 'gf128mul.o', 'consteq.o',
             'psbt_sign.o', 'bip85.o', 'vault.o', 'shamir.o', 'memzero.o', 'segwit_addr.o', 'fountain.o',
             'sampler.o', 'prng.o', 'bytewords.o', 'qrcode.o', 'ff.o', 'ffunicode.o', 'sd_files.o', 'TFT.o',
             'SPI.o', 'plib_spi1_master.o', 'plib_spi3_master.o', 'plib_uart2.o', 'interrupts.o')

variants = {
    'base':        ('-O1', ''),
    'Os':          ('-Os', ''),
    'O2':          ('-O2', ''),
    'G64':         ('-O1', '-G 64'),
    'G1024':       ('-O1', '-G 1024'),
    'G16384':      ('-O1', '-G 16384'),
    'memcpy':      ('-O1', '-mmemcpy'),
    'nozerodiv':   ('-O1', '-mno-check-zero-division'),
    'o2passes':    ('-O1', '-fcrossjumping -foptimize-sibling-calls -fipa-icf -fcode-hoisting -ftree-tail-merge -freorder-blocks-algorithm=simple'),
    'nocalledonce':('-O1', '-fno-inline-functions-called-once'),
    'nojumptab':   ('-O1', '-fno-jump-tables'),
    'mergeconst':  ('-O1', '-fmerge-all-constants'),
    'lto':         ('-O1', '-flto'),
}
want = sys.argv[2:] or list(variants)
for t in want:
    if t in variants:
        run(t, *variants[t])
    else:
        parts = t.split('|')
        opt, extra = parts[0], parts[1]
        hot = None
        if len(parts) > 2:      # Speed critical files keep their own flags
            hot = {n: parts[2] for n in HOT_FILES}
        run('V%d' % want.index(t), opt, extra, hot)
