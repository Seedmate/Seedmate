import re, sys, collections
p = sys.argv[1]
lines = open(p, errors='replace').read().splitlines()
start = next(i for i, l in enumerate(lines) if l.startswith('Linker script and memory map'))
per_obj = collections.defaultdict(lambda: collections.defaultdict(int))
per_sec = collections.defaultdict(int)
rows = []
name = None
rx = re.compile(r'^\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(\S.*\.(?:o|a\(.*\)|a))\s*$')
rx1 = re.compile(r'^ (\S+)\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(\S.*)$')
for l in lines[start:]:
    m = rx1.match(l)
    if m:
        sec, addr, size, obj = m.group(1), int(m.group(2), 16), int(m.group(3), 16), m.group(4)
    else:
        m2 = rx.match(l)
        if m2 and name:
            sec, addr, size, obj = name, int(m2.group(1), 16), int(m2.group(2), 16), m2.group(3)
        else:
            s = l.strip()
            name = s if (l.startswith(' ') and s and ' ' not in s) else None
            continue
    name = None
    if size == 0 or not (0x9D000000 <= addr < 0x9D040000):
        continue
    o = obj.replace('\\', '/').split('/')[-1]
    kind = 'text' if sec.startswith('.text') else ('rodata' if sec.startswith('.rodata') else ('data-init' if sec.startswith('.dinit') else sec.split('.')[1] if '.' in sec else sec))
    per_obj[o][kind] += size
    per_sec[kind] += size
    rows.append((size, sec, o))
tot = sum(sum(v.values()) for v in per_obj.values())
print('total in program flash listed: %d' % tot)
print('by kind:', dict(per_sec))
print()
print('%-34s %8s %8s %8s' % ('object', 'text', 'rodata', 'total'))
for o, v in sorted(per_obj.items(), key=lambda kv: -sum(kv[1].values())):
    t = sum(v.values())
    if t < 150: continue
    print('%-34s %8d %8d %8d' % (o[:34], v.get('text', 0), v.get('rodata', 0), t))
if len(sys.argv) > 2:
    print()
    for size, sec, o in sorted(rows, reverse=True)[:int(sys.argv[2])]:
        print('%6d  %-48s %s' % (size, sec[:48], o[:30]))
