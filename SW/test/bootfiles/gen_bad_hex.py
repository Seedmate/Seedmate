#!/usr/bin/env python3
"""Bad UPDATE.HEX files for the bootloader device tests BOOT-06 and BOOT-17.

Each file is made from a real app HEX (by default the test signature of index
1 in signatures/, which is in git, so the files are the same on any computer)
and goes to the SD card as UPDATE.HEX. What the bootloader must answer is in
EXPECTED below; check_pass1.c runs the bootloader's own pass 1 checks over
every file and compares.

    python gen_bad_hex.py [app.hex]      writes out/*.hex
"""
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.join(HERE, "..", "..", "signatures", "001_2026-11-17_v2.0-beta17112026_test", "UPDATE.HEX")
OUT = os.path.join(HERE, "out")

APP_BASE, APP_RESET, APP_END = 0x1D003000, 0x1D003800, 0x1D03F800

# File -> what pass 1 of the bootloader answers: 0 (accepted: it goes on to the
# signature), 5 "FILE DAMAGED", 9 "HEX NOT FOR THIS DEVICE"
EXPECTED = {
    "BOOT06_truncated.hex": 5,          # Cut in the middle: no end record
    "BOOT06_bad_checksum.hex": 5,       # One record with a wrong checksum
    "BOOT06_short_record.hex": 5,       # One record shorter than its length says
    "BOOT06_not_a_hex.hex": 5,          # A text file: no record, no end
    "BOOT06_bootloader_area.hex": 9,    # Data at 0x1D000000: an old 64 KB Seedmate, or a bootloader
    "BOOT06_config_words.hex": 9,       # Data in the boot flash / configuration words
    "BOOT06_settings_page.hex": 9,      # Data in the settings page, the last 2 KB
    "BOOT06_past_the_end.hex": 9,       # Data past the program flash of this chip
    "BOOT06_no_reset_block.hex": 9,     # The app without its reset block: another flash layout
    "BOOT17_junk_app.hex": 0,           # Valid addresses and reset block, random code: installs as unofficial
    # Accepted by pass 1 before the fixes of 2026-11-18 (audit P2, B5)
    "BOOT06_too_big.hex": 5,            # The app followed by text up to 1.1 MB: over the 1 MB limit
    "BOOT06_long_line.hex": 5,          # A valid record of 96 bytes, 203 characters: was skipped
    "BOOT06_address_length.hex": 5,     # An extended address record of 4 bytes: failed only after the erase
    "BOOT06_bad_digit.hex": 5,          # 'Q' for 'a' in one record: was read as the same digit
}


def record(rtype, addr, data):
    body = bytes([len(data), (addr >> 8) & 0xFF, addr & 0xFF, rtype]) + bytes(data)
    return ":" + (body + bytes([(-sum(body)) & 0xFF])).hex().upper()


def ext_lin(upper):
    return record(4, 0, [(upper >> 8) & 0xFF, upper & 0xFF])


END = record(1, 0, b"")


def data_records(phys, data):
    """Records for data at a physical address, 16 bytes each, with their extended address"""
    lines, upper = [], None
    for ofs in range(0, len(data), 16):
        a = phys + ofs
        if a >> 16 != upper:
            upper = a >> 16
            lines.append(ext_lin(upper))
        lines.append(record(0, a & 0xFFFF, data[ofs:ofs + 16]))
    return lines


def parse(lines):
    """(line, physical address of its first byte or None, length) for every record"""
    out, upper = [], 0
    for ln in lines:
        b = bytes.fromhex(ln[1:])
        if b[3] == 4:
            upper = (b[4] << 8) | b[5]
        phys = ((upper << 16) + ((b[1] << 8) | b[2])) & 0x1FFFFFFF if b[3] == 0 else None
        out.append((ln, phys, b[0]))
    return out


def with_extra(lines, phys, data):
    """The app with data added before its end record"""
    return lines[:-1] + data_records(phys, data) + [ext_lin(0), lines[-1]]


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else BASE
    with open(src) as f:
        app = [ln.strip() for ln in f if ln.startswith(":")]
    assert app[-1] == END, "the app HEX must end with its end record"
    recs = parse(app)
    os.makedirs(OUT, exist_ok=True)
    files = {}

    files["BOOT06_truncated.hex"] = app[:len(app) // 2]

    i = next(k for k, (_, p, n) in enumerate(recs) if p is not None and n > 0 and k > len(app) // 3)
    bad = bytearray(bytes.fromhex(app[i][1:]))
    bad[-1] ^= 0x01
    files["BOOT06_bad_checksum.hex"] = app[:i] + [":" + bad.hex().upper()] + app[i + 1:]
    files["BOOT06_short_record.hex"] = app[:i] + [app[i][:-6]] + app[i + 1:]

    files["BOOT06_not_a_hex.hex"] = ["THIS IS NOT AN INTEL HEX FILE", "SEEDMATE BOOTLOADER TEST"]

    code = bytes(range(16))
    files["BOOT06_bootloader_area.hex"] = with_extra(app, 0x1D000000, code)
    files["BOOT06_config_words.hex"] = with_extra(app, 0x1FC017C0, code)
    files["BOOT06_settings_page.hex"] = with_extra(app, APP_END, code)
    files["BOOT06_past_the_end.hex"] = with_extra(app, 0x1D040000, code)

    # Every record touching the reset block double-word left out
    files["BOOT06_no_reset_block.hex"] = [ln for ln, p, n in recs
                                          if p is None or p + n <= APP_RESET or p >= APP_RESET + 8]

    # 4 KB of random bytes from the reset block, nothing else: passes every
    # check of pass 1, so only the signature tells (UNOFFICIAL FIRMWARE). Fixed
    # seed: the same file every time.
    rng = random.Random(0x5EED)
    junk = bytes(rng.randrange(256) for _ in range(4096))
    files["BOOT17_junk_app.hex"] = data_records(APP_RESET, junk) + [ext_lin(0), END]

    # Text after the end record up to 1.1 MB: pass 1 ignored it, the size limit refuses it
    pad = ["; SEEDMATE BOOTLOADER TEST: THIS FILE IS OVER 1 MB " + "-" * 46] * 1
    size = sum(len(ln) + 2 for ln in app)
    pad *= (1100000 - size) // (len(pad[0]) + 2) + 1
    files["BOOT06_too_big.hex"] = app + pad

    # One record of 96 bytes (erased flash, 0xFF) in the app area: valid, but longer than the bootloader reads
    files["BOOT06_long_line.hex"] = app[:-1] + [ext_lin(APP_END >> 16), record(0, (APP_END - 0x800) & 0xFFFF, b"\xff" * 96),
                                                ext_lin(0), app[-1]]

    # The first extended address record with two more bytes (its value unchanged)
    k = next(n for n, ln in enumerate(app) if ln[7:9] == "04")
    b4 = bytes.fromhex(app[k][1:])
    files["BOOT06_address_length.hex"] = app[:k] + [record(4, 0, b4[4:6] + b"\x00\x00")] + app[k + 1:]

    # 'Q' for the first 'a' in the data of a record: the old conversion read both as ten
    k = next(n for n, (ln, p, cnt) in enumerate(recs) if p is not None and "a" in ln[9:-2] and n > len(app) // 3)
    j = app[k].index("a", 9)
    files["BOOT06_bad_digit.hex"] = app[:k] + [app[k][:j] + "Q" + app[k][j + 1:]] + app[k + 1:]

    assert set(files) == set(EXPECTED)
    for name, lines in files.items():
        with open(os.path.join(OUT, name), "w", newline="\r\n") as f:
            f.write("\n".join(lines) + "\n")
        print("%-28s %6d records  expected pass 1: %d" % (name, len(lines), EXPECTED[name]))
    with open(os.path.join(OUT, "expected.txt"), "w") as f:
        for name in sorted(EXPECTED):
            f.write("%d %s\n" % (EXPECTED[name], name))


if __name__ == "__main__":
    main()
