# Seedmate firmware - where the flash goes and how to save it (2026-11-10)

Working document. Measured on the build of 2026-11-08 (226,942 B of 243,712,
93.1%, 16.4 KB free). Nothing was changed in the firmware: every figure
marked "measured" comes from a real build in a scratch folder, the others are
estimates from the disassembly and need a build to confirm.

Tools, in `test/size/`:
- `mapsize.py <map> [n]`: flash per object file, and the n largest sections.
- `flagtest.py cmds.txt <variants>`: builds the firmware with other compiler
  options in the temp folder and prints flash and RAM. Its "base" variant gives
  226,942 B, the same as the project build.

## 1. Where the flash goes

| Part | Bytes | Share |
|---|---|---|
| Code (`.text`) | 195,556 | 86% |
| Constants (`.rodata`) | 29,970 | 13% |
| Data init table, vectors, reset | 2,576 | 1% |

Constants: the text strings 14,140 B (971 different texts, already merged by
the linker; the map lists them under `bip32.o` because that is the first
object that has one), BIP39 list 5,718, EFF list 2,984, SHA-512 constants 640,
QR tables 560, Bytewords 512, GCM table 512, font 475.

Per object file (code + constants):

| Object | Bytes | | Object | Bytes |
|---|---|---|---|---|
| `main.o` | 108,881 | | `psbt_sign.o` | 3,457 |
| `screens.o` | 15,035 | | `aesgcm.o` + `gf128mul.o` + AES | 6,492 |
| Text strings (all files) | 14,140 | | `vault.o` | 2,928 |
| `ff.o` + `ffunicode.o` | 10,359 | | `bignum.o` | 2,788 |
| `descriptor.o` | 6,416 | | `sha512.o` | 2,596 |
| `psbt.o` | 5,934 | | `kef.o` | 2,440 |
| `qrcode.o` | 5,152 | | `shamir.o` | 2,432 |
| `ecdsa.o` | 4,428 | | `snake.o` | 2,318 |
| `EFF_short.o` | 3,470 | | Soft float (`libm`, for `sampler.c`) | 3,112 |

Largest functions: `main()` 21,552, `psbt_review_and_sign()` 7,020 (plan,
confirmation and signing inlined), `full_text_editor()` 5,196,
`psbt_viewer()` 3,880, `qrcode_initBytes()` 3,108, `scan_ur_message()` 3,052,
`vault_run()` 2,516, `derive_menu_run()` 2,036, `psbt_ecdsa_sign()` 1,956,
`print_reader_screen()` 1,888, `check_scanned_address()` 1,776.

By feature, approximate (static functions inlined into `main()` are not
counted, so the real figures are higher): PSBT review and signing 26 KB,
vault with AES-GCM 17.8 KB, FAT files 11.4 KB, descriptors 7.8 KB, text editor
7.4 KB, UR scan with its float code 6.4 KB, QR encoder and viewer 6.2 KB, EFF
5.6 KB, KEF 5.0 KB, cards 3.2 KB, Shamir 2.9 KB, QR READER 2.8 KB, snake
1.8 KB, transcript check 1.7 KB, obfuscation 0.9 KB, triple 0.7 KB, Nostr
0.5 KB.

## 2. Compiler options (measured, no code change)

The project builds with `-O1`. All of these work with the free license.

| Options added to `-O1` | Flash | Saved |
|---|---|---|
| (none) | 226,942 | - |
| `-mmemcpy` | 217,817 | 9,125 |
| `-G 1024` | 224,514 | 2,428 |
| `-fcrossjumping` | 225,114 | 1,828 |
| `-fno-tree-ch` | 224,626 | 2,316 |
| `-fcode-hoisting -ftree-tail-merge` | 226,082 | 860 |
| `-fno-inline` | 226,126 | 816 |
| `-foptimize-sibling-calls` | 226,586 | 356 |
| **A:** `-mmemcpy -G 1024` | 215,429 | **11,513** |
| **B:** A + `-fcrossjumping -foptimize-sibling-calls -fcode-hoisting -ftree-tail-merge -fno-tree-ch` | 210,173 | **16,769** |
| **C:** B + `-fno-move-loop-invariants -fno-tree-loop-im -fno-inline` | 207,965 | **18,977** |
| C on the interface files, A on the crypto files | 209,925 | 17,017 |

What they do:
- `-mmemcpy`: copies of structures and of fixed size blocks call `memcpy()`
  instead of being written out as loads and stores (`HDNode` copies, 32 and 33
  byte keys). No change of behaviour; slightly slower copies.
- `-G 1024`: globals up to 1 KB are reached with one instruction from the
  `gp` register instead of two. RAM +36 B. The data init table also shrinks
  (1,344 to 864 B).
- `-fcrossjumping`, `-ftree-tail-merge`, `-fcode-hoisting`,
  `-foptimize-sibling-calls`: `-O2` passes that merge repeated code.
- `-fno-tree-ch`, `-fno-tree-loop-im`, `-fno-move-loop-invariants`,
  `-fno-inline`: stop the compiler from duplicating or moving loop code. They
  can slow tight loops, so the last row keeps them off the crypto files
  (hashes, bignum, ECDSA, AES, PBKDF2, Shamir, fountain, TFT, SPI).

Tried and discarded: `-Os` (the free license builds 240,201 B, worse),
`-O2` (does not fit), `-flto` (needs the license, no effect),
`-mno-check-zero-division` (120 B), `-fipa-icf`, `-fmerge-all-constants`,
`-fno-jump-tables`, `-fno-ivopts`, `-fno-if-conversion` (nothing or worse).

Proposal, in two steps so each can be tested alone on the board:
1. Set A (11.5 KB). The whole device test pass afterwards: timing of the LCD,
   the scanner and the SD does not depend on these, but the binary changes
   everywhere.
2. Set B or C (5 to 7 KB more), for the interface files only if the key
   derivation gets slower (measure "1/2 SEED (PBKDF2)" and the KEF time
   before and after).

The options go in the project (`configurations.xml`, additional options of
xc32-gcc, with MPLAB closed, then the makefiles regenerated) so the build
stays reproducible. `-fno-inline` and `noinline` attributes already in the
code do not conflict. Stack use can change: do the stack measurement of
`pending.md` after this.

## 3. Code changes

Estimates on today's build; after section 2 each one is worth somewhat less,
because the options already remove part of the same repetition.

| # | Change | Saves (est.) | Effort | Risk |
|---|---|---|---|---|
| 1 | Text formatter for the `strcpy` / `fast_itoa` / `strcat` chains | 2.5 KB | Medium | Low |
| 2 | `drawtext` with 4 arguments for the 500 calls on black, size 1 | 2.0 KB | Low | Low |
| 3 | Several lines in one call, or screens as tables | 1.5 - 3 KB | Medium | Low |
| 4 | `main()` menus: one handler for the states that only move a cursor | 2 - 4 KB | High | High |
| 5 | Unused SPI drivers and interrupt handlers of the generated code | 1.3 KB | Low | Medium |
| 6 | One scanner read function instead of three | 0.5 KB | Low | Low |
| 7 | Key helpers (`BTx == 0` waits, OK / BACK loops, the six debounce blocks) | 0.5 - 0.8 KB | Low | Low |
| 8 | `const char *` in the drawing functions (no copies to a buffer) | 0.4 KB | Low | Low |
| 9 | Debug screen "CRC FAIL (PAUSED)" in `scan_ur_message()` | 0.35 KB | Low | Low |
| 10 | Smaller crypto helpers (see below) | 2.5 KB | Medium | Medium |
| 11 | Single vector interrupts | 0.8 KB | Medium | Medium |
| 12 | Packed text strings | 3 KB | High | Medium |
| 13 | Integer code instead of floating point in `sampler.c` | 3 KB | High | High |

1. **Text formatter.** 106 calls to `fast_itoa()`, 112 to `strcat()` and 48
   to `strcpy()` build texts such as "SIGN 2 OF 3 INPUTS" piece by piece, 10
   to 14 B per call. One function `fmt(buf, size, "SIGN %u OF %u INPUTS", a,
   b)` (numbers and strings only, about 200 B) replaces four to six calls with
   one. Taking the buffer size, it also ends the short buffer bugs of the
   audit (M4) for good.
2. **`drawtext` with 4 arguments.** 593 calls; a constant one costs 24 B.
   500 of them pass black background and size 1, which are two stores to the
   stack each (4 B). A wrapper removes them.
3. **Lines in one call.** 264 calls have literal position and text; 121 of
   them come in 43 runs with the same column and color (warnings, help
   texts). `draw_lines(x, y, pitch, color, "LINE 1\nLINE 2\n...")` draws a
   run with one call (about 24 B saved per extra line). Going further, a
   static screen as a table of `{x, y, color, text}` (8 B per line instead of
   24).
4. **`main()`.** 21.5 KB. Many states repeat the same UP / DOWN / BACK code
   around `print_generic_menu()` (53 calls). A table of menus (title, entries,
   count, cursor, parent state) with one handler would remove most of it. It
   touches every flow: only with the device test pass ready.
5. **Generated code.** `SPI1_Initialize()` and `SPI3_Initialize()` run and
   then `main()` sets both SPI modules by hand; their drivers (796 B) stay
   linked only for that and for two interrupt handlers that never fire. The
   UART2 transmit handler is not used either. Each handler saves the whole
   context (about 180 B). Best removed in MCC, not by hand.
6. **Scanner reads.** `qr_read_raw()`, `qr_read_text()` and the code inside
   `QR_SCANNING` do the same job three times. Using `qr_read_raw()` for all
   also removes the 2 KB `rx_buf` from the stack of `main()` (audit M1).
9. Also audit M5.
10. **Crypto helpers**, none speed critical:
    - `gf256_mul()` in `shamir.c` is written out bit by bit (1,068 B): a loop
      does it in about 250 B.
    - `ripemd160_compress()` (1,188 B, macros for the 160 steps): a loop over
      tables takes about 600 B. Only used for fingerprints and addresses.
    - GCM: one authentication path for header and data (0.7 KB, already in
      `pending.md`); `gf_tab` (512 B) can be computed.
    These are vendored files: each change needs its test vectors run again.
11. The vector table is 102 entries of 8 B for one interrupt in use.
12. 89% of the text is upper case letters and spaces: 6 bits per character
    would save a quarter of 13 KB, but every text user needs a decoder. Not
    before the rest.
13. `sampler.c` pulls 3.1 KB of 64 bit floating point, and UR needs the
    results bit exact. Listed as not advised in `pending.md`; still so.

## 4. Features that could be left out

Product decisions, with what each returns (approximate, see section 1):
long file names 5 KB (`FF_USE_LFN`, with `ffunicode.c`), snake 2.3 KB
(`DECOY_SNAKE 0`), cards 3.2 KB, EFF password 5.6 KB, KEF 5 to 6 KB, UR
crypto-account QR about 0.6 KB, Nostr 0.5 KB, triple and obfuscation 1.6 KB.

## 5. Suggested order

| Step | Saves | Free after it |
|---|---|---|
| Today | - | 16.4 KB |
| Options A (`-mmemcpy -G 1024`) | 11.5 KB measured | 27.9 KB |
| Options B or C on the interface files | 5 to 7 KB measured | 33 to 35 KB |
| Changes 2, 5, 6, 8, 9 (small and safe) | about 3 to 4 KB | 36 to 39 KB |
| Changes 1, 3, 7 | about 3 to 5 KB | 39 to 44 KB |
| Change 4 and the rest | when needed | |

Nested segwit, taproot and legacy together are estimated at 10 to 13 KB in
`pending.md`: the first two rows alone make room for them.
