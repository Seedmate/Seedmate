# Seedmate firmware - project rules

Offline cryptographic calculator (BIP39 seeds, Shamir, XOR, BIP85, BIP84) that is being extended to sign Bitcoin transactions (PSBT).
Hardware: PIC32MM0256GPM036 (256 KB flash, 32 KB RAM), XC32, MPLAB X project in `BIP39_MCC.X`, single configuration `v2`.
The old v1 hardware (PIC32MM0064GPL028) was removed from this branch; do not reintroduce `v1`/`v2` conditional compilation.

## Rule 1 - English only

All code written or modified for this project must be in English:
- identifiers (functions, variables, types, macros, files)
- comments (inline, block, Doxygen)
- log/debug strings, commit messages and documentation

Do not translate existing non-English code unless asked, but anything new must be English.

## Rule 2 - No git commits

Never run `git commit`, `git push`, or any other command that records or publishes changes. The user reviews the diff and makes all commits personally. Leave changes in the working tree and just summarize what changed; do not offer or ask to commit.

## Rule 3 - Memory is tight (RAM and flash)

Even on v2 the budget is limited. Every change must be justified against it.

v2 budget (last build of `Seedmate_v2`):
- Flash: 240 KB usable (0x9D004000, 0x3C000; the first 16 KB belong to the bootloader). Used about 141.6 KB (57.6%).
- RAM: 32 KB (0x80000000, 0x8000). Used about 22 KB (67.2%), and the reserved stack is about 12 KB.
- RAM address `0x80007F00` is the bootloader shared flag (`UPDATE_FLAG_ADDR`); never place data there.
- Biggest RAM users today: UR fountain decoder buffers `pure_parts` (8.7 KB) and `mixed_frames` (3.2 KB), `next_beams`/`current_beams` (1.5 KB each), `fast_bw_lookup` (1.3 KB), the loaded multisig wallet `ms_wallet` (0.6 KB).
- Biggest flash users: `.text` (about 78 KB) and the BIP39 word list string (about 13 KB).

RAM guidelines:
- Avoid large local arrays and big static buffers; reuse existing buffers (for example share scratch space between screens that are never active together).
- No dynamic allocation (`malloc`/`free`); the heap is only 512 bytes.
- No recursion; keep stack depth shallow, especially inside crypto code (secp256k1, bignum).
- Prefer the smallest integer type that fits; pack structs.
- Wipe secrets (seeds, keys, mnemonics, nonces) with `memzero` as soon as they are no longer needed.

Flash guidelines:
- Keep constant tables `const` so they stay in flash.
- Avoid `printf`-family and floating point; they pull in large library code.
- Do not add or enable crypto modules, curves, or wordlists that are not strictly needed.

After any change that adds code or data, rebuild `Seedmate_v2`, read the memory report (`dist/v2/production/*.map`, "Total ... used") and mention the flash and RAM delta in the summary.

## Rule 4 - Transparency and user control come first

The user must always see what the device is doing and stay in control. This is a priority in both the interface and the flow logic, on the same level as security:
- Never sign, write to the SD card, export or change anything without an explicit confirmation step that shows what will happen (amounts, destinations, which keys/inputs).
- Long operations (key derivation, checks, signing, file I/O) show a progress bar plus the step currently running (for example "INPUT 2 OF 3", the derivation path, "SIGNING", "VERIFYING SIGNATURE").
- When something is refused or fails, say why on screen in plain words ("PREV TX MISMATCH", "SWITCH TO MULTI SIG"); never fail silently or fall back to a different action.
- Show verified facts and unverified claims differently (colors, "VERIFIED" / "NOT VERIFIED" labels); do not present data from the PSBT as checked when it was not.
- Every flow can be cancelled with BACK before any irreversible step.

## Rule 5 - No real wallet data in the repo

Never put data from the user's real wallets (xpubs, descriptors, fingerprints, addresses, QR captures or exports) in source, test or documentation files, not even temporarily: it reveals the wallet's addresses and balances. Test data comes from generated test seeds ("abandon x11 about" and seeds derived in the Python generators). If the user shares a real export to show a format, use it only to learn the format and rebuild an equivalent from test keys.

## Rule 6 - Button grid on every screen that waits for a key

Whenever a screen waits for a key, show the button grid (bottom right, x 63-153 from `GRID_X` in `screens.h`, y 105-125: BACK, UP, OK on the top row, LEFT, DOWN, RIGHT on the bottom row) with what each button does on that screen, and only the buttons that do something. Do not describe keys in text footers ("OK=SIGN BACK=CANCEL", "PRESS ANY KEY"). Use the helpers in `screens.c` (`grid_menu2()`, `grid_OK_back()`, `grid_confirm()`, `grid_labels()`...) and add a new `grid_*()` there when no existing one fits. Lay out the screen so nothing is drawn inside the grid area (progress bars go above it, at y 92-97); only full-screen QR codes may leave it out.

## Rule 7 - Consistent colors

Every color has one meaning on every screen; reuse it, never pick a color for looks:
- WHITE: normal text and values. Dark gray `0x8410`: disabled items and decoration (key outlines).
- YELLOW: screen title (top line). In the body: warnings and unverified data ("NOT VERIFIED", "AMOUNTS NOT VERIFIED").
- ORANGE: only the selected item or cursor (menus, keys, editable fields). Not for titles, hints or amounts.
- GREEN: success and verified facts ("VERIFIED", "OK", "LOADED", our own key or fingerprint).
- RED: errors, refusals and dangerous actions ("PSBT PARSE ERROR", "KEY MISMATCH", wipe), also as the title of an error screen.
- CYAN: secondary information and progress (derivation paths, counters, active layer, "CHECKING...", the running step above a progress bar).
- Progress bar: white outline, green fill.
Before adding a screen, look at a similar existing one and copy its colors.

## Building and checking (no IDE needed)

The project builds from the command line with MPLAB X's `make` and XC32 v5.10 (`-O1 -ffunction-sections -fdata-sections`, linked with `--gc-sections`, no LTO, and `-Werror -Wall`, so any new warning breaks the build). From `BIP39_MCC.X`:

```bash
export PATH="/c/Program Files/Microchip/MPLABX/v6.35/gnuBins/GnuWin32/bin:/c/Program Files/Microchip/xc32/v5.10/bin:$PATH"
make -f nbproject/Makefile-v2.mk SUBPROJECTS= .build-conf
```

Add `-B` to force a full rebuild. The memory totals are in `dist/v2/production/BIP39_MCC.X.production.map` ("Total kseg0_program_mem used" and "Total Data Memory used"). `nbproject/Makefile-*.mk` are generated by MPLAB X from its in-memory project model. If the IDE has the project open, editing `configurations.xml` by hand is NOT picked up: MPLAB regenerates the makefile without the new file and may overwrite the XML on save. When a source file is added or removed, tell the user to add it in the IDE (Source Files > Add Existing Item) or to close and reopen the project before building.

With the project closed in the IDE, edit `configurations.xml` and regenerate the makefiles exactly as MPLAB would (no hand patching), from `SW`:

```bash
"/c/Program Files/Microchip/MPLABX/v6.35/mplab_platform/bin/prjMakefilesGenerator.bat" "BIP39_MCC.X@v2"
```

## Source layout (`src/`)

- `main.c` - application core: a `state_t` state machine in `main()`, entropy sources (coins, dice, words, cards, timer), SD card driver over SPI3, BIP39 helpers, BIP85, BIP84 (xpub/addresses), Shamir/XOR/obfuscation, text editor, and `scan_ur_message()` which rebuilds a UR message (`ur:crypto-psbt` for SIGN, `ur:crypto-output` for IMPORT DESCRIPTOR) from animated QR frames received on UART2 from a GM861 scanner.
  Text editor (`full_text_editor()`, BIP39 passphrase and notes): 3 alphabetical rows of 9 outlined keys plus CANCEL/SAVE/RETURN, the 2x3 control keys (aA, #@, cursor arrows) next to the untouched `grid_keyboard()`; NUM and SYM layers hold each printable ASCII symbol once. Passphrase mode adds a character counter and a review screen after SAVE (BACK edits again); `edit_bip39_passphrase()` edits a copy, so CANCEL keeps the old one, and `transition_to_main()` wipes it.
  BIP84/BIP48 keys are derived only when the user opens the wallet menu from the words screen (`load_wallet_keys()`: loading screen with progress phases, BACK cancels the PBKDF2). The key cache is bound to the seed on screen by `bip84_seed_tag` (truncated SHA256 of entropy, size and passphrase), so another Shamir share or a BIP85 child is never shown with stale keys.
  GM861 scanner (UART2, 115200, manual "GM861S User Manual V1.2.4", zone bits in chapter 10): its stored setup is command triggered mode with a 500 ms break between reads. For the UR animated scan only, `scan_ur_message()` writes to the scanner RAM (never its flash, `gm861_override()`): 0x0000 continuous mode, 0x0005 break 0, 0x0013 same-code delay 500 ms, 0x0060 CR tail; it receives through the UART2 interrupt into a 512 B ring buffer (`scan_rx_*`, the 4-byte hardware FIFO would overflow while a frame is processed) and restores every register on exit, mode first (`gm861_restore()`, error shown if it fails). If the setup fails it falls back to command trigger mode (trigger after each processed code, wait for the 7-byte ACK, resend after 50 ms). Frame end = CR or 15 ms of silence, timed with the core timer (`_CP0_GET_COUNT()`, 12 MHz). Other QR functions keep polled UART and the stored scanner setup.
- `screens.c/h` - TFT drawing only: bitmaps, menu text tables, grids/arrows, menus, QR views and input screens. Screens that still mix drawing with mnemonic/SD/BIP84 logic remain in `main.c` until `mnemonic.c`, `sd_card.c` and `bip84.c` exist.
- `app_defs.h` - application constants (menu sizes/indices, option values, messages, `cVersion`). `app_state.h` - `extern` declarations of the state variables that `main.c` owns and `screens.c` reads. Keep it small; prefer passing parameters in new code.
- `psbt.c/h` - zero-copy PSBT (BIP174 v0) parser: inputs/outputs, amounts, fee, BIP32 derivations, sighash, partial signatures, multisig scripts. No crypto inside; key verification against the seed lives in `main.c` (`psbt_check_owner`). Host tests in `../test/psbt/`.
- `psbt_sign.c/h` - signing crypto: BIP143 sighash (P2WPKH and P2WSH), NON_WITNESS_UTXO txid check, ECDSA with RFC6979 nonces, low S and low R grinding, verified after signing, built on the vendored bignum/ecdsa (the trimmed `crypto/ecdsa.c` has no signing), and BIP32 public child derivation (`psbt_public_ckd()`, for cosigner xpubs). Host tests (`../test/psbt/test_sign.c`) check the BIP143 vector and that the firmware signs the abandon PSBT byte-identically to the Python signer. The decision of what to sign (`psbt_plan_signing`: mainnet only, SIGHASH_ALL only, txid check, key/change verification, confirmation screen) and key derivation live in `main.c` (`psbt_review_and_sign`).
- `descriptor.c/h` - multisig wallet descriptor parser, no crypto: output descriptor `wsh(sortedmulti|multi(...))` (BIP380 checksum verified when present, keys ending in /<0;1>/*, /0/* or /1/*) and the Coldcard multisig setup file (Policy/Format/Derivation, xpub or Zpub), and the CBOR of a UR crypto-output (BCR-2020-010, Sparrow's animated "Output Descriptor" QR, also read by Krux/SeedSigner/Jade; `desc_parse_cbor()`, iterative CBOR skip, v1 and v2 tags). Mainnet P2WSH only, up to `DESC_MAX_KEYS` (7) cosigners. IMPORT DESCRIPTOR in the multisig menu opens the SIGN submenu (FROM QR / FROM SD, `sign_menu_descriptor`): FROM QR scans the animated `UR:CRYPTO-OUTPUT/` with the same scanner as PSBTs (`scan_ur_message()` takes the UR type), FROM SD reads a .TXT (`import_descriptor_from_sd()`); both go through `descriptor_check_and_load()`, which refuses the wallet unless this seed's m/48'/0'/n'/2' xpub is one of the keys ("SWITCH TO ACCOUNT n", "MY KEY DOES NOT MATCH"), shows policy, checksum, fingerprints and receive address 0 to compare, and on OK keeps it in RAM (`ms_wallet`, bound to the seed tag and account, wiped in `transition_to_main()`). While it is active, multisig inputs and change are checked against the script built from every cosigner xpub (`psbt_public_ckd()` in `psbt_sign.c`, `desc_witness_script()`): matching change counts as change, other outputs as sent, inputs of another wallet are refused ("INPUT NOT IN WALLET"). Host tests `../test/psbt/test_descriptor.c` with data from `gen_descriptor.py` (also the wallet as crypto-output CBOR with v1 and v2 tags), which also writes SD test files (MSDESC.TXT, MSCOLD.TXT, MSWALLET.PSB, MSATTACK.PSB) for the "abandon x11 about" seed.
- `sd_files.c/h` - read-only FAT16 file access (root directory, 8.3 names) over Petit FatFs, plus the pff disk interface on top of `sd_read_partial()` in `main.c`. Used to load PSBTs (`.PSB` binary or `.TXT` base64) and multisig descriptors (`.TXT`) into the fountain buffer (`fountain_scratch_buffer()`); `sd_pick_file()` in `main.c` is the shared file list.
- Bootloader (`../../bootloader`, first 8 KB of flash, built with `make -f nbproject/Makefile-default.mk BUILD_SUBPROJECTS= .build-conf`, which also writes `bootloader.production.unified.hex` with the current app for the PICkit): flashes `UPDATE.HEX` from the SD when the app sets the flag at `0x80007F00`, or when OK + BACK are held at power-on (forced update, 10 fast LED flickers; recovers a broken app without a programmer). LED blink codes at the end: 7 success, 4 SD read error, 5 bad record or missing end, 6 flash error, 8 empty flash; the whole file is read and checked first (record checksums, end record, SD reads) without touching the flash, so a damaged card or file leaves the current app working; only then is the app area erased and programmed, and an error during that second pass leaves no app (use the forced update). Host test `../../bootloader/test/test_hex_flash.c` (feed it the app hex).
- `pff_app.c` - compiles `../../bootloader/src/pff.c` for the app (Petit FatFs is shared with the bootloader, not copied). `pffconf.h` is shared too: a change there also changes the bootloader, so rebuild both and check the bootloader still fits its 8 KB.
- `ur_encode.c/h` - UR encoder: `crypto-psbt` for exporting PSBTs as animated QR (pure parts only, uppercase minimal Bytewords for QR alphanumeric mode, no buffers) and `crypto-account` (BCR-2020-015, `ur_account_cbor()`) for the XPUB QR: master fingerprint, origin path, chain code and parent fingerprint as `wpkh(hdkey)` or `wsh(cosigner(hdkey))`. The BIP84 menu account index (`bip84_account_index`, 0..255 so the QR stays one version 8 code) applies to `m/84'/0'/n'` and `m/48'/0'/n'/2'`; the coin-level nodes are cached so changing it skips the PBKDF2. Also owns the shared CRC32 (`ur_crc32_update`). Host tests in `../test/psbt/test_ur.c`, including a byte-exact match against frames captured from Sparrow. Test data (`ur_test_psbt.h`: PSBT signed by the independent Python signer `sign_abandon.py`, plus its public test key) lives in `../test/psbt/`, not in the firmware.
- `fountain.c`, `sampler.c`, `prng.c`, `bytewords.c` - UR fountain-code decoder (Xoshiro256 PRNG and alias sampler). They are only for decoding UR frames and must never be used for entropy.
- `TFT.c`, `SPI.c` - ST7735 160x128 display driver.
- `sha256.c`, `sha512.c`, `SSS/` (Shamir, `memzero`), `QRCode-master/` (QR encoder), `words_opt.h` (BIP39 word list as one continuous string).
- `crypto/` - third-party trezor-crypto (bip32, secp256k1, ecdsa, base58, segwit_addr, ...). Treat as vendored: avoid editing it, and only link what is needed.
- `config/v2/` - MCC/Harmony generated code and the linker script `p32MM0256GPM036.ld`. Do not hand-edit generated files unless necessary.
- `main _derive.c`, `main_intento e ir a crypto.c`, `main_wipe_v1.c`, `main.c.bak` - old snapshots, not part of the build; do not edit them.
- `../test/` - host-side test benches.
