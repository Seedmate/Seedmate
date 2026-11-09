# Seedmate firmware - pending work

The open work list, kept up to date with every change (Claude updates it when
a task is done, decided or added). Last update: 2026-11-10.

Memory today: flash 221.6 KB of 238 KB (93.1%, about 16.4 KB free); RAM
23.7 KB of 32 KB (about 11.5 KB of stack).

## 1. Before shipping v2.0

| Task | Notes |
|---|---|
| Signed PSBT to SD: rest of the device test | Signing and writing checked on 2026-11-07: six PSBTs signed on the device (1 to 12 inputs, account 1) verified on the PC by an independent signer (every signature, low R and low S, SIGHASH_ALL, the right keys, the rest of each file unchanged); the same PSBT signed twice gives the same file. Names: the 8.3 alias of a long name is unpredictable ("abandon sweep.psbt" became ABE9BE~1, so ABE9BE-S.PSB), so long names were turned on (LFN, +3.7 KB): "abandon sweep.psbt" now gives "abandon sweep-signed.psbt"; try that on the device. Still to try: loading them in Sparrow, a FAT32 card, a full card, a seed card (must refuse). Test PSBTs for the abandon seed as Sparrow saves them: `test/psbt/sparrow/` (`gen_sparrow.py`, checked with `check_sparrow.c`). FatFs checked on 2026-11-07: `ff.c`, `ff.h`, `diskio.h` are byte-identical to the official ff16.zip of elm-chan.org |
| PSBT review: device test | Partly done on 2026-11-07: `abandon multisig.psbt` reviewed and signed on the device, its 3 signatures verified on the PC; the diagram moved up 10 px after that (not seen yet). "TYPE NOT SUPPORTED" not tried (needs a PSBT with only taproot or nested inputs). New review: checks first (progress bar), then the flow diagram (inputs, outputs and fee as blocks in proportion), one page per output (SEND / CHANGE / TO YOU n OF m, amount, whole address in groups of 4, path), inputs, DETAILS; OK is NEXT until every destination was shown, then SIGN; new confirmation with the address, the fee in sats and ~sat/vB. Amounts: under 100 000 sats in SAT, otherwise BTC with grouped decimals. Try: the Sparrow test PSBTs (1, 3 and 12 inputs), multisig with and without descriptor (`test/psbt/abandon multisig.psbt`: 3 inputs, a send over and one under 100 000 sats, change, with `MSDESC.TXT`), REVIEW PSBT. Cost +5.6 KB flash: candidate for savings (the diagram code, the per-kind count) |
| Thorough device test pass | Everything since the vault: vault notes and descriptors, descriptor QR (Sparrow PDF), DERIVE (passwords, Nostr), transcript check, start screen, settings defaults, key repeat |
| Firmware signature: test on the device | The bootloader is built, not tried on a board: signed and unsigned update, bad signature, the warning at boot, time of "VERIFYING SIGNATURE". Needs the PICkit once: the 12 KB layout refuses old apps, and old bootloaders refuse new apps |
| Firmware signature: real key | The bootloader has a TEST public key (`boot_lms.c`). Choose the signing words (12 or 24; 24 keeps the post-quantum margin), replace the key, start `SIGNATURES.md` with every index used |
| Bootloader write protection | Today a running app can rewrite the bootloader. The bootloader must lock `NVMPWP` / `NVMBWP` (`PWPULOCK` / `BWPULOCK`) before it jumps to the app, up to 0x9D003000 so it covers its state page too: until then a running app can fake "official". Production: `CP = ON`, JTAG off (already), programming pads covered |
| Firmware rollback | A signature stays valid forever, so an old signed firmware with a known bug can be installed. Decide whether the bootloader warns or refuses (would need a version inside the signed data) |
| Bootloader updates without a PICkit | A signed bootloader package that the current bootloader verifies and writes itself from RAM; it can carry a new public key signed by the old one. Power loss during the write needs the PICkit |
| FAT32 in the bootloader | Cards over 32 GB: today only a small FAT16 partition works. The bootloader has 136 B free in its code area, so it needs savings first |
| Stack measurement | Stack watermark, before Taproot |
| PSBT and AUTO UNLOAD: device test | Built on 2026-11-08, not tried on the board. HIGH FEE on the flow and on the confirmation (fee over 1/4 of what is sent, change excluded, or at least 1/10 of the inputs); BURNS BTC and "THIS AMOUNT IS BURNED" for an OP_RETURN with an amount. SETTINGS > AUTO UNLOAD (never, 5, 10, 20, 30 minutes, never by default): try it inside a deep flow (editor, vault, PSBT review, QR scan, words on screen) and check that it wipes, says why and returns to the main menu; the keys pressed and long operations must restart the time |
| Packed word lists: device test | Done on 2026-11-08, saved 11.1 KB, PC tests only. On the device: word entry and its keyboard (should not feel slower), showing 24 words, seeds from QR and SD, EFF PASSWORD |
| Try it all with real PSBTs | On the device with PSBTs made by real wallets (Sparrow, Nunchuk, single sig and multisig, by SD and by QR): the new review, HIGH FEE, the stricter parser (nothing valid may be refused: the PC tests use generated files, and a real wallet may add fields they lack), AUTO UNLOAD during a signing. Nothing from those wallets goes into the repo (rule 5) |
| PSBT hardening: device test | Done on 2026-11-08, PC tests only. The parser refuses duplicate keys and known fields with a key of the wrong form (all 20 invalid BIP174 vectors refused now); outputs without an address are yellow; HIGH CHANGE INDEX is relative to the inputs (over the highest input index + 100). Try the Sparrow PSBTs again to confirm nothing valid is refused. What is still accepted on purpose, with the reason: `test/psbt/malicious_gaps.txt` |
| Skewed dice warning | Maybe (2026-11-08): a count per face, no floating point, about 400 B |
| User documentation | Which card for what: keep the seed card apart from the card for updates and PSBTs, so it never goes into a PC (the device refuses to write files on a seed card, but a PC would offer to format it); the file card FAT16 (the bootloader needs FAT16, PSBTs also work on FAT32), updates, the camera icons (green safe / red not safe for a phone: the start screen legend was removed), SD seeds are not encrypted |
| Version 2.0 final | Release notes, `cVersion` |
| Reproducible build | Check that two builds give the same `.hex`, document XC32 / MPLAB versions and the expected hash, publish it per release (WalletScrutiny verification). Do not use XC32 PRO `-Os`: verifiers would need the PRO license |

## 2. Bitcoin features

| Task | Flash | Notes |
|---|---|---|
| Nested segwit P2SH-P2WPKH (BIP49, ypub, "3" addresses) | 2-3 KB | Same BIP143 sighash. The menu is ready: WALLET > CONFIG > SCRIPT has placeholders for nested, taproot and legacy ("NOT AVAILABLE YET"). SIGN should then sign any supported type with a yellow note when it differs from CONFIG, and still check the change |
| Nested multisig P2SH-P2WSH (BIP48 1') | ~1 KB | With the one above |
| Taproot keypath (BIP86) | 5-7 KB | Schnorr BIP340, BIP341 sighash, bech32m; measure the stack first |
| Legacy P2PKH (BIP44) | 2-3 KB | Least used |
| Testnet / signet | 1-2 KB | A session setting (not permanent), yellow "TESTNET" label on the wallet, signing and address screens |
| BBQr reading | 1-3 KB | Sparrow / Coldcard "B$" frames; the Z encoding needs raw inflate (shared with KEF v21) |
| Nostr event signing | ~2-3 KB | Shares Taproot's Schnorr; under SIGN |
| SCAN ADDRESS in multisig | Not measured | Today single sig only: the multisig menu has IMPORT DESCRIPTOR instead of ADDRESSES. With a descriptor loaded, check a scanned address against the receive and change scripts of the wallet (`psbt_public_ckd()`, `desc_witness_script()`, as the change check when signing) |

## 3. Other features

| Task | Notes |
|---|---|
| Vault HTML recovery page | It exists, needs a revision; it must read records by the bitmap (old versions stay on the card until reused) |
| Encrypted SD seed slots | Today XOR obfuscation only. Decided on 2026-11-08: use the same KEF envelope (`kef.c`) with a key per seed, as the encrypted QR. New slot format, old slots still load |
| Vault entry with a password's recipe | Keeps only format, length and index of a BIP85 password, regenerates it |
| BIP85 WIF / XPRV | On demand only (~0.5 KB each, DERIVE submenu) |
| Shamir shares and XOR results: transcript check | The same VERIFY TRANSCRIPT as new seeds |

## 4. Ease of use

| Task | Notes |
|---|---|
| Help line under menus | Agreed, not done. One cyan line (up to 26 characters) at y~95 for menus with up to 8 entries (not the 9 entry wallet menu). Drafts below |
| First-boot welcome screens | Later: what Seedmate is, how the keys move, the tutorial QR |
| Spanish firmware variant | Future, a separate build: about +3-4 KB over 13.3 KB of UI text; add accented glyphs (~50 B) or write without accents; BIP39 words stay English |
| WIPE ALL CARD progress bar | Quick fix |

Help line drafts:

| Entry | Help |
|---|---|
| CREATE NEW SEED WORDS | FROM COINS, DICE OR CARDS |
| LOAD SEED WORDS | OPEN A SEED YOU ALREADY HAVE |
| BIP85 CHILD SEED | SPARE SEEDS FROM YOUR SEED |
| OPSEC | SPLIT, HIDE OR DISGUISE |
| TOOLS | QR, PASSWORDS, CHECK A TX |
| SD CARD | PREPARE OR ERASE THE CARD |
| RESOURCES | GUIDES AND TOOLS AS QR |
| SETTINGS | DECOY, QR, SD, VERSION |
| THROW COINS | 128 OR 256 COIN FLIPS |
| ROLL DICE | 50 OR 99 DICE ROLLS |
| RANDOM WORD PICK | DRAW WORDS ONE BY ONE |
| POKER CARDS | A WELL SHUFFLED DECK |
| TRIPLE MNEMONIC | (needs its description) |
| SHAMIR SECRET SHARE | SPLIT IN SHARES, E.G. 2 OF 3 |
| SEED WORD XOR | SPLIT IN PARTS, ALL NEEDED |
| OBFUSCATION | DISGUISE THE WRITTEN WORDS |
| MNEMONIC TO CARDS | HIDE A SEED IN A CARD DECK |
| QR READER | SEE WHAT A QR CONTAINS |
| QR FROM TEXT | TURN A TEXT INTO A QR |
| EFF PASSWORD | A PASSWORD FROM DICE |
| REVIEW PSBT | CHECK A TX WITHOUT A SEED |

## 5. Flash savings, when space runs out

Full analysis of 2026-11-10 in `docs/flash-savings.md` (measuring scripts in
`test/size/`). Nothing done yet:

| Option | Saves | Risk |
|---|---|---|
| Compiler options `-mmemcpy -G 1024` | 11.5 KB (measured build) | Low: whole device test pass |
| More size options on the interface files | 5 to 7 KB (measured build) | Low: check the derivation times |
| Small code changes (drawtext wrapper, unused SPI drivers, one scanner read, debug screen) | 3 to 4 KB (estimate) | Low |
| Text formatter, lines in one call, key helpers | 3 to 5 KB (estimate) | Low |
| One GCM authentication path (header and data) | ~0.7 KB | Low |
| `main()` refactor (20.7 KB, repeated menu code) | 2-4 KB | High |
| Soft float of `sampler.c` (~4 KB) | - | Not advised: UR needs bit exact doubles |

## 6. Housekeeping

- Untracked files to decide: unused `src/crypto` files, poker tests, `bootloader/documents`, the `SPI` / `TFT` / `mainold` copies in `bootloader/src`.
