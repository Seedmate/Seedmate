# Seedmate firmware - pending work

The open work list, kept up to date with every change (Claude updates it when
a task is done, decided or added). Last update: 2026-11-05.

Memory today: flash 208.0 KB of 238 KB (85.3%, about 35.8 KB free); RAM
22.5 KB of 32 KB (about 11.5 KB of stack).

## 1. Before shipping v2.0

| Task | Notes |
|---|---|
| Thorough device test pass | Everything since the vault: vault notes and descriptors, descriptor QR (Sparrow PDF), DERIVE (passwords, Nostr), transcript check, start screen, settings defaults, key repeat |
| Firmware signature | The bootloader verifies `UPDATE.HEX` before flashing. Custom firmware: still installable, the bootloader shows "UNOFFICIAL FIRMWARE" (and its hash) on every boot (Trezor model) |
| Bootloader write protection | Today a running app can rewrite the bootloader. The bootloader must lock `NVMPWP` / `NVMBWP` (`PWPULOCK` / `BWPULOCK`) before it jumps to the app. Production: `CP = ON`, JTAG off (already), programming pads covered |
| Bootloader layout | 12 KB instead of 16: the app loses nothing (its vectors go to 0x9D003000, 4 KB aligned, its startup code after them). Signature check that fits in +4 KB: LMS (RFC 8554, hash based, only SHA-256, ~1-1.5 KB; a ~2 KB `.SIG` file; a fixed number of signatures, e.g. 1024 releases). ECDSA would need 4-6 KB |
| Bootloader updates without a PICkit | A signed bootloader package that the current bootloader verifies and writes itself from RAM; it can carry a new public key signed by the old one. Power loss during the write needs the PICkit |
| FAT32 in the bootloader | With the new layout. Cards over 32 GB: today only a small FAT16 partition works |
| Stack measurement | Stack watermark, before Taproot |
| User documentation | Which card for what (seed card never in a PC, file card FAT16/32), updates, the camera icons (green safe / red not safe for a phone: the start screen legend was removed), SD seeds are not encrypted |
| Version 2.0 final | Release notes, `cVersion` |
| Reproducible build | Check that two builds give the same `.hex`, document XC32 / MPLAB versions and the expected hash, publish it per release (WalletScrutiny verification). Do not use XC32 PRO `-Os`: verifiers would need the PRO license |

## 2. Bitcoin features

| Task | Flash | Notes |
|---|---|---|
| Nested segwit P2SH-P2WPKH (BIP49, ypub, "3" addresses) | 2-3 KB | Same BIP143 sighash |
| Nested multisig P2SH-P2WSH (BIP48 1') | ~1 KB | With the one above |
| Taproot keypath (BIP86) | 5-7 KB | Schnorr BIP340, BIP341 sighash, bech32m; measure the stack first |
| Legacy P2PKH (BIP44) | 2-3 KB | Least used |
| Testnet / signet | 1-2 KB | A session setting (not permanent), yellow "TESTNET" label on the wallet, signing and address screens |
| Signed PSBT back to the SD card | +6-8 KB | Not decided. Proposal: full FatFs (ChaN) in the app, FAT16/32 read and write, no exFAT (Microsoft patent and license risk); always a new file (`NAME-SIGNED.PSB`) after a confirmation; the bootloader keeps Petit FatFs |
| BBQr reading | 1-3 KB | Sparrow / Coldcard "B$" frames; the Z encoding needs raw inflate (shared with KEF v21) |
| Nostr event signing | ~2-3 KB | Shares Taproot's Schnorr; under SIGN |

## 3. Other features

| Task | Notes |
|---|---|
| KEF encrypted mnemonic QR (Krux v26.09.0) | Design in `docs/kef.md`: export v20 (AES-GCM), import v20 / v15; ~5-6 KB; about 35-40 s at 100,000 iterations on the device |
| Vault HTML recovery page | It exists, needs a revision; it must read records by the bitmap (old versions stay on the card until reused) |
| Encrypted SD seed slots | Today XOR obfuscation only |
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

Measured, not done (the user prefers to wait until it is needed):

| Option | Saves | Risk |
|---|---|---|
| EFF list packed 5 bits per letter (words stay whole, decoded on use) | ~3.3 KB | Low (host test against the official hash) |
| BIP39 list packed the same way | ~5 KB | Medium (`get_word()` callers) |
| One GCM authentication path (header and data) | ~0.7 KB | Low |
| `main()` refactor (20.7 KB, repeated menu code) | 2-4 KB | High |
| Soft float of `sampler.c` (~4 KB) | - | Not advised: UR needs bit exact doubles |

## 6. Housekeeping

- Untracked files to decide: unused `src/crypto` files, poker tests, `bootloader/documents`, the `SPI` / `TFT` / `mainold` copies in `bootloader/src`.
