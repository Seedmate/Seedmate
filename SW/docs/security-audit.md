# Seedmate firmware - security audit (2026-11-09)

Code review of the working tree after commit 095cbb2 (KEF, packed word lists
and the SD warning included, not yet committed). Nothing was changed in the
code: this document lists what was found and the fix proposed for each.

## 1. Scope and method

Read in full: `psbt.c`, `psbt_sign.c`, `descriptor.c`, `vault.c`, `kef.c`,
`kdf.c`, `bip85.c`, `fountain.c`, `sampler.c`, `prng.c`, `bytewords.c`,
`ur_encode.c`, `settings.c`, `sd_files.c`, `SSS/shamir.c`, `memzero.c`, the
bootloader's `main.c`, `hex_flash.c` and `boot_lms.c`, and `docs/`.

`main.c` (13.5k lines): read in full the entropy and Shamir code, key
derivation and caches, the wipes, the SD driver and slots, every PSBT function,
the descriptor import, the QR scanners (UR, raw, seed), the QR READER, the text
editor, the vault screens, DERIVE, KEF and AUTO UNLOAD. The menu state machine
(about 3,000 lines of `main()`) and `screens.c` were only sampled.

Not reviewed: the vendored code (trezor-crypto, Gladman AES/GCM, FatFs, Petit
FatFs, the QR encoder), the hardware, side channels and fault injection, the
HTML tools and the PC tests themselves.

Threat model used: the device is offline and keeps no secrets when off, so the
attacker reaches it through what it reads (QR codes, PSBTs, descriptors, SD
cards, firmware files) or by handling it or its cards while the owner is away.

One finding was confirmed by running the firmware's own parser on the PC (C1).
The others come from reading the code; none was tried on the board.

## Status (2026-11-11)

Fixed in the firmware, host tests passing, not yet tried on the board:

| Id | Fix |
|---|---|
| C1 | `parse_cbor_output()` refuses a second key array; test in `test_descriptor.c` (nothing written past the wallet) |
| H1 | `load_and_verify_sd_slot()` refuses a size byte other than 12 or 24 words ("NO SEED") |
| M1 | `QR_SCANNING` reads into the fountain buffer (wiped with the session) and wipes it on every exit; 2 KB less stack in `main()` |
| M2 | `transition_to_main()` runs `secrets_wipe()`: `session_wipe()` (share buffers of `main()` registered at start) plus keys and passphrase |
| M4 | Buffers enlarged (`text[32]` and a shorter label in QR READER, `text[40]` and "IDX" in BIP85 PASSWORD, `rate[24]`, `amount[][20]`) |
| M5 | "CRC FAIL / USE" removed: a joined UR message with a bad checksum says "UR CHECKSUM FAILED" and the scan starts again |
| M6 | `psbt_bip84_path()` / `psbt_multisig_path()` check the length first; the plan clears the derivation of each input |
| L1 | `get_current_bip84_result()` wipes its node; UNLOAD SEED also runs `stack_wipe()` |
| L2 | UPDATE FIRMWARE runs `secrets_wipe()` and `stack_wipe()` before the software reset |
| L5 | `rd_varint()` refuses non canonical CompactSize values (as Bitcoin Core); the corpus vector `ENC-08.nonminimal_keylen` is now refused and left the gaps list |
| L6 | `u16_to_str()` and `u16_to_str_pad()` take any 32 bit value |

Open: H2 and L10 (bootloader), M3 (vault nonce, needs a new record
format), L3 (an iteration cap for imported KEF QR codes; the time is now
shown before the key is asked. Clearing the key press pool after the IV is
not done on purpose: the pool also feeds the next Shamir split, and the IV
and the coefficients are separate hashes of it), L4, L7, L8, L9, L11.

## 2. Summary

| Id | Severity | Finding |
|---|---|---|
| C1 | Critical | Stack overflow in the UR crypto-output (descriptor) parser, from a QR |
| H1 | High | Seed size byte of an SD slot is not checked: buffer overflows from a card |
| H2 | High | Firmware signature protects nothing yet (test key, no flash lock, CP off) |
| M1 | Medium | A seed read by QR stays in RAM after UNLOAD SEED (`rx_buf` in `main()`) |
| M2 | Medium | `transition_to_main()` does not wipe the seed; only two paths do |
| M3 | Medium | Vault: a rolled back header makes AES-GCM nonces repeat |
| M4 | Medium | Three small stack overflows in screens, two of them in normal use |
| M5 | Medium | "CRC FAIL / USE" accepts a UR message whose checksum failed |
| M6 | Medium | PSBT check reads a derivation that may not exist (wild read, hang) |
| L1-L11 | Low | See section 5 |

## 3. Critical and high

### C1. Stack overflow in the UR crypto-output parser

`parse_cbor_output()` in `descriptor.c` (line 497): map key 2 is the array of
cosigner keys. The array length is checked against `DESC_MAX_KEYS`, but the
map may hold key 2 more than once, and every key is written at
`w->keys[w->key_count]`. Two arrays of 7 keys write 14 keys into room for 7.
The parser even returns `DESC_OK` with `key_count` 14, which then overflows
`keys[DESC_MAX_KEYS][33]` in `ms_wallet_script()` and `order[]` in
`desc_witness_script()`.

Confirmed on the PC with the firmware's `descriptor.c`: a 1,063 byte CBOR
wrote 641 bytes past a `desc_wallet_t` and was accepted. The map count is not
limited, so much more can be written.

The destination is a local of `import_descriptor_from_qr()` and of
`vault_descriptor_from_qr()`, so this is a stack overflow with bytes the
attacker chooses (chain code 32 free bytes, fingerprint 4, origin 16, public
key 32 of 33). The MCU has no stack protection and RAM is executable.

Reached from WALLET > IMPORT DESCRIPTOR > FROM QR and VAULT > NEW ENTRY >
MULTISIG DESCRIPTOR > FROM QR, both with the seed loaded. A malicious
coordinator, cosigner or PC shows the QR.

Fix: refuse when `w->key_count + count > DESC_MAX_KEYS` (or a second key 2),
and refuse a repeated key in every CBOR map of this parser. Add the vector to
`test_descriptor.c`. The text and Coldcard parsers are bounded correctly.

### H1. Seed size byte of an SD slot is not checked

`size_pointer = buffer[cSD_SIZE_ADDR]` takes the byte from the card as it is
(`main.c` lines 11321, 11517, 11592). Every length is then
`16 + 16 * size_pointer`: with 255 that is 4,096 bytes. `append_checksum()`
copies that many bytes into a static of 33, the Shamir split copies them over
`data_array_256b[36]`, the XOR loop runs over arrays of 32. Part of what is
copied can be the SD sector itself. The slot checksum is one byte (a sum), so a
random sector passes 1 time in 256 and a crafted one always.

Reached by loading a slot (LOAD, XOR, Shamir, BIP85, cards, obfuscation) from a
card someone else wrote to.

Fix: in `load_and_verify_sd_slot()` return "NO SEED" unless the byte is
`cSIZE_12` or `cSIZE_24`, and set `size_pointer` there.

### H2. Firmware signature protects nothing yet

Already in `pending.md`, listed here because they decide what the signature is
worth: the bootloader holds a TEST public key; the flash is not locked, so a
running app can rewrite the bootloader and its "official" record; `CP = OFF`,
so flash and RAM can be read through the programming pads of a powered device;
no version in the signed data, so an old signed firmware installs. Until the
lock is in, an unofficial firmware installed with OK + BACK can remove its own
warning.

## 4. Medium

### M1. A seed read by QR stays in RAM after UNLOAD SEED

`QR_SCANNING` reads into `uint8_t rx_buf[2048]`, a local of `main()` (line
13312), and never wipes it. It holds the SeedQR, the words or the compact
entropy in clear. `session_wipe()` does not know it and `stack_wipe()` only
clears below `main()`. The copy survives UNLOAD SEED and AUTO UNLOAD until
another QR is scanned or the power is cut. Fix: `memzero(rx_buf)` on every
exit of that case, or read into the fountain buffer, which is already wiped
(this also returns 2 KB of stack).

### M2. `transition_to_main()` does not wipe the seed

It clears the keys, the passphrase and the multisig wallet, not
`data_array_256b`, the XOR inputs, the shares or the coefficients. Those go
only through CONFIRM_UNLOAD and AUTO UNLOAD (`session_wipe()`). Other paths
reach a menu with them still in RAM, for example END_MODE after "SD ERROR" or
"SHAMIR ERROR", and BACK from a source menu in the middle of an XOR or Shamir
merge. Fix: call the same wipe from `transition_to_main()` (the shares would
become statics, or their pointers kept in a static).

### M3. Vault: a rolled back header makes nonces repeat

The nonce is `write_counter || sector`, and the counter lives in the header
sector, in clear, protected by a CRC only. Someone who can write to the card
twice can put back an old header (lower counter, the sector marked free): the
next save reuses a nonce with the same key. With two records under one nonce
the XOR of the texts is known and the GCM authentication key can be recovered.
`check_card()` only notices a change while the vault is open. The design note
"a nonce is never reused" holds for accidents, not for this.

Fix (new format version): make the nonce depend on the text, for example
`nonce = HMAC-SHA256(vault_key, counter || sector || plaintext)[0..11]`, so a
repeated counter with another text gives another nonce. No random source is
needed and HMAC-SHA256 is already in the firmware.

### M4. Small stack overflows in screens

- `print_reader_screen()` (line 8197): `"LOOKS LIKE A COMPACT SEEDQR"` is 27
  characters, copied into `text[24]`. Happens whenever QR READER reads a binary
  code of 16 or 32 bytes. 4 bytes past the buffer. It also does not fit the
  screen (26 characters).
- `bip85_password_show()` (line 9362): `"BASE64, 21 CHARS, INDEX n"` in
  `text[26]` fits only one digit of index. Index 10 and above writes 1 to 9
  bytes past it, next to the buffer that holds the password.
- `psbt_confirm_signing()`: `rate[16]` takes up to 17 characters plus the end
  (`"~3636363.6 SAT/VB"`). From 100,000 sat/vB, which a hostile PSBT can ask
  for when the wallet holds about 0.11 BTC.

The bytes written are fixed text, not chosen by an attacker; what they hit
depends on the stack layout, which was not examined. Fix: `text[32]` or a
shorter label, `text[40]`, `rate[20]`.

### M5. "CRC FAIL / USE"

`scan_ur_message()` (line 6817): when the joined message fails its CRC32 the
screen offers OK = USE. This is a debug leftover. A descriptor accepted this
way is then shown with "CHECKSUM OK", because `desc_parse_cbor()` sets
`has_checksum` on the assumption that the CRC was checked. Fix: remove the
override (restart the scan, as BACK does today).

### M6. PSBT check reads a derivation that may not exist

`psbt_plan_signing()` declares `psbt_keypath_t kp` without a value and calls
`psbt_bip84_path(&kp, ...)` for every input. `psbt_check_owner()` only fills it
when the input has a BIP32 derivation, and `psbt_bip84_path()` /
`psbt_multisig_path()` read path element 2 before they test `path_len`. A PSBT
whose first input has no derivation reads through an uninitialized pointer: a
bus error (the device hangs) or nothing, depending on what the stack held.
Fix: start `kp` at zero and test `path_len` first in both functions.

## 5. Low

- **L1. Private key traces on the stack.** `get_current_bip84_result()` does
  not wipe its `HDNode` (the other functions do); `hmac_sha256()` and the
  SHA-256 working array in `psbt_sign.c` keep parts of the private key.
  Suggested: run `stack_wipe()` from UNLOAD SEED too, not only AUTO UNLOAD.
- **L2. RAM survives the jump to the bootloader.** UPDATE FIRMWARE resets by
  software, which keeps RAM. Zero it before the reset, or at the start of the
  bootloader (except the flag).
- **L3. KEF.** The iteration count of a QR is accepted up to 100,000,000
  (about 12 hours; BACK cancels): cap it or say the time. No minimum key
  length. `kef_new_iv()` hashes the key press pool and leaves it, unlike
  `vault_new_id()`; not exploitable, clear it for consistency.
- **L4. Entropy.** STOPWATCH credits 16 bits per press with no conditioning,
  and the timer runs from the same clock as the loop that samples it; hash
  the samples and credit fewer bits. Cards drawn without replacement are not
  independent, and one deck holds 225 bits: 24 words need a second shuffle.
  Coins and both dice modes are sound.
- **L5. Non canonical lengths in a PSBT.** `psbt_add_partial_sig()` assumes
  the map separator is one byte; `FD 00 00` is accepted as zero and the
  signature is inserted inside it, giving a broken file. Refuse non canonical
  CompactSize values in `rd_varint()`.
- **L6. Number helpers.** `u16_to_str()` takes 32 bit values into `tmp[6]`:
  from 1,000,000 it overflows (a card that reports 2 TB in WIPE ALL CARD).
  `psbt_format_amount_short()` can write 18 bytes into `amount[14]` in REVIEW
  PSBT with absurd amounts; today it stays inside the array.
- **L7. SD seed slots.** One byte XOR and one byte checksum: known, encrypted
  slots are in `pending.md`.
- **L8. Shamir has no integrity check.** A wrong share ID, or shares of two
  different splits, give another valid seed with no warning. Show the
  fingerprint to compare after a merge, or add a digest to the scheme.
- **L9. "AMOUNTS NOT VERIFIED" is only a warning.** Without the previous
  transactions a signer can be made to pay a larger fee over two signings.
  Acceptable as a policy; consider a setting that refuses.
- **L10. Bootloader.** In the writing pass a record longer than `hexRec[200]`
  is read past its end if the card answers differently than in the checking
  pass; the hash comparison then erases the app. Harmless, bound it anyway.
- **L11. AUTO UNLOAD is off by default.**

## 6. Checked and found sound

- PSBT parser: bounded reader, no out of bounds access found, duplicate keys
  and map sizes refused, amounts capped at 21M BTC.
- What is signed: only SIGHASH_ALL, only P2WPKH and standard P2WSH multisig,
  the key and script derived again from the seed before each signature, the
  previous transaction hashed against the outpoint, change verified by key
  (single sig) or by every cosigner key (descriptor), the PSBT parsed again
  after each signature.
- ECDSA: RFC 6979 nonces, low S, low R, and every signature verified before
  it leaves. BIP143 sighash matches the specification.
- Fountain decoder, Bytewords, base43, base64: lengths bounded.
- PBKDF2 and HMAC (both hash sizes), BIP85, KEF sealing and opening, vault
  record sealing with the header as additional data: correct, secrets wiped.
- Shamir coefficients: SHA-256 of a pool fed by every key press, cleared
  after use; enough presses happen before any split.
- Text shown from outside (file names, QR text, KEF ID, vault titles) cannot
  index the font out of range; unprintable bytes become "?" or hexadecimal.
- Settings page: only fixed slots inside its own page can be written.
- Firmware signature check (RFC 8554) and the HEX target check in the
  bootloader: correct.
