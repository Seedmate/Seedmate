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

Bootloader, 2026-11-11 (built, not yet on the board): H2 release public key and
write protection of the bootloader flash before the jump to the app (`CP`
stays off and there is no version check, both decided); L10 every record
checked again in the programming pass.

Vault, 2026-11-11: M3 the record nonce is the first 12 bytes of
HMAC-SHA256(key, counter, plain header, text), so an old header put back
repeats a nonce only for the very same text. No new format was needed: the
nonce is stored in every record, so older records open as before (tested).

Decided on 2026-11-11: L11 AUTO UNLOAD is 10 minutes from the factory (done).
Left as they are on purpose: L3 (no cap; the time is shown before the key is
asked and BACK cancels), L7 (SD slots stay XOR: losing the keys is a far more
likely risk than a physical attack), L8 (the fingerprint shown when the wallet
is loaded already tells a wrong merge). Clearing the key press pool after the
KEF IV is not done on purpose: the pool also feeds the next Shamir split, and
the IV and the coefficients are separate hashes of it.

L4 and L9, 2026-11-11: STOPWATCH counts each timer sample as 8 bits (twice
the presses) and the seed is the SHA-256 of all of them; POKER CARDS says
first that each card goes back into the deck and the deck is shuffled; a PSBT
without previous transactions gets a red "PREVIOUS TX MISSING / CHECK INPUT
AMOUNTS MANUALLY" screen and can still be signed (the user decided not to
refuse it).

Nothing is open any more apart from the device tests.

Second pass on 2026-11-16 over the code added since then: section 7 (five low
findings, R1-R5; R1 fixed on 2026-11-17, R5 on 2026-11-18, the rest not yet).
Third pass the same day on the signing code: section 8 (R1 confirmed by a
test, S1 on power analysis).
Fourth pass the same day on the bootloader: section 9 (B1 medium, fixed on
2026-11-17; B2-B5 low, B2 and B3 fixed the same day).
Its Petit FatFs and SD layer: section 10 (P1, P2 low).
The vendored cryptography against upstream: section 11 (no arithmetic
changed; the side channel protections were removed). **The list of what to
fix, in order, is section 12.**
The firmware signing page: section 13 (T1 medium: index reuse depends on
the person).

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
so flash and RAM can be read through the programming pads of a powered device
(kept on purpose, decided on 2026-11-11: no secrets in flash, and anyone can
verify the installed firmware);
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

## 7. Review of the changes since the audit (2026-11-16)

Second pass, by Fable 5.2, over what changed between commit 2ecb81c (the
fixes of the first audit, 2026-11-11) and 9e8f380. Nothing was changed in the
code. Nothing critical, high or medium was found; five low findings and three
notes follow.

### 7.1 Scope and method

Read in full: `bbqr.c`, the diffs of `psbt.c`, `psbt_sign.c`, `descriptor.c`,
`sd_files.c`, `fountain.c`, `ur_encode.c` and of the local edit to
`crypto/aes/aesgcm.c`, and `desc_pack()` / `desc_unpack()`.

`main.c` (4,800 lines of diff): read in full `scan_ur_message()` with the BBQr
and single part UR paths, `scan_descriptor_qr()`, the ownership checks,
`psbt_plan_signing()`, `psbt_sign_inputs()`, the script type and CONFIG code,
the address code (single sig, multisig, SCAN ADDRESS and +20), the account
file, the KEF slots on the SD card (`load_and_verify_sd_slot()`,
`sd_write_kef()`, `kef_load_from_qr()`, the seed QR read), the entropy check,
the SD file list, the seed count of INITIALIZE / WIPE and the stack
measurement. The changes that only swap `drawtext()` for `text_at()` or
`fast_itoa()` for `strcat_num()` were filtered out and not read line by line;
the state machine changes were skimmed.

Not reviewed: `tinf/tinflate.c` beyond its bounds checks (vendored; that it is
byte-identical to the 1.2.1 tag was not checked again), `screens.c`, the
generated SPI files, the HTML tools and the validation page, side channels
and fault injection. The bootloader did not change in this range.

Everything below comes from reading the code. No test was run for this pass
and nothing was tried on the board.

### 7.2 Summary

| Id | Severity | Finding |
|---|---|---|
| R1 | Low | Legacy and "amounts verified" rely on `prev_tx != NULL`, not on where the amount was read. **Fixed on 2026-11-17** |
| R2 | Low | The BBQr inflate path is the deepest stack use so far and has not been measured; there is no stack guard |
| R3 | Low | CONFIG: a cancelled key derivation can leave multisig mode with LEGACY or TAPROOT |
| R4 | Low | A BBQr series is fixed by the first code read, even one that fails; a single part UR read during an animated scan leaves the fountain state inconsistent |
| R5 | Low | The SD file list stops without notice at a file whose directory position is 99 or more (fixed on 2026-11-18) |
| I1-I3 | Note | See 7.4 |

### 7.3 Low

**R1. Legacy signing and `amounts_unverified` test the wrong thing.**
`psbt_plan_signing()` refuses a legacy input when `in.prev_tx == NULL` and
sets `amounts_unverified` on the same test. But `psbt_get_input()` falls back
to WITNESS_UTXO when the previous transaction is present and
`read_prev_tx_output()` fails, so an input can carry a previous transaction
that hashes to the outpoint and still take its amount and script from
WITNESS_UTXO (`amount_from_witness` is set, nobody reads it here). A legacy
signature does not commit to the amount, so this is the one place where that
would let a PSBT lie about it.

Not exploitable today: the only way to make `read_prev_tx_output()` fail on a
transaction that passes `psbt_prev_tx_matches()` is an output index past its
outputs (both parsers share the reader and the SegWit test), and such an
outpoint does not exist, so the signed transaction can never be mined. The
safety rests on that argument instead of a check.

Fixed on 2026-11-17: `psbt_plan_signing()` takes an amount as verified only
when it was read and not from WITNESS_UTXO (`amount_verified`), for both tests;
`OWN-legacy_prev_tx_bad_vout` is refused in the legacy mode.

Fix: in `psbt_plan_signing()` use `in.amount_from_witness` for both tests
(`amounts_unverified`, and "LEGACY NEEDS PREV TX"). Add a vector to the
hostile PSBT test suite: a legacy input with a valid previous transaction,
`vout` out of range and a WITNESS_UTXO with another amount; it must be
refused.

**R2. Stack depth of the BBQr inflate is not measured.**
Guard added on 2026-11-17 (`stack_check()`). Measured the same day on a board:
the vault path with MSDESC.TXT as BBQr Z peaks at 5,968 of 8,264 B (72%,
2,296 B left, plus the unused 512 B heap below); SIGN > FROM QR with a
multisig BBQr Z PSBT, signed, 5,032 B (61%). Enough margin: R2 is closed.
The guard seen on the board with a test build that fires at once (SEC-04).

`bbqr_finish()` runs at the end of `scan_ur_message()`, whose frame still
holds `burst_buffer` (850 B) and `decoded_bytes` (512 B). tinf adds about
1.7 KB (two trees of 612 B, `lengths[320]`, its state). That is about 3.3 KB
below the caller, and the deepest caller is VAULT > NEW ENTRY > MULTISIG
DESCRIPTOR > FROM QR (`vault_descriptor_from_qr()` with a `desc_wallet_t` of
about 600 B, inside the vault and the state machine of `main()`). The stack
is 8,264 B and nothing stops it from growing into the heap and `.bss`: an
overflow would corrupt RAM silently, with a seed loaded.

Fix: measure it with the existing STACK PEAK screen after a BBQr Z scan from
that vault entry and after SIGN > FROM QR with a BBQr Z PSBT, and write the
figures in `pending.md`. Cheap guard worth adding: `app_tasks()` checks that
the lowest stack word still holds `STACK_FILL` and stops with "STACK
OVERFLOW" (as `tc_fault_handler()` does) when it does not. If the margin is
small, `burst_buffer` can be wiped and its scope closed before
`bbqr_finish()`, or `decoded_bytes` moved out of the frame.

**R3. CONFIG can leave multisig with LEGACY or TAPROOT.**
`config_step()` clamps the script type to NESTED / NATIVE when MODE goes to
MULTI SIG. On SAVE, `config_run()` sets the mode first and then the script;
if `single_purpose_refresh()` is cancelled it puts the old script type back
(`bip84_script = old`), which can be LEGACY or TAPROOT, with multisig mode
already on. With TAPROOT every multisig PSBT is then refused with "SWITCH TO
NATIVE SEGWIT" (`psbt_other_single_script()`), and the screens name a script
type multisig does not have; with LEGACY multisig works as native. Nothing is
signed that should not be. It needs BACK during a derivation that is nearly
instant while the root is cached, so it is hard to reach.

Fix: when the refresh is cancelled, put the mode back too, or clamp
`bip84_script` to the range of the mode after restoring it.

**R4. Scan state that a bad code can fix.**
- `bbqr_add_part()` stores the encoding, the type and the part count of the
  first code before it decodes it, and the part length before the decode can
  fail. A first code that is damaged, or of another series, decides them for
  the whole scan: every good code that follows is refused ("BBQR OF ANOTHER
  FILE", "BBQR PARTS DO NOT MATCH") until BACK. The reason is on screen and
  no memory is at risk. Fix: set them only after the part decoded, or start
  the series again after a few refusals in a row.
- In an animated UR scan, a code with the target and no second "/" is
  decoded as a single part UR into the part buffer:
  `fountain_scratch_buffer()` clears `has_pure` but not `pure_count` or the
  mixed frames. If it fails its CRC the scan goes on with that state. All
  lengths stay bounded and the message CRC rejects the result ("UR CHECKSUM
  FAILED", new scan), so this is robustness only. Fix: decode the single
  part only while no part has been received, or call `fountain_init()` when
  it fails.

**R5. SD file list: files past directory position 99.** Fixed on 2026-11-18 as proposed below (`sd_pick_file()`, host test `run_over_99()`, device test SD-06).
`sd_pick_file()` keeps the directory position of each file in `order[99]`
(one byte each) and stops building the list at the first file, in
alphabetical order, whose position is 99 or more. A card with over 99 files
of the extension shows a shorter list, or "no file" when the first name in
the alphabet is one of those, with no reason on screen (rule 4). Not a
security issue. Fix: skip such a file instead of stopping, and say "MORE
FILES NOT SHOWN" when any was left out.

### 7.4 Notes

- **I1. `desc_unpack()` does not bound `origin_len`.** It is copied as read
  (0..255). Today it is only compared with 4, and a vault record is
  authenticated with the vault key, so nothing follows from it. Refuse a
  value over `DESC_ORIGIN_MAX` there, to keep the unpack strict as its
  comment says.
- **I2. Deterministic Schnorr nonces.** `psbt_taproot_sign()` uses 32 zero
  bytes of auxiliary randomness, which BIP340 allows. The signature is
  verified against the output key computed from the public key alone before
  it leaves, which also covers a wrong tweak or a fault during signing.
  Mixing the key press pool into `aux` would be defence in depth against
  fault attacks, at the price of signatures that the host tests could no
  longer compare byte for byte. Open: the user decides.
- **I3. BBQr has no checksum.** As the code says, the PSBT parser and the
  review are the check: what is shown is what is signed, so a damaged series
  cannot change a destination unseen. A descriptor read as a BBQr text file
  is covered by its BIP380 checksum when it has one and by the Base58Check
  of each key.

### 7.5 Checked and found sound

- BBQr decoder: every part is placed inside the buffer (`off + blen` against
  the capacity, the last part never longer than the others), a repeated part
  is compared and never rewritten, the header digits and both alphabets are
  validated, leftover base32 bits must be zero. The inflate reads the
  compressed copy from the end of the buffer and its output is limited to
  the bytes before it; tinf checks every write and every back reference
  against those limits, and the leftover is wiped. UR and BBQr cannot be
  mixed in one scan, so neither overwrites the other's data in the shared
  buffer. A code over 850 characters is dropped whole.
- Taproot: the BIP341 signature message matches the specification for the
  key path with SIGHASH_DEFAULT and ALL (no other type passes the plan or
  the hash function); the 65 byte form is used only for ALL. The input
  script must be the P2TR of the BIP86 output key of our own derived key, so
  TAP_INTERNAL_KEY, TAP_MERKLE_ROOT and script path leaves in the PSBT
  cannot redirect a signature (a derivation with leaf hashes is refused).
  Clearing `amounts_unverified` in taproot mode is right: every amount and
  script is in the signed hash, and a missing one fails before signing.
  BIP340 signing follows the specification and wipes its secrets.
- BIP371 fields: sizes checked in `map_check()`, the leaf hash count of a
  Taproot derivation is bounded by the value length before it is used.
- Legacy: the signature hash serialization is right for P2PKH and
  SIGHASH_ALL; the scriptCode is built from our own key, not taken from the
  PSBT; the input script must be the P2PKH of that key.
- Nested segwit, single and multisig: the redeem script is computed here,
  never taken from the PSBT; the descriptor's script type must match the
  one in CONFIG before it is loaded and while it is used.
- KEF slots on the SD card: the length is bounded before the copy, the text
  goes through the same parser and key check as an encrypted QR, a wrong key
  or damaged text never loads anything, `size_pointer` is set from the
  decrypted length. Writing reads back and compares.
- Vault with a descriptor from QR: the scan overwrites the vault list in the
  shared buffer, and the save reads the header again from the card
  (`vault_reserve()`), so nothing stale is used.
- SCAN ADDRESS: the scanned text is bounded before it is kept, and it is
  stored in the address cache marked invalid, so it is never shown as ours.
- Text buffers of the new screens (account file, address menus, entropy
  warning, CONFIG, password and KEF screens): sizes checked against the
  longest text each can hold.
- The GCM change (one GHASH function for header and data) is equivalent to
  the two copies it replaced.

## 8. Signing: the decision as an attacker, and side channels (2026-11-16)

Third pass, by Fable 5.2, on the signing code only: what
`psbt_plan_signing()` and `psbt_sign_inputs()` can be made to sign or to call
ours, and what the signing arithmetic leaks. No firmware code was changed.
Ten hostile PSBTs were added to the test suite and run; the side channel part
comes from reading the code, nothing was measured on the board.

### 8.1 Summary

| Id | Severity | Finding |
|---|---|---|
| R1 | Low | Confirmed by a test: a legacy input is signed as verified with its amount taken from the witness UTXO (see 7.3) |
| S1 | Low (physical access) | No protection against power or EM analysis: the coordinate blinding of trezor-crypto was removed by a local edit, the table lookups are indexed by the secret, the nonces are deterministic |
| S2 | Note | Signing time is constant except for three things that leak nothing useful |
| S3 | Note | An output to our own key of the other mode (single sig / multisig) is called change |

### 8.2 The signing decision

Tried, as PSBTs or by reading the code, with what the firmware does:

| Attack | Result |
|---|---|
| Output to a script tree that commits to our key, annotated as our change | Refused, "CHANGE KEY MISMATCH" (`OWN-taproot_change_script_tree`): only the BIP86 key of our own derived key is ours |
| Taproot input whose output key commits to a merkle root | Refused, "INPUT KEY MISMATCH" (`OWN-taproot_input_script_tree`); TAP_MERKLE_ROOT and TAP_INTERNAL_KEY are never read |
| Our key in a derivation with leaf hashes (script path) | Refused (`OWN-taproot_leaf_hash`) |
| SIGHASH_NONE, or ALL with ANYONECANPAY, on a taproot input | Refused, "SIGHASH NOT ALL" (`OWN-taproot_sighash_none`, `_acp`); explicit ALL signs with the 65 byte form (`_sighash_all`) |
| A TAP_KEY_SIG of zeros already in the input | "NOTHING TO SIGN" (`OWN-taproot_key_sig_present`): it is never replaced, and nothing is signed |
| An m/86' key in a 33 byte derivation | Refused (`OWN-taproot_plain_derivation`) |
| Legacy input, previous tx without that output, amount in a witness UTXO | **Signed, and not marked unverified** (`OWN-legacy_prev_tx_bad_vout`). This is R1: harmless only because that outpoint cannot exist. Listed in `malicious_gaps.txt` until it is fixed |
| Lie about the amount of one of our segwit v0 or taproot inputs | The signature commits to it (BIP143, BIP341): invalid on chain. With taproot every input's amount and script is committed, so the fee shown is the fee paid |
| Lie about the amount of a foreign input | Changes the fee shown, never what leaves our wallet; "AMOUNTS NOT VERIFIED" when its previous tx is missing |
| Change at a far index, or on the receive chain | Ours (it is), with "HIGH CHANGE INDEX" over 100 past our inputs; chain 0 is shown as TO YOU |
| Change with our fingerprint on a path of 6 elements, another account, another script type or another purpose | Not ours: counted and shown as a destination |
| Multisig change without the descriptor | Never ours: "CHANGE NOT VERIFIED" |
| Multisig change that matches the descriptor only with a cosigner key swapped | Not ours: the script is rebuilt from every xpub of the descriptor |
| Witness script, redeem script or scriptCode supplied by the PSBT | The scriptCode of single sig is built from our key; a witness script must hash to the script being spent and hold our derived key; the redeem script of nested is never read |
| A plan that vets one set of inputs and a loop that signs another | Both use the same `psbt_check_owner()` on the same buffer, parsed again after each signature; an input the plan refuses stops the whole PSBT before any signature |

Nothing was found that makes the device sign what it does not show, or call
an output ours that the seed (single sig) or the descriptor (multisig) does
not own, apart from R1.

**S3. Change of the other mode.** `psbt_check_owner()` does not look at the
mode for outputs: in multisig mode an output to our own single sig key
(m/84' of the same seed and account) is VERIFIED and counted as change, and
in single sig mode an output to the loaded multisig wallet is too. The coins
do stay with this seed, so nothing is lost, but in multisig they leave the
shared wallet for this signer alone and the review says CHANGE. A cosigner
has nothing to gain from it against this user. Worth a different label ("TO
YOUR SINGLE SIG") if the flash allows; open, the user decides.

### 8.3 Side channels

What handles the private key and the nonce: `hdnode_private_ckd()`,
`ecdsa_sign_rfc6979()`, `bip340_sign_even()`, `psbt_taproot_sign()`, and
under them `point_multiply()`, `bn_inverse()`, `bn_multiply()`, `bn_mod()` and
HMAC-SHA256.

**Timing: sound.** `point_multiply()` runs a fixed 63 windows of four
doublings and one addition with conditional negation (`bn_cnegate()`), with
no branch on the scalar. `bn_inverse()` is the "fast" variant
(`USE_INVERSE_FAST` 1), which has constant control flow; its memory accesses
depend on the data, which costs no time on a core without a cache. The
bignum multiply, reduce, add and compare are constant time, and so is
HMAC-SHA256. The comparisons with `memcmp()` in the signing path are of
public values (public keys, hashes, addresses); the tag of an encrypted seed
uses `consteq()`.

**S2. What does vary, and why it does not matter.**
- Low R grinding: the number of attempts (two on average, about one
  signature time each) depends on the key and the message. It tells how many
  discarded nonces had a high R, a predicate on hash outputs that gives no
  linear relation on the nonce used. Bitcoin Core and libsecp256k1 do the
  same.
- Schnorr: one subtraction is skipped or not with the parity of R's y
  (`bip340_sign_even()`), one bit about which of k and n - k the hash gave;
  the R of the signature is public either way.
- The retries for a nonce of zero or over the order happen once in 2^128.

**S1. Power and EM analysis: no protection.** `crypto/ecdsa.c` is not only
trimmed: `curve_to_jacobian()` was edited to start every multiplication at
z = 1 (its comment, in Spanish, says the random generator was dropped as too
heavy). In trezor-crypto that random z is the countermeasure against
differential power analysis of the scalar multiplication. Without it, and
with the eight entry table indexed by the scalar's windows, the same key
always follows the same intermediate values. `ecdsa_sign_rfc6979()` also
inverts the nonce without the blinding trezor-crypto uses, and the nonces of
both schemes are deterministic, so one message can be signed again and again
with identical traces.

What it takes to use this: probes on the device while it signs with the
seed loaded, many signatures, and equipment. That is outside the threat model
of section 1 (the device keeps nothing when off, so the attacker must be
there while the owner signs), which is why this is low. A timing attack, the
kind that needs no contact, does not apply.

Options, none needing a random source the device does not have: take z, and
a blinding factor for the nonce inverse, from a hash of the scalar and a
counter (unknown to the attacker and different for each key and message, so
traces of different signatures no longer line up; it does not hide a single
trace); or leave it and say so in the documentation. Either way
`THIRD_PARTY_NOTICES.md` and `crypto/README.md` should say that `ecdsa.c`
carries this local change.

Decided by the user on 2026-11-16: left as it is. The device keeps no
secrets; the key exists only while a seed is loaded. The threat model
document (see `pending.md`) is to say so.

**Faults.** Both schemes verify the signature before it leaves (ECDSA
against the public key, Schnorr against the output key computed from the
public key alone), which covers a fault after the nonce is fixed, the case
that would leak the key. A fault before that gives a valid signature with
another nonce, which leaks nothing.

**Residues.** As L1 says, HMAC and SHA-256 leave key dependent words on the
stack; `stack_wipe()` on UNLOAD SEED and AUTO UNLOAD clears them. The new
Schnorr code wipes its scalars and the tweaked secret; the SHA-256 context of
`tagged_scalar()` is left on the stack like the others.

### 8.4 Tests added

`test/psbt/gen_malicious_own.py` writes ten more vectors
(`OWN-legacy_prev_tx_bad_vout` and nine `OWN-taproot_*`), with their truth in
`malicious_truth.txt` and their outcome in every mode frozen in
`malicious_expected.txt`. `test_malicious.exe`: 135 vectors, 26 reviewed
gaps (one new, R1), 0 problems, the 20 invalid BIP174 vectors refused.

## 9. Bootloader: signature check, update flow and flash lock (2026-11-16)

Fourth pass, by Fable 5.2, on the bootloader as committed in 67706af (it has
not changed since). Read in full: `main.c`, `hex_flash.c`, `boot_lms.c`,
`boot_sha.c` and the update helpers of `boot_ui.c`. Petit FatFs and `diskio.c` are in section 10. Not reviewed: the display
driver, the linker script. Nothing
was changed in the bootloader. Its host tests were run (`test_boot_lms.c`
built again, `test_hex_flash.exe` as it was): both pass. Nothing was tried on
the board, and the flash lock in particular has still never run on one.

### 9.1 Summary

| Id | Severity | Finding |
|---|---|---|
| B1 | Medium | A write pass that fails leaves a half written app that OK then starts, under a screen that says "APP ERASED"; with a card that answers differently the second time, code nobody checked runs once, right after "OFFICIAL FIRMWARE" **Fixed on 2026-11-17** |
| B2 | Low | The app area is not write protected, although the same register could cover it at no cost |
| B3 | Low | The lock is not read back and has not been tried on a board |
| B4 | Low | Programming is trusted to the error flags: the flash is never read back |
| B5 | Low | The checking pass accepts things the writing pass refuses or ignores |

### 9.2 Medium

**B1. A failed write pass does not erase what it wrote.**
Fixed on 2026-11-17 the sturdier way (below): the reset block double-word is
programmed last, by `hexflash_commit()`, after the hash comparison. Tried on
a board the same day: card taken out while writing, OK retried the update;
power cut while writing, the update started again at power-on.

Pass 2 programs the flash record by record. It can stop half way with "SD
READ ERROR", "FILE DAMAGED" or "FLASH WRITE FAILED" (`process_hex_file(true)`
returning an error). `fail_app_erased()` then shows "APP ERASED: OK RETRIES",
but only the "FILE CHANGED" path erases again (`hexflash_begin()`); in the
others the records written so far stay. `finish()` waits for OK and tests
`app_missing()`, which looks only at the reset block, at 0x1D003800, near
the start of the file and so written early: the app is not "missing", and OK
jumps into it.

With an honest card this starts half an application, with undefined results,
under a screen that says something else (rule 4). With a card that answers
differently on the second read (a card with its own controller firmware, or
an emulator in the slot) it is an attack: pass 1 reads the official file,
the signature verifies, the screen says "OFFICIAL FIRMWARE" with the right
SHA-256; pass 2 gets other records and then a read error before the end, so
the hash comparison that would catch it is never reached. OK then runs that
code. The state page was erased at the start, so every later boot shows
"UNOFFICIAL FIRMWARE / NO SIGNATURE RECORD", but the first run comes with no
warning, straight after an update the user believes was official, and it is
the run in which they are likely to load a seed.

Needs a hostile card, not just a hostile file, hence medium.

Fix: `fail_app_erased()` erases the page of the reset block
(`nvm_erase_page(HEXFLASH_APP_PHYS_RESET & ~(HEXFLASH_PAGE_SIZE - 1u))`) or
the whole area before `finish()`, so the screen is true and OK retries. One
call; the code area has 96 B free. Sturdier, if room is found: program the
double-word of the reset block last, after the hash comparison, so that no
interrupted update (a power cut included) leaves anything that can start.

### 9.3 Low

**B2. The app area stays writable by the app.**
Fixed on 2026-11-17: locked at `HEXFLASH_APP_PHYS_END`.

`JumpToApp()` locks NVMPWP at `HEXFLASH_APP_PHYS_BASE`: the bootloader and
its state page are protected, the app is not. An app that is taken over
while it runs (a bug like C1) can rewrite itself and stay, and the state
page keeps saying "official": the record proves what the bootloader
installed, not what is in the flash now.

NVMPWP protects everything below one address, and the only page the app
writes is the settings page, the last one. Locking at
`HEXFLASH_APP_PHYS_END` (0x1D03F800) instead would protect the bootloader
and the whole app and leave the settings writable, with no extra code:
after a boot, the program flash is then what the bootloader put there (or a
programmer). To try on a board first: that the settings still save, since
the manual's wording on a boundary that is the first address of a page
leaves room for doubt.

**B3. The lock is taken on trust.**
Fixed on 2026-11-17: SETTINGS > MCU SERIAL NUMBER reads it back. Seen on a
board the same day: "FLASH LOCK OK" with the B2 limit, and a setting still saves;
"FLASH NOT LOCKED" with a test bootloader locking at the old limit.

`nvm_protect()` writes the registers and the jump follows; nothing reads
them back, and per `pending.md` this code has not run on a board yet. If the
unlock sequence did not take (the keys and the write are separate
instructions in a small function, which should be fine), the device would
work the same and protect nothing. The bootloader has no room for a check
with a message, but the app has: SETTINGS can show whether NVMPWP and NVMBWP
hold the expected values with both unlock bits clear ("FLASH LOCK OK" /
"FLASH NOT LOCKED" in red). That also gives the validation document a test
for it. A second test for the same document: a debug build of the app that
tries to erase the state page must fail.

**B4. No read back of what is programmed.**
`nvm_execute()` returns the WRERR / LVDERR flags and nothing compares the
flash with the data. The SHA-256 that is compared at the end is of the file
bytes read from the card, twice, never of the flash. A double-word that
programs wrong without raising a flag gives a damaged app recorded as
official. Fix, when there is room: compare each double-word after writing it
(`nvm_read()` is there), or hash the app area once at the end and keep that
hash in the state page.

**B5. The two passes do not check the same things.**
- An extended address record whose length is not 2 passes
  `hexflash_check_record()` and fails `hexflash_write_record()`: the file is
  called good, the app is erased, and then the update fails.
- A line of 190 characters or more is skipped without a word in both passes
  (`record.len < 190`): it should be "FILE DAMAGED".
- `ConvertAsciiToHex()` takes every character from '0' to 'f' as a digit,
  including ':' to '@' and 'G' to '`', so different texts give the same
  record.
None of this lets a file write outside the app area or changes what the
signature covers (the hash is of the file bytes, and both passes read them
the same way). They are about pass 1 keeping its promise that a file it
accepted will install.

### 9.4 Notes

- The card's file system is parsed by Petit FatFs before anything is
  checked: see section 10. A crafted file system can stall the update, no
  more. Whoever can put a card in and hold OK + BACK can also use a
  programmer (`CP` is off, decided), so this was not taken further.
- A unit programmed at the factory with the unified hex has a blank state
  page and shows "UNOFFICIAL FIRMWARE / NO SIGNATURE RECORD" at every boot
  until it installs a signed update from a card. That is the design; the
  production procedure has to include that step.
- One LMS index signs one file: the scheme breaks if an index is used
  twice. That is kept in `SIGNATURES.md`, outside the code.
- No version in what is signed: an older signed firmware installs as
  official. Decided on 2026-11-11.

### 9.5 Checked and found sound

- `boot_lms_verify()` against RFC 8554, algorithms 4b and 6a, line by line:
  the message hash with D_MESG, the 34 digits and their checksum (w = 8, no
  shift), each chain run from its digit to 254 with the index and step in
  the hash, the one time key with D_PBLC, the leaf with D_LEAF, the ten
  inner nodes with D_INTR and the sibling on the side the node number
  gives, and the comparison with the root. The three type fields and the
  leaf number are checked; the signature has one fixed length. Nothing
  secret is handled.
- `boot_sha.c`: padding and length are right; one context, used in turn by
  the file hash and the signature check, never both at once.
- `process_hex_file()`: the carry of a split record cannot pass the 2,048
  byte buffer; a record is converted only under 190 characters, into 200
  bytes, and used only up to the length its checksum covered.
- The writing pass drops any byte outside the app area on its own, without
  relying on the first pass, so even a card that changes its answers cannot
  reach the bootloader, the state page, the configuration words or the
  settings page.
- The state page: erased before the app is touched, written last and only
  after the hash of the second pass matched the one shown, its magic word in
  the last write. Every interrupted update ends as "unofficial", never as
  official.
- Every reset starts in the boot flash, which is write protected; the app
  cannot skip the bootloader, and the lock is set on every path that starts
  it (normal boot, after the warning, after an update).

## 10. Bootloader: Petit FatFs and the SD layer (2026-11-16)

The part section 9 left out: `pff.c` (Petit FatFs R0.03a, built read only,
FAT16 only, no seek, no write) and `diskio.c`, read in full with a card whose
contents are chosen by an attacker in mind. Nothing was changed.

No way was found for a card to write outside a buffer or to make the
bootloader write anything: two low findings, both ways to stall it.

| Id | Severity | Finding |
|---|---|---|
| P1 | Low | A boot sector with zero sectors per cluster divides by zero in `pf_mount()`: the bootloader stops with no message |
| P2 | Low | The file size of the directory entry is trusted: a card can keep the checking pass reading for hours |

**P1. Sectors per cluster is not checked.** `pf_mount()` takes
`BPB_SecPerClus` as it is and divides by it (`mclst = (...) / fs->csize`).
With zero, the division traps on this compiler and
`_general_exception_handler()` loops for ever: the screen stays on "READING
SD CARD" until the power is cut (rule 4). The current app is not touched. A
value that is not a power of two is also accepted and only gives wrong
sector numbers, which are read, never written. Fix: return
`FR_NO_FILESYSTEM` unless the value is a power of two (about 16 B; it is an
edit to vendored code, to be marked as such).

**P2. No limit on the size of UPDATE.HEX.** `pf_read()` follows the cluster
chain while the file pointer is under the size in the directory entry, up to
4 GB, and a chain may loop. A card made for it keeps pass 1 reading and
hashing for hours; a loop of valid records does not even end in an error.
Nothing can be pressed to leave. The app is not touched in pass 1. Fix:
refuse a file over a fixed size before reading it (the app area is 240 KB,
its HEX text under 700 KB: 1 MB is ample), "FILE DAMAGED".

### Checked and found sound

- Every read goes into a buffer of the caller with a count the caller
  fixed: 2, 16 and 36 bytes in the mount, 32 for a directory entry, 2 for a
  FAT entry, and in `pf_read()` never more than was asked for, whatever the
  card says. Offset plus count is at most 512 in every call of
  `disk_readp()`, so its skip of the rest of the sector cannot underflow.
- Cluster numbers from the card are range checked before use
  (`get_fat()`, `clust2sect()`); the FAT type is accepted only as FAT16, so
  the cluster count is under 65,527.
- The root directory search ends at the entry count of the boot sector, at
  most 65,535 entries.
- A card that stops answering ends every wait: the command, token and
  ready loops are counted.
- `disk_writep()` is an empty stub and the write code of Petit FatFs is not
  compiled: the bootloader cannot write to the card.
- The card's data has no CRC at this layer (SPI mode, CRC off). It does not
  matter here: the file is hashed in both passes, the hashes must match, and
  the signature is over that hash.

## 11. The vendored cryptography against its upstream (2026-11-16)

`src/crypto/` was edited by hand and with another assistant before it was
trimmed. Every file was compared with trezor-crypto as it is today in
trezor-firmware (`crypto/`, main branch, fetched for this pass), the two
rewritten files function by function with comments, spacing and line breaks
ignored. Nothing was changed.

**No arithmetic was altered and no functional error was found.** What was
lost are the two protections against power and EM analysis (C1, C2, which is
S1 of section 8 with its cause), some assertions, and the documentation of
what was changed.

### 11.1 File by file

| File | Against upstream |
|---|---|
| `bignum.c`, `bignum.h` | Identical, apart from two `assert()` lines that only differ between upstream versions |
| `consteq.c/h`, `ripemd160.c/h`, `segwit_addr.c/h`, `memzero.h` | Identical |
| `aes/` (13 files) | Identical except the three edits marked "Seedmate": `#undef v2` in `aestab.c`, the 256 bit only key setup and the single GHASH function in `aesgcm.c` (equivalent, see 7.5) |
| `options.h`, `secp256k1.c/h`, `ecdsa.h`, `bip32.h` | Trimmed: other curves, hashers and declarations removed. The curve constants are untouched |
| `ecdsa.c` | 31 functions removed (signing, verification, recovery, DER, addresses, the random nonce). The 16 kept are the same statements as upstream except the changes below |
| `bip32.c` | 18 functions removed, the rest rewritten on the firmware's own `HmacSha512()`; the derivation is the same algorithm, see below |

### 11.2 Changes in `ecdsa.c`

- **C1. `curve_to_jacobian()` no longer randomizes z.** Upstream draws a
  random z and scales x and y by it; here z is 1 (the Spanish comment says
  the random generator was dropped as too heavy). This is the blinding of
  the scalar multiplication.
- **C2. `point_multiply()` indexes its table with the secret.** Upstream
  copies the entry with `point_select()`, which reads all eight and keeps
  one without a data dependent access; here it is `&pmult[bits >> 1]`. On
  this core that costs no time (no cache), but the address read depends on
  four bits of the scalar in each of the 64 windows, which is what EM and
  power analysis look for.
- **C3. Assertions removed** in `point_jacobian_add()`,
  `point_jacobian_double()` (`-3 <= a <= 0`) and `point_multiply()` (the
  recoded scalar is odd). They guard against misuse with another curve and
  cost nothing in a release build. No effect with secp256k1.
- `LOCAL_CONFIDENTIAL` dropped from the locals of `point_multiply()`: it is
  a placement attribute in Trezor's builds, nothing here. The scalar copy
  and the Jacobian point are still wiped; the table `pmult` holds public
  multiples of the point.
- `ecdsa_read_pubkey()` returns 0 for a NULL curve instead of assuming
  secp256k1: stricter, fine.
- `ecdsa_get_public_key33()` is upstream's `tc_ecdsa_get_public_key33()`
  with one more wipe: fine.
- The formulas of `point_double()`, `point_add()`, `point_jacobian_add()`,
  `point_jacobian_double()`, the window recoding of `point_multiply()`,
  `uncompress_coords()` and `ecdsa_validate_pubkey()` are statement for
  statement upstream's.

### 11.3 Changes in `bip32.c`

- `hdnode_private_ckd()` is upstream's `hdnode_private_ckd_bip32()` with the
  HMAC replaced by `HmacSha512()`: the same data layout, the same retry for
  a result of zero or over the order, the same wipes. Its working variables
  are locals instead of statics, all wiped on the normal exit; the two early
  exits happen before any secret is copied. It also clears
  `is_public_key_set`, which upstream leaves to the caller.
- `hdnode_from_seed()`: same, with the retry of SLIP-10; `HmacSha512()`
  writes its output only at the end, so the in place call of the retry is
  safe.
- `hdnode_validate_private_key()` and `hdnode_validate_public_key()` refuse
  a curve without parameters instead of accepting it: stricter.
- `hdnode_get_address_raw()` is written out with the firmware's SHA-256 and
  RIPEMD-160: right.

### 11.4 What the tests cover and what they do not

The host tests build these same files, so the arithmetic is exercised end to
end: BIP32 against published xpubs and addresses of four script types,
ECDSA and Schnorr signatures byte-identical to an independent Python signer
and to the BIP340 / BIP341 vectors, BIP85 and NIP-06 vectors, the AES-GCM
and KEF vectors. They do not cover the edge cases (the point at infinity, a
scalar of zero or over the order, an invalid public key in a descriptor) or
anything about side channels.

### 11.5 Documentation

`crypto/README.md` is upstream's own and lists algorithms that are no longer
here (BIP39, Ed25519, SHA3, a random source...). Neither it nor
`THIRD_PARTY_NOTICES.md` says that `ecdsa.c` and `bip32.c` are modified, and
`CLAUDE.md` calls the folder "trimmed". The MIT license asks for nothing
more than the notice, which is there; this is about anyone, an auditor
included, being told what differs from the library they know.

## 12. Work list from the passes of 2026-11-16

Everything found in sections 7 to 11, in the order suggested for fixing it.
Done so far: items 1 (R1), 3 (B3), 13 (B1) and 14 (B2), and 2 (R2), 2026-11-17. "Open" means the user has not decided whether to do
it. Each fix needs the build, the memory delta, the host tests and an entry
in `docs/validation/firmware_validation.html` where a device test applies.

### Firmware (`SW/src`)

| # | Id | What to do | Where | Done when |
|---|---|---|---|---|
| 1 | R1 | **Done on 2026-11-17**: `amount_verified` (an amount read and not from WITNESS_UTXO) sets `amounts_unverified` and refuses legacy; `OWN-legacy_prev_tx_bad_vout` now "LEGACY NEEDS PREV TX" in the legacy mode, its gap removed. Was: use `in.amount_from_witness` instead of `in.prev_tx == NULL` for `amounts_unverified` and for "LEGACY NEEDS PREV TX" | `psbt_plan_signing()` in `main.c` | `OWN-legacy_prev_tx_bad_vout` is refused in the legacy mode and marked unverified in the others; remove its line from `test/psbt/malicious_gaps.txt`, run `test_malicious.exe --update` and review the diff |
| 2 | R2 | **Done on 2026-11-17**: measured on a board (vault path 5,968 B, SIGN 5,032 B of 8,264). Guard (+148 B): `stack_check()` in `app_tasks()` and `led_busy()` stops with "STACK OVERFLOW" when the lowest stack word lost `STACK_FILL`; device test SEC-04. Was: measure the stack: STACK PEAK after VAULT > NEW ENTRY > MULTISIG DESCRIPTOR > FROM QR with a BBQr Z code, and after SIGN > FROM QR with a BBQr Z PSBT. Add the guard: `app_tasks()` stops with "STACK OVERFLOW" when the word at `stack_floor()` is not `STACK_FILL` | `main.c` (`app_tasks()`, `stack_paint()`); device | Figures written in `pending.md`; the guard shown to fire in a debug build |
| 3 | B3 | **Done on 2026-11-17** (+124 B): "FLASH LOCK OK" / "FLASH NOT LOCKED" under the stack peak, device tests BOOT-16 and SET-06. Was: show in SETTINGS > MCU SERIAL NUMBER whether NVMPWP and NVMBWP hold the values the bootloader sets with both unlock bits clear: "FLASH LOCK OK" green / "FLASH NOT LOCKED" red | `main.c` or `settings.c`; values in `bootloader/src/main.c` `JumpToApp()` | Seen on a board started through the bootloader (and "NOT LOCKED" when run from the debugger) |
| 4 | R3 | When `single_purpose_refresh()` is cancelled in `config_run()`, put the mode back as well (or clamp `bip84_script` to the mode's range) | `config_run()` in `main.c` | Multisig can never be left with LEGACY or TAPROOT |
| 5 | R4 | BBQr: set encoding, type, count and part length only after the first part decoded. UR: decode a single part code only while no fountain part was received, or `fountain_init()` when it fails | `bbqr_add_part()` in `bbqr.c`; `scan_ur_message()` in `main.c` | New cases in `test/bbqr/`: a damaged first code followed by a good series completes |
| 6 | R5 | **Done on 2026-11-18** (+96 B). Was: SD file list: skip a file whose directory position is 99 or more instead of ending the list, and say "MORE FILES NOT SHOWN" | `sd_pick_file()` in `main.c` | Case in `test/sdfiles/` or a device test with over 99 files |
| 7 | I1 | `desc_unpack()` refuses `origin_len > DESC_ORIGIN_MAX` | `descriptor.c` | Case in `test/psbt/test_descriptor.c` |
| 8 | C3 | Put back the three `assert()` of upstream in `ecdsa.c` (they vanish with NDEBUG) | `crypto/ecdsa.c` | Build unchanged in size |
| 9 | 11.5 | Say what is modified: a short `crypto/README.md` of our own (what is kept, what is edited and why), the same in `THIRD_PARTY_NOTICES.md` (ask first: outside SW) and in `CLAUDE.md`; translate the Spanish comment in `ecdsa.c` | docs | - |
| 10 | S1, C1, C2 | **Not to be done**, decided by the user on 2026-11-16: the device keeps no secrets, the key is in RAM only while a seed is loaded and it signs. For the record, it would be: restore the blinding of `curve_to_jacobian()` and `point_select()` in `point_multiply()`. There is no random source: z can come from a hash of the scalar and a counter, or from a pool mixed with key press times. Costs flash (`point_select()` and one more hash per multiplication) and time per signature; measure both | `crypto/ecdsa.c`, `psbt_sign.c` | Host tests unchanged (the results do not depend on z); signing time on the board noted |
| 11 | I2 | **Open** (the user has not decided; it is of the same family as item 10). Schnorr with auxiliary randomness from the key press pool instead of zeros | `psbt_taproot_sign()` | The byte-identical comparison with the Python signer would have to pass the same aux |
| 12 | S3 | **Open.** Another label for an output to our own key of the other mode (single sig key while in multisig, and the reverse) | `psbt_check_owner()`, `psbt_output_kind()` | - |

### Bootloader (`bootloader/src`, ask before touching; full since B1 and B2; bump nothing: BOOT_VERSION stays 1.0 until units ship)

| # | Id | What to do | Where | Done when |
|---|---|---|---|---|
| 13 | B1 | **Done on 2026-11-17**, the sturdier way: `hex_flash.c` keeps the reset block double-word in RAM (`reset_dw`) and `hexflash_commit()` programs it after the hash comparison; the extra erase on "FILE CHANGED" went (the reset block is still blank there). +92 B, 4 B left. Host test: the reset block stays blank through a page rewrite and after an update stopped at every tenth of the app's records. Was: `fail_app_erased()` erases the page of the reset block (`nvm_erase_page(HEXFLASH_APP_PHYS_RESET & ~(HEXFLASH_PAGE_SIZE - 1u))`) before `finish()`, so OK retries instead of starting a half written app. Better if it fits: program the reset double-word last, after the hash comparison | `boot_ui.c`, `hex_flash.c` | Device: pull the card during "WRITING THE NEW APP"; the screen says erased and OK retries. Host case in `bootloader/test/test_hex_flash.c` if the logic moves to `hex_flash.c` |
| 14 | B2 | **Done on 2026-11-17**: locked at `HEXFLASH_APP_PHYS_END`; the bootloader is now full (the address takes one instruction more). Device test BOOT-16. Was: lock NVMPWP at `HEXFLASH_APP_PHYS_END` instead of `HEXFLASH_APP_PHYS_BASE` (the app area is protected too, the settings page is not) | `JumpToApp()` in `main.c` | Device: a setting still saves; item 3 shows the new value |
| 15 | B5 | The checking pass refuses what the writing pass would: an extended address record whose length is not 2, a line of 190 characters or more, a character that is not a hex digit | `hexflash_check_record()`, `process_hex_file()`, `ConvertAsciiToHex()` | Cases in `test_hex_flash.c` |
| 16 | P1 | `pf_mount()` returns `FR_NO_FILESYSTEM` unless sectors per cluster is a power of two (mark the edit: vendored) | `pff.c` | A card image with zero there says "SD CARD NOT FAT16" |
| 17 | P2 | Refuse an UPDATE.HEX over 1 MB before reading it | `process_hex_file()` | "FILE DAMAGED" at once |
| 18 | B4 | When there is room: compare each double-word after programming it | `program_dw()` in `hex_flash.c` | Host test with a mock that corrupts one write |

Item 13 took 92 of the 96 B free and item 14 the last 4 (2026-11-17): the
bootloader is full, 15 to 17 wait for space.

### Signing page and procedure (`tools/lms_sign.html`, `SIGNATURES.md`; both in `signatures/` since 2026-11-17)

| # | Id | What to do | Where | Done when |
|---|---|---|---|---|
| 19 | T1 | **Done on 2026-11-17** (host tests in `test_lms.js`; tried in a browser, not yet on the signing computer). The page reads `SIGNATURES.md` and previous `UPDATE.SIG` files (index = first 4 bytes), refuses an index already used for another file hash and offers the next free one. Add the rule: record the index before the signature leaves the page, test signatures included | `lms_sign.html`, `SIGNATURES.md` | Cases in `test/lms/test_lms.js` for the parsing and the refusal |
| 20 | T2 | Open: `navigator.onLine` only says that a network adapter is up (cable, virtual or Bluetooth adapters), not that there is internet, so the signing computer shows "online" with Wi-Fi off; blocking on it would block always. The procedure part is done (`SIGNATURES.md`). Was: SIGN disabled while online unless a second tick; the signing procedure written in `SIGNATURES.md` (offline computer, private window, no extensions, close the browser after) | same | - |
| 21 | T3 | **Done on 2026-11-17**: the hash is in `SIGNATURES.md`, `test_lms.js` fails when it is stale, `signatures/.gitattributes` keeps git from changing the line endings. Publish the SHA-256 of `lms_sign.html` with each release and in `SIGNATURES.md`; check it before typing the words | docs, release procedure | - |

### Device tests that these passes ask for

- The flash lock, never run on a board (item 3 makes it visible).
- STACK PEAK on the two BBQr paths (item 2).
- An update interrupted in the write pass (item 13), before and after the fix.

## 13. The firmware signing page (2026-11-16)

`tools/lms_sign.html`, read in full: the other half of what section 9
checked. Its host tests were run and pass (`test/lms/test_lms.js`: byte-exact
against RFC 8554 Test Case 2, the firmware parameters, refusals;
`verify_lms.py`, the independent verifier, on the sample signature). Nothing
was changed.

**The cryptography is right.** What can go wrong is the use: one index
signing two files, and the place where the words are typed.

| Id | Severity | Finding |
|---|---|---|
| T1 | Medium | Only a checkbox and a hand kept list stand between a slip and a signing key broken for good |
| T2 | Low | The page warns when the computer is online but signs all the same |
| T3 | Low | Nothing tells that the page itself is the published one before the words are typed into it |
| T4 | Note | A 12 word mnemonic gives the key 128 bits; 24 words match the scheme |

**T1. Index reuse depends on the person.** The page keeps no state (it
cannot: it is an offline file). It refuses a second file on an index only
within one session (`usedThisSession`), and otherwise asks for a tick on "I
checked SIGNATURES.md". Two different files signed with one index are enough
to forge: for each of the 34 chains the lower of the two digits is then
public, and a file whose digits are all at or above them is found with a few
million hashes. Every release publishes its signature, so one test build
signed with an index that a release later takes is all it needs. There is no
revocation and no version check, and the public key is in a bootloader that
only a PICkit can replace: a forged file would be "OFFICIAL FIRMWARE" on
every unit sold, for ever. `SIGNATURES.md` says all this; the page does not
help beyond the tick.

Fix: let the page check instead of the person. It takes `SIGNATURES.md` (and,
or instead, the `UPDATE.SIG` files already made: the index is their first
four bytes) and refuses an index found there with another file hash, offers
the next free one, and gives the line to append, as it already does. The tick
stays for what the page cannot see: signatures made and never recorded. Rule
to add to `SIGNATURES.md`: record the index before the signature leaves the
page, test signatures included.

**T2. Online is only a warning.** `navigator.onLine` shows "THIS COMPUTER
LOOKS ONLINE", and SIGN works the same. The page's CSP stops the page from
sending anything, but not a browser extension, which reads the text area
whatever the CSP. Fix: keep SIGN disabled while online unless a second tick
says it is on purpose, and write the procedure down in `SIGNATURES.md`: a
computer that is offline and stays offline until the browser is closed, a
private window with no extensions, the words never pasted from a clipboard
manager.

**T3. The page is not checked before use.** A changed copy (with the CSP
removed, say) looks the same. Fix: publish the SHA-256 of `lms_sign.html`
with each release and in `SIGNATURES.md`, and check it (`certutil -hashfile`)
on the offline computer before typing the words.

**T4.** The key is SHA-256 of the mnemonic's entropy, with no stretching,
which is fine for a random mnemonic. LMS with 32 byte hashes is chosen for
its margin against quantum search; a 12 word mnemonic is the weaker link
there (128 bits). Nothing to do for the key in use; for a future key, 24
words.

### Checked and found sound

- Key generation is RFC 8554 Appendix A (`x_q[i] = H(I || q || i || 0xff ||
  SEED)`), the one time public key, the leaves, the tree and the public key
  layout are the RFC's; the signature is a plain RFC 8554 one, which is why
  an independent verifier and the bootloader both take it.
- C is derived from the seed, the index and the message, so it is secret and
  the same file and index always give the same signature: signing again is
  harmless, as `SIGNATURES.md` says.
- The signature is verified with the public key before it can be saved. That
  also covers a corrupted computation, which in a one time scheme would
  otherwise give away a second set of chain values for the same index.
- The message is the SHA-256 of the file bytes, the same bytes the
  bootloader hashes.
- Everything shown comes through `textContent`; the CSP allows no network,
  no external script, no form target.
- The words leave the text area after signing; the entropy, seed, tree and
  work buffers are overwritten. JavaScript cannot promise that no copy stays
  in memory: close the browser afterwards.

## 14. What has not been reviewed, and how these passes were done

For whoever takes this up next. The passes of 2026-11-16 (sections 7 to 13)
were code reading by Fable 5.2, plus the host tests named in each section.
Nothing was run on a board and no firmware or bootloader code was changed;
the only files changed are this document, `pending.md`, `CLAUDE.md`, the
validation catalogue and the hostile PSBT tests (ten new vectors).

Still not reviewed by anyone, in the order suggested:

1. **The state machine of `main()`**, about 3,000 lines. The first audit
   sampled it and section 7 only skimmed its changes. What to look for: on
   every exit of every flow, the secrets it holds are wiped and the mode
   flags it set are cleared (`xor_from_create`, `kef_sd_mode`,
   `sign_menu_descriptor`, `psbt_inspect_only`, `reader_*`, `qr_from_*`...),
   including END_MODE after an error and AUTO UNLOAD from inside it.
2. **The entropy arithmetic**: that coins, raw dice (the 1 and 2 bit rolls),
   cards (5, 4 and 2 bit cards) and the dice string give uniform bits with no
   bias, and that the bits credited are the bits obtained. The first audit
   called coins and dice sound without writing the argument down.
3. **`screens.c`**: drawing only, but with text buffers of fixed size that
   take strings from callers. Never read.
4. **The vault recovery HTML page** (`pending.md` already asks for its
   revision): it must read records by the bitmap.
5. **The other HTML tools** (`ur_psbt_animator.html`, the validation page):
   test tools, low stakes.
6. **`tinf/tinflate.c`** beyond its bounds checks, and that it is
   byte-identical to the 1.2.1 tag (the comparison of section 11 was done
   for `crypto/` only).
7. **The linker scripts** of the app and the bootloader, and the display
   driver shared by both.

Not in the scope of any pass, by decision or by nature: power and EM
analysis (decided on 2026-11-16, section 8), fault injection, the hardware.

Method notes that save time:
- `src/crypto/` was compared with upstream by fetching trezor-firmware's
  `crypto/` and comparing function bodies with comments and spacing removed;
  a line diff is useless because the local files were reformatted.
- The hostile PSBT suite runs one file in every mode with
  `test_malicious.exe --file x.psbt [descriptor.txt]`: the quickest way to
  see what the firmware does with a PSBT idea before writing a vector.
- The bootloader host tests build with the commands in the first lines of
  each `bootloader/test/*.c`; `boot_lms.c` must be on the command line.
