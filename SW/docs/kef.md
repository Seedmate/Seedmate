# Seedmate KEF - encrypted mnemonic QR compatible with Krux

Status: done on 2026-11-08: the core (`src/kef.c`, host tested in `test/kef/`, 2.5 KB) and the screens (`kef_export_run()`, `kef_load_from_qr()` in `main.c`, 3.2 KB). Tried with a Krux on 2026-11-08 in both directions, AES-GCM and AES-CTR, and with a wrong key. Differences with sections 4 and 5: on export the ID is always the fingerprint (no option: decided on 2026-11-08, few would understand it) and the iterations come from the permanent setting KEF ITERATIONS (10,000 by default, up to 300,000, added on 2026-11-11; import still accepts any ID and count from the QR, the ID shown up to 20 characters), the estimated time is shown in the setting and on the import screen (44 s per 100,000 iterations, measured), and the delta is added before the confirmation, so it shows the real count.

Goal: export the seed on screen as an encrypted QR that a Krux can load, and
load the encrypted mnemonic QRs that Krux exports. Only the current Krux
release is considered: **v26.09.0** (2026-10-03). Allowed even when the
SEEDQR setting is off: the QR is encrypted (its strength is the key's, said
on screen).

Sources (read at tag v26.09.0, MIT licensed):
`docs/getting-started/features/encryption/kef-specifications.en.md`,
`src/krux/kef.py`, `src/krux/encryption.py`, `src/krux/pages/encryption_ui.py`,
`src/krux/pages/mnemonic_loader.py`, `src/krux/baseconv.py`,
`src/krux/krux_settings.py`, `src/krux/key.py`, `tests/test_kef.py`,
`tests/test_encryption.py`, `tests/pages/test_encryption_ui.py`.

## 1. What Krux does today

**Export** (wallet > Backup > Encrypted, "Encrypted QR Code"):
- Plaintext: the BIP39 entropy bytes (`bip39.mnemonic_to_bytes`): 16 bytes for
  12 words, 32 for 24 (Krux also has 15/18/21 words: 20/24/28 bytes).
- Key `K`: typed or scanned, up to 200 characters, utf-8 bytes as they are.
- `id` (salt and label): default the master fingerprint **with the loaded
  passphrase**, 8 lower case hex characters (`key.fingerprint_hex_str()`, e.g.
  "353175d8"); the user may change it. It is stored in clear in the QR.
- Mode: setting "Encryption Mode", default **AES-GCM**; `suggest_versions()`
  then picks, for a 16/32 byte plaintext: AES-GCM -> v20, AES-CTR -> v15,
  AES-CBC -> v10, AES-ECB -> v5 (never the legacy v0/v1, never compressed or
  PKCS7 versions for these sizes).
- Iterations: setting "PBKDF2 iter.", default **100,000** (10,000..500,000),
  plus a delta `ticks_ms % (iterations / 10)`, so usually not a multiple of
  10,000 and stored as is.
- IV: from the camera entropy (12 bytes for GCM / CTR, 16 for CBC).
- QR content: the KEF envelope encoded in **base43** (Electrum alphabet
  `0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$*+-./:`, QR alphanumeric mode):
  66 characters for 12 words, 90 for 24 (with an 8 character id).

**Import** (Load mnemonic > via camera, `load_key_from_qr_code()`):
- If the text looks like hex, base32, base43 or base64 it is decoded and parsed
  as a KEF envelope (any version its `kef.py` knows); a parsed envelope shows
  id, version and iterations, asks the key, decrypts ("Failed to decrypt" for
  any failure, with a growing delay after failures).
- The plaintext must be 16 or 32 bytes (12 or 24 words), else "Invalid
  mnemonic length".

## 2. The envelope (KEF spec)

```
len_id (1) | id (len_id, 0..252) | version (1) | iterations (3, big endian) | cpl
k = PBKDF2-HMAC-SHA256(K, id, effective iterations), 32 bytes
effective iterations = i if i > 10,000, else i * 10,000 (minimum 10,000)
```

Versions a Krux v26.09.0 produces for a mnemonic:

| v  | Mode | cpl | Authentication |
|----|------|-----|----------------|
| 20 | GCM  | IV(12) + ct + tag[:4] | GCM tag truncated to 4 bytes, no AAD |
| 15 | CTR  | IV(12) + ct(P + sha256(P)[:4]) | hidden, inside the ciphertext |
| 10 | CBC  | IV(16) + ct(P NUL padded) + sha256(v + IV + P + k)[:4] | exposed |
| 5  | ECB  | ct(P NUL padded) + sha256(v + P + k)[:3] | exposed |

Checked with an independent Python (hashlib + cryptography): the Krux test
vector `GCM_ENCRYPTED_QR` (key "test key", id "test ID", 100,000 iterations,
IV `4f52a1936c3e3271209e9d64`) decrypts to its entropy and is rebuilt byte
for byte; the base43 vector `ENCRYPTED_QR_DATA_CBC_b43` encodes and decodes.
The truncated GCM tag is the first 4 bytes of the standard 16 byte tag.
v15 is AES-CTR with the 12 byte IV and a 4 byte big endian counter from 0. Use the
vector `CTR_ENCRYPTED_QR` of `tests/test_encryption.py` (100,000 iterations); the
one in `tests/test_kef.py` is for other tests and does not open with "test key".

## 3. Scope for Seedmate

- **Export: v20 only** (AES-GCM, Krux's default). Uses the vault's AES-GCM
  (`crypto/aes/`, encrypt only, tag length 4).
- **Import: v20 and v15** (both need only AES encryption, already linked).
  v10 and v5 need the AES decryption code (about 2 KB more flash, already in
  `aescrypt.c` / `aeskey.c` but dropped by the linker): optional, decided at
  implementation time. Legacy v0/v1 and the compressed / PKCS7 versions are
  out of scope (Krux never makes them for a mnemonic).
- Only 12 and 24 words, as everywhere in Seedmate: a 20/24/28 byte plaintext
  says "15/18/21 WORDS NOT SUPPORTED".
- Input encoding for import: base43 (what Krux exports). Hex and base64 could
  be added later for envelopes copied from a `seeds.json`.

## 4. Generating (SEED BACKUP > ENCRYPTED QR (KEF))

New entry in `menu_backup[]`, not blocked by the SEEDQR setting.

1. **Yellow notice**: "ENCRYPTED FOR KRUX (KEF)", "AS STRONG AS ITS KEY",
   "THE ID IS SHOWN IN CLEAR".
2. **Key**: the single line editor (passphrase mode: counter, review screen),
   up to 200 characters, QR and die keys available (an EFF dice password is a
   good key). Refused if empty.
3. **ID**: editor with the default master fingerprint of the seed and
   passphrase on screen, 8 lower case hex characters as Krux makes it (if the
   wallet keys are not derived yet, the fingerprint needs the seed PBKDF2:
   shown with its progress), editable, 0..252 bytes (limit it to the 20 of a
   vault title for the screen?).
4. **Iterations**: default 100,000, UP / DOWN in steps of 10,000 from 10,000
   to 500,000, with the estimated time on screen; a delta like Krux's
   (`timer % (iterations / 10)`) is added when sealing.
5. **Confirmation**: words (12/24), id, iterations, "AES-GCM (KEF V20)";
   OK = ENCRYPT.
6. **Progress**: "DERIVING THE KEY" with a bar and the iteration count
   (PBKDF2), then "ENCRYPTING", then "VERIFYING": the envelope is decrypted
   again with the derived key and compared with the entropy before it is shown.
7. **QR**: the base43 text in the zoomable text QR viewer
   (`draw_text_qr_view()`: alphanumeric mode, version 4-5). BACK returns to the
   SEED BACKUP menu. Key, derived key and plaintext are wiped right after
   sealing; the envelope is public.

IV (12 bytes): SHA256(key press pool `sss_entropy_pool` || TMR1 || core timer
|| a counter || "KEF IV")[:12]. The key typed in the editor feeds the pool
(one timer sample per key press), the delta makes the derived key differ even
with the same key, id and iterations, and the counter keeps two IVs of the
same session apart. Krux uses camera entropy here; GCM needs a unique IV per
derived key, not a secret one.

## 5. Loading (LOAD > FROM QR, and QR READER)

- The existing QR load path tries, before SeedQR / Compact SeedQR: decode
  base43, parse a KEF envelope (version known, iterations >= 10,000, payload
  long enough). If it parses:
  1. **Public info**: "KRUX ENCRYPTED (KEF)", id (as text, or hex if not
     printable), version name, iterations, estimated time.
  2. **Key**: the editor (QR key available); BACK leaves.
  3. **Progress**: "DERIVING THE KEY" bar, "DECRYPTING".
  4. Failure for any reason: "NOT DECRYPTED", "WRONG KEY OR DAMAGED QR"
     (vague on purpose, as the spec asks); OK tries another key.
  5. Success: 16/32 bytes -> the seed on screen as with any other source
     (words screen); other sizes say why.
- QR READER labels such a code "KRUX ENCRYPTED (KEF)" with its id (it never
  decrypts).

## 6. Time

PBKDF2-HMAC-SHA256 with the inner and outer pad states computed once: two
SHA256 compressions per iteration, 200,000 for Krux's default. The BIP39 seed
PBKDF2 (`kdf.c`) now precomputes its pads too: 2 SHA512 compressions per
iteration, 4,096 for 2,048 iterations, each about 3-4 times a SHA256
compression. Estimate: KEF at 100,000 iterations takes about **12 times the
"1/2 SEED (PBKDF2)" phase** of LOADING WALLET (as measured after that
change). To be measured on the device before the defaults are fixed. A Krux
QR made with 500,000 has to be derived with 500,000.

Side finding, done: precomputing the pads made the BIP39 PBKDF2 (wallet
loading, BIP85 child, any seed derivation) about twice as fast (1.9x on the
host).

## 7. Code

- `kef.c/h` (no UI, host tested): `kef_pbkdf2_sha256()` (pads precomputed,
  progress callback, cancellable), `kef_base43_encode()` / `_decode()`
  (in place in a small buffer, no big numbers: repeated division of the byte
  array), `kef_unwrap()` (strict parse), `kef_seal_v20()`, `kef_open()` (v20,
  v15, optionally v10 / v5), all in the caller's buffer.
- HMAC-SHA256 with a key of any length (the one in `psbt_sign.c` takes a 32
  byte key): own small version in `kef.c` on `sha256.c`.
- Screens in `main.c`: SEED BACKUP entry, the load path, QR READER label.
- RAM: the envelope and its base43 text fit in `buffer` (90 + 61 bytes for 24
  words); the key is edited in a local like the passphrase copy.
- Flash: the core measures 2.5 KB (XC32 -O1); with the screens the estimate is 4-5 KB, +2 KB
  with v10 / v5.

## 8. Tests

- `test/kef/gen_kef.py`: independent reference (hashlib, cryptography),
  vectors in `kef_vectors.h`: the Krux vectors above (GCM and CTR envelopes,
  base43 strings), plus Seedmate's own seal with a fixed IV and the "abandon
  x11 about" entropy (rule 5: no real wallet data).
- `test/kef/test_kef.c`: base43 round trips (leading zero bytes), unwrap of
  every vector and refusals (unknown version, iterations below 10,000, short
  payload), PBKDF2 against hashlib, open of the Krux vectors, seal
  byte-exact with the fixed IV, wrong key refused.
- On the device: a QR exported by Seedmate loaded in a Krux, a QR exported by
  a Krux loaded in Seedmate (both with GCM, and one with CTR).

## 9. Order of work

1. `kef.c` with base43, PBKDF2-SHA256, unwrap / seal / open, and the host test.
2. Load path (FROM QR + QR READER label): measure the PBKDF2 time on the
   device with a Krux test QR.
3. Export screens (SEED BACKUP), defaults set from the measured time.
4. Optional: v10 / v5 import, hex / base64 input.
