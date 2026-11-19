# crypto/ - trezor-crypto as used by Seedmate

These files come from trezor-crypto (`crypto/` of
https://github.com/trezor/trezor-firmware), MIT License, see `LICENSE`. The
AES / GCM files of `aes/` are Brian Gladman's (https://github.com/BrianGladman/aes),
as vendored by trezor-crypto, with their own license in their headers;
RIPEMD-160 comes from mbed TLS through trezor-crypto.

Only what the firmware and its host tests use is kept; the rest of the
library (BIP39, Ed25519, SHA-3, Base58, the random source, signing...) was
removed on 2026-11-15. The firmware has its own SHA-256 / SHA-512, HMAC and
PBKDF2 (`../sha256.c`, `../sha512.c`, `../kdf.c`) and does the signing in
`../psbt_sign.c`.

The files were compared with upstream on 2026-11-16, function by function
(`../../docs/security-audit.md`, section 11). What differs:

| File | Against upstream |
|---|---|
| `bignum.c/h`, `consteq.c/h`, `ripemd160.c/h`, `segwit_addr.c/h`, `memzero.h` | Identical |
| `aes/` | Identical except three edits marked "Seedmate": `#undef v2` in `aestab.c` (the project defines `v2` on the command line), the 256 bit key schedule only and one GHASH function for header and data in `aesgcm.c` |
| `options.h`, `secp256k1.c/h`, `ecdsa.h`, `bip32.h` | Trimmed: other curves, hashers and declarations removed; the curve constants are untouched |
| `ecdsa.c` | Trimmed to the 16 functions of public key arithmetic (no signing, verification, recovery or DER); the formulas are upstream's statement for statement, with these changes: `curve_to_jacobian()` sets z = 1 instead of a random z, and `point_multiply()` indexes its table directly instead of `point_select()` (both protections against power and EM analysis removed, audit C1 / C2, decided on 2026-11-16: the device keeps no secrets; marked "Seedmate" in the code); `ecdsa_read_pubkey()` refuses a NULL curve; `ecdsa_get_public_key33()` wipes one more buffer. Upstream's three `assert()` were put back on 2026-11-19 (audit C3) |
| `bip32.c` | Trimmed (18 functions removed) and adapted: the HMAC is the firmware's `HmacSha512()`, working variables are locals and are wiped, the key validation refuses a curve without parameters, `hdnode_get_address_raw()` uses the firmware's hashes. The derivation is upstream's algorithm |
| `fault_handler_noop.c` | Host tests only; the firmware has its own `tc_fault_handler()` in `../main.c`, which stops the device |

Do not edit these files beyond what is needed; mark any change "Seedmate" and
add it to this table.
