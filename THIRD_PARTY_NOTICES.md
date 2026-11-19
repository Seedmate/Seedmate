# Third-Party Notices

Seedmate includes third-party source code, data and generated code in the firmware (`SW/`) and the bootloader (`bootloader/`). This file lists every third-party component that is built into either image, with its origin and license. Code not listed here was written for this project (MIT, see the headers of `SW/src/main.c` and the other project files).

Only the files named below are compiled. `SW/src/crypto/` was trimmed on 2026-11-15 to the files listed in section 1; `fault_handler_noop.c` there is built by the host tests only. `SW/src/crypto/README.md` lists, file by file, how the trezor-crypto files differ from upstream.

---

## 1. trezor-crypto

- **Directory:** `SW/src/crypto/`
- **Upstream:** https://github.com/trezor/trezor-firmware/tree/main/crypto
- **Files built:** `bignum.c/.h`, `bip32.c/.h`, `ecdsa.c/.h`, `secp256k1.c/.h`, `options.h`, `memzero.h`, `script.h`, `ripemd160.c/.h`, `segwit_addr.c/.h`, `consteq.c/.h`, `fault_handler.h`, and the AES files in `aes/` (section 1a)
- **Used for:** 256-bit big number arithmetic, secp256k1 curve operations, BIP32 key derivation, RIPEMD-160 (key fingerprints, addresses), bech32/bech32m addresses, constant-time comparison of the AES-GCM tag (`consteq`)
- **Local changes** (compared with upstream function by function on 2026-11-16, `SW/docs/security-audit.md` section 11; the list is in `SW/src/crypto/README.md`): `ecdsa.c` is trimmed to the public-key operations, and two protections against power and EM analysis were removed: `curve_to_jacobian()` uses z = 1 instead of a random z, and `point_multiply()` indexes its table directly instead of through `point_select()` (both marked "Seedmate" in the source); upstream's `assert()` lines are kept. `bip32.c` is trimmed and uses the project's HMAC-SHA512 (`SW/src/kdf.c`). `options.h`, `secp256k1.c/.h`, `ecdsa.h` and `bip32.h` are trimmed to secp256k1; `bignum.c`, `consteq.c`, `ripemd160.c` and `segwit_addr.c` are unchanged. The ECDSA signing in `SW/src/psbt_sign.c` follows the steps of trezor-crypto's `ecdsa_sign_digest()` on top of these files. `tc_fault_handler()` (declared in `fault_handler.h`) is provided by `SW/src/main.c`, which stops the device; the upstream no-op `fault_handler_noop.c` is not built.
- **License:** MIT (`SW/src/crypto/LICENSE`)
- **Copyright:** (c) 2013-2016 Tomas Dzetkulic, (c) 2013-2016 Pavol Rusnak, (c) 2015-2016 Jochen Hoenicke, (c) 2016 Alex Beregszaszi, and the trezor-crypto contributors

Exceptions inside this directory:

- `ripemd160.c` - adapted by Pieter Wuille (2012); **public domain** (CC0-style dedication in the file header).
- `segwit_addr.c` - Copyright (c) 2017, 2021 Pieter Wuille; **MIT**.
- `consteq.c/.h`, `fault_handler.h` - Copyright (c) Trezor Company s.r.o.; **MIT** (same terms as below).
- `aes/` - Brian Gladman's AES and GCM code; its own license, see section 1a.

```
The MIT License (MIT)

Copyright (c) 2013 Tomas Dzetkulic
Copyright (c) 2013 Pavol Rusnak

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 1a. AES and GCM (Brian Gladman, as distributed in trezor-crypto)

- **Directory:** `SW/src/crypto/aes/`
- **Upstream:** https://github.com/BrianGladman/AES (copied from trezor-crypto's `crypto/aes/`)
- **Files built:** `aescrypt.c`, `aeskey.c`, `aestab.c`, `aesgcm.c`, `gf128mul.c`, `aes.h`, `aesopt.h`, `aestab.h`, `aesgcm.h`, `gf128mul.h`, `gf_mul_lo.h`, `mode_hdr.h`, `brg_endian.h`
- **Used for:** AES-256-GCM encryption of the vault records on the SD card (`SW/src/vault.c`)
- **Local changes:** `aes.h` enables only the 256-bit key schedule (no tables in any option); `gcm_init_and_key()` in `aesgcm.c` calls `aes_encrypt_key256()` when variable key sizes are disabled; `aesgcm.c` authenticates the header and the data with one GHASH function instead of two identical copies; `aestab.c` undefines the project's `v2` macro before its own `v2()`. Each change is marked "Seedmate" in the source.
- **License:** Brian Gladman's BSD-style license (in each file header)
- **Copyright:** (c) 1998-2014, Brian Gladman, Worcester, UK. All rights reserved.

```
The redistribution and use of this software (with or without changes)
is allowed without the payment of fees or royalties provided that:

  source code distributions include the above copyright notice, this
  list of conditions and the following disclaimer;

  binary distributions include the above copyright notice, this list
  of conditions and the following disclaimer in their documentation.

This software is provided 'as is' with no explicit or implied warranties
in respect of its operation, including, but not limited to, correctness
and fitness for purpose.
```

---

## 2. Shamir Secret Sharing (SSS)

- **Directory:** `SW/src/SSS/` (`shamir.c/.h`, `memzero.c/.h`)
- **Upstream:** https://github.com/trezor/trezor-firmware/tree/main/crypto (based on https://github.com/dsprenkels/sss)
- **Used for:** Shamir split/merge arithmetic over GF(256); secure wiping of secrets (`memzero`)
- **Local changes:** the GF(256) helpers of `shamir.c` (`bitslice()`, `gf256_mul()`...) are no longer `static`, so the split in `SW/src/main.c` can use them, and `shamir_interpolate()` takes `uint8_t **` instead of `const uint8_t **`; the arithmetic is upstream's (compared on 2026-11-19)
- **License:** MIT
- **Copyright:** (c) 2017 Daan Sprenkels <hello@dsprenkels.com>, (c) 2019 SatoshiLabs

```
Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
```

---

## 3. QRCode

- **Directory:** `SW/src/QRCode-master/`
- **Upstream:** https://github.com/ricmoo/QRCode (major parts derived from Project Nayuki's QR Code generator)
- **Used for:** QR code generation (SeedQR, addresses, xpub / crypto-account, animated PSBT export)
- **Local changes:** `<stdbool.h>` instead of its own `bool` type, and the Xcode `#pragma mark` lines removed (compared on 2026-11-19)
- **License:** MIT
- **Copyright:** (c) 2017 Richard Moore, (c) 2017 Project Nayuki

```
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

---

## 4. SHA-256 (crypto-algorithms)

- **File:** `SW/src/sha256.c/.h`
- **Upstream:** https://github.com/B-Con/crypto-algorithms
- **Used for:** BIP39 checksums, key fingerprints, txids and BIP143 sighashes, UR fountain PRNG seeding, RFC6979 HMAC-SHA256
- **License:** Public domain (released by the author into the public domain)
- **Author:** Brad Conte

---

## 5. SHA-512 (WjCryptLib)

- **File:** `SW/src/sha512.c/.h`
- **Upstream:** https://github.com/WaterJuice/WjCryptLib
- **Used for:** HMAC-SHA512 and PBKDF2 (`SW/src/kdf.c`): BIP39 seed, BIP32 derivation, BIP85
- **License:** Public domain (Unlicense)
- **Author:** WaterJuice, based on LibTomCrypt by Tom St Denis (public domain)

---

## 6. Petit FatFs

- **Files:** `bootloader/src/pff.c`, `pff.h`, `pffconf.h`, `diskio.h`
- **Upstream:** http://elm-chan.org/fsw/ff/00index_p.html (R0.03a)
- **Used for:** reading `UPDATE.HEX` in the bootloader (the firmware uses FatFs, section 6a)
- **Local changes:** `pffconf.h` configuration (FAT16, directory functions enabled); `pf_mount()` refuses a cluster size that is not a power of two (marked "Seedmate", audit P1); the linker script of the bootloader places `pf_read()` and `check_fs()` in free boot flash (no source change)
- **License:** BSD-style 1-clause license
- **Copyright:** (C) 2019, ChaN, all right reserved.

```
Petit FatFs module is an open source software. Redistribution and use of
Petit FatFs in source and binary forms, with or without modification, are
permitted provided that the following condition is met:

1. Redistributions of source code must retain the above copyright notice,
   this condition and the following disclaimer.

This software is provided by the copyright holder and contributors "AS IS"
and any warranties related to this software are DISCLAIMED.
The copyright owner or contributors be NOT LIABLE for any damages caused
by use of this software.
```

---

## 6a. FatFs

- **Files:** `SW/src/fatfs/ff.c`, `ff.h`, `diskio.h`, `ffunicode.c` (unmodified, byte-identical to the official `ff16.zip`), `ffconf.h` (Seedmate configuration)
- **Upstream:** https://elm-chan.org/fsw/ff/ (R0.16, July 2025)
- **Used for:** reading PSBT and descriptor files from the SD card and writing signed PSBTs (FAT12/16/32, long names, no exFAT)
- **Local changes:** none in the module; `ffconf.h` is our own configuration
- **License:** BSD-style 1-clause license
- **Copyright:** (C) 2025, ChaN, all right reserved.

```
FatFs module is an open source software. Redistribution and use of FatFs in
source and binary forms, with or without modification, are permitted provided
that the following condition is met:

1. Redistributions of source code must retain the above copyright notice,
   this condition and the following disclaimer.

This software is provided by the copyright holder and contributors "AS IS"
and any warranties related to this software are DISCLAIMED.
The copyright owner or contributors be NOT LIABLE for any damages caused
by use of this software.
```

---

## 6b. tinf (tiny inflate)

- **Directory:** `SW/src/tinf/` (`tinflate.c`, `tinf.h`, `LICENSE`)
- **Upstream:** https://github.com/jibsen/tinf (v1.2.1)
- **Used for:** inflating the raw deflate data of BBQr codes with the Z encoding (`SW/src/bbqr.c`, which compiles `tinflate.c` inside it)
- **Local changes:** none; the files are byte-identical to the v1.2.1 tag (SHA-256 compared again on 2026-11-19)
- **License:** zlib license (`SW/src/tinf/LICENSE`)
- **Copyright:** (c) 2003-2019 Joergen Ibsen

```
This software is provided 'as-is', without any express or implied
warranty. In no event will the authors be held liable for any damages
arising from the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must
     not claim that you wrote the original software. If you use this
     software in a product, an acknowledgment in the product
     documentation would be appreciated but is not required.

  2. Altered source versions must be plainly marked as such, and must
     not be misrepresented as being the original software.

  3. This notice may not be removed or altered from any source
     distribution.
```

---

## 7. Microchip generated code (MCC / Harmony)

- **Directories:** `SW/src/config/v2/` (firmware), `bootloader/src/config/default/` (bootloader), including the linker scripts and the peripheral libraries (`plib_*`)
- **Provider:** Microchip Technology Inc.
- **Used for:** clock, interrupt controller, GPIO, SPI and UART initialization; startup and exception handling
- **License:** Microchip software license (in each file header): may be used only with Microchip products, subject to its terms
- **Copyright:** (C) 2025 Microchip Technology Inc. and its subsidiaries

---

## 8. Word lists and data

| Data | File | Source | License |
|---|---|---|---|
| BIP39 English word list | `SW/src/words_opt.h` | BIP-0039, https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt | Published with BIP-0039 (bitcoin/bips) |
| EFF Short Wordlist v1 (1,296 words) | `SW/src/EFF_short.c` | Electronic Frontier Foundation, https://www.eff.org/dice | CC BY 3.0 US |
| Bytewords (256 words, minimal form) | `SW/src/bytewords.c` | Blockchain Commons, BCR-2020-012 | Specification by Blockchain Commons |

---

## 9. Specifications implemented (no third-party code)

These parts were written for this project from public specifications; they are listed for reference, not because third-party code is included:

- Uniform Resources and fountain codes (Blockchain Commons BCR-2020-005), including the Xoshiro256** PRNG (D. Blackman, S. Vigna, public domain algorithm) and the alias-method sampler: `fountain.c`, `prng.c`, `sampler.c`, `bytewords.c`, `ur_encode.c`
- BBQr (Coinkite, https://github.com/coinkite/BBQr, public domain specification): `bbqr.c`; the Z encoding is inflated with tinf (section 6b)
- UR types `crypto-psbt` (BCR-2020-006), `crypto-hdkey` (BCR-2020-007), `crypto-output` (BCR-2020-010) and `crypto-account` (BCR-2020-015): `ur_encode.c`
- PSBT (BIP174), SegWit v0 signature hash (BIP143), low-S signatures (BIP146), RFC6979 deterministic nonces with low-R grinding as in Bitcoin Core / libsecp256k1: `psbt.c`, `psbt_sign.c`
- BIP32, BIP39, BIP44, BIP48, BIP84, BIP85; HMAC (RFC 2104) and PBKDF2 (RFC 8018): `main.c`, `kdf.c`, `bip85.c`
- Vault record format (`SW/docs/vault.md`): AES-256-GCM (NIST SP 800-38D, code from section 1a) with a BIP85 HEX key, CRC32: `vault.c`
- Taproot key path: BIP340 Schnorr signatures, BIP341 signature hash, BIP86 output keys: `psbt_sign.c`
- Output descriptor checksum (BIP380): `main.c`, `descriptor.c`
- Krux KEF encrypted mnemonic format (base43, PBKDF2-HMAC-SHA256, AES-GCM; `SW/docs/kef.md`): `kef.c`
- Nostr keys (NIP-06 derivation, NIP-19 npub / nsec): `main.c`, `nostr.c`
- LMS hash-based signatures (RFC 8554) for the firmware update check: `bootloader` (`boot_lms.c`) and `SW/signatures/lms_sign.html`; SHA-256 of the update file in the bootloader: `boot_sha.c`
- GM861S barcode reader serial protocol (GM861S User Manual V1.2.4): `main.c`

---

## 10. Test data (not part of the firmware)

- `SW/test/psbt/sparrow_frames.txt` - animated QR frames captured from Sparrow Wallet (https://sparrowwallet.com), used to check that the UR encoder reproduces them byte for byte.
- `SW/test/psbt/malicious/` - hostile PSBT test set: the `psbt_faker` corpus by Coinkite (https://github.com/Coldcard/psbt_faker, MIT, Copyright (c) 2020 Coinkite Inc.) as vendored and extended in ShieldSigner (https://github.com/3rdIteration/seedsigner, MIT, Copyright (c) 2021 SeedSigner), the invalid PSBT vectors of BIP174, and our own `OWN-*` files; details in `SW/test/psbt/malicious/README.md`.
- The host tests use published test vectors: BIP84 ("abandon ... about"), BIP143, BIP39 (Trezor vectors), RFC 4231, BIP85 (master key of the BIP85 specification), BIP340 and BIP341 (`bip-0340/test-vectors.csv`, `bip-0341/wallet-test-vectors.json`, read by `SW/test/psbt/gen_taproot.py` from the bitcoin/bips repository), the SIGHASH_ALL cases of Bitcoin Core's `sighash.json` (MIT), RFC 8554 test case 2, NIP-06, and the KEF vectors of Krux v26.09.0 (https://github.com/selfcustody/krux, MIT).
- `SW/tools/ur_psbt_animator.html` (a test page, not firmware) contains a JavaScript port of the QRCode library of section 3 (MIT).
- `SW/test/vault/gen_vault.py` uses the Python `cryptography` package (Apache 2.0 / BSD) as an independent AES-GCM reference to generate `vault_vectors.h`; it is a test tool only and is not distributed with the firmware. `SW/test/vault/test_vault.c` links the upstream `fault_handler_noop.c` (trezor-crypto, MIT) for the host build only.
- `SW/test/bbqr/gen_bbqr.py` is an independent BBQr encoder written from the specification (Python `zlib` for the deflate data); `SW/test/bbqr/anim_frames.js` uses Node's `zlib`. Test tools only.
