# Third-Party Notices

Seedmate includes third-party source code, data and generated code in the firmware (`SW/`) and the bootloader (`bootloader/`). This file lists every third-party component that is built into either image, with its origin and license. Code not listed here was written for this project (MIT, see the headers of `SW/src/main.c` and the other project files).

Only the files named below are compiled. `SW/src/crypto/` may contain more files from the upstream project; they are not part of any build.

---

## 1. trezor-crypto

- **Directory:** `SW/src/crypto/`
- **Upstream:** https://github.com/trezor/trezor-firmware/tree/main/crypto
- **Files built:** `bignum.c/.h`, `bip32.c/.h`, `ecdsa.c/.h`, `secp256k1.c/.h`, `options.h`, `memzero.h`, `script.h`, `ripemd160.c/.h`, `segwit_addr.c/.h`
- **Used for:** 256-bit big number arithmetic, secp256k1 curve operations, BIP32 key derivation, RIPEMD-160 (key fingerprints, addresses), bech32/bech32m addresses
- **Local changes:** `ecdsa.c` is trimmed to the public-key operations; `bip32.c` is trimmed and uses the project's HMAC-SHA512 (`SW/src/kdf.c`). The ECDSA signing in `SW/src/psbt_sign.c` follows the steps of trezor-crypto's `ecdsa_sign_digest()` on top of these files.
- **License:** MIT (`SW/src/crypto/LICENSE`)
- **Copyright:** (c) 2013-2016 Tomas Dzetkulic, (c) 2013-2016 Pavol Rusnak, (c) 2015-2016 Jochen Hoenicke, (c) 2016 Alex Beregszaszi, and the trezor-crypto contributors

Exceptions inside this directory:

- `ripemd160.c` - adapted by Pieter Wuille (2012); **public domain** (CC0-style dedication in the file header).
- `segwit_addr.c` - Copyright (c) 2017, 2021 Pieter Wuille; **MIT**.

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

## 2. Shamir Secret Sharing (SSS)

- **Directory:** `SW/src/SSS/` (`shamir.c/.h`, `memzero.c/.h`)
- **Upstream:** https://github.com/trezor/trezor-firmware/tree/main/crypto (based on https://github.com/dsprenkels/sss)
- **Used for:** Shamir split/merge arithmetic over GF(256); secure wiping of secrets (`memzero`)
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

- **Files:** `bootloader/src/pff.c`, `pff.h`, `pffconf.h`, `diskio.h` (the firmware compiles the same `pff.c` through `SW/src/pff_app.c`; it is not copied)
- **Upstream:** http://elm-chan.org/fsw/ff/00index_p.html (R0.03a)
- **Used for:** reading `UPDATE.HEX` in the bootloader; listing and reading PSBT files from the SD card in the firmware
- **Local changes:** `pffconf.h` configuration (FAT16, directory functions enabled)
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
- UR types `crypto-psbt` (BCR-2020-006), `crypto-hdkey` (BCR-2020-007), `crypto-output` (BCR-2020-010) and `crypto-account` (BCR-2020-015): `ur_encode.c`
- PSBT (BIP174), SegWit v0 signature hash (BIP143), low-S signatures (BIP146), RFC6979 deterministic nonces with low-R grinding as in Bitcoin Core / libsecp256k1: `psbt.c`, `psbt_sign.c`
- BIP32, BIP39, BIP44, BIP48, BIP84, BIP85; HMAC (RFC 2104) and PBKDF2 (RFC 8018): `main.c`, `kdf.c`
- GM861S barcode reader serial protocol (GM861S User Manual V1.2.4): `main.c`

---

## 10. Test data (not part of the firmware)

- `SW/test/animated_QR_scan/captures_pure.txt` - animated QR frames captured from Sparrow Wallet (https://sparrowwallet.com), used to check that the UR encoder reproduces them byte for byte.
- The host tests use published test vectors: BIP84 ("abandon ... about"), BIP143, BIP39 (Trezor vectors), RFC 4231.
