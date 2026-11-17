# Firmware signatures

Every official `UPDATE.HEX` comes with an `UPDATE.SIG` made with
`lms_sign.html`, the page in this folder (RFC 8554 LMS, LMS_SHA256_M32_H10, LMOTS_SHA256_N32_W8).
The bootloader checks it against the public key built into it
(`bootloader/src/boot_lms.c`) and shows "OFFICIAL FIRMWARE" in green, or
"UNOFFICIAL FIRMWARE" in red with the reason.

## Public key

Release key, in the bootloader since 2026-11-11 (BOOT 1.0):

```
0000000600000004c0f2a217123bd1f49d67a61a35ede5c5c19fa602d5efe757c443eba79a86b148b31978c21f87fdb7906bc1879394d473
```

Anyone can check a firmware file against it: the SHA-256 of `UPDATE.HEX` is the
message signed, and `test/lms/verify_lms.py` is an independent verifier.

## The one rule: one index, one file

LMS is a one-time signature scheme with 1024 indexes (0 to 1023). **Each index
may sign only one file.** Signing two different files with the same index lets
anyone forge signatures: the key would have to be replaced in every device,
which needs a PICkit.

- Every file is a different signature: a new version, a rebuild with any
  change, and each language variant of the same version (English, Spanish...).
  Each one takes the next free index.
- Signing the very same file again with the same index is harmless: the page
  derives everything from the key, the index and the file, so it gives the same
  `UPDATE.SIG` byte for byte.
- Indexes are never reused, also when a release is withdrawn: a withdrawn file
  keeps its row.
- 1024 indexes are enough for many years of releases; at about 900 used, plan
  the next key (a bootloader update).

The signing page checks the index itself: it reads this file and the
`UPDATE.SIG` of every subfolder when it is given this folder. It refuses an index whose row here has another hash
(or none), and one with an earlier signature that does not verify for the file
being signed; it proposes the next free index; and before signing it checks
that the words give the public key written above.

How to sign a release:

1. Build the release and compute the SHA-256 of `UPDATE.HEX`
   (`certutil -hashfile UPDATE.HEX SHA256` on Windows).
2. Add its row to the table below (index: the first after the last row; date,
   version, language, hash) and commit it **before** signing, so an index is
   never taken twice. Test signatures get a row too.
3. Copy this whole folder to a USB stick and take it to the signing
   computer; check the page there (next section).
4. Open `lms_sign.html` offline, press "Open the signatures folder" and choose
   this folder: the page reads the record and every earlier signature, takes
   the index, date and version from the row, and ticks "Test signature" when
   the notes of the row say test. Drop `UPDATE.HEX` and sign.
5. "Save into signatures/..." writes `<index>_<date>_<version>[_test]/` with
   `UPDATE.HEX` and `UPDATE.SIG` into the folder (Chrome and Edge; other
   browsers read the folder but give the new one as a .zip to extract here).
6. Bring the folder back and copy it over this one: `git status` must show the
   new subfolder only. Any other change (this file, the page) is a reason to
   stop and look. The pre-commit hook adds `signatures/` to the next commit;
   publish `UPDATE.HEX` and `UPDATE.SIG` together.

## This folder

Every signature made with the key is kept here, test signatures included,
one subfolder per index with the file it signed:

```
signatures/
  SIGNATURES.md
  lms_sign.html                 the signing page
  000_2026-11-11_v2.0b1_test/   UPDATE.HEX  UPDATE.SIG
  001_<date>_<version>/         UPDATE.HEX  UPDATE.SIG
```

The name starts with the index in three digits, so the folders sort in index
order, then the date of the row, the version and `test` for a signature that
is not a release. The files keep the names the bootloader reads, so the pair
can be copied to an SD card as it is. A signature is public: it only proves
that the key signed that file. Keep the `UPDATE.HEX` next to it, since
without it the signature cannot be checked again.
`test/lms/test_lms.js` checks that every row has its folder, named from the
row, with a signature that verifies for the hash of the row (and the
`UPDATE.HEX` of that hash when it is there), and that no folder lacks a row.

Its `.SIG` and `.HEX` files are ignored by the whitelist `.gitignore`, so a
local pre-commit hook adds the whole folder to every commit. It is not part of
the repository; in a new clone, create `.git/hooks/pre-commit` with:

```
#!/bin/sh
cd "$(git rev-parse --show-toplevel)" || exit 1
git add -f -- SW/signatures || exit 1
```

## The signing page

Before typing the words, check that the page is this one: a changed copy looks
the same and could send the words away (audit T3). On the signing computer:

```
certutil -hashfile lms_sign.html SHA256
```

SHA-256 of lms_sign.html, as committed:

```
4C92424A920760CB73805FFF4ECE9A2B86294EFCF24DDC23CE7C23FE81A79CF1
```

The hash changes with every change to the page: it is updated here in the same
commit (`test/lms/test_lms.js` fails otherwise). Take the page from git or from
the release, never from a link someone sends. `.gitattributes` here keeps git
from changing its line endings, which would change the hash.

Use a computer that stays offline until the browser is closed, a private window
with no extensions, and type the words (never paste them from a clipboard
manager). Close the browser afterwards.

## Indexes used

| Index | Date | Version | Language | SHA-256 of UPDATE.HEX | Notes |
|---|---|---|---|---|---|
| 0 | 2026-11-11 | v2.0b1 | English | 5D9FE6CCA9624610872E4C8806CE6FEF9EE97BFA406C67D705F0FDB5C32CDB7A | Bootloader test only, not a release: build with the temporary BOOT_LOCK_TEST |
| 1 | 2026-11-17 | v2.0-beta17112026 | English | 78E90D1B2F0218FA89110619F8CCFE094A12C7B8ED6ADFD38456331FE748D1C8 | Test signature, not a release |
