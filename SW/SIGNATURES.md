# Firmware signatures

Every official `UPDATE.HEX` comes with an `UPDATE.SIG` made with
`tools/lms_sign.html` (RFC 8554 LMS, LMS_SHA256_M32_H10, LMOTS_SHA256_N32_W8).
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

How to sign a release:

1. Build the release and compute the SHA-256 of `UPDATE.HEX`
   (`certutil -hashfile UPDATE.HEX SHA256` on Windows).
2. Take the first index after the last row of the table below.
3. Add the row (index, date, version, language, hash) and commit it **before**
   publishing the files, so an index is never taken twice.
4. Sign with that index in `tools/lms_sign.html`, offline, and check that the
   public key the page shows is the one above.
5. Publish `UPDATE.HEX` and `UPDATE.SIG` together.

## Indexes used

| Index | Date | Version | Language | SHA-256 of UPDATE.HEX | Notes |
|---|---|---|---|---|---|
| 0 | 2026-11-11 | v2.0b1 | English | 5D9FE6CCA9624610872E4C8806CE6FEF9EE97BFA406C67D705F0FDB5C32CDB7A | Bootloader test only, not a release: build with the temporary BOOT_LOCK_TEST |
