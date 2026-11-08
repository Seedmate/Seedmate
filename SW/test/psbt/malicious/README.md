# Hostile PSBT test set

Every vector is for the test seed "abandon x11 about" (fingerprint 73c5da0a).
`../test_malicious.c` runs them through the firmware's parser and signing
decision. No real wallet data.

## Where the files come from

- `ENC-*`, `NORMAL-*`, `TX-*`, `XTRAS.*`: the `psbt_faker` signing-test corpus
  by Coinkite (https://github.com/Coldcard/psbt_faker, MIT, Copyright (c) 2020
  Coinkite Inc.), as vendored and extended in ShieldSigner
  (https://github.com/3rdIteration/seedsigner, `tests/data/psbt_test_suite/`,
  MIT, Copyright (c) 2021 SeedSigner), fetched on 2026-11-08 from branch `dev`.
- `../malicious_truth.txt`: what each one is and how many outputs are really
  ours, taken from `tests/psbt_suite_util.py` of the same repository.
- `../bip174_invalid.txt`: the invalid PSBT test vectors of BIP174.
- `OWN-*`: ours, from `../gen_malicious_own.py` (OP_RETURN amounts and the limits
  of the high fee warning).

The files are test data only and are not part of the firmware.

## Files next to the test

- `malicious_expected.txt`: the outcome of each vector in each mode (single sig,
  multisig, multisig with the corpus' descriptor). `test_malicious --update`
  rewrites it; review the diff.
- `malicious_gaps.txt`: vectors meant to be refused that Seedmate would still
  sign, each with the reason it is not dangerous. A new gap needs a reason.
