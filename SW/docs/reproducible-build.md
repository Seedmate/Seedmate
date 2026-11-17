# Reproducible build

Anyone can rebuild the firmware from this repository and check that it is
byte for byte the `UPDATE.HEX` that was signed and published: the same
source, tools and command always give the same `.hex`.

## Tools (exact versions)

| Tool | Version | Notes |
|---|---|---|
| MPLAB X IDE | v6.35 | Only its command line parts are used: `make` (gnuBins) and `prjMakefilesGenerator` |
| XC32 compiler | v5.10 | Free mode is enough: the project uses `-O1`, never the PRO-only options (`-Os`, `-O2`...), so nobody needs a license to check it |
| Device pack | PIC32MM-GPM-0XX_DFP 1.6.166 | Named in `BIP39_MCC.X/nbproject/configurations.xml`; MPLAB X installs it |

Installed in their default folders (`C:\Program Files\Microchip\...`). Another
version of any of them can give another `.hex`.

## Steps

From a clean clone of the release tag (Git Bash on Windows):

```bash
git clone <repository> seedmate && cd seedmate
git checkout <release tag>
cd SW

# The makefiles are not in git: MPLAB generates them from the project
"/c/Program Files/Microchip/MPLABX/v6.35/mplab_platform/bin/prjMakefilesGenerator.bat" "BIP39_MCC.X@v2"

cd BIP39_MCC.X
export PATH="/c/Program Files/Microchip/MPLABX/v6.35/gnuBins/GnuWin32/bin:/c/Program Files/Microchip/xc32/v5.10/bin:$PATH"
make -B -f nbproject/Makefile-v2.mk SUBPROJECTS= .build-conf

sha256sum dist/v2/production/BIP39_MCC.X.production.hex
```

The hash must be the one published for that release (table below), which is
also the SHA-256 the bootloader shows before it installs `UPDATE.HEX`
(`certutil -hashfile UPDATE.HEX SHA256` gives it on Windows). The signature
`UPDATE.SIG` signs that hash; its LMS index is recorded in `../signatures/SIGNATURES.md`.

## What was checked

On 2026-11-15, commit 1ff84f6 (`v2.0b1`, not a release): two fresh clones, one
of them in a folder whose path has a space, and the working tree, each
built from scratch, gave the same file:

```
e337388ce1072b1b2e7b480b69c287c200bcb7d0fbad881a0c0ac00d561befef  BIP39_MCC.X.production.hex  (622,261 bytes)
```

So the build does not depend on the folder, the clone or the time of the
build: no date, time or file path ends up in the firmware (the code has no
`__DATE__`, `__TIME__` or `__FILE__`; the debug information with the paths
stays in the `.elf`, not in the `.hex`), and every file the build needs is in
git.

Not checked yet: another computer with a clean installation of the same tools.

## Published releases

| Version | Tag | SHA-256 of the `.hex` | LMS index |
|---|---|---|---|
| (none yet) | | | |
