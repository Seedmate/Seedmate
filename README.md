# SeedMate

SeedMate is a PIC32MM-based offline device for generating, loading, transforming, splitting, merging, displaying, and exporting BIP39-compatible seed data.

www.seedmate.net

Status: Tested and production-ready. However, unexpected bugs may still occur.

## Features

- Offline seed handling
- Entropy capture from multiple sources and multiple conversion methods
- BIP39 word-based workflows
- SeedXOR operations
- Shamir Secret Sharing over BIP39
- BIP85 derivation
- QR export
- SD card storage/export
- TFT display and button-driven interface

## Typical build flow and reproducibility

1. Install [MPLAB X IDE 6.35](https://www.microchip.com/en-us/tools-resources/develop/mplab-x-ide), ensuring the **32-bit MCUs** box is checked during installation.
2. When prompted afterwards, install the **XC32 compiler** (select the free version).
3. Download the source code `.zip` and the pre-compiled `.hex` file from the Seedmate Releases page(https://github.com/Seedmate/Seedmate/releases).
4. Extract the `.zip` file to any local folder.
5. Open MPLAB X IDE 6.35, go to **File > Open Project**, and select the project located at: `[unzipped_folder]\seedmate_release\SW\BIP39_MCC.X`
6. In the top menu, go to **Production > Build Project (Seedmate)**.
7. Once finished, locate your generated `.hex` file here: `\SW\BIP39_MCC.X\dist\default\production\BIP39_MCC.X.production.hex`
8. Use WinMerge or any other diff tool to compare your generated `.hex` file against the one downloaded from GitHub.
9. Compare the SHA256 hash of your generated file against the SHA256 hash provided on the GitHub release page to verify a perfect match.

## Hardware target - See HW folder

This project targets a PIC32MM-based device with:

- TFT display
- Physical buttons
- SD card interface
- LED blinking

MCU and tools:

- MCU: `PIC32MM0064GPL028`
- Toolchain: `XC32 v5.10`
- IDE / generated files: `MPLAB X / Harmony`

## Project structure

```text
src/
  main.c
  SPI.*
  TFT.*
  SHA256.*
  SHA512.*
  words.h
  SSS/
  SD/
  QRCode-master/
  WjCryptLib-master/
  config/default/    
  
  
  ## Build


This project is intended to be built with Microchip tools.


### Requirements

- MPLAB X

- XC32 compiler

- PIC32MM device pack

- Any project-generated files required by Harmony / MPLAB



## Programming instructions / firmware update
See https://www.seedmate.net/FW_update.html


## Usage notes


- This device is designed to work offline 

- Do not use phones, cloud notes, or networked systems to store sensitive seed material.

- Review the full workflow yourself before trusting it with real funds.

- Treat QR and SD export paths as sensitive.

- See Security Risks & Guidelines https://www.seedmate.net/security.html



## Security warning


This project handles highly sensitive cryptographic material.



This repository is provided for development, educational, and commercial applications unless explicitly stated otherwise.


## Third-party components


This project includes or references third-party code. See:



- THIRD_PARTY_NOTICES.md



## Roadmap / pending cleanup




## License

This project is licensed under the MIT License.

MIT License

Copyright (c) 2026 Seedmate

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


## Author


Seedmate


## Disclaimer


Use at your own risk. The authors provide no warranty of correctness, fitness, or security.
