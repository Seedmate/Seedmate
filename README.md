# SeedMate

SeedMate is a PIC32MM-based offline tool for generating, loading, transforming, splitting, merging, displaying, and exporting BIP39-compatible seed data.

Status: Tested and production-ready. However, unexpected bugs may still occur. Review security, licensing, and third-party dependencies before deployment.

## Features

- Offline seed handling
- Entropy capture from multiple input methods
- BIP39 word-based workflows
- XOR-based seed operations
- Shamir Secret Sharing workflows
- QR export
- SD card storage/export
- TFT display and button-driven interface

## Hardware target - See HW folfer

This project targets a PIC32MM-based device with:

- TFT display
- Physical buttons
- SD card interface
- LED blinking

MCU and tools:

- MCU: `PIC32MM0064GPL028`
- Toolchain: `XC32 v4.60`
- IDE / generated files: `MPLAB X / Harmony`

## Project structure

```text
src/
  main.c
  SPI.*
  TFT.*
  SHA256.*
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



### Typical build flow



1. Open the project in MPLAB X.

2. Select the correct configuration.

3. Build the project with XC32.

4. Flash the generated firmware to the target board. A Microchip programmer tool is required:
https://www.microchip.com/en-us/development-tool/pg164130




## Usage notes



- This device is designed to work offline 

- Do not use phones, cloud notes, or networked systems to store sensitive seed material.

- Review the full workflow yourself before trusting it with real funds.

- Treat QR and SD export paths as sensitive.



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

Copyright (c) 2026 [Tu Nombre o Nombre de la Empresa]

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