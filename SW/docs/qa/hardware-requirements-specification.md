# Seedmate - Hardware Requirements Specification (HWRS)

| Document | SM-HWRS |
|---|---|
| Issue | 0.4 (draft for the project owner's review) |
| Date | 2026-11-23 |
| Hardware item | Seedmate v2: the device as delivered (electronics, display, QR scanner, case) |
| Criticality category | B (`SPAP.md`, section 4) |

## 1. Introduction

This document states what the Seedmate hardware shall be and do. Each
requirement has an identifier, a verification method and a validation
method, as the SRS does for the firmware. It states requirements only: the
design that meets them, and the design data, come after it and are named in
the verification and validation reports.

The interface between hardware and firmware is stated here (section 4) and
referred to by the SRS.

### 1.1 Verification and validation of hardware

The methods are those of the SPAP: T test, A analysis, R review of design,
I inspection. For hardware:

- **Verification** is done on the design, without hardware: review of the
  design data, analysis (power budget, derating, tolerances, thermal),
  inspection of the design data, and tests that run on the design (ERC,
  DRC, simulation).
- **Validation** is done on physical units: tests on prototypes once per
  hardware revision (qualification: drop, temperature, ESD, autonomy,
  reverse cells), the acceptance test of every unit built (section 5.9),
  and finished units in real use.

## 2. Applicable and reference documents

As `SPAP.md`, section 2, and:

| Id | Document |
|---|---|
| HD1 | ECSS-E-ST-10-03C, Space engineering - Testing (qualification and acceptance concept, tailored) |
| HD2 | ECSS-Q-ST-30-11C Rev.2, Derating - EEE components (guidance for the derating analysis) |
| HD3 | ECSS-Q-ST-70-12C, Design rules for printed circuit boards (guidance; IPC-2221 applies) |
| HD4 | IPC-2221, Generic standard on printed board design |
| HD5 | IPC-6012, Qualification and performance specification for rigid printed boards, class 2 |
| HD6 | IPC-A-610, Acceptability of electronic assemblies, class 2 |
| HD7 | IEC 60068-2-31, Rough handling shocks (free fall) |
| HD8 | IEC 61000-4-2, Electrostatic discharge immunity test |
| HD9 | EN 55035, Immunity requirements for multimedia equipment (the ESD levels) |
| HD10 | RoHS Directive 2011/65/EU and REACH Regulation (EC) 1907/2006 |
| HD11 | ISO 15184, Pencil hardness test |

The space standards are guidance: a consumer device follows the IPC, IEC and
EN standards named, tailored as section 7 says.

## 3. Acronyms

| Acronym | Meaning |
|---|---|
| AOI | Automated optical inspection |
| BOM | Bill of materials |
| CE | Conformité Européenne (EU conformity marking) |
| DRC | Design rule check (of the board layout) |
| EMC | Electromagnetic compatibility |
| ERC | Electrical rule check (of the schematic) |
| ESD | Electrostatic discharge |
| FW | Firmware (the application and the bootloader) |
| HW | Hardware |
| IC | Integrated circuit |
| ICSP | In-circuit serial programming |
| IPC | Association Connecting Electronics Industries (board standards) |
| LED | Light emitting diode |
| MCU | Microcontroller unit |
| NiMH | Nickel metal hydride (rechargeable cell) |
| PCB | Printed circuit board |
| PMMA | Polymethyl methacrylate (acrylic, "metacrilato") |
| QR | Quick response code |
| REACH | Registration, Evaluation, Authorisation and Restriction of Chemicals |
| RoHS | Restriction of Hazardous Substances |
| SD | Secure Digital (memory card) |
| SPI | Serial peripheral interface |
| SW | Software |
| UART | Universal asynchronous receiver-transmitter |
| USB | Universal serial bus |
| WEEE | Waste electrical and electronic equipment |

## 4. Hardware overview and interfaces

### 4.1 Functions

- An MCU that runs the FW, with its program memory on chip.
- Power from user-replaceable cells, through a power switch, a reverse
  polarity protection and a voltage regulator.
- A colour display, six push buttons, a power LED and an activity LED.
- An SD card slot.
- A QR scanner.
- A case with a transparent cover over the electronics.
- No radio, no antenna, no USB, no external connector.

### 4.2 Hardware-firmware interface

| Function | Interface to the MCU |
|---|---|
| Display | SPI, with reset, command/data and backlight lines |
| SD card | SPI |
| QR scanner | UART, 115200 bps, 3.3 V logic |
| Keys | Six digital inputs, active low, filtered |
| Activity LED | One digital output |
| Programming | ICSP, reachable only with the case open |

The pin assignment is part of the design.

## 5. Requirements

Each row gives the identifier, the requirement, the verification method,
the validation method and the reason or source.

### 5.1 Architecture and security (ARC)

| Id | Requirement | Ver | Val | Src |
|---|---|---|---|---|
| HR-ARC-001 | The device shall contain no radio transmitter or receiver and no antenna, nor any trace or part designed as one. | R | I | Air gap |
| HR-ARC-002 | The device shall have no external connector for data or power. | R | I | Air gap |
| HR-ARC-003 | The SD card, the QR scanner, the buttons and the display shall be the only data paths into and out of the device. | R | I | Air gap, SR-IF-001 |
| HR-ARC-004 | The device shall have no non-volatile memory besides the MCU program memory and the SD card, and no part able to keep data with the power off besides them. | R | I | SR-SEC |
| HR-ARC-005 | The programming port shall be reachable only with the case open, and no programming connector shall be fitted on delivered units. | R | I | Air gap |
| HR-ARC-006 | Every electronic part shall be visible through the closed case without opening it, with no potting, opaque coating, label or shield over it. | R | I | Tamper evidence |
| HR-ARC-007 | High resolution photographs of both sides of the reference board and of the open device shall be published, so a user can compare a unit with them. | R | I | Tamper evidence |
| HR-ARC-008 | The markings of every IC shall be readable through the closed case. | R | I | Tamper evidence |
| HR-ARC-009 | The device, its case and its packaging shall show no product name or logo. | R | I | Discretion |

### 5.2 Power (PWR)

| Id | Requirement | Ver | Val | Src |
|---|---|---|---|---|
| HR-PWR-001 | The device shall be powered by alkaline cells of a standard size sold in ordinary shops, and by nothing else. | R | I | Usability, air gap |
| HR-PWR-002 | With new cells the device shall work at least 15 hours of normal use. | A | T | Autonomy |
| HR-PWR-003 | The user shall be able to replace the cells without tools other than an Allen key, in under one minute, with the polarity marked at the holder. | R | T | Usability |
| HR-PWR-004 | A physical power switch shall disconnect the cells from every circuit, so that the device draws no current from them when off. | R | T | Battery life in storage |
| HR-PWR-005 | Cells inserted in any orientation, one or all reversed, shall not damage the device, and the device shall work normally once they are inserted correctly. | A | T | Robustness |
| HR-PWR-006 | The MCU shall be able to measure its own supply voltage, so that the FW can warn of low cells and stop writing the SD card before the voltage falls below the minimum of the card. | A | T | Reliability, SR-REL-003 |
| HR-PWR-007 | The voltage regulator shall work below 80 % of each of its limits (input voltage, output current, power dissipation, junction temperature) in the worst case of cells, load and temperature. | A | T | Derating, HD2 |
| HR-PWR-008 | A power LED shall show that the device is on. | R | I | Transparency |

### 5.3 User interface (HMI)

| Id | Requirement | Ver | Val | Src |
|---|---|---|---|---|
| HR-HMI-001 | The display shall be a colour screen of at least 160 x 128 pixels, enough for every screen of the FW without overlap. | R | T | Usability |
| HR-HMI-002 | The display shall show the QR codes of the FW at a size that the phones and wallets of the COMP tests read. | A | T | Interoperability |
| HR-HMI-003 | The display shall be readable at 30 cm under ordinary indoor light. | R | T | Usability |
| HR-HMI-004 | The device shall have six push buttons placed as the grid of the FW: BACK, UP, OK on the top row, LEFT, DOWN, RIGHT on the bottom row. | R | I | Usability, SR-HF |
| HR-HMI-005 | The buttons shall be rated for at least 100,000 presses and give a tactile click. | R | R | Reliability |
| HR-HMI-006 | An activity LED driven by the MCU shall be visible through the closed case. | R | I | Transparency (project rule 4) |
| HR-HMI-007 | The QR scanner shall read the static and animated QR codes of the formats the FW takes, from a phone screen and from paper. | R | T | Interoperability |
| HR-HMI-008 | The device shall have a slot for full size SD cards (SDSC and SDHC), reachable with the case closed. | R | T | Interoperability |

### 5.4 Printed circuit board (PCB)

| Id | Requirement | Ver | Val | Src |
|---|---|---|---|---|
| HR-PCB-001 | The PCB shall have four copper layers. | I | I | Signal integrity, EMC |
| HR-PCB-002 | Every signal shall be routed on one layer, without changing layer, over a continuous reference plane that no other trace or split interrupts under it. | R | I | Signal integrity, EMC |
| HR-PCB-003 | Signals with fast edges shall be routed with controlled impedance in the stack-up of the board maker. | A | T | Signal integrity |
| HR-PCB-004 | Every IC shall have proper decoupling of its supply pins. | R | I | Signal integrity |
| HR-PCB-005 | The PCB shall be designed to IPC-2221 and built to IPC-6012 class 2. | R | I | HD4, HD5 |
| HR-PCB-006 | The design shall pass ERC and DRC with no error, and every waived warning shall be justified. | T | R | Design quality |
| HR-PCB-007 | The PCB shall have test pads for the programming port, every supply rail and ground, reachable by a test fixture. | R | I | Manufacturing test (5.9) |

### 5.5 Components (EEE)

| Id | Requirement | Ver | Val | Src |
|---|---|---|---|---|
| HR-EEE-001 | Every part shall be rated for at least the operating and storage ranges of section 5.6, and used within the derating of HD2. | A | T | Reliability, HD2 |
| HR-EEE-002 | Every part shall be RoHS and REACH compliant. | R | I | HD10 |

### 5.6 Environment (ENV)

| Id | Requirement | Ver | Val | Src |
|---|---|---|---|---|
| HR-ENV-001 | The device shall work from 0 C to 45 C ambient. | A | T | Use |
| HR-ENV-002 | The device shall survive storage from -10 C to 45 C without cells. | A | T | Use |
| HR-ENV-003 | The device shall work from 10 % to 90 % relative humidity, without condensation. | A | A | Use |
| HR-ENV-004 | The device shall work after free falls of 0.8 m onto a hard floor on each face (HD7), without loss of function and without the cells leaving the holder; marks on the case are accepted. | A | T | Robustness |
| HR-ENV-005 | The cover shall be of a hardness of at least 2H (HD11) and, after the drop tests and ordinary handling, the markings of HR-ARC-008 shall still be readable through it; surface scratches are accepted. | R | T | Tamper evidence, robustness |
| HR-ENV-006 | The device shall withstand ESD of 4 kV contact and 8 kV air (HD8) on its keys, switch, cover, SD slot and cards, without damage and without loss of data; a reset is accepted. | A | T | Robustness, HD9 |

### 5.7 Regulatory (REG)

| Id | Requirement | Ver | Val | Src |
|---|---|---|---|---|
| HR-REG-001 | The device shall meet RoHS and REACH. | R | R | HD10 |
| HR-REG-002 | Every unit shall carry a label with its hardware revision and serial number. | R | I | Traceability |

### 5.8 Design data (DOC)

| Id | Requirement | Ver | Val | Src |
|---|---|---|---|---|
| HR-DOC-001 | The schematic, BOM, PCB manufacturing files, placement file and case models of every hardware revision shall be in the repository and match what is built. | R | I | Open design, configuration |
| HR-DOC-002 | Every hardware change shall raise the hardware revision, printed on the PCB. | R | I | Configuration |

### 5.9 Manufacturing and acceptance test (MFG)

| Id | Requirement | Ver | Val | Src |
|---|---|---|---|---|
| HR-MFG-001 | Every bare PCB shall pass the electrical test of the board maker (opens and shorts). | R | I | HD5 |
| HR-MFG-002 | Every assembled PCB shall be inspected to IPC-A-610 class 2, by AOI or by eye. | R | I | HD6 |
| HR-MFG-003 | Every unit (100 %) shall pass the acceptance test: current off and on within limits, supply rails, each key, a display pattern, both LEDs, SD write and read back, the scanner reading a reference QR. | R | T | Quality |
| HR-MFG-004 | Every unit shall be programmed with the bootloader and the signed release FW, and shall show the expected versions and the flash locked on the FW's own screen. | R | T | Quality, SR-BL |
| HR-MFG-005 | The result of the acceptance test of every unit shall be recorded with its MCU serial number, FW hash, date and tester, and kept. | R | I | Traceability |
| HR-MFG-006 | A unit that fails a test shall be repaired and tested again in full, or scrapped, and the failure recorded as a nonconformance. | R | I | SPAP 6.5 |
| HR-MFG-007 | Assembly and test shall be done with ESD protection. | R | I | Quality |
| HR-MFG-008 | The first units of every hardware revision shall pass the qualification tests (HR-PWR-002, HR-PWR-005, HR-ENV-001 to HR-ENV-006) before others are delivered. | R | T | HD1 |

## 6. Traceability

Each requirement is checked by the methods named. The hardware test
specification (qualification and acceptance procedures) is to be written,
with test ids that name these requirements, as the device tests of the FW
do. `SW/test/qa/check_srs.py` checks the form of this file.

## 7. Open points for the project owner

Values to confirm before the HWRS is approved:

1. HR-ENV-002 and HR-ENV-003: storage -10..45 C, humidity 10..90 %.
2. HR-ENV-004: drop height 0.8 m.
3. HR-ENV-005: 2H is about the hardness of untreated PMMA; the requirement
   accepts surface scratches as long as the electronics stay readable.
4. HR-ENV-006: ESD 4 kV contact, 8 kV air (the EN 55035 levels).
5. HR-HMI-005: 100,000 presses.
