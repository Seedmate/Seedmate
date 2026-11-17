# Setting up a new QR scanner (GM861)

A GM861 comes from the factory at 9600 bps; the firmware talks to it at
115200 bps in command triggered mode. Every new sensor is set up once, before
it is used, with two setting codes of the manual ("GM861S GM861S-LED Barcode
reader module User Manual" V1.2.4):

1. Scan **115200bps** (section 2.1, "Baud Rate Settlement").
2. Scan **POS Mode** (section 3.5): command triggered mode, serial port, no
   start-up tone, no end character.
3. **Power the device off and on** before using the scanner. Without it the
   sensor answered late or not at all to the first scans (seen on
   2026-11-17 with a new sensor).

The codes are saved in the sensor's flash. The order of 1 and 2 does not
matter: POS Mode does not change the speed.

How to scan them: with the scanner mounted on a device, any screen that
scans (TOOLS > QR READER) makes it read a code; setting codes are taken by
the sensor itself. If the device firmware cannot talk to the sensor (a new
sensor is at 9600 bps), a build at 9600 bps is needed for step 1: the same
firmware with `U2BRG = 155` instead of `12` in `main()`, never released.

## What it should hold afterwards

Zone bits as read on an old and on a new sensor (manual, chapter 10):

| Zone bit | Value | Meaning |
|---|---|---|
| 0x0000 | 0xD5 | Command triggered mode, standard light and aiming, LED on a good read, sound on |
| 0x0003 | 0x00 | Setting codes open (see `pending.md`: lock them) |
| 0x0004 | 0x00 | No image stabilization time |
| 0x0005 | 0x05 | 0.5 s between reads |
| 0x0006 | 0x1E | 3.0 s per read |
| 0x002A, 0x002B | 0x1A, 0x00 | 115200 bps |
| 0x0060 | 0x00 | No end character |

The firmware only ever writes the sensor's RAM (the animated UR scan,
restored on exit), never its flash.
