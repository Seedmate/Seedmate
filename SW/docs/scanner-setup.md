# Setting up a new QR scanner (GM861)

A GM861 comes from the factory at 9600 bps and reading on its own, with no
trigger; the firmware talks to it at 115200 bps in command triggered mode.
Every new sensor is set up once, mounted on the device, with two setting
codes of the manual ("GM861S GM861S-LED Barcode reader module User Manual"
V1.2.4):

1. Power the device on: the factory sensor reads by itself, nothing else is
   needed (the firmware cannot talk to it yet, so it leaves it alone).
2. Scan **115200bps** (section 2.1, "Baud Rate Settlement").
3. Scan **POS Mode** (section 3.5): command triggered mode, serial port, no
   start-up tone, no end character. **It must be the last one**: in command
   triggered mode the sensor stops reading on its own.
4. **Power the device off and on** before using the scanner. Without it the
   sensor answered late or not at all to the first scans (seen on
   2026-11-17 with a new sensor).

The codes are saved in the sensor's flash.

From then on the firmware closes the setting codes before every scan
(zone bit 0x0003 bit 1, in the sensor's RAM, `gm861_lock_setting_codes()`):
a QR on a screen or a sticker can no longer change the sensor. The price: a
sensor already set up cannot be set up again with codes while it is on a
device with this firmware; it would need a service screen or build (not
made, see `pending.md`).

## What it should hold afterwards

Zone bits as read on an old and on a new sensor after the setup (manual,
chapter 10), before the firmware closes the setting codes:

| Zone bit | Value | Meaning |
|---|---|---|
| 0x0000 | 0xD5 | Command triggered mode, standard light and aiming, LED on a good read, sound on |
| 0x0003 | 0x00 | Setting codes open in its flash; the firmware sets bit 1 (0x02) in its RAM before every scan |
| 0x0004 | 0x00 | No image stabilization time |
| 0x0005 | 0x05 | 0.5 s between reads |
| 0x0006 | 0x1E | 3.0 s per read |
| 0x002A, 0x002B | 0x1A, 0x00 | 115200 bps |
| 0x0060 | 0x00 | No end character |

The firmware only ever writes the sensor's RAM (the setting codes lock, and
the animated UR scan, restored on exit), never its flash.
