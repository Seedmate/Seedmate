/*******************************************************************************
 * Project:     SeedMate
 * File:        settings.h
 *
 * Summary:
 *   Permanent settings (decoy game, SeedQR, SD write) in a reserved flash page.
 *
 * Description:
 *   The last 2 KB page of the program flash (0x1D03F800) is reserved: the
 *   app's linker script does not use it and the bootloader neither erases
 *   nor writes it, so the settings survive power off and firmware updates.
 *   Only non-secret preferences go here, never seeds, keys or passphrases.
 *
 *   The page is a log of 8 byte records (one flash double-word each, written
 *   once between erases): a change appends a record, the newest valid one
 *   wins, and the page is erased only when its 256 slots are full (about
 *   250 changes per erase). A page erased or never written reads as all
 *   0xFF, which means the factory defaults: every flag is stored as 1 =
 *   factory default, so no initialization is needed and settings added in
 *   later firmware keep their default for older records.
 *
 *   Record: A5 flags ~flags kef FF FF FF 5A. kef is the KEF iteration
 *   count of the encrypted QR export, stored as SETTING_KEF_FIELD(): 0xFF
 *   (blank, or a record of an older firmware) is the default. A record that
 *   does not match (power lost while writing) is ignored.
 *   The only function that writes flash takes a slot number, so it cannot
 *   touch anything outside the page. Host tests in ../test/settings/.
 *
 * License:     MIT, same as main.c
 ******************************************************************************/

#ifndef SETTINGS_H
#define SETTINGS_H

#include <stdint.h>
#include <stdbool.h>

#define SETTINGS_SLOTS      256                 // 2 KB / 8 byte records

// Flags, 1 = factory default. Bit 0x01 was "decoy on" until the decoy became
// off by default: it is no longer read (kept 1), and the decoy has a new bit,
// so a record saved by an older firmware turns it off instead of meaning the
// opposite of what was chosen.
#define SETTING_LEGACY_DECOY 0x01u              // Not used any more
#define SETTING_SEEDQR_OFF  0x02u               // SeedQR disabled (default off: disabled)
#define SETTING_SDWRITE_OFF 0x04u               // Writing seeds to the SD disabled (default: disabled)
#define SETTING_DECOY_OFF   0x08u               // No snake game at power-on (default: no game)
#define SETTING_STOPWATCH_OFF 0x10u             // STOPWATCH hidden in CREATE (default: hidden)
#define SETTING_IDLE_MASK   0xE0u               // AUTO UNLOAD time: 7 = 10 minutes (default), see main.c
#define SETTING_IDLE_SHIFT  5
// High byte: KEF iterations in steps of 10,000, as ~(steps - 1), so 0xFF is
// 10,000 (default). Not secret: the count is written in clear in the QR.
#define SETTING_KEF_MASK    0xFF00u
#define SETTING_KEF_FIELD(steps) ((uint16_t)((uint8_t)~((steps) - 1u) << 8))
#define SETTING_KEF_STEPS(flags) ((uint8_t)(~((flags) >> 8) + 1u))
#define SETTINGS_DEFAULT    0xFFFFu

// Flags (low byte) and KEF field (high byte) of the newest valid record, or
// SETTINGS_DEFAULT if there is none
uint16_t settings_load(void);

// Saves flags as a new record (nothing is written if they are the current
// ones). Returns false if the flash did not take it: the settings in flash
// are then unchanged.
bool settings_save(uint16_t flags);

#endif // SETTINGS_H
