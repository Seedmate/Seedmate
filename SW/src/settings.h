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
 *   Record: A5 flags ~flags FF FF FF FF 5A. A record that does not match
 *   (power lost while writing) is ignored.
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

// Flags, 1 = factory default
#define SETTING_DECOY_ON    0x01u               // Snake game at power-on (default on)
#define SETTING_SEEDQR_OFF  0x02u               // SeedQR disabled (default off: disabled)
#define SETTING_SDWRITE_OFF 0x04u               // Writing seeds to the SD disabled (default: disabled)
#define SETTINGS_DEFAULT    0xFFu

// Flags of the newest valid record, or SETTINGS_DEFAULT if there is none
uint8_t settings_load(void);

// Saves flags as a new record (nothing is written if they are the current
// ones). Returns false if the flash did not take it: the settings in flash
// are then unchanged.
bool settings_save(uint8_t flags);

#endif // SETTINGS_H
