/*******************************************************************************
 * Project:     SeedMate
 * File:        sd_files.h
 *
 * Summary:
 *   Read-only access to files on the SD card (FAT16 root directory).
 *
 * Description:
 *   Thin wrapper over Petit FatFs, whose sources are shared with the
 *   bootloader (../../bootloader/src/pff.c, pff.h, pffconf.h). sd_files.c also
 *   implements the pff disk interface on top of the app's own SD driver
 *   (sd_init / sd_read_partial in main.c), so no sector buffer is needed.
 *
 *   Petit FatFs only sees 8.3 short names: "transaction.psbt" shows up as
 *   "TRANSA~1.PSB". Only one file can be open at a time.
 *
 *   The raw seed slots that the app writes live in sectors outside the FAT
 *   volume; this module never writes to the card.
 *
 * License:     MIT, same as main.c
 ******************************************************************************/

#ifndef SD_FILES_H
#define SD_FILES_H

#include <stdint.h>
#include <stdbool.h>

#define SD_FILES_NAME_LEN 13    // "NAME1234.EXT" + NUL

// Initializes the card and mounts its FAT volume.
bool sd_files_mount(void);

// Finds the n-th (0-based) file in the root directory whose extension is
// one of exts (3 uppercase chars each). Fills name and size on success.
bool sd_files_find(uint32_t n, const char *const *exts, uint32_t ext_count,
                   char *name, uint32_t *size);

// Opens a file by 8.3 name for reading.
bool sd_files_open(const char *name);

// Reads up to len bytes from the open file. Returns the bytes read
// (0 at end of file) or -1 on error.
int32_t sd_files_read(void *dst, uint32_t len);

#endif // SD_FILES_H
