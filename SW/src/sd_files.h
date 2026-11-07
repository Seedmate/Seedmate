/*******************************************************************************
 * Project:     SeedMate
 * File:        sd_files.h
 *
 * Summary:
 *   Files on the SD card (FAT12/16/32 root directory, long names): read, and
 *   write a new file.
 *
 * Description:
 *   Thin wrapper over FatFs R0.16 (fatfs/, configured in fatfs/ffconf.h: long
 *   names up to 64 characters, no exFAT). sd_files.c also implements the FatFs disk interface
 *   on top of the app's SD driver (sd_init, sd_read_partial, sd_write_block in
 *   main.c).
 *
 *   Names are the long ones a PC wrote ("abandon send.psbt"); a longer name
 *   than 64 characters shows up as its 8.3 alias. One file is open at a time.
 *   A file is only ever written new, never over another one.
 *
 *   The seed slots and the vault live on a card without a file system (see
 *   SD CARD > INITIALIZE CARD); the caller must refuse such a card before
 *   writing (its marker sector), since this module cannot tell.
 *
 * License:     MIT, same as main.c
 ******************************************************************************/

#ifndef SD_FILES_H
#define SD_FILES_H

#include <stdint.h>
#include <stdbool.h>

#define SD_FILES_NAME_LEN 65    // Long name (FF_LFN_BUF) + NUL

// Initializes the card and mounts its FAT volume.
bool sd_files_mount(void);

// Releases the volume (nothing is cached when writing has finished).
void sd_files_unmount(void);

// Finds the n-th (0-based) file in the root directory whose extension is
// one of exts (upper case; the name's case does not matter). Fills name and
// size on success.
bool sd_files_find(uint32_t n, const char *const *exts, uint32_t ext_count,
                   char *name, uint32_t *size);

// Opens a file by name for reading.
bool sd_files_open(const char *name);

// Reads up to len bytes from the open file. Returns the bytes read
// (0 at end of file) or -1 on error.
int32_t sd_files_read(void *dst, uint32_t len);

// Name for a signed PSBT that is not on the card yet, as Coldcard does: src
// without its extension + "-signed.psbt" ("abandon send.psbt" -> "abandon
// send-signed.psbt"; NULL -> "signed.psbt"), then "-signed-2.psbt" ..
// "-signed-9.psbt". False if all are taken or the card fails.
bool sd_files_new_name(const char *src, char *name);

typedef enum {
    SD_SAVE_OK = 0,
    SD_SAVE_EXISTS,         // The name is taken: nothing written
    SD_SAVE_FULL,           // No room on the card: the partial file is removed
    SD_SAVE_WRITE_ERROR,    // The card refused a write: the partial file is removed
    SD_SAVE_VERIFY_ERROR    // Read back differs: the file is removed
} sd_save_t;

// Creates file name with the len bytes of data and reads it back to compare.
// progress (may be NULL) gets the bytes written, then the bytes verified.
sd_save_t sd_files_save(const char *name, const uint8_t *data, uint32_t len,
                        void (*progress)(bool verifying, uint32_t done, uint32_t total));

#endif // SD_FILES_H
