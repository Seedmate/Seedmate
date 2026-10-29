/*******************************************************************************
 * Project:     SeedMate
 * File:        sd_files.c
 *
 * Summary:
 *   Read-only SD card file access over Petit FatFs. See sd_files.h.
 *
 * License:     MIT, same as main.c
 ******************************************************************************/

#include <string.h>
#include "sd_files.h"
#include "../../bootloader/src/pff.h"
#include "../../bootloader/src/diskio.h"

// SD driver in main.c
bool sd_init(void);
bool sd_read_partial(uint32_t sector, uint32_t offset, uint32_t count, uint8_t *dst);

static FATFS fs;

// ============================================================================
// Petit FatFs disk interface
// ============================================================================

DSTATUS disk_initialize(void) {
    return sd_init() ? 0 : STA_NOINIT;
}

DRESULT disk_readp(BYTE *buff, DWORD sector, UINT offset, UINT count) {
    return sd_read_partial(sector, offset, count, buff) ? RES_OK : RES_ERROR;
}

DRESULT disk_writep(const BYTE *buff, DWORD sc) {
    (void)buff;
    (void)sc;
    return RES_ERROR;   // Read-only
}

// ============================================================================
// Public API
// ============================================================================

bool sd_files_mount(void) {
    return disk_initialize() == 0 && pf_mount(&fs) == FR_OK;
}

// True if the 8.3 name "NAME.EXT" has one of the wanted extensions
static bool has_extension(const char *name, const char *const *exts, uint32_t ext_count) {
    const char *dot = strrchr(name, '.');
    if (dot == NULL) return false;
    for (uint32_t i = 0; i < ext_count; i++) {
        if (strcmp(dot + 1, exts[i]) == 0) return true;
    }
    return false;
}

bool sd_files_find(uint32_t n, const char *const *exts, uint32_t ext_count,
                   char *name, uint32_t *size) {
    DIR dir;
    FILINFO info;

    if (pf_opendir(&dir, "") != FR_OK) return false;
    while (pf_readdir(&dir, &info) == FR_OK && info.fname[0] != '\0') {
        if (info.fattrib & AM_DIR) continue;
        if (!has_extension(info.fname, exts, ext_count)) continue;
        if (n-- != 0) continue;

        memcpy(name, info.fname, SD_FILES_NAME_LEN);
        *size = info.fsize;
        return true;
    }
    return false;
}

bool sd_files_open(const char *name) {
    return pf_open(name) == FR_OK;
}

int32_t sd_files_read(void *dst, uint32_t len) {
    UINT got = 0;
    if (pf_read(dst, (UINT)len, &got) != FR_OK) return -1;
    return (int32_t)got;
}
