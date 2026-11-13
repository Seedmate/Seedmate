/*******************************************************************************
 * Project:     SeedMate
 * File:        sd_files.c
 *
 * Summary:
 *   SD card files over FatFs. See sd_files.h.
 *
 * License:     MIT, same as main.c
 ******************************************************************************/

#include <string.h>
#include "sd_files.h"
#include "fatfs/ff.h"
#include "fatfs/diskio.h"

// SD driver in main.c (a RAM card in the host test)
bool sd_init(void);
bool sd_read_partial(uint32_t sector, uint32_t offset, uint32_t count, uint8_t *dst);
bool sd_write_block(uint32_t sector, const uint8_t *buffer);
#ifdef SD_FILES_HOST_TEST
DWORD sd_host_sector_count(void);
#endif

static FATFS fs;
static FIL file;                // The one open file
static bool card_ready;

// Sectors one sd_files_* call may read or write. A card taken out can answer
// garbage that looks valid, and FatFs then walks a directory of up to 2 MB
// (4096 sectors, seconds on the device) on every pass: a page of the file
// list would take minutes. Past the budget every access fails, so every call
// ends soon. A listing pass needs a few sectors on a real card (the root
// directory and the FAT entries of its chain); saving a PSBT and reading it
// back needs well under the file budget.
#define SD_FILES_LIST_BUDGET 256u
#define SD_FILES_FILE_BUDGET 4096u
static uint32_t sector_budget;

static void budget_reset(uint32_t sectors) {
    sector_budget = sectors;
}

#ifdef SD_FILES_HOST_TEST
// The host test formats and fills its RAM cards with FatFs directly
void sd_files_host_no_budget(void) {
    sector_budget = 0xFFFFFFFFu;
}
#endif

static bool budget_take(void) {
    if (sector_budget == 0) return false;
    sector_budget--;
    return true;
}

// ============================================================================
// FatFs disk interface (one drive, 512 byte sectors)
// ============================================================================

DSTATUS disk_initialize(BYTE pdrv) {
    (void)pdrv;
    card_ready = sd_init();
    return card_ready ? 0 : STA_NOINIT;
}

DSTATUS disk_status(BYTE pdrv) {
    (void)pdrv;
    return card_ready ? 0 : STA_NOINIT;
}

DRESULT disk_read(BYTE pdrv, BYTE *buff, LBA_t sector, UINT count) {
    (void)pdrv;
    for (UINT i = 0; i < count; i++) {
        if (!budget_take() || !sd_read_partial(sector + i, 0, 512, buff + 512u * i)) return RES_ERROR;
    }
    return RES_OK;
}

DRESULT disk_write(BYTE pdrv, const BYTE *buff, LBA_t sector, UINT count) {
    (void)pdrv;
    for (UINT i = 0; i < count; i++) {
        if (!budget_take() || !sd_write_block(sector + i, buff + 512u * i)) return RES_ERROR;
    }
    return RES_OK;
}

DRESULT disk_ioctl(BYTE pdrv, BYTE cmd, void *buff) {
    (void)pdrv;
    if (cmd == CTRL_SYNC) return RES_OK;    // Every block is written before returning
#ifdef SD_FILES_HOST_TEST
    if (cmd == GET_SECTOR_COUNT) { *(LBA_t *)buff = sd_host_sector_count(); return RES_OK; }
    if (cmd == GET_BLOCK_SIZE) { *(DWORD *)buff = 1; return RES_OK; }
#else
    (void)buff;
#endif
    return RES_PARERR;
}

// ============================================================================
// Reading
// ============================================================================

bool sd_files_mount(void) {
    budget_reset(SD_FILES_FILE_BUDGET);
    f_mount(NULL, "", 0);
    card_ready = false;
    return f_mount(&fs, "", 1) == FR_OK;    // Initializes the card and reads the volume now
}

void sd_files_unmount(void) {
    f_mount(NULL, "", 0);
}

// True if the name ends in one of the wanted extensions, in any case
static bool has_extension(const char *name, const char *const *exts, uint32_t ext_count) {
    const char *dot = strrchr(name, '.');
    if (dot == NULL) return false;
    for (uint32_t i = 0; i < ext_count; i++) {
        const char *a = dot + 1, *b = exts[i];
        while (*a != '\0' && *b != '\0' && (char)(*a >= 'a' && *a <= 'z' ? *a - 32 : *a) == *b) {
            a++;
            b++;
        }
        if (*a == '\0' && *b == '\0') return true;
    }
    return false;
}

bool sd_files_find(uint32_t n, const char *const *exts, uint32_t ext_count,
                   char *name, uint32_t *size) {
    budget_reset(SD_FILES_LIST_BUDGET);
    DIR dir;
    FILINFO info;
    bool found = false;
    uint32_t seen = 0;

    if (f_opendir(&dir, "") != FR_OK) return false;
    while (f_readdir(&dir, &info) == FR_OK && info.fname[0] != '\0' && ++seen <= SD_FILES_MAX_ENTRIES) {
        if (info.fattrib & (AM_DIR | AM_HID | AM_SYS)) continue;
        if (!has_extension(info.fname, exts, ext_count)) continue;
        if (n-- != 0) continue;

        memcpy(name, info.fname, SD_FILES_NAME_LEN);
        *size = (uint32_t)info.fsize;
        found = true;
        break;
    }
    f_closedir(&dir);
    return found;
}

// Names compared with ASCII letters in upper case, as FAT treats them
static int name_cmp(const char *a, const char *b) {
    while (*a != '\0' && *b != '\0') {
        char x = (*a >= 'a' && *a <= 'z') ? (char)(*a - 32) : *a;
        char y = (*b >= 'a' && *b <= 'z') ? (char)(*b - 32) : *b;
        if (x != y) return (int)(uint8_t)x - (int)(uint8_t)y;
        a++;
        b++;
    }
    return (int)(uint8_t)*a - (int)(uint8_t)*b;
}

int32_t sd_files_next_sorted(const char *after, const char *const *exts, uint32_t ext_count, char *name) {
    budget_reset(SD_FILES_LIST_BUDGET);
    DIR dir;
    FILINFO info;
    int32_t best = -1, n = 0;
    uint32_t seen = 0;

    if (f_opendir(&dir, "") != FR_OK) return -1;
    while (f_readdir(&dir, &info) == FR_OK && info.fname[0] != '\0' && ++seen <= SD_FILES_MAX_ENTRIES) {
        if (info.fattrib & (AM_DIR | AM_HID | AM_SYS)) continue;
        if (!has_extension(info.fname, exts, ext_count)) continue;
        if ((after == NULL || name_cmp(info.fname, after) > 0) && (best < 0 || name_cmp(info.fname, name) < 0)) {
            best = n;
            memcpy(name, info.fname, SD_FILES_NAME_LEN);
        }
        n++;
    }
    f_closedir(&dir);
    return best;
}

bool sd_files_open(const char *name) {
    budget_reset(SD_FILES_FILE_BUDGET);
    f_close(&file);
    return f_open(&file, name, FA_READ) == FR_OK;
}

int32_t sd_files_read(void *dst, uint32_t len) {
    budget_reset(SD_FILES_FILE_BUDGET);
    UINT got = 0;
    if (f_read(&file, dst, (UINT)len, &got) != FR_OK) return -1;
    return (int32_t)got;
}

// ============================================================================
// Writing
// ============================================================================

bool sd_files_new_name(const char *src, char *name) {
    budget_reset(SD_FILES_FILE_BUDGET);
    static const char suffix[] = "-signed";
    const size_t room = SD_FILES_NAME_LEN - 1 - (sizeof(suffix) - 1) - 2 - 5;     // "-2" ".psbt"
    size_t n = 0;
    FILINFO info;

    if (src != NULL) {
        const char *dot = strrchr(src, '.');
        n = (dot != NULL) ? (size_t)(dot - src) : strlen(src);
        if (n > room) n = room;
    }
    for (int k = 1; k <= 9; k++) {
        size_t len = n;
        memcpy(name, src, n);
        if (n > 0) {
            memcpy(&name[len], suffix, sizeof(suffix) - 1);
            len += sizeof(suffix) - 1;
        } else {
            memcpy(name, "signed", 6);                  // A PSBT that came from a QR
            len = 6;
        }
        if (k > 1) {
            name[len++] = '-';
            name[len++] = (char)('0' + k);
        }
        memcpy(&name[len], ".psbt", 6);

        FRESULT r = f_stat(name, &info);
        if (r == FR_NO_FILE) return true;
        if (r != FR_OK) return false;
    }
    return false;
}

sd_save_t sd_files_save(const char *name, const uint8_t *data, uint32_t len,
                        void (*progress)(bool verifying, uint32_t done, uint32_t total)) {
    budget_reset(SD_FILES_FILE_BUDGET);
    UINT done;
    uint32_t pos = 0;
    sd_save_t result = SD_SAVE_OK;

    f_close(&file);
    FRESULT r = f_open(&file, name, FA_WRITE | FA_CREATE_NEW);
    if (r == FR_EXIST) return SD_SAVE_EXISTS;
    if (r == FR_DENIED) return SD_SAVE_FULL;         // No free directory entry
    if (r != FR_OK) return SD_SAVE_WRITE_ERROR;

    while (pos < len) {
        uint32_t chunk = (len - pos > 512u) ? 512u : len - pos;
        r = f_write(&file, &data[pos], (UINT)chunk, &done);
        if (r != FR_OK) { result = SD_SAVE_WRITE_ERROR; break; }
        if (done < chunk) { result = SD_SAVE_FULL; break; }
        pos += chunk;
        if (progress != NULL) progress(false, pos, len);
    }
    if (f_close(&file) != FR_OK && result == SD_SAVE_OK) result = SD_SAVE_WRITE_ERROR;

    // Read back what was written, from the card
    if (result == SD_SAVE_OK) {
        uint8_t back[64];
        if (f_open(&file, name, FA_READ) != FR_OK || f_size(&file) != len) result = SD_SAVE_VERIFY_ERROR;
        for (pos = 0; result == SD_SAVE_OK && pos < len; pos += done) {
            uint32_t chunk = (len - pos > sizeof(back)) ? sizeof(back) : len - pos;
            if (f_read(&file, back, (UINT)chunk, &done) != FR_OK || done != chunk ||
                memcmp(back, &data[pos], chunk) != 0) {
                result = SD_SAVE_VERIFY_ERROR;
                break;
            }
            if (progress != NULL && (((pos + done) & 511u) == 0 || pos + done == len)) progress(true, pos + done, len);
        }
        f_close(&file);
    }
    if (result != SD_SAVE_OK) f_unlink(name);       // No half or wrong file is left
    return result;
}
