// Host test of sd_files.c with FatFs on a RAM card (FAT16 and FAT32, formatted
// here with f_mkfs): find, read, long names, names for signed PSBTs, save with
// read-back, full card, refused writes and a card that answers wrong data.
//   gcc -std=c99 -Wall -Wextra -O1 -DSD_FILES_HOST_TEST -DFF_USE_MKFS=1 -I../../src
//       test_sd_files.c ../../src/sd_files.c ../../src/fatfs/ff.c ../../src/fatfs/ffunicode.c -o test_sd_files
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sd_files.h"
#include "fatfs/ff.h"

static uint8_t *card;
static uint32_t card_sectors;
static int fail_writes_after = -1;      // >= 0: one write fails after this many more
static int flip_reads = 0;              // Reads return changed data
static int failures = 0;

#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); failures++; } } while (0)

bool sd_init(void) { return card != NULL; }
DWORD sd_host_sector_count(void) { return card_sectors; }

bool sd_read_partial(uint32_t sector, uint32_t offset, uint32_t count, uint8_t *dst) {
    if (sector >= card_sectors || offset + count > 512) return false;
    memcpy(dst, &card[sector * 512u + offset], count);
    if (flip_reads && count > 0) dst[0] ^= 0x01;
    return true;
}

bool sd_write_block(uint32_t sector, const uint8_t *buffer) {
    if (sector >= card_sectors) return false;
    if (fail_writes_after == 0) {           // One write fails, the next ones work again
        fail_writes_after = -1;
        return false;
    }
    if (fail_writes_after > 0) fail_writes_after--;
    memcpy(&card[sector * 512u], buffer, 512);
    return true;
}

static void format(uint32_t sectors, BYTE fmt) {
    static BYTE work[4096];
    FATFS fs;
    free(card);
    card_sectors = sectors;
    card = calloc(sectors, 512);
    MKFS_PARM opt = { fmt, 1, 0, 0, 0 };
    f_mount(&fs, "", 0);
    CHECK(f_mkfs("", &opt, work, sizeof(work)) == FR_OK);
    f_mount(NULL, "", 0);
}

// A file written with FatFs directly, as a PC would leave it
static void put_file(const char *name, const void *data, UINT len) {
    FATFS fs;
    FIL f;
    UINT bw;
    CHECK(f_mount(&fs, "", 1) == FR_OK);
    CHECK(f_open(&f, name, FA_WRITE | FA_CREATE_ALWAYS) == FR_OK);
    CHECK(f_write(&f, data, len, &bw) == FR_OK && bw == len);
    CHECK(f_close(&f) == FR_OK);
    f_mount(NULL, "", 0);
}

static uint32_t progress_calls, last_written, last_verified;
static void progress(bool verifying, uint32_t done, uint32_t total) {
    progress_calls++;
    if (done > total) failures++;
    if (verifying) last_verified = done; else last_written = done;
}

static void run(const char *label, uint32_t sectors, BYTE fmt) {
    static uint8_t psbt[3000], back[3000];
    static const char *const exts[] = {"PSBT", "PSB", "TXT"};
    char name[SD_FILES_NAME_LEN], found[SD_FILES_NAME_LEN];
    uint32_t size;

    printf("%s\n", label);
    format(sectors, fmt);
    for (uint32_t i = 0; i < sizeof(psbt); i++) psbt[i] = (uint8_t)(i * 31 + 7);
    memcpy(psbt, "psbt\xff", 5);
    put_file("abandon send.psbt", psbt, 1000);                 // As Sparrow names it
    put_file("NOTES.DOC", "x", 1);

    // Reading what a PC left
    CHECK(sd_files_mount());
    CHECK(sd_files_find(0, exts, 3, found, &size) && strcmp(found, "abandon send.psbt") == 0 && size == 1000);
    CHECK(!sd_files_find(1, exts, 3, found, &size));
    CHECK(sd_files_open("abandon send.psbt"));
    CHECK(sd_files_read(back, sizeof(back)) == 1000 && memcmp(back, psbt, 1000) == 0);
    CHECK(sd_files_read(back, sizeof(back)) == 0);

    // Names and saving
    CHECK(sd_files_new_name("abandon send.psbt", name) && strcmp(name, "abandon send-signed.psbt") == 0);
    progress_calls = last_written = last_verified = 0;
    CHECK(sd_files_save(name, psbt, sizeof(psbt), progress) == SD_SAVE_OK);
    CHECK(last_written == sizeof(psbt) && last_verified == sizeof(psbt) && progress_calls >= 7);
    CHECK(sd_files_save(name, psbt, 10, NULL) == SD_SAVE_EXISTS);
    CHECK(sd_files_new_name("abandon send.psbt", name) && strcmp(name, "abandon send-signed-2.psbt") == 0);
    for (int k = 2; k <= 9; k++) {
        CHECK(sd_files_new_name("abandon send.psbt", name));
        CHECK(sd_files_save(name, psbt, 100, NULL) == SD_SAVE_OK);
    }
    CHECK(!sd_files_new_name("abandon send.psbt", name));   // All nine taken
    CHECK(sd_files_new_name(NULL, name) && strcmp(name, "signed.psbt") == 0);
    CHECK(sd_files_new_name("", name) && strcmp(name, "signed.psbt") == 0);
    CHECK(sd_files_new_name("MSWALLET.PSB", name) && strcmp(name, "MSWALLET-signed.psbt") == 0);
    // A long name is cut so the result fits 64 characters
    CHECK(sd_files_new_name("a very long name of a transaction saved by some wallet app.psbt", name));
    CHECK(strlen(name) <= SD_FILES_NAME_LEN - 1 && strstr(name, "-signed.psbt") != NULL);
    CHECK(sd_files_save(name, psbt, 10, NULL) == SD_SAVE_OK);
    CHECK(sd_files_open(name));
    sd_files_unmount();

    // The saved file, read again after a new mount
    CHECK(sd_files_mount());
    CHECK(sd_files_open("abandon send-signed.psbt"));
    CHECK(sd_files_read(back, sizeof(back)) == (int32_t)sizeof(psbt) && memcmp(back, psbt, sizeof(psbt)) == 0);
    uint32_t n = 0;
    while (sd_files_find(n, exts, 3, found, &size)) n++;
    CHECK(n == 11);                                         // The original, nine signed, the long one

    // A write that fails half way: no file is left
    CHECK(sd_files_new_name(NULL, name));
    fail_writes_after = 3;
    CHECK(sd_files_save(name, psbt, sizeof(psbt), NULL) == SD_SAVE_WRITE_ERROR);
    CHECK(f_stat(name, NULL) == FR_NO_FILE);

    // A card that returns other data: the read-back check catches it
    flip_reads = 1;
    sd_save_t r = sd_files_save("flip-signed.psbt", psbt, sizeof(psbt), NULL);
    flip_reads = 0;
    CHECK(r != SD_SAVE_OK);
    sd_files_unmount();
    CHECK(sd_files_mount());
    CHECK(f_stat("flip-signed.psbt", NULL) == FR_NO_FILE);
    sd_files_unmount();
}

static void run_full(void) {
    static uint8_t big[600000];
    char name[SD_FILES_NAME_LEN];
    printf("FAT12 card of 512 KB, a file bigger than the card\n");
    format(1024, FM_FAT);
    CHECK(sd_files_mount());
    CHECK(sd_files_new_name("big.psbt", name));
    CHECK(sd_files_save(name, big, sizeof(big), NULL) == SD_SAVE_FULL);
    CHECK(f_stat(name, NULL) == FR_NO_FILE);
    sd_files_unmount();

    printf("A card without a file system (a seed card)\n");
    memset(card, 0, 1024u * 512u);
    CHECK(!sd_files_mount());
}

int main(void) {
    run("FAT16 card of 16 MB", 32768, FM_FAT);
    run("FAT32 card of 64 MB", 131072, FM_FAT32);
    run_full();
    free(card);
    printf(failures ? "\n%d FAILURE(S)\n" : "\nALL TESTS PASSED\n", failures);
    return failures != 0;
}
