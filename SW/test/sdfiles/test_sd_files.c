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
static uint32_t reads;                  // Sectors read from the card

#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); failures++; } } while (0)

bool sd_init(void) { return card != NULL; }
DWORD sd_host_sector_count(void) { return card_sectors; }
void sd_files_host_no_budget(void);

bool sd_read_partial(uint32_t sector, uint32_t offset, uint32_t count, uint8_t *dst) {
    if (sector >= card_sectors || offset + count > 512) return false;
    reads++;
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
    sd_files_host_no_budget();
    f_mount(&fs, "", 0);
    CHECK(f_mkfs("", &opt, work, sizeof(work)) == FR_OK);
    f_mount(NULL, "", 0);
}

// A file written with FatFs directly, as a PC would leave it
static void put_file(const char *name, const void *data, UINT len) {
    FATFS fs;
    FIL f;
    UINT bw;
    sd_files_host_no_budget();
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

// The card is taken out, files are added on a PC and it comes back: the next
// mount must list them (the SIGN FROM SD list is read again on every entry)
static uint32_t count_psbts(void) {
    static const char *const exts[] = {"PSBT", "PSB", "TXT"};
    char name[SD_FILES_NAME_LEN];
    uint32_t size, n = 0;
    while (n < 99 && sd_files_find(n, exts, 3, name, &size)) n++;
    return n;
}

static void run_card_swap(void) {
    printf("Files added on a PC while the card is out\n");
    format(32768, FM_FAT);
    put_file("first.psbt", "psbt", 4);
    put_file("second.psbt", "psbt", 4);
    CHECK(sd_files_mount());
    CHECK(count_psbts() == 2);

    uint8_t *saved = card;                  // Out of the slot: reads fail
    card = NULL;
    CHECK(count_psbts() == 0 || count_psbts() == 2);
    card = saved;
    put_file("third with a long name.psbt", "psbt", 4);     // On the PC
    CHECK(sd_files_mount());
    CHECK(count_psbts() == 3);
    sd_files_unmount();
}

// A card that answers garbage (taken out) can describe a directory whose
// cluster chain loops: FatFs would follow it forever, even inside one
// f_readdir(). Here the FAT32 root cluster points to itself and all its
// entries are deleted ones: every call must still end, with nothing found.
static void run_looping_directory(void) {
    static const char *const exts[] = {"PSBT", "PSB", "TXT"};
    char name[SD_FILES_NAME_LEN];
    uint32_t size;
    FATFS fs;

    printf("A directory whose cluster chain loops\n");
    format(131072, FM_FAT32);
    sd_files_host_no_budget();
    CHECK(f_mount(&fs, "", 1) == FR_OK);
    uint32_t root = (uint32_t)fs.dirbase, fat = (uint32_t)fs.fatbase, data = (uint32_t)fs.database;
    uint32_t csize = fs.csize;
    f_mount(NULL, "", 0);
    uint8_t *entry = &card[(fat + root * 4u / 512u) * 512u + (root * 4u) % 512u];
    entry[0] = (uint8_t)root;                       // FAT32 entry of the root: itself
    entry[1] = (uint8_t)(root >> 8);
    entry[2] = (uint8_t)(root >> 16);
    entry[3] = (uint8_t)(root >> 24);
    uint8_t *dir = &card[(data + (root - 2) * csize) * 512u];
    for (uint32_t i = 0; i < csize * 512u; i += 32) dir[i] = 0xE5;     // Every entry deleted

    // Without the budget each pass reads the whole 2 MB FatFs allows (4096 sectors)
    CHECK(sd_files_mount());
    reads = 0;
    CHECK(!sd_files_find(0, exts, 3, name, &size));
    CHECK(reads <= 256);
    reads = 0;
    CHECK(sd_files_next_sorted(NULL, exts, 3, name) < 0);
    CHECK(reads <= 256);
    sd_files_unmount();
}

// Alphabetical order, case ignored, whatever the directory order; other
// extensions skipped. As sd_pick_file() in main.c builds its list.
static void run_sorted(void) {
    static const char *const exts[] = {"PSBT", "PSB", "TXT"};
    static const char *const want[] = {"Alpha.psbt", "beta.TXT", "Gamma-signed.psbt", "zeta.psbt"};
    char name[SD_FILES_NAME_LEN], prev[SD_FILES_NAME_LEN], check[SD_FILES_NAME_LEN];
    uint32_t size, count = 0;

    printf("Alphabetical list\n");
    format(32768, FM_FAT);
    put_file("zeta.psbt", "p", 1);
    put_file("Gamma-signed.psbt", "p", 1);
    put_file("notes.doc", "p", 1);
    put_file("beta.TXT", "p", 1);
    put_file("Alpha.psbt", "p", 1);
    CHECK(sd_files_mount());
    for (;;) {
        int32_t entry = sd_files_next_sorted(count ? prev : NULL, exts, 3, name);
        if (entry < 0) break;
        CHECK(count < 4 && strcmp(name, want[count]) == 0);
        CHECK(sd_files_find((uint32_t)entry, exts, 3, check, &size) && strcmp(check, name) == 0);
        memcpy(prev, name, sizeof(prev));
        count++;
    }
    CHECK(count == 4);
    sd_files_unmount();
}

int main(void) {
    run_card_swap();
    run_sorted();
    run_looping_directory();
    run("FAT16 card of 16 MB", 32768, FM_FAT);
    run("FAT32 card of 64 MB", 131072, FM_FAT32);
    run_full();
    free(card);
    printf(failures ? "\n%d FAILURE(S)\n" : "\nALL TESTS PASSED\n", failures);
    return failures != 0;
}
