// Host-side test for hex_flash.c. Not part of the bootloader image.
// The mock flash fails the test if a double-word is programmed twice
// without an erase, which corrupts the ECC on the real PIC32MM.
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "hex_flash.h"

#define FLASH_PHYS_BASE 0x1D000000u
#define FLASH_SIZE      0x40000u

static uint8_t flash[FLASH_SIZE];
static uint8_t dw_programmed[FLASH_SIZE / 8];
static uint8_t expected[FLASH_SIZE];
static int double_writes = 0, page_rewrites = 0, failures = 0;

#define CHECK(cond) do { if (!(cond)) { printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); failures++; } } while (0)

bool nvm_erase_page(uint32_t phys) {
    uint32_t ofs = phys - FLASH_PHYS_BASE;
    if (phys < HEXFLASH_APP_PHYS_BASE || (ofs % HEXFLASH_PAGE_SIZE) != 0) return false;
    memset(&flash[ofs], 0xFF, HEXFLASH_PAGE_SIZE);
    memset(&dw_programmed[ofs / 8], 0, HEXFLASH_PAGE_SIZE / 8);
    page_rewrites++;
    return true;
}

bool nvm_write_dw(uint32_t phys, uint32_t w0, uint32_t w1) {
    uint32_t ofs = phys - FLASH_PHYS_BASE;
    if (phys < HEXFLASH_APP_PHYS_BASE || (ofs & 7) != 0) return false;
    if (dw_programmed[ofs / 8]) double_writes++;
    dw_programmed[ofs / 8] = 1;
    for (int i = 0; i < 4; i++) {
        flash[ofs + i] &= (uint8_t)(w0 >> (8 * i));     // Flash can only clear bits
        flash[ofs + 4 + i] &= (uint8_t)(w1 >> (8 * i));
    }
    return true;
}

void nvm_read(uint32_t phys, uint8_t *dst, uint32_t len) {
    memcpy(dst, &flash[phys - FLASH_PHYS_BASE], len);
}

static int hexval(char c) { return (c <= '9') ? c - '0' : (c | 0x20) - 'a' + 10; }

// Feeds an Intel HEX file record by record, in file order, like the bootloader
static hexflash_status_t flash_hex_file(const char *path, bool build_expected) {
    FILE *f = fopen(path, "r");
    char line[600];
    uint8_t rec[260];
    uint32_t ext = 0;
    hexflash_status_t st = HEXFLASH_OK;
    if (!f) { printf("cannot open %s\n", path); failures++; return HEXFLASH_ERR_RECORD; }
    while (fgets(line, sizeof(line), f) && st == HEXFLASH_OK) {
        if (line[0] != ':') continue;
        int n = 0;
        for (char *p = line + 1; hexval(p[0]) >= 0 && hexval(p[0]) < 16 && hexval(p[1]) >= 0 && hexval(p[1]) < 16; p += 2) {
            rec[n++] = (uint8_t)(hexval(p[0]) << 4 | hexval(p[1]));
        }
        if (build_expected) {
            if (rec[3] == 4) ext = ((uint32_t)rec[4] << 24) | ((uint32_t)rec[5] << 16);
            if (rec[3] == 0) {
                for (int i = 0; i < rec[0]; i++) {
                    uint32_t phys = (ext + ((uint32_t)rec[1] << 8 | rec[2]) + i) & 0x1FFFFFFF;
                    if (phys >= HEXFLASH_APP_PHYS_BASE && phys < HEXFLASH_APP_PHYS_END)
                        expected[phys - FLASH_PHYS_BASE] = rec[4 + i];
                }
            }
        }
        st = hexflash_write_record(rec);
    }
    fclose(f);
    return st;
}

static void reset_all(void) {
    memset(flash, 0xFF, sizeof(flash));
    memset(expected, 0xFF, sizeof(expected));
    memset(dw_programmed, 0, sizeof(dw_programmed));
    double_writes = 0;
    CHECK(hexflash_begin() == HEXFLASH_OK);
    page_rewrites = 0;
}

static void test_file(const char *path) {
    reset_all();
    CHECK(flash_hex_file(path, true) == HEXFLASH_OK);
    CHECK(double_writes == 0);
    CHECK(memcmp(flash, expected, sizeof(flash)) == 0);
    printf("%s: %d page rewrites, %d double writes\n", path, page_rewrites, double_writes);
}

// Builds a binary record with a valid checksum
static void make_rec(uint8_t *rec, uint8_t type, uint16_t addr, const uint8_t *data, uint8_t len) {
    uint8_t sum = 0;
    rec[0] = len; rec[1] = addr >> 8; rec[2] = addr & 0xFF; rec[3] = type;
    memcpy(&rec[4], data, len);
    for (int i = 0; i < len + 4; i++) sum += rec[i];
    rec[len + 4] = (uint8_t)(-sum);
}

static void test_synthetic(void) {
    uint8_t rec[64];
    const uint8_t seg[2] = {0x1D, 0x01};    // 0x1D010000
    const uint8_t a[4] = {0x11, 0x22, 0x33, 0x44};
    const uint8_t b[4] = {0x55, 0x66, 0x77, 0x88};
    const uint8_t c[2] = {0xAB, 0xCD};
    const uint8_t neighbour[8] = {1, 2, 3, 4, 5, 6, 7, 8};

    reset_all();
    make_rec(rec, 4, 0, seg, 2);            CHECK(hexflash_write_record(rec) == HEXFLASH_OK);
    make_rec(rec, 0, 0x0108, neighbour, 8); CHECK(hexflash_write_record(rec) == HEXFLASH_OK);
    make_rec(rec, 0, 0x0100, a, 4);         CHECK(hexflash_write_record(rec) == HEXFLASH_OK);
    make_rec(rec, 0, 0x0800, a, 4);         CHECK(hexflash_write_record(rec) == HEXFLASH_OK); // Other dw: flushes 0x100
    make_rec(rec, 0, 0x0104, b, 4);         CHECK(hexflash_write_record(rec) == HEXFLASH_OK); // Back to 0x100: page rewrite
    make_rec(rec, 0, 0x0102, c, 2);         CHECK(hexflash_write_record(rec) == HEXFLASH_OK); // Overwrites programmed bytes
    make_rec(rec, 1, 0, NULL, 0);           CHECK(hexflash_write_record(rec) == HEXFLASH_OK);

    const uint8_t want[16] = {0x11, 0x22, 0xAB, 0xCD, 0x55, 0x66, 0x77, 0x88, 1, 2, 3, 4, 5, 6, 7, 8};
    CHECK(memcmp(&flash[0x10100], want, 16) == 0);
    CHECK(memcmp(&flash[0x10800], a, 4) == 0);
    CHECK(double_writes == 0 && page_rewrites == 2);

    make_rec(rec, 0, 0x0200, a, 4);
    rec[8] ^= 1;                             // Corrupt the checksum
    CHECK(hexflash_write_record(rec) == HEXFLASH_ERR_RECORD);
}

int main(int argc, char **argv) {
    test_synthetic();
    for (int i = 1; i < argc; i++) test_file(argv[i]);
    printf(failures ? "\n%d FAILURE(S)\n" : "\nALL TESTS PASSED\n", failures);
    return failures != 0;
}
