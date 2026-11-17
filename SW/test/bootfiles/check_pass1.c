// Host check of the bad UPDATE.HEX files of gen_bad_hex.py: pass 1 of the
// bootloader (process_hex_file(false) in bootloader/src/main.c, nothing
// written) over one file, with the bootloader's own hexflash_check_record().
// The record scan and record_is_valid() are copied from main.c.
//   check_pass1 <expected code> <file>      exit 0 when the answer matches
// One file per run: hexflash_check_record() keeps its state until an end
// record, as the bootloader does from one power-on to the next.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "hex_flash.h"

// Not reached in pass 1; the writer needs them to link
bool nvm_erase_page(uint32_t a) { (void)a; return false; }
bool nvm_write_dw(uint32_t a, uint32_t w0, uint32_t w1) { (void)a; (void)w0; (void)w1; return false; }
void nvm_read(uint32_t a, uint8_t *d, uint32_t n) { (void)a; memset(d, 0xFF, n); }

// As in main.c
static void ConvertAsciiToHex(uint8_t *asciiRec, uint8_t *hexRec) {
    uint8_t i = 0, hex;
    while ((asciiRec[i] >= 0x30) && (asciiRec[i] <= 0x66)) {
        if (asciiRec[i] < 0x3A) hex = asciiRec[i] & 0x0F;
        else hex = 0x09 + (asciiRec[i] & 0x0F);
        if (i % 2) hexRec[i / 2] |= hex;
        else hexRec[i / 2] = (hex << 4) & 0xF0;
        i++;
    }
}

static bool record_is_valid(const uint8_t *rec, uint32_t hex_chars) {
    uint32_t bytes = (uint32_t)rec[0] + 5u;
    if (bytes * 2u > hex_chars) return false;
    uint8_t sum = 0;
    for (uint32_t i = 0; i < bytes; i++) sum += rec[i];
    return sum == 0;
}

// The record loop of process_hex_file(false), over the whole file at once
static int pass1(const uint8_t *buf, size_t size) {
    uint8_t hexRec[200];
    bool eof = false, in_rec = false;
    const uint8_t *start = NULL;
    uint32_t len = 0;
    for (size_t i = 0; i < size; i++) {
        if (!in_rec) {
            if (buf[i] == ':') { start = &buf[i]; len = 0; in_rec = true; }
        } else if (buf[i] == 0x0A || buf[i] == 0x0D) {
            if (len > 0 && len < 190) {
                memset(hexRec, 0, sizeof(hexRec));
                ConvertAsciiToHex((uint8_t *)&start[1], hexRec);
                if (hexRec[3] == 0x01) eof = true;
                if (!record_is_valid(hexRec, len - 1)) return HEXFLASH_ERR_RECORD;
                hexflash_status_t st = hexflash_check_record(hexRec);
                if (st != HEXFLASH_OK) return st;
            }
            in_rec = false;
        }
        if (in_rec) len++;
    }
    return eof ? 0 : 5;
}

int main(int argc, char **argv) {
    if (argc != 3) { printf("usage: check_pass1 <expected> <file>\n"); return 2; }
    FILE *f = fopen(argv[2], "rb");
    if (!f) { printf("cannot open %s\n", argv[2]); return 2; }
    static uint8_t buf[2u << 20];
    size_t size = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    int want = atoi(argv[1]), got = pass1(buf, size);
    printf("%s %-28s pass 1 %d (expected %d)\n", got == want ? "ok  " : "FAIL", strrchr(argv[2], '/') ? strrchr(argv[2], '/') + 1 : argv[2], got, want);
    return got != want;
}
