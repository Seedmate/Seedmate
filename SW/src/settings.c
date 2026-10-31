/*******************************************************************************
 * Project:     SeedMate
 * File:        settings.c
 *
 * Summary:
 *   Permanent settings in a reserved flash page (see settings.h).
 *
 * License:     MIT, same as main.c
 ******************************************************************************/

#include <string.h>
#include "settings.h"

#ifndef SETTINGS_HOST_TEST
#include <xc.h>
#endif

#define REC_TAG     0xA5u
#define REC_END     0x5Au

// Flash access layer. Implemented at the end of this file for the PIC32MM;
// the host test provides its own versions. Slot numbers only: nothing here
// can address flash outside the settings page.
static bool nvm_erase_page(void);
static bool nvm_write_slot(unsigned slot, const uint8_t rec[8]);
static void nvm_read_slot(unsigned slot, uint8_t rec[8]);

static bool is_blank(const uint8_t *r) {
    for (int i = 0; i < 8; i++) {
        if (r[i] != 0xFF) return false;
    }
    return true;
}

static bool is_valid(const uint8_t *r) {
    return r[0] == REC_TAG && r[2] == (uint8_t)~r[1] && r[7] == REC_END;
}

// Scans the page: newest valid flags (or default), and the first blank slot
// (SETTINGS_SLOTS if the page is full)
static uint8_t scan(unsigned *first_blank) {
    uint8_t flags = SETTINGS_DEFAULT;
    uint8_t rec[8];

    *first_blank = SETTINGS_SLOTS;
    for (unsigned i = 0; i < SETTINGS_SLOTS; i++) {
        nvm_read_slot(i, rec);
        if (is_blank(rec)) {
            if (*first_blank == SETTINGS_SLOTS) *first_blank = i;
        } else if (is_valid(rec)) {
            flags = rec[1];     // Later slots are newer
        }
    }
    return flags;
}

uint8_t settings_load(void) {
    unsigned blank;
    return scan(&blank);
}

bool settings_save(uint8_t flags) {
    unsigned slot;
    uint8_t current = scan(&slot);
    uint8_t rec[8] = {REC_TAG, flags, (uint8_t)~flags, 0xFF, 0xFF, 0xFF, 0xFF, REC_END};

    if (flags == current) return true;
    if (slot == SETTINGS_SLOTS) {               // Full: start the page over with the new value
        if (!nvm_erase_page()) return false;
        slot = 0;
    }
    if (!nvm_write_slot(slot, rec)) return false;

    nvm_read_slot(slot, rec);                   // Read it back
    return is_valid(rec) && rec[1] == flags;
}

#ifndef SETTINGS_HOST_TEST

#define SETTINGS_PHYS   0x1D03F800u             // Reserved page, physical address
#define SETTINGS_KSEG1  0xBD03F800u             // The same, uncached: reads see fresh writes

// Runs one NVM operation (NVMOP in op) with the unlock sequence
static bool nvm_execute(uint32_t op) {
    NVMCON = 0x4000u | op;                      // WREN + operation
    __builtin_disable_interrupts();
    NVMKEY = 0xAA996655;
    NVMKEY = 0x556699AA;
    NVMCONSET = 0x8000;                         // WR
    while (NVMCONbits.WR);
    NVMCONCLR = 0x4000;
    __builtin_enable_interrupts();
    return (NVMCON & 0x3000u) == 0;             // WRERR / LVDERR
}

static bool nvm_erase_page(void) {
    NVMADDR = SETTINGS_PHYS;
    return nvm_execute(0x4);                    // Page erase
}

static bool nvm_write_slot(unsigned slot, const uint8_t rec[8]) {
    uint32_t w0, w1;
    if (slot >= SETTINGS_SLOTS) return false;
    memcpy(&w0, rec, 4);
    memcpy(&w1, rec + 4, 4);
    NVMADDR = SETTINGS_PHYS + 8u * slot;
    NVMDATA0 = w0;
    NVMDATA1 = w1;
    return nvm_execute(0x2);                    // Double-word program
}

static void nvm_read_slot(unsigned slot, uint8_t rec[8]) {
    memcpy(rec, (const void *)(SETTINGS_KSEG1 + 8u * slot), 8);
}

#endif // SETTINGS_HOST_TEST
