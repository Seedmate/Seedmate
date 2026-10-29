/*******************************************************************************
  Intel HEX to PIC32MM flash writer (Bootloader). See hex_flash.h.
 *******************************************************************************/

#include <string.h>
#include "hex_flash.h"

#ifndef HEXFLASH_HOST_TEST
#include <xc.h>
#endif

// --- Intel Hex Record Types ---
#define DATA_RECORD             0x00
#define END_OF_FILE_RECORD      0x01
#define EXT_SEG_ADRS_RECORD     0x02
#define EXT_LIN_ADRS_RECORD     0x04

#define DW_COUNT ((HEXFLASH_APP_PHYS_END - HEXFLASH_APP_PHYS_BASE) / 8u)

static uint8_t dw_written[DW_COUNT / 8u];       // 1 bit per programmed double-word
static uint8_t page_buf[HEXFLASH_PAGE_SIZE];    // Read-merge-erase-write buffer

static uint32_t ext_addr = 0;   // Extended address from type 02/04 records
static uint32_t dw_addr = 0;    // Physical address of the pending double-word
static uint8_t dw_bytes[8];     // Pending bytes, 0xFF where not provided
static uint8_t dw_mask = 0;     // Bit i set = dw_bytes[i] came from the HEX file

static bool dw_is_written(uint32_t phys) {
    uint32_t idx = (phys - HEXFLASH_APP_PHYS_BASE) >> 3;
    return (dw_written[idx >> 3] >> (idx & 7u)) & 1u;
}

static void dw_set_written(uint32_t phys, bool written) {
    uint32_t idx = (phys - HEXFLASH_APP_PHYS_BASE) >> 3;
    if (written) dw_written[idx >> 3] |= (uint8_t)(1u << (idx & 7u));
    else         dw_written[idx >> 3] &= (uint8_t)~(1u << (idx & 7u));
}

static bool all_erased(const uint8_t *p) {
    for (int i = 0; i < 8; i++) {
        if (p[i] != 0xFF) return false;
    }
    return true;
}

static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// Programs one double-word unless it is blank (erased flash already reads 0xFF)
static hexflash_status_t program_dw(uint32_t phys, const uint8_t *data) {
    if (all_erased(data)) {
        dw_set_written(phys, false);
        return HEXFLASH_OK;
    }
    if (!nvm_write_dw(phys, le32(data), le32(data + 4))) return HEXFLASH_ERR_NVM;
    dw_set_written(phys, true);
    return HEXFLASH_OK;
}

// The pending double-word is already programmed: rebuild its whole page
static hexflash_status_t rewrite_page(void) {
    uint32_t page = dw_addr & ~(HEXFLASH_PAGE_SIZE - 1u);
    uint32_t ofs = dw_addr - page;

    nvm_read(page, page_buf, HEXFLASH_PAGE_SIZE);
    for (int i = 0; i < 8; i++) {
        if (dw_mask & (1u << i)) page_buf[ofs + i] = dw_bytes[i];
    }

    if (!nvm_erase_page(page)) return HEXFLASH_ERR_NVM;
    for (uint32_t o = 0; o < HEXFLASH_PAGE_SIZE; o += 8) {
        hexflash_status_t st = program_dw(page + o, &page_buf[o]);
        if (st != HEXFLASH_OK) return st;
    }
    return HEXFLASH_OK;
}

static hexflash_status_t flush_dw(void) {
    hexflash_status_t st = HEXFLASH_OK;
    if (dw_mask != 0) {
        st = dw_is_written(dw_addr) ? rewrite_page() : program_dw(dw_addr, dw_bytes);
        dw_mask = 0;
        memset(dw_bytes, 0xFF, sizeof(dw_bytes));
    }
    return st;
}

hexflash_status_t hexflash_begin(void) {
    ext_addr = 0;
    dw_mask = 0;
    memset(dw_bytes, 0xFF, sizeof(dw_bytes));
    memset(dw_written, 0, sizeof(dw_written));

    for (uint32_t page = HEXFLASH_APP_PHYS_BASE; page < HEXFLASH_APP_PHYS_END; page += HEXFLASH_PAGE_SIZE) {
        if (!nvm_erase_page(page)) return HEXFLASH_ERR_NVM;
    }
    return HEXFLASH_OK;
}

hexflash_status_t hexflash_write_record(const uint8_t *rec) {
    uint8_t len = rec[0];
    uint32_t address = ((uint32_t)rec[1] << 8) | rec[2];
    uint8_t type = rec[3];
    const uint8_t *data = &rec[4];

    // Checksum over length, address, type, data and checksum must be zero
    uint8_t checksum = 0;
    for (uint32_t i = 0; i < (uint32_t)len + 5u; i++) {
        checksum += rec[i];
    }
    if (checksum != 0) return HEXFLASH_ERR_RECORD;

    switch (type) {
        case DATA_RECORD:
            for (uint32_t i = 0; i < len; i++) {
                uint32_t phys = (address + ext_addr + i) & 0x1FFFFFFFu;
                if (phys < HEXFLASH_APP_PHYS_BASE || phys >= HEXFLASH_APP_PHYS_END) continue;

                if (dw_mask != 0 && (phys & ~7u) != dw_addr) {
                    hexflash_status_t st = flush_dw();
                    if (st != HEXFLASH_OK) return st;
                }
                dw_addr = phys & ~7u;
                dw_bytes[phys & 7u] = data[i];
                dw_mask |= (uint8_t)(1u << (phys & 7u));

                if ((phys & 7u) == 7u) {
                    hexflash_status_t st = flush_dw();
                    if (st != HEXFLASH_OK) return st;
                }
            }
            return HEXFLASH_OK;

        case EXT_SEG_ADRS_RECORD:
            if (len != 2) return HEXFLASH_ERR_RECORD;
            ext_addr = (((uint32_t)data[0] << 8) | data[1]) << 4;
            return flush_dw();

        case EXT_LIN_ADRS_RECORD:
            if (len != 2) return HEXFLASH_ERR_RECORD;
            ext_addr = (((uint32_t)data[0] << 8) | data[1]) << 16;
            return flush_dw();

        case END_OF_FILE_RECORD:
            ext_addr = 0;
            return flush_dw();

        default:
            return HEXFLASH_OK;     // Start address records (03/05) are not needed
    }
}

#ifndef HEXFLASH_HOST_TEST

// Runs one NVM operation (NVMOP in op) with the unlock sequence
static bool nvm_execute(uint32_t op) {
    NVMCON = 0x4000u | op;          // WREN + operation
    __builtin_disable_interrupts();
    NVMKEY = 0xAA996655;
    NVMKEY = 0x556699AA;
    NVMCONSET = 0x8000;             // WR
    while (NVMCONbits.WR);
    NVMCONCLR = 0x4000;
    __builtin_enable_interrupts();
    return (NVMCON & 0x3000u) == 0; // WRERR / LVDERR
}

bool nvm_erase_page(uint32_t phys_addr) {
    NVMADDR = phys_addr;
    return nvm_execute(0x4);        // Page erase
}

bool nvm_write_dw(uint32_t phys_addr, uint32_t word0, uint32_t word1) {
    NVMADDR = phys_addr;
    NVMDATA0 = word0;
    NVMDATA1 = word1;
    return nvm_execute(0x2);        // Double-word program
}

void nvm_read(uint32_t phys_addr, uint8_t *dst, uint32_t len) {
    // KSEG1 (uncached) view, so freshly programmed data is read back
    memcpy(dst, (const void *)(0xA0000000u | phys_addr), len);
}

#endif // HEXFLASH_HOST_TEST
