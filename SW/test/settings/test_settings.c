// Host-side test for settings.c with a mock of the reserved flash page. The
// mock fails the test if a double-word is programmed twice without an erase
// (that corrupts the ECC on the real PIC32MM) or if a slot is out of range.
#define SETTINGS_HOST_TEST
#include <stdio.h>
#include <string.h>
#include "settings.c"

static uint8_t page[SETTINGS_SLOTS][8];
static uint8_t written[SETTINGS_SLOTS];
static int erases = 0, writes = 0, double_writes = 0, failures = 0;
static int fail_next_write = 0;

#define CHECK(cond) do { if (!(cond)) { printf("FAIL line %d: %s\n", __LINE__, #cond); failures++; } } while (0)

static bool nvm_erase_page(void) {
    memset(page, 0xFF, sizeof(page));
    memset(written, 0, sizeof(written));
    erases++;
    return true;
}

static bool nvm_write_slot(unsigned slot, const uint8_t rec[8]) {
    if (slot >= SETTINGS_SLOTS) { printf("FAIL: slot %u out of range\n", slot); failures++; return false; }
    if (fail_next_write) { fail_next_write = 0; return false; }
    if (written[slot]) double_writes++;
    written[slot] = 1;
    for (int i = 0; i < 8; i++) page[slot][i] &= rec[i];    // Flash can only clear bits
    writes++;
    return true;
}

static void nvm_read_slot(unsigned slot, uint8_t rec[8]) {
    memcpy(rec, page[slot], 8);
}

static void fresh_page(void) {
    nvm_erase_page();
    erases = 0; writes = 0; double_writes = 0;
}

int main(void) {
    // A new or erased page means the factory defaults
    fresh_page();
    CHECK(settings_load() == SETTINGS_DEFAULT);
    CHECK((settings_load() & SETTING_DECOY_ON) && (settings_load() & SETTING_SEEDQR_OFF));
    CHECK(settings_load() & SETTING_SDWRITE_OFF);

    // Saving the current value writes nothing
    CHECK(settings_save(SETTINGS_DEFAULT) && writes == 0);

    // Round trip, newest wins
    CHECK(settings_save((uint8_t)~SETTING_DECOY_ON) && settings_load() == (uint8_t)~SETTING_DECOY_ON);
    CHECK(settings_save((uint8_t)~(SETTING_DECOY_ON | SETTING_SEEDQR_OFF)));
    CHECK(settings_load() == (uint8_t)~(SETTING_DECOY_ON | SETTING_SEEDQR_OFF));
    CHECK(settings_save(SETTINGS_DEFAULT) && settings_load() == SETTINGS_DEFAULT);
    CHECK(writes == 3 && erases == 0 && double_writes == 0);

    // Many changes: the page rotates, never writes a slot twice, keeps the last value
    fresh_page();
    for (int i = 0; i < 1000; i++) {
        uint8_t flags = (uint8_t)(0xFC | (i & 1) | ((i & 2) ? 0 : 2));
        if (flags == settings_load()) flags ^= 1;
        CHECK(settings_save(flags));
        CHECK(settings_load() == flags);
    }
    CHECK(double_writes == 0);
    CHECK(erases >= 3 && erases <= 5);          // About one erase every 256 changes
    printf("1000 changes: %d writes, %d erases, %d double writes\n", writes, erases, double_writes);

    // A record that was not completely written (power loss) is ignored
    fresh_page();
    CHECK(settings_save(0xF5));
    memcpy(page[1], (uint8_t[8]){0xA5, 0xF0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 8);    // Half record
    written[1] = 1;
    CHECK(settings_load() == 0xF5);
    CHECK(settings_save(0xF6) && settings_load() == 0xF6);      // Goes to the next blank slot
    CHECK(double_writes == 0);

    // A bad checksum or complement is ignored
    fresh_page();
    CHECK(settings_save(0xFA));
    page[1][0] = 0xA5; page[1][1] = 0x00; page[1][2] = 0x01; page[1][7] = 0x5A;   // flags != ~complement
    CHECK(settings_load() == 0xFA);

    // A write the flash refuses is reported and leaves the settings as they were
    fresh_page();
    CHECK(settings_save(0xFB));
    fail_next_write = 1;
    CHECK(!settings_save(0xFC));
    CHECK(settings_load() == 0xFB);

    if (failures == 0) printf("test_settings: all tests passed\n");
    return failures != 0;
}
