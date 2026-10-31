/*******************************************************************************
  SHA-256 of the update file (Bootloader)

  Summary:
    Hash of UPDATE.HEX as read from the SD card, shown to the user before
    anything is erased so it can be compared with the published one.

  Description:
    The app's sha256.c (shared, not copied) in a small wrapper with one
    context. Use boot_sha_init(), then boot_sha_update() on every chunk of
    the file and boot_sha_final() for the 32 byte digest.
 *******************************************************************************/

#ifndef BOOT_SHA_H
#define BOOT_SHA_H

#include <stdint.h>

void boot_sha_init(void);
void boot_sha_update(const uint8_t *data, uint32_t len);
void boot_sha_final(uint8_t digest[32]);

#endif // BOOT_SHA_H
