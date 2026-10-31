// Host-side test for boot_sha.c: prints the SHA-256 of a file, fed in odd
// chunks like the bootloader does, to compare with Python's hashlib.
// Not part of the bootloader image.
#include <stdio.h>
#include "boot_sha.h"

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    uint8_t buf[500], digest[32];
    FILE *f = fopen(argv[1], "rb");
    size_t n;
    if (!f) return 2;
    boot_sha_init();
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) boot_sha_update(buf, (uint32_t)n);
    fclose(f);
    boot_sha_final(digest);
    for (int i = 0; i < 32; i++) printf("%02x", digest[i]);
    printf("\n");
    return 0;
}
