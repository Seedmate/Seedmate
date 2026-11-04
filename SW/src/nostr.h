/*******************************************************************************
 * Project:     SeedMate
 * File:        nostr.h
 *
 * Summary:
 *   Nostr keys of the seed (NIP-06, m/44'/1237'/account'/0/0) as NIP-19
 *   strings: npub (the x-only public key) and nsec (the private key). The
 *   derivation itself is BIP32 in main.c; this file only encodes.
 ******************************************************************************/

#ifndef NOSTR_H
#define NOSTR_H

#include <stdint.h>
#include <stdbool.h>

#define NOSTR_ACCOUNT_PURPOSE   44u
#define NOSTR_COIN_TYPE         1237u
#define NOSTR_BECH32_LEN        63              // "npub1" / "nsec1" + 58 characters

// Bech32 (not bech32m) of a 32 byte key with the prefix "npub" or "nsec";
// out holds NOSTR_BECH32_LEN + 1. False if the encoder refuses it.
bool nostr_bech32(const char *hrp, const uint8_t key[32], char *out);

#endif // NOSTR_H
