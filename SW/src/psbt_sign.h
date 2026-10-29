/*******************************************************************************
 * Project:     SeedMate
 * File:        psbt_sign.h
 *
 * Summary:
 *   Cryptography for signing PSBT inputs (SegWit v0, P2WPKH).
 *
 * Description:
 *   - BIP143 signature hash, streamed from the PSBT buffer (no copies).
 *   - txid check of a NON_WITNESS_UTXO against the input's outpoint.
 *   - ECDSA over secp256k1 with RFC6979 deterministic nonces, low S
 *     (BIP146) and low R grinding, DER encoded: the same signatures as
 *     Bitcoin Core, libsecp256k1 and embit. Built on the vendored
 *     bignum/ecdsa code.
 *
 *   Key derivation and the decision of what to sign live in main.c.
 *
 * License:     MIT, same as main.c
 ******************************************************************************/

#ifndef PSBT_SIGN_H
#define PSBT_SIGN_H

#include <stdint.h>
#include <stdbool.h>
#include "psbt.h"

// DER signature (max 72 bytes) plus the sighash type byte
#define PSBT_SIG_MAX_LEN 73

// BIP143 sighash for input 'index' spending a SegWit v0 output of 'amount'
// satoshis. script_code is the script without its length prefix: the
// witness script for P2WSH. Only SIGHASH_ALL is accepted.
bool psbt_sighash_segwit_v0(const psbt_t *psbt, uint32_t index, const uint8_t *script_code,
                            uint32_t script_code_len, uint64_t amount, uint32_t sighash_type,
                            uint8_t digest[32]);

// Same for a P2WPKH output that pays to pubkey hash 'pkh' (20 bytes).
bool psbt_sighash_p2wpkh(const psbt_t *psbt, uint32_t index, const uint8_t *pkh,
                         uint64_t amount, uint32_t sighash_type, uint8_t digest[32]);

// True if script is the P2WSH output (OP_0 <32>) of witness_script.
bool psbt_p2wsh_matches(const uint8_t *script, uint32_t script_len,
                        const uint8_t *witness_script, uint32_t witness_script_len);

// True if the input's NON_WITNESS_UTXO hashes to its prev_txid. False if it
// does not match, cannot be parsed, or is absent.
bool psbt_prev_tx_matches(const psbt_input_t *in);

// Signs a 32-byte digest. Writes the DER signature followed by sighash_type
// to sig (PSBT_SIG_MAX_LEN bytes) and its length to sig_len.
// The signature is verified against pub_key (33-byte compressed public key
// of priv_key) before it is returned: if a fault corrupted the computation,
// or pub_key is not the signing key, nothing is output and false is returned.
// on_verify (may be NULL) is called between signing and verifying, so the
// interface can show both steps.
bool psbt_ecdsa_sign(const uint8_t priv_key[32], const uint8_t pub_key[33], const uint8_t digest[32],
                     uint8_t sighash_type, uint8_t *sig, uint32_t *sig_len, void (*on_verify)(void));

#endif // PSBT_SIGN_H
