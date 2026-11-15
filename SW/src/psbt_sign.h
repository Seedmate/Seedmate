/*******************************************************************************
 * Project:     SeedMate
 * File:        psbt_sign.h
 *
 * Summary:
 *   Cryptography for signing PSBT inputs (SegWit v0 and Taproot key path).
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

// Legacy (pre-SegWit) signature hash of input 'index' with SIGHASH_ALL: the
// unsigned tx with script_code (the scriptPubKey spent, without its length)
// as the scriptSig of that input and empty scriptSigs elsewhere, plus the
// hash type, hashed twice. It does not commit to the input amounts.
bool psbt_sighash_legacy(const psbt_t *psbt, uint32_t index, const uint8_t *script_code,
                         uint32_t script_code_len, uint32_t sighash_type, uint8_t digest[32]);

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

// BIP341 signature hash of input 'index' spent by the key path (no annex),
// for hash type SIGHASH_DEFAULT (0) or SIGHASH_ALL (1). Every input needs its
// amount and script (WITNESS_UTXO or NON_WITNESS_UTXO): they are all signed,
// so a wrong amount of any input makes the signature invalid.
bool psbt_sighash_taproot(const psbt_t *psbt, uint32_t index, uint8_t hash_type, uint8_t digest[32]);

// BIP86 output key of a single key (no script tree): x(P + hash_TapTweak(x(P))*G),
// P the even-y point of the compressed key pub33. The P2TR script is
// OP_1 <32 bytes>, the bc1p address its bech32m.
bool psbt_taproot_output_key(const uint8_t pub33[33], uint8_t q_x[32]);

// Schnorr signature (BIP340) of the Taproot key path for the BIP86 output key
// of pub_key, with priv_key its secret: 64 bytes, nonce from 32 zero bytes of
// auxiliary randomness (deterministic). Verified against the output key
// computed from pub_key before it is returned, as psbt_ecdsa_sign() does.
bool psbt_taproot_sign(const uint8_t priv_key[32], const uint8_t pub_key[33], const uint8_t digest[32],
                       uint8_t sig[64], void (*on_verify)(void));

// Plain BIP340 signing and verification of a 32 byte message (host tests,
// against the BIP340 vectors). pub_x is an x-only public key.
bool psbt_bip340_sign(const uint8_t seckey[32], const uint8_t msg[32], const uint8_t aux[32], uint8_t sig[64]);
bool psbt_bip340_verify(const uint8_t pub_x[32], const uint8_t msg[32], const uint8_t sig[64]);

// BIP32 public child derivation (non-hardened index) of an extended public
// key given as chain code and compressed key. The outputs may be the input
// buffers. Derives the cosigner keys of a multisig descriptor. Returns false
// for a hardened index or an invalid key.
bool psbt_public_ckd(const uint8_t chain_code[32], const uint8_t public_key[33], uint32_t index,
                     uint8_t child_chain[32], uint8_t child_key[33]);

#endif // PSBT_SIGN_H
