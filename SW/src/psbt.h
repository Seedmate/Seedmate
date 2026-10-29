/*******************************************************************************
 * Project:     SeedMate
 * File:        psbt.h
 *
 * Summary:
 *   Minimal zero-copy parser for Partially Signed Bitcoin Transactions
 *   (BIP174, PSBT version 0).
 *
 * Description:
 *   The parser never copies the PSBT: it validates the structure once and
 *   stores offsets into the caller's buffer. Inputs and outputs are then read
 *   on demand by index, so RAM usage does not grow with the transaction size.
 *   The buffer must stay valid and unchanged while a psbt_t refers to it.
 *
 *   SECURITY NOTE: amounts taken from NON_WITNESS_UTXO are not yet checked
 *   against the input's prev_txid (double SHA256 of the previous transaction).
 *   That check is mandatory before this data is used to sign.
 *
 * License:     MIT, same as main.c
 ******************************************************************************/

#ifndef PSBT_H
#define PSBT_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

// Enough for any bech32/bech32m (max 90 chars) or base58 address plus NUL
#define PSBT_ADDRESS_MAX_LEN 91
// "21000000.00000000" plus NUL, rounded up
#define PSBT_BTC_STR_LEN 24

typedef enum {
    PSBT_OK = 0,
    PSBT_ERR_MAGIC,         // Missing "psbt\xff" header
    PSBT_ERR_TRUNCATED,     // A length field points past the end of the buffer
    PSBT_ERR_FORMAT,        // Structurally invalid data
    PSBT_ERR_NO_TX,         // No PSBT_GLOBAL_UNSIGNED_TX found
    PSBT_ERR_UNSUPPORTED    // PSBT version 2 or other unsupported feature
} psbt_status_t;

typedef struct {
    const uint8_t *buf;         // Points at the "psbt\xff" magic
    uint32_t len;               // Bytes from buf to the end of the PSBT
    uint32_t tx_version;
    uint32_t locktime;
    uint32_t input_count;
    uint32_t output_count;
    uint32_t tx_inputs_ofs;     // First input inside the unsigned tx
    uint32_t tx_outputs_ofs;    // First output inside the unsigned tx
    uint32_t input_maps_ofs;    // First per-input key/value map
    uint32_t output_maps_ofs;   // First per-output key/value map
} psbt_t;

// Sighash types (low 5 bits) and the ANYONECANPAY flag
#define PSBT_SIGHASH_ALL            0x01
#define PSBT_SIGHASH_NONE           0x02
#define PSBT_SIGHASH_SINGLE         0x03
#define PSBT_SIGHASH_ANYONECANPAY   0x80

// nSequence values below this one signal opt-in RBF (BIP125)
#define PSBT_SEQUENCE_RBF_LIMIT     0xFFFFFFFEu
// nLockTime values from this one on are UNIX timestamps, below it block heights
#define PSBT_LOCKTIME_THRESHOLD     500000000u

typedef struct {
    const uint8_t *prev_txid;   // 32 bytes, internal (little-endian) byte order
    uint32_t prev_vout;
    uint32_t sequence;
    bool has_amount;            // false when the PSBT has no UTXO data for it
    bool amount_from_witness;   // true: WITNESS_UTXO, false: NON_WITNESS_UTXO
    uint64_t amount;            // Satoshis spent by this input
    const uint8_t *script;      // scriptPubKey being spent (NULL if unknown)
    uint32_t script_len;
    const uint8_t *prev_tx;     // NON_WITNESS_UTXO: full previous tx (NULL if absent)
    uint32_t prev_tx_len;
    bool has_sighash;           // false: signer uses the default (SIGHASH_ALL)
    uint32_t sighash;
    bool finalized;             // FINAL_SCRIPTSIG or FINAL_SCRIPTWITNESS present
    uint32_t partial_sig_count; // Signatures already in the PSBT
    uint32_t keypath_count;     // BIP32_DERIVATION entries
    const uint8_t *redeem_script;   // P2SH redeem script (NULL if absent)
    uint32_t redeem_script_len;
    const uint8_t *witness_script;  // P2WSH witness script (NULL if absent)
    uint32_t witness_script_len;
} psbt_input_t;

typedef struct {
    uint64_t amount;            // Satoshis
    const uint8_t *script;      // scriptPubKey
    uint32_t script_len;
    uint32_t keypath_count;     // BIP32_DERIVATION entries
    const uint8_t *redeem_script;
    uint32_t redeem_script_len;
    const uint8_t *witness_script;
    uint32_t witness_script_len;
} psbt_output_t;

// One BIP32 derivation record: a key plus the master fingerprint and path
// it was derived from. For inputs/outputs the key is a public key (33 or 65
// bytes); for PSBT_GLOBAL_XPUB it is the 78-byte serialized extended key.
typedef struct {
    const uint8_t *key;
    uint32_t key_len;
    uint32_t fingerprint;       // As usually displayed: first byte is the MSB
    const uint8_t *path;        // path_len little-endian uint32 elements
    uint32_t path_len;
} psbt_keypath_t;

#define PSBT_HARDENED 0x80000000u
// "m" plus up to 10 elements of "/4294967295'" fits easily
#define PSBT_PATH_STR_LEN 64
// Largest standard CHECKMULTISIG (n <= 16)
#define PSBT_MULTISIG_MAX_KEYS 16

typedef enum {
    PSBT_SCRIPT_UNKNOWN = 0,
    PSBT_SCRIPT_P2PKH,
    PSBT_SCRIPT_P2SH,
    PSBT_SCRIPT_P2WPKH,
    PSBT_SCRIPT_P2WSH,
    PSBT_SCRIPT_P2TR,
    PSBT_SCRIPT_OP_RETURN
} psbt_script_type_t;

// Parses and validates a PSBT. Accepts raw PSBT bytes or the same bytes
// wrapped in a CBOR byte string (the ur:crypto-psbt payload format).
psbt_status_t psbt_parse(const uint8_t *data, uint32_t len, psbt_t *psbt);

// Reads input/output number 'index' (0-based). Return false on bad index.
bool psbt_get_input(const psbt_t *psbt, uint32_t index, psbt_input_t *in);
bool psbt_get_output(const psbt_t *psbt, uint32_t index, psbt_output_t *out);

// Sums all inputs and outputs. Returns false if any input amount is unknown
// or a value is out of range; the totals are still filled as far as known.
bool psbt_get_totals(const psbt_t *psbt, uint64_t *in_total, uint64_t *out_total);

// Fee = inputs - outputs. Returns false if it cannot be computed or is negative.
bool psbt_get_fee(const psbt_t *psbt, uint64_t *fee);

psbt_script_type_t psbt_script_type(const uint8_t *script, uint32_t len);
const char *psbt_script_type_name(psbt_script_type_t type);

// Encodes a SegWit scriptPubKey (P2WPKH, P2WSH, P2TR) as a bech32/bech32m
// address. hrp is "bc" for mainnet or "tb" for testnet. out_size must be at
// least PSBT_ADDRESS_MAX_LEN. Returns false for non-SegWit scripts.
bool psbt_segwit_address(const uint8_t *script, uint32_t len, const char *hrp,
                         char *out, size_t out_size);

// Formats satoshis as "B.BBBBBBBB" (8 decimals). out must hold PSBT_BTC_STR_LEN.
void psbt_format_btc(uint64_t sats, char *out);

// Formats a txid in the usual display order (reversed) as 64 hex chars + NUL.
void psbt_format_txid(const uint8_t *txid, char *out);

// Reads the n-th (0-based) BIP32 derivation of an input, an output, or the
// global map (PSBT_GLOBAL_XPUB). Return false when there is no such entry.
bool psbt_input_keypath(const psbt_t *psbt, uint32_t index, uint32_t n, psbt_keypath_t *kp);
bool psbt_output_keypath(const psbt_t *psbt, uint32_t index, uint32_t n, psbt_keypath_t *kp);
bool psbt_global_xpub(const psbt_t *psbt, uint32_t n, psbt_keypath_t *kp);

// Element i of a derivation path (bit 31 set = hardened). i < kp->path_len.
uint32_t psbt_path_element(const psbt_keypath_t *kp, uint32_t i);

// Formats a path as "m/84'/0'/0'/1/5". out must hold PSBT_PATH_STR_LEN; a
// path too long for it ends in "...".
void psbt_format_path(const psbt_keypath_t *kp, char *out);

// Formats a fingerprint as 8 uppercase hex chars + NUL.
void psbt_format_fingerprint(uint32_t fingerprint, char *out);

// Recognizes "OP_m <pubkey>... OP_n OP_CHECKMULTISIG" with compressed keys.
// On success fills m (required signatures) and n (keys).
bool psbt_multisig_info(const uint8_t *script, uint32_t len, uint8_t *m, uint8_t *n);

// True if the 33-byte compressed pubkey is one of the keys of a multisig
// script recognized by psbt_multisig_info().
bool psbt_multisig_has_key(const uint8_t *script, uint32_t len, const uint8_t *pubkey);

// True if input 'index' already carries a PSBT_IN_PARTIAL_SIG for pubkey.
bool psbt_input_has_sig_from(const psbt_t *psbt, uint32_t index, const uint8_t *pubkey, uint32_t pubkey_len);

// Readable sighash type, e.g. "ALL" or "SINGLE|ACP"; "UNKNOWN" if invalid.
const char *psbt_sighash_name(uint32_t sighash);

// True if any input signals opt-in replace-by-fee (BIP125).
bool psbt_signals_rbf(const psbt_t *psbt);

// Serialized outputs of the unsigned tx (as hashed by BIP143 hashOutputs).
bool psbt_tx_outputs(const psbt_t *psbt, const uint8_t **outputs, uint32_t *len);

// For a full transaction (legacy or SegWit serialization), finds the part
// that the txid hashes between version and locktime: the inputs and outputs.
// txid = SHA256d(tx[0..4] || tx[body_ofs .. body_ofs + body_len] || tx[len-4 .. len]).
bool psbt_tx_txid_body(const uint8_t *tx, uint32_t len, uint32_t *body_ofs, uint32_t *body_len);

// Adds PSBT_IN_PARTIAL_SIG {pubkey: sig} at the end of input 'index' map,
// moving the rest of the PSBT up. buf must be the raw PSBT that psbt was
// parsed from (psbt->buf == buf, no CBOR wrapper), with room up to
// capacity. Returns the new PSBT length, or 0 if it does not fit. The
// offsets in psbt are stale afterwards: parse again.
uint32_t psbt_add_partial_sig(uint8_t *buf, uint32_t capacity, const psbt_t *psbt, uint32_t index,
                              const uint8_t *pubkey, uint32_t pubkey_len,
                              const uint8_t *sig, uint32_t sig_len);

// Streaming base64 decoder for PSBTs stored as text (they start "cHNidP8").
// Whitespace is skipped, so line-wrapped files work. Feed the text in chunks
// of any size, then call psbt_base64_finish().
typedef struct {
    uint32_t acc;       // Pending bits
    uint8_t bits;       // Number of pending bits
    uint8_t quad;       // Characters seen in the current 4-char group
    bool padded;        // '=' seen: only '=' and whitespace may follow
    bool err;
} psbt_base64_t;

void psbt_base64_init(psbt_base64_t *b);

// Decodes len chars, appending the bytes at out[*out_len]. Returns false on
// an invalid character or if out_size would be exceeded.
bool psbt_base64_feed(psbt_base64_t *b, const char *text, uint32_t len,
                      uint8_t *out, uint32_t out_size, uint32_t *out_len);

// True if the text ended on a whole 4-char group without errors.
bool psbt_base64_finish(const psbt_base64_t *b);

const char *psbt_status_name(psbt_status_t status);

#endif // PSBT_H
