/*******************************************************************************
 * Project:     SeedMate
 * File:        app_defs.h
 *
 * Summary:
 *   Application-level constants (menu sizes, menu indices, option values,
 *   messages) shared by main.c and screens.c.
 ******************************************************************************/

#ifndef APP_DEFS_H
#define APP_DEFS_H

#define cVersion "v2.0b1"
#define BOOT_TAG_ADDRESS 0x9D001FF0u    // Bootloader version tag ("BOOT 1.0"), see bootloader boot_ui.c
#define cMAIN_n_opt 8               // Entries of the main menu (positions)
#define cOPSEC_n_opt 4              // Entries of the OPSEC menu
#define cTOOLS_n_opt 4              // Entries of the TOOLS menu
#define cTOOLS_READER 0
#define cTOOLS_TEXTQR 1
#define cTOOLS_EFF 2
#define cTOOLS_PSBT 3               // REVIEW PSBT: the signing viewer, without signing
#define cEFF_MAX_WORDS 12           // EFF PASSWORD: 1..12 words of 4 dice
#define cTEXTQR_MAX 320             // QR FROM TEXT: fits a version 11 code (61 modules, 2 px each)
#define cPASS_n_opt 3               // PASSPHRASE FROM menu: KEYBOARD, QR, VAULT
#define cPASS_KEYBOARD 0
#define cPASS_QR 1
#define cPASS_VAULT 2
#define cSEED_n_opt 6
#define cSIZE_n_opt 2
#define cOBFUS_n_opt 6
#define cXOR_n_opt 3
#define cSSS_n_opt 2
#define cQR_n_opt 2
#define cSDBLOCK_n_opt 8
#define cSD_WRITE_LAST_SLOT 200     // Seeds are written to slots 2..200 (sectors 1..199); slot 1 (sector 0) is legacy, read only
#define cSD_WRITE_LAST_PAGE ((cSD_WRITE_LAST_SLOT - 1) / cSDBLOCK_n_opt)
#define cBACKUP_n_opt 3             // SEED BACKUP menu: SD, SEEDQR, COMPACT SEEDQR
#define cBACKUP_SD 0
#define cBACKUP_SEEDQR 1
#define cBACKUP_COMPACT 2
// SD card layout: sector 0 legacy seed slot (read only), 1..199 seed slots 2..200,
// the vault will start at 501, and the last sector of the first 1 MB holds the
// marker written by INITIALIZE CARD. Seeds are written only if the marker is valid.
#define cSD_MARKER_SECTOR 2047
#define cSD_FORMAT_VERSION 1
#define cERASE_n_opt 3              // SD CARD menu: ERASE SECTOR, INITIALIZE CARD, WIPE ALL CARD
#define cERASE_SECTOR 0
#define cERASE_INIT 1
#define cERASE_WIPE 2
#define cSELINPUT_n_opt 3
#define cDICE_MODE_n_opt 2
#define cHASH_MODE_n_opt 2
#define cRESOURCE_n_opt 6
#define cSETTINGS_n_opt 5
#define cSETTINGS_SEEDQR 0
#define cSETTINGS_SDWRITE 1
#define cSETTINGS_DECOY 2
#define cSETTINGS_MCU_SERIAL 3
#define cSETTINGS_UPDATE_FW 4
#define cEND_OF_LINE 150
#define cENTROPY_BITS12W 127
#define cENTROPY_BITS24W 255
#define cCARD_MAX_HISTORY 128
#define cMAIN_create 0
#define cMAIN_LOAD 1
#define cMAIN_BIP85 2
#define cMAIN_SSS 3
#define cMAIN_XOR 4
#define cMAIN_OBFUS 5
#define cMAIN_MNEM2CARD 6
#define cMAIN_ERASESD 7
#define cMAIN_QR 8 // Resources menu
#define cMAIN_SETTINGS 9
#define cMAIN_OPSEC 10              // Group: Shamir, XOR, obfuscation, cards
#define cMAIN_TOOLS 11              // Group: QR reader, QR from text, dice password
// cMAIN_* are function ids, used by the flows (main_pointer); the menus map
// their positions to them (main_menu_ids[], opsec_menu_ids[] in main.c)
#define cRESOURCE_tutorial 0
#define cRESOURCE_backup 1
#define cRESOURCE_dice_test 2
#define cRESOURCE_wordlist 3
#define cRESOURCE_BINlist 4
#define cRESOURCE_security 5
#define cBIP84_ADDRESSES 1        // Opens the RECEIVE / CHANGE address menu (single sig only)
#define cBIP84_XPUB 4
#define cBIP84_PASSPHRASE 5
#define cBIP84_SIGN 6
#define cBIP84_MODE 7           // Toggles single sig / multisig
#define cBIP84_DESCRIPTOR 8     // Multisig menu only
#define cBIP84_ACCOUNT 9        // Account index of m/84'/0'/n' and m/48'/0'/n'/2'
#define cBIP84_DERIVE 10        // BIP85 child seed from the key on screen
#define cBIP84_VAULT 11         // Placeholder, does nothing yet
#define cBIP84_n_opt 8          // Single sig menu entries
#define cBIP84_MULTI_n_opt 8    // Multisig menu entries (no addresses)
#define cADDRESS_RECEIVE 0      // ADDRESSES menu entries = address chain
#define cADDRESS_CHANGE 1
#define cADDRESS_SCAN 2         // Checks a scanned address against our first ones
#define cADDRESS_n_opt 3

#define cSIGN_QR 0
#define cSIGN_SD 1
#define cSIGN_n_opt 2
#define cOBFUS_SHIFT 0
#define cOBFUS_NOT 1
#define cOBFUS_ADD 2
#define cOBFUS_1WORD_XOR 3
#define cOBFUS_BYTE_SWAP 4      // Swaps bytes 0-1, 2-3...: applying it again undoes it
#define cOBFUS_HOWTO 5
#define cSEED_coin 0
#define cSEED_dice 1
#define cSEED_word 2
#define cSEED_cards 3
#define cSEED_timer 4
#define cSEED_triple 5
#define cSIZE_12 0
#define cSIZE_24 1
#define cKEYBOARD 0
#define cFROMSD 1
#define cQRSCAN 2
#define cSD_CHECKSUM_ADDR 64
#define cSD_SIZE_ADDR 65
#define cSD_XOR_ADDR 66 // Key storage offset
#define cLEFT 0
#define cRIGTH 1
#define cADD 0
#define cSUB 1
#define cNOTSAFE 0
#define cSAFE 1
#define cREAD 0
#define cWRITE 1
#define cQRCOMPACT 1
#define cSPLIT 0
#define cMERGE 1
#define cK_MAX 6 // Max 6th order polynomial
#define cN_MAX 9 // Max 9 samples
#define INCORRECT_MSG "INCORRECT SET OF WORDS"
#define LOAD_OK "LOAD OK"
#define OK_MSG "OK"
#define char_hash_limit 501
#define c12_rolls 50
#define c24_rolls 99

#endif // APP_DEFS_H
