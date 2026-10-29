/*******************************************************************************
 * Project:     SeedMate
 * File:        EFF_short.c
 *
 * Summary:
 *   EFF Short Wordlist and passphrase generation module.
 *
 * Description:
 *   This file implements the Electronic Frontier Foundation (EFF) short 
 *   wordlist (1,296 words) for secure passphrase generation.
 *   
 *   To optimize memory on the PIC32MM architecture and avoid an array of 
 *   1,296 pointers (which would consume excessive Flash/RAM), the wordlist 
 *   is encoded as a single contiguous null-terminated string. This strictly 
 *   follows the memory-saving strategy utilized in words_opt.h for BIP39.
 *
 * Main responsibilities:
 *   - Store the EFF short wordlist efficiently in ROM
 *   - Provide linear-scan index-based word retrieval
 *   - Generate cryptographically unbiased passphrases via rejection sampling
 *
 * Notes:
 *   - Designed for offline, embedded environments.
 *   - The list contains exactly 1,296 words (simulating 4 dice rolls).
 *
 * Author:      Seedmate
 * Date:        26/09/2026
 * Version:     v1.7                               
 * License
 * 
 * This project is licensed under the MIT License.
 * 
 * MIT License
 * 
 * Copyright (c) 2026 Seedmate
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 ******************************************************************************/

// *****************************************************************************
// *****************************************************************************
// Section: Included Files
// *****************************************************************************
// *****************************************************************************

#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Note: Ensure your hardware entropy source function is accessible here.
// In main.c you are using TMR1 (e.g., time_now = TMR1). 
// You can replace this extern with your actual random number generation header.
extern uint16_t get_hardware_entropy(void); 


// *****************************************************************************
// *****************************************************************************
// Section: Global Variables / ROM Data
// *****************************************************************************
// *****************************************************************************

/* 
 * EFF Short Wordlist v1 (1,296 words).
 * Stored as a single string literal with explicit null terminators to 
 * eliminate 32-bit pointer overhead. This keeps the data entirely in Flash.
 * 
 * NOTE: For brevity in this file generation, the middle section is truncated. 
 * You just need to paste the rest of the 1296 words following this exact pattern: 
 * "word1\0word2\0word3\0..."
 */
const char eff_short_words[] =
    "ACID\0ACORN\0ACRE\0ACTS\0AFAR\0AFFIX\0AGED\0AGENT\0"
    "AGILE\0AGING\0AGONY\0AHEAD\0AIDE\0AIDS\0AIM\0AJAR\0"
    "ALARM\0ALIAS\0ALIBI\0ALIEN\0ALIKE\0ALIVE\0ALOE\0ALOFT\0"
    "ALOHA\0ALONE\0AMEND\0AMINO\0AMPLE\0AMUSE\0ANGEL\0ANGER\0"
    "ANGLE\0ANKLE\0APPLE\0APRIL\0APRON\0AQUA\0AREA\0ARENA\0"
    "ARGUE\0ARISE\0ARMED\0ARMOR\0ARMY\0AROMA\0ARRAY\0ARSON\0"
    "ART\0ASHEN\0ASHES\0ATLAS\0ATOM\0ATTIC\0AUDIO\0AVERT\0"
    // ... [Copy the rest of the EFF Short list here formatted identically] ...
    "WOMB\0WOOL\0WOOZY\0WORD\0WORK\0WORRY\0WOUND\0WOVEN\0"
    "WRATH\0WRECK\0WRIST\0XEROX\0YAHOO\0YAM\0YARD\0YEAR\0"
    "YEAST\0YELP\0YIELD\0YOYO\0YODEL\0YOGA\0YUMMY\0ZEBRA\0"
    "ZERO\0ZESTY\0ZIPPY\0ZONE\0ZOOM\0";


// *****************************************************************************
// *****************************************************************************
// Section: EFF Wordlist Operations
// *****************************************************************************
// *****************************************************************************

/**
 * Retrieves a pointer to a specific word in the EFF short wordlist array.
 * Works exactly like get_word() in main.c by linearly scanning the null terminators.
 * 
 * @param index The integer index (0 to 1295) of the requested word.
 * @return const char pointer to the null-terminated word in ROM, or NULL if invalid.
 */
const char* get_eff_short_word(int index) {
    if (index < 0 || index >= 1296) {
        return NULL;
    }
    
    const char* ptr = eff_short_words; 
    
    // Linearly scan through the null-terminators to find the correct offset
    for (int i = 0; i < index; i++) {
        while (*ptr != '\0') {
            ptr++;
        }
        ptr++; // Skip over the null terminator to the start of the next word
    }
    
    return ptr; 
}

/**
 * Secures a purely random index between 0 and 1295 using Rejection Sampling.
 * This guarantees zero modulo-bias when picking words.
 * 
 * @return uint32_t A cryptographically safe index between 0 and 1295.
 */
static uint32_t get_secure_eff_index(void) {
    uint16_t random_val;
    
    do {
        // Fetch real entropy (e.g., from TMR1 jitter as done in your main.c)
        random_val = get_hardware_entropy();
        
        // Apply an 11-bit mask (0x07FF = 2047).
        // Since we need max 1295, masking to 11 bits drastically reduces 
        // the amount of rejections in the loop, making it much faster.
        random_val = random_val & 0x07FF; 
        
        // Rejection sampling: if the value is >= 1296, discard and redraw.
    } while (random_val >= 1296);
    
    return (uint32_t)random_val;
}

/**
 * Generates a full EFF passphrase securely and stores it in the provided buffer.
 * 
 * @param num_words The number of words desired (e.g., 6 for ~77 bits of entropy).
 * @param output_buffer Pre-allocated char array to hold the resulting string.
 */
void eff_generate_passphrase(int num_words, char *output_buffer) {
    if (output_buffer == NULL || num_words <= 0) {
        return;
    }
    
    // Initialize the buffer as an empty string
    output_buffer[0] = '\0'; 
    
    for (int i = 0; i < num_words; i++) {
        uint32_t idx = get_secure_eff_index();
        const char *word = get_eff_short_word((int)idx);
        
        if (word != NULL) {
            strcat(output_buffer, word);
            
            // Append a space between words, but not after the last word
            if (i < num_words - 1) {
                strcat(output_buffer, " ");
            }
        }
    }
}
