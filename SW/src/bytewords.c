#include "bytewords.h"
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

// 256 minimal Bytewords mappings (first and last letter of each standard word)
static const char bytewords_minimal[256][2] = {
    // 0x00 - 0x0F
    {'A','E'}, {'A','D'}, {'A','O'}, {'A','X'}, {'A','A'}, {'A','H'}, {'A','M'}, {'A','T'},
    {'A','Y'}, {'A','S'}, {'B','K'}, {'B','D'}, {'B','N'}, {'B','T'}, {'B','A'}, {'B','S'},
    // 0x10 - 0x1F
    {'B','E'}, {'B','Y'}, {'B','G'}, {'B','W'}, {'B','B'}, {'B','Z'}, {'C','M'}, {'C','H'},
    {'C','S'}, {'C','F'}, {'C','Y'}, {'C','W'}, {'C','E'}, {'C','A'}, {'C','K'}, {'C','T'},
    // 0x20 - 0x2F
    {'C','X'}, {'C','L'}, {'C','P'}, {'C','N'}, {'D','K'}, {'D','A'}, {'D','S'}, {'D','I'},
    {'D','E'}, {'D','T'}, {'D','R'}, {'D','N'}, {'D','W'}, {'D','P'}, {'D','M'}, {'D','L'},
    // 0x30 - 0x3F
    {'D','Y'}, {'E','H'}, {'E','Y'}, {'E','O'}, {'E','E'}, {'E','C'}, {'E','N'}, {'E','M'},
    {'E','T'}, {'E','S'}, {'F','T'}, {'F','R'}, {'F','N'}, {'F','S'}, {'F','M'}, {'F','H'},
    // 0x40 - 0x4F
    {'F','Z'}, {'F','P'}, {'F','W'}, {'F','X'}, {'F','Y'}, {'F','E'}, {'F','G'}, {'F','L'},
    {'F','D'}, {'G','A'}, {'G','E'}, {'G','R'}, {'G','S'}, {'G','T'}, {'G','L'}, {'G','W'},
    // 0x50 - 0x5F
    {'G','D'}, {'G','Y'}, {'G','M'}, {'G','U'}, {'G','H'}, {'G','O'}, {'H','F'}, {'H','G'},
    {'H','D'}, {'H','K'}, {'H','T'}, {'H','P'}, {'H','H'}, {'H','L'}, {'H','Y'}, {'H','E'},
    // 0x60 - 0x6F
    {'H','N'}, {'H','S'}, {'I','D'}, {'I','A'}, {'I','E'}, {'I','H'}, {'I','Y'}, {'I','O'},
    {'I','S'}, {'I','N'}, {'I','M'}, {'J','E'}, {'J','Z'}, {'J','N'}, {'J','T'}, {'J','L'},
    // 0x70 - 0x7F
    {'J','O'}, {'J','S'}, {'J','P'}, {'J','K'}, {'J','Y'}, {'K','P'}, {'K','O'}, {'K','T'},
    {'K','S'}, {'K','K'}, {'K','N'}, {'K','G'}, {'K','E'}, {'K','I'}, {'K','B'}, {'L','B'},
    // 0x80 - 0x8F
    {'L','A'}, {'L','Y'}, {'L','F'}, {'L','S'}, {'L','R'}, {'L','P'}, {'L','N'}, {'L','T'},
    {'L','O'}, {'L','D'}, {'L','E'}, {'L','U'}, {'L','K'}, {'L','G'}, {'M','N'}, {'M','Y'},
    // 0x90 - 0x9F
    {'M','H'}, {'M','E'}, {'M','O'}, {'M','U'}, {'M','W'}, {'M','D'}, {'M','T'}, {'M','S'},
    {'M','K'}, {'N','L'}, {'N','Y'}, {'N','D'}, {'N','S'}, {'N','T'}, {'N','N'}, {'N','E'},
    // 0xA0 - 0xAF
    {'N','B'}, {'O','Y'}, {'O','E'}, {'O','T'}, {'O','X'}, {'O','N'}, {'O','L'}, {'O','S'},
    {'P','D'}, {'P','T'}, {'P','K'}, {'P','Y'}, {'P','S'}, {'P','M'}, {'P','L'}, {'P','E'},
    // 0xB0 - 0xBF
    {'P','F'}, {'P','A'}, {'P','R'}, {'Q','D'}, {'Q','Z'}, {'R','E'}, {'R','P'}, {'R','L'},
    {'R','O'}, {'R','H'}, {'R','D'}, {'R','K'}, {'R','F'}, {'R','Y'}, {'R','N'}, {'R','S'},
    // 0xC0 - 0xCF
    {'R','T'}, {'S','E'}, {'S','A'}, {'S','R'}, {'S','S'}, {'S','K'}, {'S','W'}, {'S','T'},
    {'S','P'}, {'S','O'}, {'S','G'}, {'S','B'}, {'S','F'}, {'S','N'}, {'T','O'}, {'T','K'},
    // 0xD0 - 0xDF
    {'T','I'}, {'T','T'}, {'T','D'}, {'T','E'}, {'T','Y'}, {'T','L'}, {'T','B'}, {'T','S'},
    {'T','P'}, {'T','A'}, {'T','N'}, {'U','Y'}, {'U','O'}, {'U','T'}, {'U','E'}, {'U','R'},
    // 0xE0 - 0xEF
    {'V','T'}, {'V','Y'}, {'V','O'}, {'V','L'}, {'V','E'}, {'V','W'}, {'V','A'}, {'V','D'},
    {'V','S'}, {'W','L'}, {'W','D'}, {'W','M'}, {'W','P'}, {'W','E'}, {'W','Y'}, {'W','S'},
    // 0xF0 - 0xFF
    {'W','T'}, {'W','N'}, {'W','Z'}, {'W','F'}, {'W','K'}, {'Y','K'}, {'Y','N'}, {'Y','L'},
    {'Y','A'}, {'Y','T'}, {'Z','S'}, {'Z','O'}, {'Z','T'}, {'Z','C'}, {'Z','E'}, {'Z','M'}
};

// 26x26 grid = 1352 bytes in RAM
static int16_t fast_bw_lookup[26][26];
static bool lookup_initialized = false;

void init_bytewords_lookup(void) {
    if (lookup_initialized) return;
    
    // Fill matrix with -1 (invalid combination marker)
    for (int i = 0; i < 26; i++) {
        for (int j = 0; j < 26; j++) {
            fast_bw_lookup[i][j] = -1;
        }
    }
    
    // Map valid combinations to their byte index
    for (int i = 0; i < 256; i++) {
        uint8_t c1 = bytewords_minimal[i][0] - 'A';
        uint8_t c2 = bytewords_minimal[i][1] - 'A';
        fast_bw_lookup[c1][c2] = (int16_t)i;
    }
    
    lookup_initialized = true;
}

int decode_bytewords_pair(char c1, char c2) {
    if (!lookup_initialized) init_bytewords_lookup();
    
    // Ensure uppercase
    if (c1 >= 'a' && c1 <= 'z') c1 -= 32;
    if (c2 >= 'a' && c2 <= 'z') c2 -= 32;
    
    // Reject non-alphabet characters instantly
    if (c1 < 'A' || c1 > 'Z' || c2 < 'A' || c2 > 'Z') return -1;
    
    int16_t val = fast_bw_lookup[c1 - 'A'][c2 - 'A'];
    if (val == -1) return -1;
    
    return (int)val;
}