/*******************************************************************************
 * Project:     SeedMate
 * File:        EFF_short.h
 *
 * Summary:
 *   EFF Short Wordlist 1 (EFF_short.c, generated): 1296 words, 4 dice each.
 ******************************************************************************/

#ifndef EFF_SHORT_H
#define EFF_SHORT_H

#include <stdbool.h>

#define EFF_SHORT_WORDS 1296            // 6^4: one word per 4 dice

// Word of a dice number, index = (d1-1)*216 + (d2-1)*36 + (d3-1)*6 + (d4-1), in
// out (WORDLIST_WORD_MAX + 1 bytes); false if out of range. Lower case, as in
// the official list.
bool get_eff_short_word(int index, char *out);

#endif // EFF_SHORT_H
