/*******************************************************************************
 * Project:     SeedMate
 * File:        pff_app.c
 *
 * Summary:
 *   Builds Petit FatFs for the app straight from the bootloader sources.
 *
 * Description:
 *   pf_readdir() stores the address of a local buffer in DIR.fn. It is set
 *   again on every call before use, so the pointer is never followed after
 *   returning, but GCC's -Wdangling-pointer (an error here with -Werror)
 *   flags it. The warning is disabled for this translation unit only,
 *   without editing the shared pff.c.
 *
 * License:     MIT, same as main.c
 ******************************************************************************/

#pragma GCC diagnostic ignored "-Wdangling-pointer"
#include "../../bootloader/src/pff.c"
