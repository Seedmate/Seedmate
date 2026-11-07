/*---------------------------------------------------------------------------/
/  FatFs R0.16 configuration for Seedmate (sd_files.c)
/
/  FAT12/16/32 read and write, long names up to 64 characters (LFN, static
/  buffer; ffunicode.c holds the conversion tables), no exFAT, one volume,
/  512 byte sectors, the "tiny" buffer (one 512 B window in FATFS shared by
/  the open file), no clock: files get the fixed date below.
/---------------------------------------------------------------------------*/

#define FFCONF_DEF  80386       /* Must match FF_DEFINED of ff.h (R0.16) */

/* Function set: unused functions are dropped by --gc-sections */
#define FF_FS_READONLY      0
#define FF_FS_MINIMIZE      0
#define FF_USE_FIND         0
#ifndef FF_USE_MKFS
#define FF_USE_MKFS         0   /* The host test formats its RAM card with -DFF_USE_MKFS=1 */
#endif
#define FF_USE_FASTSEEK     0
#define FF_USE_EXPAND       0
#define FF_USE_CHMOD        0
#define FF_USE_LABEL        0
#define FF_USE_FORWARD      0
#define FF_USE_STRFUNC      0
#define FF_PRINT_LLI        0
#define FF_PRINT_FLOAT      0
#define FF_STRF_ENCODE      0

/* Names: long names (VFAT, its patents expired) up to 64 characters, code page 437 */
#define FF_CODE_PAGE        437
#define FF_USE_LFN          1   /* Static working buffer: one file operation at a time */
#define FF_MAX_LFN          64
#define FF_LFN_UNICODE      0
#define FF_LFN_BUF          64
#define FF_SFN_BUF          12
#define FF_FS_RPATH         0
#define FF_PATH_DEPTH       10

/* Drive */
#define FF_VOLUMES          1
#define FF_STR_VOLUME_ID    0
#define FF_VOLUME_STRS      "SD"
#define FF_MULTI_PARTITION  0
#define FF_MIN_SS           512
#define FF_MAX_SS           512
#define FF_LBA64            0
#define FF_MIN_GPT          0x10000000
#define FF_USE_TRIM         0

/* System */
#define FF_FS_TINY          1
#define FF_FS_EXFAT         0   /* exFAT stays out (Microsoft patents and license) */
#define FF_FS_NORTC         1
#define FF_NORTC_MON        1
#define FF_NORTC_MDAY       1
#define FF_NORTC_YEAR       2026
#define FF_FS_CRTIME        0
#define FF_FS_NOFSINFO      0
#define FF_FS_LOCK          0
#define FF_FS_REENTRANT     0
#define FF_FS_TIMEOUT       1000
