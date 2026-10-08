/*--------------------------------------------------------------------------
 * MPLAB XC Compiler - PIC32MM0256GPM036 linker script (Bootloader)
 *--------------------------------------------------------------------------*/

OUTPUT_FORMAT("elf32-tradlittlemips")
OUTPUT_ARCH(pic32mx)
ENTRY(_reset)

EXTERN (_min_stack_size _min_heap_size)
PROVIDE(_min_stack_size = 0x400) ;

#if defined(__XC32_VERSION__) && (__XC32_VERSION__ < 2100)
OPTIONAL("processor.o")
#endif

PROVIDE(_vector_spacing = 0x0001);
PROVIDE(_ebase_address = 0xBFC01000);

/* Explicitly provide symbols expected by the startup routines */
PROVIDE(_stack = ORIGIN(kseg0_data_mem) + LENGTH(kseg0_data_mem));
PROVIDE(_ramfunc_begin = 0);

_RESET_ADDR                    = 0xBFC00000;
_BEV_EXCPT_ADDR                = 0xBFC00380;
_DBG_EXCPT_ADDR                = 0xBFC00480;
_DBG_CODE_ADDR                 = 0x9FC00490;
_DBG_CODE_SIZE                 = 0x760;
_SIMPLE_TLB_REFILL_EXCPT_ADDR  = _ebase_address + 0;
_GEN_EXCPT_ADDR                = _ebase_address + 0x180;

MEMORY
{
  /* Allocate exactly 8KB (0x2000) of main flash for the bootloader's heavy code */
  kseg0_program_mem     (rx)  : ORIGIN = 0x9D000000, LENGTH = 0x2000
  
  debug_exec_mem              : ORIGIN = 0x9FC00490, LENGTH = 0x760
  kseg0_boot_mem        (rx)  : ORIGIN = 0x9FC00490, LENGTH = 0x0
  
  /* Physical Boot Flash allocation for reset and exception vectors */
  kseg1_boot_mem        (rx)  : ORIGIN = 0xBFC00000, LENGTH = 0x1700
  
  config_BFC01744             : ORIGIN = 0xBFC01744, LENGTH = 0x4
  config_BFC01748             : ORIGIN = 0xBFC01748, LENGTH = 0x4
  config_BFC0174C             : ORIGIN = 0xBFC0174C, LENGTH = 0x4
  config_BFC01750             : ORIGIN = 0xBFC01750, LENGTH = 0x4
  config_BFC01754             : ORIGIN = 0xBFC01754, LENGTH = 0x4
  config_BFC01758             : ORIGIN = 0xBFC01758, LENGTH = 0x4
  config_BFC01760             : ORIGIN = 0xBFC01760, LENGTH = 0x4
  config_BFC017C4             : ORIGIN = 0xBFC017C4, LENGTH = 0x4
  config_BFC017C8             : ORIGIN = 0xBFC017C8, LENGTH = 0x4
  config_BFC017CC             : ORIGIN = 0xBFC017CC, LENGTH = 0x4
  config_BFC017D0             : ORIGIN = 0xBFC017D0, LENGTH = 0x4
  config_BFC017D4             : ORIGIN = 0xBFC017D4, LENGTH = 0x4
  config_BFC017D8             : ORIGIN = 0xBFC017D8, LENGTH = 0x4
  config_BFC017E0             : ORIGIN = 0xBFC017E0, LENGTH = 0x4
  kseg0_data_mem       (w!x)  : ORIGIN = 0x80000000, LENGTH = 0x8000
  sfrs                        : ORIGIN = 0xBF800000, LENGTH = 0x100000
  configsfrs_BFC01740         : ORIGIN = 0xBFC01740, LENGTH = 0x1C
  configsfrs_BFC017C0         : ORIGIN = 0xBFC017C0, LENGTH = 0x1C
}

SECTIONS
{
  .config_BFC01744 : { KEEP(*(.config_BFC01744)) KEEP(*(.config_9FC01744)) } > config_BFC01744
  .config_BFC01748 : { KEEP(*(.config_BFC01748)) KEEP(*(.config_9FC01748)) } > config_BFC01748
  .config_BFC0174C : { KEEP(*(.config_BFC0174C)) KEEP(*(.config_9FC0174C)) } > config_BFC0174C
  .config_BFC01750 : { KEEP(*(.config_BFC01750)) KEEP(*(.config_9FC01750)) } > config_BFC01750
  .config_BFC01754 : { KEEP(*(.config_BFC01754)) KEEP(*(.config_9FC01754)) } > config_BFC01754
  .config_BFC01758 : { KEEP(*(.config_BFC01758)) KEEP(*(.config_9FC01758)) } > config_BFC01758
  .config_BFC01760 : { KEEP(*(.config_BFC01760)) KEEP(*(.config_9FC01760)) } > config_BFC01760
  .config_BFC017C4 : { KEEP(*(.config_BFC017C4)) KEEP(*(.config_9FC017C4)) } > config_BFC017C4
  .config_BFC017C8 : { KEEP(*(.config_BFC017C8)) KEEP(*(.config_9FC017C8)) } > config_BFC017C8
  .config_BFC017CC : { KEEP(*(.config_BFC017CC)) KEEP(*(.config_9FC017CC)) } > config_BFC017CC
  .config_BFC017D0 : { KEEP(*(.config_BFC017D0)) KEEP(*(.config_9FC017D0)) } > config_BFC017D0
  .config_BFC017D4 : { KEEP(*(.config_BFC017D4)) KEEP(*(.config_9FC017D4)) } > config_BFC017D4
  .config_BFC017D8 : { KEEP(*(.config_BFC017D8)) KEEP(*(.config_9FC017D8)) } > config_BFC017D8
  .config_BFC017E0 : { KEEP(*(.config_BFC017E0)) KEEP(*(.config_9FC017E0)) } > config_BFC017E0
}

SECTIONS
{
  .reset _RESET_ADDR :
  {
    KEEP(*(.reset))
    KEEP(*(.reset.startup))
  } > kseg1_boot_mem
  
  .bev_excpt _BEV_EXCPT_ADDR :
  {
    KEEP(*(.bev_handler))
  } > kseg1_boot_mem
  
  .dbg_excpt _DBG_EXCPT_ADDR (NOLOAD) :
  {
    . += (DEFINED (_DEBUGGER) ? 0x8 : 0x0);
  } > kseg1_boot_mem
  
  .dbg_code _DBG_CODE_ADDR (NOLOAD) :
  {
    . += (DEFINED (_DEBUGGER) ? _DBG_CODE_SIZE : 0x0);
  } > debug_exec_mem

  .simple_tlb_refill_excpt _SIMPLE_TLB_REFILL_EXCPT_ADDR :
  {
    KEEP(*(.simple_tlb_refill_vector))
  } > kseg1_boot_mem
  
  .app_excpt _GEN_EXCPT_ADDR :
  {
    KEEP(*(.gen_handler))
  } > kseg1_boot_mem

  /* Move startup code and C runtime to 8KB main program memory */
  .startup :
  {
    KEEP(*(.startup))
  } > kseg0_program_mem

  .text :
  {
    *(.text .text.*)
    *(.stub .gnu.linkonce.t.*)
    KEEP (*(.text.*personality*))
    *(.mips16.fn.*)
    *(.mips16.call.*)
    *(.gnu.warning)
    . = ALIGN(4) ;
  } > kseg0_program_mem  

  .init :
  {
    KEEP (*crti.o(.init))
    KEEP (*crtbegin.o(.init))
    KEEP (*(EXCLUDE_FILE (*crtend.o *crtend?.o *crtn.o ).init))
    KEEP (*crtend.o(.init))
    KEEP (*crtn.o(.init))
    . = ALIGN(4) ;
  } > kseg0_program_mem

  .fini :
  {
    KEEP (*(.fini))
    . = ALIGN(4) ;
  } > kseg0_program_mem

  .rodata :
  {
    *(.rodata .rodata.*)
    *( .gnu.linkonce.r.*)
    *(.rodata1)
    . = ALIGN(4) ;
  } > kseg0_program_mem

  .sdata2 ALIGN(4) :
  {
    *(.sdata2 .sdata2.* .gnu.linkonce.s2.*)
    . = ALIGN(4) ;
  } > kseg0_program_mem

  .sbss2 ALIGN(4) :
  {
    *(.sbss2 .sbss2.* .gnu.linkonce.sb2.*)
    . = ALIGN(4) ;
  } > kseg0_program_mem

  .eh_frame_hdr :
  {
    *(.eh_frame_hdr)
  } > kseg0_program_mem
    . = ALIGN(4) ;
    
  .eh_frame : ONLY_IF_RO
  {
    KEEP (*(.eh_frame))
  } > kseg0_program_mem
    . = ALIGN(4) ;
    
  .gcc_except_table : ONLY_IF_RO
  {
    *(.gcc_except_table .gcc_except_table.*)
  } > kseg0_program_mem
    . = ALIGN(4) ;

  .dbg_data (NOLOAD) :
  {
    . += (DEFINED (_DEBUGGER) ? 0x200 : 0x0);
  } > kseg0_data_mem

  .data :
  {
    *(.data .data.*)
    *( .gnu.linkonce.d.*)
    SORT(CONSTRUCTORS)
    *(.data1)
    . = ALIGN(4) ;
  } > kseg0_data_mem

  . = .;
  _gp = ALIGN(16) + 0x7ff0;
  .got ALIGN(4) :
  {
    *(.got.plt) *(.got)
    . = ALIGN(4) ;
  } > kseg0_data_mem

  .sdata ALIGN(4) :
  {
    _sdata_begin = . ;
    *(.sdata .sdata.* .gnu.linkonce.s.*)
    . = ALIGN(4) ;
    _sdata_end = . ;
  } > kseg0_data_mem

  .sbss ALIGN(4) :
  {
    _sbss_begin = . ;
    *(.dynsbss)
    *(.sbss .sbss.* .gnu.linkonce.sb.*)
    *(.scommon)
    _sbss_end = . ;
    . = ALIGN(4) ;
  } > kseg0_data_mem

  .bss :
  {
    *(.bss .bss.*)
    *(.dynbss)
    *(COMMON)
   . = ALIGN(. != 0 ? 4 : 1);
  } > kseg0_data_mem
  
  . = ALIGN(4) ;
  _end = . ;
  _bss_end = . ;
  _bmxdudba_address = LENGTH(kseg0_data_mem) ;
  _bmxdupba_address = LENGTH(kseg0_data_mem) ;
  
  /DISCARD/ : { *(.pdr) }
}