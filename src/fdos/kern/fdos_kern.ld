ENTRY(fdos_kern_entry)
OUTPUT_FORMAT(elf64-x86-64)

PHDRS
{
  ROM  PT_LOAD AT(0) FLAGS(4);
  CODE PT_LOAD FLAGS(5);
  RAM  PT_LOAD FLAGS(6);
}

SECTIONS
{
  .text 0x2001000 : AT(0x1000) ALIGN(4K)
  {
    *(.text)
  } :CODE

  .rodata 0x3001000 : AT(LOADADDR(.text) + SIZEOF(.text)) ALIGN(4K)
  {
    *(.eh_frame)
    *(.rodata)
    *(.rodata.*)
  } :ROM

  .data 0x4001000 : AT(LOADADDR(.rodata) + SIZEOF(.rodata)) ALIGN(4K)
  {
    *(.data)
  } :RAM

  .bss (0x4001000 + SIZEOF(.data)) (NOLOAD) : AT(LOADADDR(.data) + SIZEOF(.data)) ALIGN(4K)
  {
    *(.bss)
  } :RAM

  /DISCARD/ :
  {
    *(.note.GNU-stack)
    *(.comment)
    *(.interp)
    *(.hash)
    *(.gnu.hash)
  }
}
