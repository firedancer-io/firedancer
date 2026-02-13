ENTRY(fdos_kern_entry)
OUTPUT_FORMAT(elf64-x86-64)

PHDRS
{
  ROM  PT_LOAD FLAGS(4);
  CODE PT_LOAD FLAGS(5);
  RAM  PT_LOAD FLAGS(6);
}

SECTIONS
{
  . = 0xffffffff80000000;

  .text : AT(ADDR(.text) - 0xffffffff80000000) {
    *(.text)
  } :CODE

  . = ALIGN(4K);

  .rodata : AT(ADDR(.rodata) - 0xffffffff80000000) {
    *(.rodata)
    *(.rodata.*)
  } :ROM

  . = ALIGN(4K);

  .data : AT(ADDR(.data) - 0xffffffff80000000) {
    *(.data)
  } :RAM

  .bss : AT(ADDR(.bss) - 0xffffffff80000000) {
    *(.bss)
  } :RAM

  .got.plt (INFO) : { *(.got.plt) }
	ASSERT(SIZEOF(.got.plt) == 0, "Unexpected GOT entries detected!")

  .got : {
		*(.got) *(.igot.*)
	}
	ASSERT(SIZEOF(.got) == 0, "Unexpected GOT entries detected!")

  .plt : {
		*(.plt) *(.plt.*) *(.iplt)
	}
	ASSERT(SIZEOF(.plt) == 0, "Unexpected run-time procedure linkages detected!")

	.rel.dyn : {
		*(.rel.*) *(.rel_*)
	}
	ASSERT(SIZEOF(.rel.dyn) == 0, "Unexpected run-time relocations (.rel) detected!")

	.rela.dyn : {
		*(.rela.*) *(.rela_*)
	}
	ASSERT(SIZEOF(.rela.dyn) == 0, "Unexpected run-time relocations (.rela) detected!")

  /DISCARD/ :
  {
    *(.note.GNU-stack)
    *(.comment)
    *(.interp)
    *(.hash)
    *(.gnu.hash)
  }
}
