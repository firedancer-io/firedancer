/* fd_gdb_scripts.S embeds GDB helper Python scripts. */

#if defined(__ELF__)

.pushsection ".debug_gdb_scripts","MS",@progbits,1

.byte 4
.ascii "fd_base58_gdb.py\n"
.incbin "src/app/shared/gdb/fd_base58_gdb.py"
.byte 0

.popsection

#endif

/* dummy symbol that main.c can reference to force this object file
   to be linked in */

.section .rodata.fd_gdb,"a",@progbits
.globl fd_gdb_scripts
.hidden fd_gdb_scripts
fd_gdb_scripts:
.byte 0

.section .note.GNU-stack,"",@progbits
