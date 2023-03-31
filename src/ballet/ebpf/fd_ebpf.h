#ifndef HEADER_fd_src_ballet_ebpf_fd_ebpf_h
#define HEADER_fd_src_ballet_ebpf_fd_ebpf_h

/* eBPF program support */

#include "../../util/fd_util_base.h"

/* fd_ebpf_sym_t: externally provided ELF symbol. */

struct fd_ebpf_sym {
  char const * name;
  ulong        value;
};
typedef struct fd_ebpf_sym fd_ebpf_sym_t;

/* fd_ebpf_link_opts_t: Input parameters to fd_ebpf_static_link */

struct fd_ebpf_link_opts {
  void *          elf;      /* Points to first byte of ELF (mutable) */
  ulong           elf_sz;   /* Byte size of elf */
  char const *    section;  /* Name of section containing bytecode */
  fd_ebpf_sym_t * sym;      /* Array of provided symbols */
  ulong           sym_cnt;
};
typedef struct fd_ebpf_link_opts fd_ebpf_link_opts_t;

FD_PROTOTYPES_BEGIN

/* fd_ebpf_static_link statically links an eBPF program.

   opts->elf points to the first byte of a mutable buffer containing an
   ELF file with size opts->elf_sz.  opts->elf has 8 byte alignment.
   opts->section is the section name containing eBPF bytecode.  opts->sym
   points to an array of externally provided symbols with count
   opts->sym_cnt, which may be NULL on zero sym_cnt.

   Applies any relocations of given symbols against bytecode section.
   This will modify the ELF buffer contents.  Relocating the same buffer
   multiple times is invalid (due to implicit addends).

   On success, returns pointer to first instruction in bytecode section
   of elf buffer.  If insn_cnt_opt is non-NULL, *insn_cnt_opt is set to
   number of instructions at returned pointer. (multiply by 8 to get\
   byte size).  On failure returns NULL and does not modify insn_cnt_opt.

   Non-exhaustive list of reasons for failure include:
   - ELF parse error
   - ELF does not match FD_ELF_CLASS_64, FD_ELF_DATA_LE, FD_ELF_ET_REL,
     FD_ELF_EM_BPF
   - Missing required section
   - Missing bytecode section or not of type FD_ELF_SHT_PROGBITS
   - Misaligned bytecode section offset or size
   - Too many symbols (limit 1024)
   - Unsupported relocation type (only R_BPF_64_64 supported for now)

   HACK: All R_BPF_64_64 relocs will mangle instructions by setting
         the src_reg field to 0x1!  See fd_ebpf.c for rationale.

   Security note: This method is not hardened against untrusted input. */

ulong *
fd_ebpf_static_link( fd_ebpf_link_opts_t const * opts,
                     ulong *                     insn_cnt_opt );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_ebpf_fd_ebpf_h */
