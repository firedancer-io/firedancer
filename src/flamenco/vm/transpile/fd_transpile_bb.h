#ifndef HEADER_fd_src_flamenco_vm_transpile_fd_transpile_bb_h
#define HEADER_fd_src_flamenco_vm_transpile_fd_transpile_bb_h

/* fd_transpile_bb.h splits sBPF text into basic blocks.  Shared by the
   machine code backends (fd_transpile_x86.dasc, fd_transpile_arm64.dasc). */

#include "fd_transpile.h"

FD_PROTOTYPES_BEGIN

/* fd_transpile_bb_splits heuristically guesses the bounds of basic
   blocks.  Control flow transitions in transpiled programs are
   restricted to the starts of basic blocks.  (Otherwise, transpiled
   execution bails transparently to the interpreter.)  Writes a bit
   vector of ceil(bpf_text_cnt/64) words to bb_splits and returns the
   popcount.  bpf_rodata/bpf_rodata_sz is the loaded program image and
   bpf_text_off the byte offset of text within it (used to find
   address-taken functions). */

ulong
fd_transpile_bb_splits( ulong *       bb_splits,
                        ulong         sbpf_version,
                        ulong const * bpf_text,
                        ulong         bpf_text_cnt,
                        ulong         bpf_entry_pc,
                        ulong const * bpf_calldests,
                        uchar const * bpf_rodata,
                        ulong         bpf_rodata_sz,
                        ulong         bpf_text_off );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_vm_transpile_fd_transpile_bb_h */
