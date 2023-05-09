#ifndef HEADER_fd_src_ballet_sbpf_fd_sbpf_loader_h
#define HEADER_fd_src_ballet_sbpf_fd_sbpf_loader_h

/* fd_sbpf_loader prepares an sBPF program for execution.  This involves
   parsing and dynamic relocation.

   Due to historical reasons, this loader is neither a pure static
   linker nor a real dynamic loader.  For instance, it will ignore the
   program header table and instead load specific sections at predefined
   addresses.  However, it will perform dynamic relocation. */

#include "../../util/fd_util_base.h"
#include "../elf/fd_elf64.h"

/* Error types ********************************************************/

/* FIXME make error types more specific */
#define FD_SBPF_ERR_INVALID_ELF (1)

/* Program struct *****************************************************/

/* fd_sbpf_calldests_t is a map type used to resolve sBPF call targets.
   This is required because loaded sBPF bytecode does not directly call
   relative addresses, but instead calls the Murmur3 hash of the
   destination program counter.  This hash is not trivially reversible
   thus we store all Murmur3(PC) => PC mappings in this map. */

struct __attribute__((aligned(16UL))) fd_sbpf_calldests {
  ulong key;  /* hash of PC */
  /* FIXME salt map key with an add-rotate-xor */
  ulong pc;
};
typedef struct fd_sbpf_calldests fd_sbpf_calldests_t;

/* fd_sbpf_syscalls_t maps syscall IDs => local function pointers. */

struct __attribute__((aligned(16UL))) fd_sbpf_syscalls {
  uint         key;       /* Murmur3-32 hash of function name */
  ulong        func_ptr;  /* Function pointer */
  char const * name;
};
typedef struct fd_sbpf_syscalls fd_sbpf_syscalls_t;

struct __attribute__((aligned(32UL))) fd_sbpf_program_info {
  /* rodata segment to be mapped into VM memory */
  uchar const *  rodata;     /* rodata segment data */
  ulong          rodata_sz;  /* size of data */

  /* text section within rodata segment */
  ulong const * text;
  ulong         text_cnt;  /* instruction count */
  ulong         entry_pc;  /* entrypoint PC (at text[ entry_pc - start_pc ]) */

  /* Map of valid call destinations */
  fd_sbpf_calldests_t * calldests;
};
typedef struct fd_sbpf_program_info fd_sbpf_program_info_t;

struct fd_sbpf_program_private;
typedef struct fd_sbpf_program_private fd_sbpf_program_t;

/* Prototypes *********************************************************/

FD_PROTOTYPES_BEGIN

ulong
fd_sbpf_program_align( void );

ulong
fd_sbpf_program_footprint( void );

fd_sbpf_program_t *
fd_sbpf_program_new( void * mem );

/* fd_sbpf_program_load loads an eBPF program for execution.  bin points
   to the first byte of an ELF shared object of bin_sz bytes.

   IMPORTANT: bin is modified in-place.  The caller must ensure that
   8 bytes past the end of bin are writable as scratch space.

   Initializes and populates the program struct with information about
   the program, including pointer prog->{rodata,text} into the memory
   region at bin.

   Arbitrarily mangles bin such that it no longer holds a valid ELF
   (this function thus is not idempotent).

   On success, returns 0.
   On error, returns FD_SBPF_ERR_* and leaves prog in an undefined
   state.

   ### Compliance

   This loader does not yet adhere to Solana protocol specs.
   It is mostly compatible with solana-labs/rbpf v0.3.0 with the
   following config:

     new_elf_parser:     true
     enable_elf_vaddr:   false
     reject_broken_elfs: true

   For documentation on these config params, see:
   https://github.com/solana-labs/rbpf/blob/v0.3.0/src/vm.rs#L198 */

int
fd_sbpf_program_load( fd_sbpf_program_t *  prog,
                      void *               _bin,
                      ulong                bin_sz,
                      fd_sbpf_syscalls_t * syscalls );

FD_FN_CONST inline fd_sbpf_program_info_t const *
fd_sbpf_program_get_info( fd_sbpf_program_t const * program ) {
  return (fd_sbpf_program_info_t const *) program;
}

void *
fd_sbpf_program_delete( fd_sbpf_program_t * program );

/* fd_csv_strerror: Returns a cstr describing the source line and error
   kind after the last call to `fd_sbpf_program_load` from the same
   thread returned non-zero.
   Always returns a valid cstr, though the content is undefined in case
   the last call to `fd_sbpf_program_load` returned zero (success). */

char const *
fd_sbpf_strerror( void );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_sbpf_fd_sbpf_loader_h */
