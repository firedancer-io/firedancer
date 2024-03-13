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

/* fd_sbpf_calldests is a bit vector of valid call destinations.
   Should be configured to fit any possible program counter.  The max
   program counter is <size of ELF binary> divided by 8. */

#define SET_NAME fd_sbpf_calldests
#include "../../util/tmpl/fd_set_dynamic.c"

/* fd_sbpf_syscall_func_t is a callback implementing an sBPF syscall.
   ctx is the executor context.  Returns 0 on suceess or an integer
   error code on failure. */
/* FIXME: THIS BELONGS IN FLAMENCO/VM */

typedef int
(*fd_sbpf_syscall_func_t)( void *  ctx,
                           ulong   arg0,
                           ulong   arg1,
                           ulong   arg2,
                           ulong   arg3,
                           ulong   arg4,
                           ulong * _ret );

/* fd_sbpf_syscalls_t maps syscall IDs => a name and a VM specific
   context.  FIXME: THIS ALSO PROBABLY BELONGS IN FLAMENCO/VM */

#define FD_SBPF_SYSCALLS_LG_SLOT_CNT (7)
#define FD_SBPF_SYSCALLS_SLOT_CNT    (1UL<<FD_SBPF_SYSCALLS_LG_SLOT_CNT)

struct fd_sbpf_syscalls {
  uint                   key;  /* Murmur3-32 hash of function name */
  fd_sbpf_syscall_func_t func; /* Function pointer */
  char const *           name; /* Infinite lifetime pointer to function name */
};

typedef struct fd_sbpf_syscalls fd_sbpf_syscalls_t;

#define MAP_NAME              fd_sbpf_syscalls
#define MAP_T                 fd_sbpf_syscalls_t
#define MAP_KEY_T             uint
#define MAP_KEY_NULL          0U
#define MAP_KEY_INVAL(k)      !(k)
#define MAP_KEY_EQUAL(k0,k1)  (k0)==(k1)
#define MAP_KEY_EQUAL_IS_SLOW 0
#define MAP_KEY_HASH(k)       (k)
#define MAP_MEMOIZE           0
#define MAP_LG_SLOT_CNT       FD_SBPF_SYSCALLS_LG_SLOT_CNT
#include "../../util/tmpl/fd_map.c"

/* fd_sbpf_elf_info_t contains basic information extracted from an ELF
   binary. Indicates how much scratch memory and buffer size is required
   to fully load the program. */

struct fd_sbpf_elf_info {
  uint text_off;    /* File offset of .text section (overlaps rodata segment) */
  uint text_cnt;    /* Instruction count */
  uint dynstr_off;  /* File offset of .dynstr section (0=missing) */
  uint dynstr_sz;   /* Dynstr char count */

  uint rodata_sz;         /* size of rodata segment */
  uint rodata_footprint;  /* size of ELF binary */

  /* Known section indices
     In [-1,USHORT_MAX) where -1 means "not found" */
  int shndx_text;
  int shndx_symtab;
  int shndx_dyn;
  int shndx_dynstr;

  /* Known program header indices (like shndx_*) */
  int phndx_dyn;

  uint entry_pc;  /* Program counter of entry point
                     NOTE: MIGHT BE OUT OF BOUNDS! */

  /* Bitmap of sections to be loaded (LSB => MSB) */
  ulong loaded_sections[ 1024UL ];
};
typedef struct fd_sbpf_elf_info fd_sbpf_elf_info_t;

/* fd_sbpf_program_t describes a loaded program in memory.

   [rodata,rodata+rodata_sz) is an externally allocated buffer holding
   the read-only segment to be loaded into the VM.  WARNING: The rodata
   area required doing load (rodata_footprint) is larger than the area
   mapped into the VM (rodata_sz).

   [text,text+8*text_cnt) is a sub-region of the read-only segment
   containing executable code. */

struct __attribute__((aligned(32UL))) fd_sbpf_program {
  fd_sbpf_elf_info_t info;

  /* rodata segment to be mapped into VM memory */
  void * rodata;     /* rodata segment data */
  ulong  rodata_sz;  /* size of data */

  /* text section within rodata segment */
  ulong * text;
  ulong   text_cnt;  /* instruction count */
  ulong   text_off;  /* instruction offset for use in CALL_REG instructions */
  ulong   entry_pc;  /* entrypoint PC (at text[ entry_pc - start_pc ]) */

  /* Bit vector of valid call destinations (bit count is rodata_sz) */
  fd_sbpf_calldests_t * calldests;
};
typedef struct fd_sbpf_program fd_sbpf_program_t;

/* Prototypes *********************************************************/

FD_PROTOTYPES_BEGIN

/* fd_sbpf_elf_peek partially parses the given ELF file in memory region
   [bin,bin+bin_sz)  Populates `info`.  Returns `info` on success.  On
   failure, returns NULL. */

fd_sbpf_elf_info_t *
fd_sbpf_elf_peek( fd_sbpf_elf_info_t * info,
                  void const *         bin,
                  ulong                bin_sz );

/* fd_sbpf_program_{align,footprint} return the alignment and size
   requirements of the memory region backing the fd_sbpf_program_t
   object. */

FD_FN_CONST ulong
fd_sbpf_program_align( void );

FD_FN_PURE ulong
fd_sbpf_program_footprint( fd_sbpf_elf_info_t const * info );

/* fd_sbpf_program_new formats prog_mem to hold an fd_sbpf_program_t.
   prog_mem must match footprint requirements of the given elf_info.
   elf_info may be deallocated on return.

   rodata is the read-only segment buffer that the program is configured
   against and must be valid for the lifetime of the program object. */

fd_sbpf_program_t *
fd_sbpf_program_new( void *                     prog_mem,
                     fd_sbpf_elf_info_t const * elf_info,
                     void *                     rodata );

/* fd_sbpf_program_load loads an eBPF program for execution.

   prog is a program object allocated with fd_sbpf_program_new and must
   match the footprint requirements of this ELF file.

   Initializes and populates the program struct with information about
   the program and prepares the read-only segment provided in
   fd_sbpf_program_new.

   Memory region [bin,bin+bin_sz) contains the ELF file to be loaded.

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
                      void const *         bin,
                      ulong                bin_sz,
                      fd_sbpf_syscalls_t * syscalls );

/* fd_sbpf_program_delete destroys the program object and unformats the
   memory regions holding it. */

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
