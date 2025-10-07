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
#define FD_SBPF_PROG_RODATA_ALIGN 8UL

/* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L17 */
#define FD_SBPF_ELF_PARSER_SUCCESS                           ( 0)
#define FD_SBPF_ELF_PARSER_ERR_INVALID_FILE_HEADER           (-1)
#define FD_SBPF_ELF_PARSER_ERR_INVALID_PROGRAM_HEADER        (-2)
#define FD_SBPF_ELF_PARSER_ERR_INVALID_SECTION_HEADER        (-3)
#define FD_SBPF_ELF_PARSER_ERR_INVALID_STRING                (-4)
#define FD_SBPF_ELF_PARSER_ERR_STRING_TOO_LONG               (-5)
#define FD_SBPF_ELF_PARSER_ERR_OUT_OF_BOUNDS                 (-6)
#define FD_SBPF_ELF_PARSER_ERR_INVALID_SIZE                  (-7)
#define FD_SBPF_ELF_PARSER_ERR_OVERLAP                       (-8)
#define FD_SBPF_ELF_PARSER_ERR_SECTION_NOT_IN_ORDER          (-9)
#define FD_SBPF_ELF_PARSER_ERR_NO_SECTION_NAME_STRING_TABLE  (-10)
#define FD_SBPF_ELF_PARSER_ERR_INVALID_DYNAMIC_SECTION_TABLE (-11)
#define FD_SBPF_ELF_PARSER_ERR_INVALID_RELOCATION_TABLE      (-12)
#define FD_SBPF_ELF_PARSER_ERR_INVALID_ALIGNMENT             (-13)
#define FD_SBPF_ELF_PARSER_ERR_NO_STRING_TABLE               (-14)
#define FD_SBPF_ELF_PARSER_ERR_NO_DYNAMIC_STRING_TABLE       (-15)

/* Map Rust ElfError (elf.rs v0.12.2) to C error codes */
/* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L40-L66 */
#define FD_SBPF_ELF_SUCCESS                                  (  0)
#define FD_SBPF_ELF_ERR_FAILED_TO_PARSE                      ( -1)
#define FD_SBPF_ELF_ERR_ENTRYPOINT_OUT_OF_BOUNDS             ( -2)
#define FD_SBPF_ELF_ERR_INVALID_ENTRYPOINT                   ( -3)
#define FD_SBPF_ELF_ERR_FAILED_TO_GET_SECTION                ( -4)
#define FD_SBPF_ELF_ERR_UNRESOLVED_SYMBOL                    ( -5)
#define FD_SBPF_ELF_ERR_SECTION_NOT_FOUND                    ( -6)
#define FD_SBPF_ELF_ERR_RELATIVE_JUMP_OUT_OF_BOUNDS          ( -7)
#define FD_SBPF_ELF_ERR_SYMBOL_HASH_COLLISION                ( -8)
#define FD_SBPF_ELF_ERR_WRONG_ENDIANNESS                     ( -9)
#define FD_SBPF_ELF_ERR_WRONG_ABI                            (-10)
#define FD_SBPF_ELF_ERR_WRONG_MACHINE                        (-11)
#define FD_SBPF_ELF_ERR_WRONG_CLASS                          (-12)
#define FD_SBPF_ELF_ERR_NOT_ONE_TEXT_SECTION                 (-13)
#define FD_SBPF_ELF_ERR_WRITABLE_SECTION_NOT_SUPPORTED       (-14)
#define FD_SBPF_ELF_ERR_ADDRESS_OUTSIDE_LOADABLE_SECTION     (-15)
#define FD_SBPF_ELF_ERR_INVALID_VIRTUAL_ADDRESS              (-16)
#define FD_SBPF_ELF_ERR_UNKNOWN_RELOCATION                   (-17)
#define FD_SBPF_ELF_ERR_FAILED_TO_READ_RELOCATION_INFO       (-18)
#define FD_SBPF_ELF_ERR_WRONG_TYPE                           (-19)
#define FD_SBPF_ELF_ERR_UNKNOWN_SYMBOL                       (-20)
#define FD_SBPF_ELF_ERR_VALUE_OUT_OF_BOUNDS                  (-21)
#define FD_SBPF_ELF_ERR_UNSUPPORTED_SBPF_VERSION             (-22)
#define FD_SBPF_ELF_ERR_INVALID_PROGRAM_HEADER               (-23)

/* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/program.rs */
#define FD_SBPF_VERSION_COUNT (5U)
#define FD_SBPF_V0            (0U)
#define FD_SBPF_V1            (1U)
#define FD_SBPF_V2            (2U)
#define FD_SBPF_V3            (3U)
#define FD_SBPF_V4            (4U)
#define FD_SBPF_RESERVED      (FD_SBPF_VERSION_COUNT)

/* Hardcoded constant for the murmur3_32 hash of the entrypoint. */
#define FD_SBPF_ENTRYPOINT_PC   (0xb00c380U)
#define FD_SBPF_ENTRYPOINT_HASH (0x71e3cf81U) /* fd_pchash( FD_SBPF_ENTRYPOINT_PC ) */

#define E_FLAGS_SBPF_V2         (0x20U)

/* Program struct *****************************************************/

/* fd_sbpf_calldests is a bit vector of valid call destinations.
   Should be configured to fit any possible program counter.  The max
   program counter is <size of ELF binary> divided by 8. */

#define SET_NAME fd_sbpf_calldests
#include "../../util/tmpl/fd_set_dynamic.c"

/* fd_sbpf_syscall_func_t is a callback implementing an sBPF syscall.
   vm is a handle to the running VM.  Returns 0 on suceess or an integer
   error code on failure.

   IMPORTANT SAFETY TIP!  See notes in
   flamenco/vm/syscall/fd_vm_syscall.h on what a syscall should expect
   to see and expect to return. */

/* FIXME: THIS BELONGS IN FLAMENCO/VM */

typedef int
(*fd_sbpf_syscall_func_t)( void *  vm,
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

/* The syscalls map keys should technically be of type uint since they are
   just murmur32 hashes. However, Agave's BTree allows the full range to be
   used as a key [0, UINT_MAX]. So we need to define a wider key type to
   allow for a NULL value that is outside this range. We use ulong here. */

struct fd_sbpf_syscalls {
  ulong                  key;  /* Murmur3-32 hash of function name */
  fd_sbpf_syscall_func_t func; /* Function pointer */
  char const *           name; /* Infinite lifetime pointer to function name */
};

typedef struct fd_sbpf_syscalls fd_sbpf_syscalls_t;

#define MAP_NAME              fd_sbpf_syscalls
#define MAP_T                 fd_sbpf_syscalls_t
#define MAP_HASH_T            ulong
#define MAP_KEY_NULL          ULONG_MAX         /* Any number greater than UINT_MAX works */
#define MAP_KEY_INVAL(k)      ( k > UINT_MAX )  /* Force keys to uint size */
#define MAP_KEY_EQUAL(k0,k1)  (k0)==(k1)
#define MAP_KEY_EQUAL_IS_SLOW 0
#define MAP_KEY_HASH(k)       (k)
#define MAP_MEMOIZE           0
#define MAP_LG_SLOT_CNT       FD_SBPF_SYSCALLS_LG_SLOT_CNT
#include "../../util/tmpl/fd_map.c"

#define FD_SBPF_SYSCALLS_FOOTPRINT (sizeof(fd_sbpf_syscalls_t) * (1UL<<FD_SBPF_SYSCALLS_LG_SLOT_CNT))
#define FD_SBPF_SYSCALLS_ALIGN     alignof(fd_sbpf_syscalls_t)

/* fd_sbpf_elf_info_t contains basic information extracted from an ELF
   binary. Indicates how much scratch memory and buffer size is required
   to fully load the program. */

struct fd_sbpf_elf_info {
  ulong bin_sz;   /* size of ELF binary */

  uint  text_off; /* File offset of .text section (overlaps rodata segment) */
  uint  text_cnt; /* Instruction count */
  ulong text_sz;  /* size of text segment. Guaranteed to be <= bin_sz. */

  /* Known section indices
     In [-1,USHORT_MAX) where -1 means "not found" */
  int shndx_text;
  int shndx_symtab;
  int shndx_strtab;
  int shndx_dyn;
  int shndx_dynstr;
  int shndx_dynsymtab; /* Section header index of the dynamic symbol table */

  /* Known program header indices (like shndx_*) */
  int phndx_dyn;

  /* Dynamic relocation table entries */
  uint dt_rel_off; /* File offset of dynamic relocation table */
  uint dt_rel_sz;  /* Number of dynamic relocation table entries */

  /* SBPF version, SIMD-0161 */
  ulong sbpf_version;
};
typedef struct fd_sbpf_elf_info fd_sbpf_elf_info_t;

/* fd_sbpf_program_t describes a loaded program in memory.

   [rodata,rodata+bin_sz) is an externally allocated buffer holding
   the read-only segment to be loaded into the VM.  WARNING: The rodata
   area required doing load (bin_sz) is larger than the area mapped into
   the VM (rodata_sz).

   [text,text+8*text_cnt) is a sub-region of the read-only segment
   containing executable code.

   We need to maintain a separate value tracking the entrypoint calldest
   because we lay out our calldests in a set instead of a map (like
   Agave does), which is more performant but comes with a few footguns.
   Since we only store the target PC and not a keypair of <hash, target
   PC>, we need to make sure we unregister the correct target PC from
   the map. For all other cases besides the b"entrypoint" string, we can
   simply check for membership within the calldests set because the
   32-bit murmur3 hash function is bijective, implying key collision iff
   value collision. However, the b"entrypoint" string is a special case
   because the key is the hardcoded hash of the b"entrypoint" string,
   but the value can correspond to any target PC. This means that
   someone could register several different target PCs with the same
   entrypoint PC, and we cannot figure out which target PC we must
   unregister. Additionally, we would not be able to check for
   collisions for multiple registered b"entrypoint" strings with
   different target PCs.

   Once entry_pc is set, any future calls to set the entry_pc within the
   loader will error out with FD_SBPF_ELF_ERR_SYMBOL_HASH_COLLISION. */

struct __attribute__((aligned(32UL))) fd_sbpf_program {
  fd_sbpf_elf_info_t info;

  /* rodata segment to be mapped into VM memory */
  void * rodata;     /* rodata segment data */
  ulong  rodata_sz;  /* size of read-only data */

  /* text section within rodata segment */
  ulong * text;
  ulong   entry_pc;  /* entrypoint PC (at text[ entry_pc ]). ULONG_MAX if not set. */

  /* Bit vector of valid call destinations (bit count is text_cnt). */
  void * calldests_shmem;
  /* Local join to bit vector of valid call destinations (target PCs) */
  fd_sbpf_calldests_t * calldests;
};
typedef struct fd_sbpf_program fd_sbpf_program_t;

struct fd_sbpf_loader_config {
  union {
   int elf_deploy_checks;
   int reject_broken_elfs;
  };
  uint sbpf_min_version;
  uint sbpf_max_version;
};
typedef struct fd_sbpf_loader_config fd_sbpf_loader_config_t;

/* Prototypes *********************************************************/

FD_PROTOTYPES_BEGIN

/* fd_sbpf_elf_peek partially parses the given ELF file in memory region
   [bin,bin+bin_sz)  Populates `info`.  Returns `info` on success.  On
   failure, returns NULL.

   elf_deploy_checks: The Agave ELF loader introduced additional checks
   that would fail on (certain) existing mainnet programs. Since it is
   impossible to retroactively enforce these checks on already deployed programs,
   a guard flag is used to enable these checks only when deploying programs.

   sbpf_min_version, sbpf_max_version: determine the min, max SBPF version
   allowed, version is retrieved from the ELF header. See SIMD-0161. */

int
fd_sbpf_elf_peek( fd_sbpf_elf_info_t *            info,
                  void const *                    bin,
                  ulong                           bin_sz,
                  fd_sbpf_loader_config_t const * config );

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
   against and must be valid for the lifetime of the program object. It
   should also meet the alignment requirements of the program object.
   */

fd_sbpf_program_t *
fd_sbpf_program_new( void *                     prog_mem,
                     fd_sbpf_elf_info_t const * elf_info,
                     void *                     rodata );

/* fd_sbpf_program_load loads an eBPF program for execution.

   prog is a program object allocated with fd_sbpf_program_new and must
   match the footprint requirements of this ELF file.

   Initializes and populates the program struct with information about
   the program and prepares the read-only segment provided in
   fd_sbpf_program_new. This includes performing relocations in the
   ELF file and zeroing gaps between rodata sections.

   Memory region [bin,bin+bin_sz) contains the ELF file to be loaded.

   syscalls should be a pointer to a map of registered syscalls and
   will be checked against when registering calldests for potential
   symbol collisions.

   On success, returns 0.
   On error, returns FD_SBPF_ERR_*.

   ### Compliance

   As of writing, this loader is conformant with Solana SBPF v0.12.2,
   SBPF versions V0, V1, and V2.
   */

int
fd_sbpf_program_load( fd_sbpf_program_t *             prog,
                      void const *                    bin,
                      ulong                           bin_sz,
                      fd_sbpf_syscalls_t *            syscalls,
                      fd_sbpf_loader_config_t const * config );

/* fd_sbpf_program_delete destroys the program object and unformats the
   memory regions holding it. */

void *
fd_sbpf_program_delete( fd_sbpf_program_t * program );

/* SBPF versions and features. This should stay in sync with the macro
   definitions in fd_vm_private.h until they are removed (once Agave
   cleans up the jump table).
   https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/program.rs#L28 */

#define FD_VM_SBPF_DYNAMIC_STACK_FRAMES_ALIGN (64U)

/* SIMD-0166 */
static inline int fd_sbpf_dynamic_stack_frames_enabled       ( ulong sbpf_version ) { return sbpf_version>=FD_SBPF_V1; }

/* SIMD-0173 */
static inline int fd_sbpf_callx_uses_src_reg_enabled         ( ulong sbpf_version ) { return sbpf_version>=FD_SBPF_V2; }
static inline int fd_sbpf_enable_lddw_enabled                ( ulong sbpf_version ) { return sbpf_version<FD_SBPF_V2; }
static inline int fd_sbpf_enable_le_enabled                  ( ulong sbpf_version ) { return sbpf_version<FD_SBPF_V2; }
static inline int fd_sbpf_move_memory_ix_classes_enabled     ( ulong sbpf_version ) { return sbpf_version>=FD_SBPF_V2; }

/* SIMD-0174 */
static inline int fd_sbpf_enable_neg_enabled                 ( ulong sbpf_version ) { return sbpf_version<FD_SBPF_V2; }
static inline int fd_sbpf_swap_sub_reg_imm_operands_enabled  ( ulong sbpf_version ) { return sbpf_version>=FD_SBPF_V2; }
static inline int fd_sbpf_explicit_sign_ext_enabled          ( ulong sbpf_version ) { return sbpf_version>=FD_SBPF_V2; }
static inline int fd_sbpf_enable_pqr_enabled                 ( ulong sbpf_version ) { return sbpf_version>=FD_SBPF_V2; }

/* SIMD-0178 */
static inline int fd_sbpf_static_syscalls_enabled            ( ulong sbpf_version ) { return sbpf_version>=FD_SBPF_V3; }
static inline int fd_sbpf_enable_elf_vaddr_enabled           ( ulong sbpf_version ) { return sbpf_version!=FD_SBPF_V0; }
static inline int fd_sbpf_reject_rodata_stack_overlap_enabled( ulong sbpf_version ) { return sbpf_version!=FD_SBPF_V0; }

/* SIMD-0189 */
static inline int fd_sbpf_enable_stricter_elf_headers_enabled( ulong sbpf_version ) { return sbpf_version>=FD_SBPF_V3; }
static inline int fd_sbpf_enable_lower_bytecode_vaddr_enabled( ulong sbpf_version ) { return sbpf_version>=FD_SBPF_V3; }

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_sbpf_fd_sbpf_loader_h */
