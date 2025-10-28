#include "fd_sbpf_loader.h"
#include "fd_sbpf_instr.h"
#include "fd_sbpf_opcodes.h"
#include "../../util/fd_util.h"
#include "../../util/bits/fd_sat.h"
#include "../murmur3/fd_murmur3.h"

#include <assert.h>
#include <stdio.h>

/* ELF loader, part 1 **************************************************

   Start with a static piece of scratch memory and do basic validation
   of the file content.  Walk the section table once and remember
   sections of interest.

   ### Terminology

   This source follows common ELF naming practices.

     section:  a named data region present in the ELF file
     segment:  a contiguous memory region containing sections
               (not necessarily contiguous in the ELF file)

     physical address (paddr): Byte offset into ELF file (uchar * bin)
     virtual  address (vaddr): VM memory address */

/* Provide convenient access to file header and ELF content */

__extension__ union fd_sbpf_elf {
  fd_elf64_ehdr ehdr;
  uchar         bin[0];
};
typedef union fd_sbpf_elf fd_sbpf_elf_t;

/* FD_SBPF_MM_{...}_ADDR are hardcoded virtual addresses of segments
   in the sBPF virtual machine.

   FIXME: These should be defined elsewhere */

#define FD_SBPF_MM_BYTECODE_ADDR (0x0UL)         /* bytecode */
#define FD_SBPF_MM_RODATA_ADDR   (0x100000000UL) /* readonly program data */
#define FD_SBPF_MM_PROGRAM_ADDR  (0x100000000UL) /* readonly program data */
#define FD_SBPF_MM_STACK_ADDR    (0x200000000UL) /* stack */
#define FD_SBPF_MM_HEAP_ADDR     (0x300000000UL) /* heap */
#define FD_SBPF_MM_REGION_SZ     (0x100000000UL) /* max region size */

#define FD_SBPF_PF_X  (1U) /* executable */
#define FD_SBPF_PF_W  (2U) /* writable */
#define FD_SBPF_PF_R  (4U) /* readable */
#define FD_SBPF_PF_RW (FD_SBPF_PF_R|FD_SBPF_PF_W)

#define EXPECTED_PHDR_CNT (4U)

struct fd_sbpf_range {
  ulong lo;
  ulong hi;
};
typedef struct fd_sbpf_range fd_sbpf_range_t;

/* fd_sbpf_range_contains returns 1 if x is in the range
   [range.lo, range.hi) and 0 otherwise. */
static inline int
fd_sbpf_range_contains( fd_sbpf_range_t const * range, ulong x ) {
  return !!(( range->lo<=x ) & ( x<range->hi ));
}

/* Mimics Elf64Shdr::file_range(). Returns a pointer to range (Some) if
   the section header type is not SHT_NOBITS, and sets range.{lo, hi} to
   the section header offset and offset + size, respectively. Returns
   NULL (None) otherwise, and sets both range.{lo, hi} to 0 (the default
   values for a Rust Range type).

   https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L87-L93 */

static fd_sbpf_range_t *
fd_shdr_get_file_range( fd_elf64_shdr const * shdr,
                        fd_sbpf_range_t *     range ) {
  if( shdr->sh_type==FD_ELF_SHT_NOBITS ) {
    *range = (fd_sbpf_range_t) { .lo = 0UL, .hi = 0UL };
    return NULL;
  } else {
    *range = (fd_sbpf_range_t) { .lo = shdr->sh_offset, .hi = fd_ulong_sat_add( shdr->sh_offset, shdr->sh_size ) };
    return range;
  }
}

/* Converts an ElfParserError code to an ElfError code.
   https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L112-L132 */
static int
fd_sbpf_elf_parser_err_to_elf_err( int err ) {
  switch( err ) {
    case FD_SBPF_ELF_SUCCESS:
      return err;
    case FD_SBPF_ELF_PARSER_ERR_OUT_OF_BOUNDS:
      return FD_SBPF_ELF_ERR_VALUE_OUT_OF_BOUNDS;
    case FD_SBPF_ELF_PARSER_ERR_INVALID_PROGRAM_HEADER:
      return FD_SBPF_ELF_ERR_INVALID_PROGRAM_HEADER;
    default:
      return FD_SBPF_ELF_ERR_FAILED_TO_PARSE;
  }
}

/* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L11-L13 */
#define FD_SBPF_SECTION_NAME_SZ_MAX (16UL)
#define FD_SBPF_SYMBOL_NAME_SZ_MAX  (64UL)

/* ELF loader, part 2 **************************************************

   Prepare a copy of a subrange of the ELF content: The rodata segment.
   Mangle the copy by applying dynamic relocations.  Then, zero out
   parts of the segment that are not interesting to the loader.

   ### Terminology

   Shorthands for relocation handling:

     S: Symbol value (typically an ELF physical address)
     A: Implicit addend, i.e. the original value of the field that the
        relocation handler is about to write to
     V: Virtual address, i.e. the target value that the relocation
        handler is about to write into where the implicit addend was
        previously stored */

ulong
fd_sbpf_program_align( void ) {
  return alignof( fd_sbpf_program_t );
}

ulong
fd_sbpf_program_footprint( fd_sbpf_elf_info_t const * info ) {
  FD_COMPILER_UNPREDICTABLE( info ); /* Make this appear as FD_FN_PURE (e.g. footprint might depened on info contents in future) */
  if( FD_UNLIKELY( fd_sbpf_enable_stricter_elf_headers_enabled( info->sbpf_version ) ) ) {
    /* SBPF v3+ no longer neeeds calldests bitmap */
    return FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_INIT,
      alignof(fd_sbpf_program_t), sizeof(fd_sbpf_program_t) ),
      alignof(fd_sbpf_program_t) );
  }
  return FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_INIT,
    alignof(fd_sbpf_program_t), sizeof(fd_sbpf_program_t) ),
    fd_sbpf_calldests_align(), fd_sbpf_calldests_footprint( info->text_cnt ) ),  /* calldests bitmap */
    alignof(fd_sbpf_program_t) );
}

fd_sbpf_program_t *
fd_sbpf_program_new( void *                     prog_mem,
                     fd_sbpf_elf_info_t const * elf_info,
                     void *                     rodata ) {

  if( FD_UNLIKELY( !prog_mem ) ) {
    FD_LOG_WARNING(( "NULL prog_mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !elf_info ) ) {
    FD_LOG_WARNING(( "NULL elf_info" ));
    return NULL;
  }

  if( FD_UNLIKELY( ((elf_info->bin_sz)>0U) & (!rodata)) ) {
    FD_LOG_WARNING(( "NULL rodata" ));
    return NULL;
  }

  /* https://github.com/solana-labs/rbpf/blob/v0.8.0/src/elf_parser/mod.rs#L99 */
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong) rodata, FD_SBPF_PROG_RODATA_ALIGN ) ) ){
    FD_LOG_WARNING(( "rodata is not 8-byte aligned" ));
    return NULL;
  }

  /* Initialize program struct */

  FD_SCRATCH_ALLOC_INIT( laddr, prog_mem );
  fd_sbpf_program_t * prog = FD_SCRATCH_ALLOC_APPEND( laddr, alignof(fd_sbpf_program_t), sizeof(fd_sbpf_program_t) );

  /* Note that entry_pc and rodata_sz get set during the loading phase. */
  *prog = (fd_sbpf_program_t) {
    .info      = *elf_info,
    .rodata    = rodata,
    .rodata_sz = 0UL,
    .text      = (ulong *)((ulong)rodata + elf_info->text_off), /* FIXME: WHAT IF MISALIGNED */
    .entry_pc  = ULONG_MAX,
  };

  /* If the text section is empty, then we do not need a calldests map. */
  ulong pc_max = elf_info->text_cnt;
  if( FD_UNLIKELY( fd_sbpf_enable_stricter_elf_headers_enabled( elf_info->sbpf_version ) || pc_max==0UL ) ) {
    /* No calldests map in SBPF v3+ or if text_cnt is 0. */
    prog->calldests_shmem = NULL;
    prog->calldests       = NULL;
  } else {
    /* Initialize calldests map. */
    prog->calldests_shmem = fd_sbpf_calldests_new(
          FD_SCRATCH_ALLOC_APPEND( laddr, fd_sbpf_calldests_align(),
                                          fd_sbpf_calldests_footprint( pc_max ) ),
          pc_max );
    prog->calldests = fd_sbpf_calldests_join( prog->calldests_shmem );
  }

  return prog;
}

void *
fd_sbpf_program_delete( fd_sbpf_program_t * mem ) {

  if( FD_LIKELY( mem->calldests ) ) {
    fd_sbpf_calldests_delete( fd_sbpf_calldests_leave( mem->calldests ) );
  }
  fd_memset( mem, 0, sizeof(fd_sbpf_program_t) );

  return (void *)mem;
}

/* fd_sbpf_loader_t contains various temporary state during loading. */

struct fd_sbpf_loader {
  /* External objects */
  ulong *              calldests; /* owned by program. NULL if text_cnt = 0 or SBPF v3+ */
  fd_sbpf_syscalls_t * syscalls;  /* owned by caller */
};
typedef struct fd_sbpf_loader fd_sbpf_loader_t;

/* fd_sbpf_slice_cstr_eq is a helper method for checking equality
   between a slice of memory to a null-terminated C-string.  Unlike
   strcmp, this function does not include the null-terminator in the
   comparison.  Returns 1 if the first slice_len bytes of the slice and
   cstr are equal, and 0 otherwise. */
static inline int
fd_sbpf_slice_cstr_eq( uchar const * slice,
                       ulong         slice_len,
                       char const *  cstr ) {
  return !!(slice_len==strlen( cstr ) && fd_memeq( slice, cstr, slice_len ));
}

/* fd_sbpf_slice_cstr_start_with is a helper method for checking that a
   null-terminated C-string is a prefix of a slice of memory.  Returns 1
   if the first strlen(cstr) bytes of cstr is a prefix of slice, and 0
   otherwise. */
static inline int
fd_sbpf_slice_cstr_start_with( uchar const * slice,
                               ulong         slice_len,
                               char const *  cstr ) {
  ulong cstr_len = strlen( cstr );
  return !!(slice_len>=cstr_len && fd_memeq( slice, cstr, cstr_len ));
}

/* fd_sbpf_lenient_get_string_in_section queries a single string from a
   section which is marked as SHT_STRTAB.  Returns an ElfParserError on
   failure, and leaves *out_slice and *out_slice_len in an undefined
   state.  On success, returns 0 and sets *out_slice to a pointer into
   elf_bytes corresponding to the beginning of the string within the
   section.  *out_slice_len is set to the length of the resulting slice.
   Note that *out_slice_len does not include the null-terminator of the
   resulting string.
   https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L467-L496 */
int
fd_sbpf_lenient_get_string_in_section( uchar const *         elf_bytes,
                                       ulong                 elf_bytes_len,
                                       fd_elf64_shdr const * section_header,
                                       uint                  offset_in_section,
                                       ulong                 maximum_length,
                                       uchar const **        out_slice,
                                       ulong *               out_slice_len ) {
  /* This could be checked only once outside the loop, but to keep the code the same...
     https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L474-L476 */
  if( FD_UNLIKELY( section_header->sh_type!=FD_ELF_SHT_STRTAB ) ) {
    return FD_SBPF_ELF_PARSER_ERR_INVALID_SECTION_HEADER;
  }

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L477-L482 */
  ulong offset_in_file;
  if( FD_UNLIKELY( __builtin_uaddl_overflow( section_header->sh_offset, offset_in_section, &offset_in_file ) ) ) {
    return FD_SBPF_ELF_PARSER_ERR_OUT_OF_BOUNDS;
  }

  ulong string_range_start = offset_in_file;
  ulong string_range_end   = fd_ulong_min( section_header->sh_offset+section_header->sh_size, offset_in_file+maximum_length );
  if( FD_UNLIKELY( string_range_end>elf_bytes_len ) ) {
    return FD_SBPF_ELF_PARSER_ERR_OUT_OF_BOUNDS;
  }
  /* In rust vec.get([n..n]) returns [], so this is accepted.
     vec.get([n..m]) with m<n returns None, so it throws ElfParserError::OutOfBounds. */
  if( FD_UNLIKELY( string_range_end<string_range_start ) ) {
    return FD_SBPF_ELF_PARSER_ERR_OUT_OF_BOUNDS;
  }

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L486-L495 */
  uchar * null_terminator_ptr = memchr( (uchar const *)elf_bytes+string_range_start, 0, string_range_end-string_range_start );
  if( FD_UNLIKELY( null_terminator_ptr==NULL ) ) {
    return FD_SBPF_ELF_PARSER_ERR_STRING_TOO_LONG;
  }

  *out_slice     = elf_bytes+string_range_start;
  *out_slice_len = (ulong)(null_terminator_ptr-*out_slice);

  return FD_SBPF_ELF_SUCCESS;
}

/* Registers a target PC into the calldests function registry. Returns
   0 on success, inserts the target PC into the calldests, and sets
   *opt_out_pc_hash to murmur3_32(target_pc) (if opt_out_pc_hash is
   non-NULL). Returns FD_SBPF_ELF_ERR_SYMBOL_HASH_COLLISION on failure
   if the target PC is already in the syscalls registry and leaves
   out_pc_hash in an undefined state.

   An important note is that Agave's implementation uses a map to store
   key-value pairs of (murmur3_32(target_pc), target_pc) within the
   calldests. We optimize this by using a set containing
   target_pc (this is our calldests map), and then deriving
   the target PC on the fly given murmur3_32(target_pc) (provided as
   imm) in the VM by computing the inverse hash (since murmur3_32 is
   bijective for uints).

   Another important note is that if a key-value pair already exists in
   Agave's calldests map, they will only throw a symbol hash collision
   error if the target PC is different from the one already registered.
   We can omit this check because of the hash function's bijective
   property, since the key-value pairs are deterministically derived
   from one another.

   TODO: this function will have to be adapted to hash the target PC
   depending on the SBPF version (>= V3). That has not been implemented
   yet.

   https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/program.rs#L142-L178 */
static int
fd_sbpf_register_function_hashed_legacy( fd_sbpf_loader_t *  loader,
                                         fd_sbpf_program_t * prog,
                                         uchar const *       name,
                                         ulong               name_len,
                                         ulong               target_pc,
                                         uint *              opt_out_pc_hash ) {
  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/program.rs#L156-L160 */
  uint pc_hash;
  uchar is_entrypoint = fd_sbpf_slice_cstr_eq( name, name_len, "entrypoint" ) ||
                        target_pc==FD_SBPF_ENTRYPOINT_PC;
  if( FD_UNLIKELY( is_entrypoint ) ) {
    if( FD_UNLIKELY( prog->entry_pc!=ULONG_MAX && prog->entry_pc!=target_pc  ) ) {
      /* We already registered the entrypoint to a different target PC,
         so we cannot register it again. */
      return FD_SBPF_ELF_ERR_SYMBOL_HASH_COLLISION;
    }
    prog->entry_pc = target_pc;

    /* Optimization for this constant value */
    pc_hash = FD_SBPF_ENTRYPOINT_HASH;
  } else {
    pc_hash = fd_pchash( (uint)target_pc );
  }

  /* loader.get_function_registry() is their equivalent of our syscalls
     registry. Fail if the target PC is present there.

     https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/program.rs#L161-L163 */
  if( FD_UNLIKELY( fd_sbpf_syscalls_query( loader->syscalls, pc_hash, NULL ) ) ) {
    return FD_SBPF_ELF_ERR_SYMBOL_HASH_COLLISION;
  }

  /* Insert the target PC into the calldests set if it's not the
     entrypoint. Due to the nature of our calldests, we also want to
     make sure that target_pc <= text_cnt, otherwise the insertion is
     UB. It's fine to skip inserting these entries because the calldests
     are write-only in the SBPF loader and only queried from the VM. */
  if( FD_LIKELY( !is_entrypoint &&
                  loader->calldests &&
                  fd_sbpf_calldests_valid_idx( loader->calldests, target_pc ) ) ) {
    fd_sbpf_calldests_insert( loader->calldests, target_pc );
  }

  if( opt_out_pc_hash ) *opt_out_pc_hash = pc_hash;
  return FD_SBPF_ELF_SUCCESS;
}

/* ELF Dynamic Relocations *********************************************

   ### Summary

   The sBPF ELF loader provides a limited dynamic relocation mechanism
   to fix up Clang-generated shared objects for execution in an sBPF VM.

   The relocation types themselves violate the eBPF and ELF specs in
   various ways.  In short, the relocation table (via DT_REL) is used to
   shift program code from zero-based addressing to the MM_PROGRAM
   segment in the VM memory map (at 0x1_0000_0000).

   As part of the Solana VM protocol it abides by strict determinism
   requirements.  This sadly means that we will have to replicate all
   edge cases and bugs in the Solana Labs ELF loader.

   Three relocation types are currently supported:
     - R_BPF_64_64: Sets an absolute address of a symbol as the
       64-bit immediate field of an lddw instruction
     - R_BPF_64_RELATIVE: Adds MM_PROGRAM_START (0x1_0000_0000) to ...
       a) ... the 64-bit imm field of an lddw instruction (if in text)
       b) ... a 64-bit integer (if not in text section)
     - R_BPF_64_32: Sets the 32-bit immediate field of a call
       instruction to ...
       a) the ID of a local function (Murmur3 hash of function PC address)
       b) the ID of a syscall

   Obviously invalid relocations (e.g. out-of-bounds of ELF file or
   unsupported reloc type) raise an error.
   Relocations that would corrupt ELF data structures are silently
   ignored (using the fd_sbpf_reloc_mask mechanism).

   ### History

   The use of relocations is technically redundant, as the Solana VM
   memory map has been hardcoded in program runtime v1 (so far the only
   runtime).  However, virtually all deployed programs as of April 2023
   are position-independent shared objects and make heavy use of such
   relocations.

   Relocations in the Solana VM have a complicated history.  Over the
   course of years, multiple protocol bugs have been added and fixed.
   The ELF loader needs to handle all these edge cases to avoid breaking
   "userspace".  I.e. any deployed programs which might be immutable
   must continue to function.

   While this complex logic will probably stick around for the next few
   years, the Solana protocol is getting increasingly restrictive for
   newly deployed ELFs.  Another proposed change is upgrading to
   position-dependent binaries without any dynamic relocations. */

/* R_BPF_64_64 relocates an absolute address into the extended imm field
   of an lddw-form instruction.  (Two instruction slots, low 32 bits in
   first immediate field, high 32 bits in second immediate field)

    Bits  0..32    32..64   64..96   96..128
         [ ... ] [ IMM_LO ] [ ... ] [ IMM_HI ]

    Returns 0 on success and writes the imm offset to the rodata.
    Returns the error code on failure.

    https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1069-L1141 */

static int
fd_sbpf_r_bpf_64_64( fd_sbpf_elf_t const *      elf,
                     ulong                      elf_sz,
                     uchar                    * rodata,
                     fd_sbpf_elf_info_t const * info,
                     fd_elf64_rel       const * dt_rel,
                     ulong                      r_offset ) {

  fd_elf64_shdr const * shdrs = (fd_elf64_shdr const *)( elf->bin + elf->ehdr.e_shoff );

  /* Note that the sbpf_version variable is ALWAYS V0 (see Agave's code
     to understand why).
     https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1070-L1080 */
  ulong imm_offset = fd_ulong_sat_add( r_offset, 4UL /* BYTE_OFFSET_IMMEDIATE */ );

  /* Bounds check.
     https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1084-L1086 */
  if( FD_UNLIKELY( fd_ulong_sat_add( imm_offset, 4UL /* BYTE_LENGTH_IMMEDIATE */ )>elf_sz ) ) {
    return FD_SBPF_ELF_ERR_VALUE_OUT_OF_BOUNDS;
  }

  /* Get the symbol entry from the dynamic symbol table.
     https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1089-L1092 */
  fd_elf64_sym const * symbol = NULL;
  {
    /* Ensure the dynamic symbol table exists. */
    if( FD_UNLIKELY( info->shndx_dynsymtab<0 ) ) {
      return FD_SBPF_ELF_ERR_UNKNOWN_SYMBOL;
    }

    /* Get the dynamic symbol table section header. The section header
       was already validated in fd_sbpf_lenient_elf_parse() so we can
       directly get the symbol table. */
    fd_elf64_shdr const * sh_dynsym    = &shdrs[ info->shndx_dynsymtab ];
    fd_elf64_sym const *  dynsym_table = (fd_elf64_sym const *)( elf->bin + sh_dynsym->sh_offset );
    ulong                 dynsym_cnt   = (ulong)(sh_dynsym->sh_size / sizeof(fd_elf64_sym));

    /* The symbol table index is stored in the lower 4 bytes of r_info.
       Check the bounds of the symbol table index. */
    ulong r_sym = FD_ELF64_R_SYM( dt_rel->r_info );
    if( FD_UNLIKELY( r_sym>=dynsym_cnt ) ) {
      return FD_SBPF_ELF_ERR_UNKNOWN_SYMBOL;
    }
    symbol = &dynsym_table[ r_sym ];
  }

  /* Use the relative address as an offset to derive the relocated
     address.
     https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1094-L1096 */
  uint  refd_addr = FD_LOAD( uint, &rodata[ imm_offset ] );
  ulong addr      = fd_ulong_sat_add( symbol->st_value, refd_addr );

  /* We need to normalize the address into the VM's memory space, which
     is rooted at 0x1_0000_0000 (the program ro-data region). If the
     linker hasn't normalized the addresses already, we treat addr as
     a relative offset into the program ro-data region. */
  if( addr<FD_SBPF_MM_PROGRAM_ADDR ) {
    addr = fd_ulong_sat_add( addr, FD_SBPF_MM_PROGRAM_ADDR );
  }

  /* Again, no need to check the sbpf_version because it's always V0.
     https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1106-L1140 */
  ulong imm_low_offset  = imm_offset;
  ulong imm_high_offset = fd_ulong_sat_add( imm_low_offset, 8UL /* INSN_SIZE */ );

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1116-L1122 */
  {
    /* Bounds check before writing to the rodata. */
    if( FD_UNLIKELY( fd_ulong_sat_add( imm_low_offset, 4UL /* BYTE_LENGTH_IMMEDIATE */ )>elf_sz ) ) {
      return FD_SBPF_ELF_ERR_VALUE_OUT_OF_BOUNDS;
    }

    /* Write back */
    FD_STORE( uint, rodata+imm_low_offset, (uint)addr );
  }

  /* Same as above, but for the imm high offset.
     https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1125-L1134 */
  {
    /* Bounds check before writing to the rodata. */
    if( FD_UNLIKELY( fd_ulong_sat_add( imm_high_offset, 4UL /* BYTE_LENGTH_IMMEDIATE */ )>elf_sz ) ) {
      return FD_SBPF_ELF_ERR_VALUE_OUT_OF_BOUNDS;
    }

    /* Write back */
    FD_STORE( uint, rodata+imm_high_offset, (uint)(addr>>32UL) );
  }

  /* ...rest of this function is a no-op because
     enable_symbol_and_section_labels is disabled in production. */

  return FD_SBPF_ELF_SUCCESS;
}

/* R_BPF_64_RELATIVE is almost entirely Solana specific. Returns 0 on
   success and an ElfError on failure.

   https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1142-L1247 */

static int
fd_sbpf_r_bpf_64_relative( fd_sbpf_elf_t const *      elf,
                           ulong                      elf_sz,
                           uchar                    * rodata,
                           fd_sbpf_elf_info_t const * info,
                           ulong                      r_offset ) {

  fd_elf64_shdr const * shdrs   = (fd_elf64_shdr const *)( elf->bin + elf->ehdr.e_shoff );
  fd_elf64_shdr const * sh_text = &shdrs[ info->shndx_text ];

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1147-L1148 */
  ulong imm_offset = fd_ulong_sat_add( r_offset, 4UL /* BYTE_OFFSET_IMMEDIATE */ );

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1150-L1246 */
  fd_sbpf_range_t text_section_range;
  if( fd_shdr_get_file_range( sh_text, &text_section_range ) &&
      fd_sbpf_range_contains( &text_section_range, r_offset ) ) {

    /* We are relocating a lddw (load double word) instruction which
       spans two instruction slots. The address top be relocated is
       split in two halves in the two imms of the instruction slots.

       https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1159-L1162 */
    ulong imm_low_offset  = imm_offset;
    ulong imm_high_offset = fd_ulong_sat_add( r_offset,
                                              4UL /* BYTE_OFFSET_IMMEDIATE */ + 8UL /* INSN_SIZE */ );

    /* Read the low side of the address. Perform a bounds check first.
       https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1164-L1171 */
    if( FD_UNLIKELY( fd_ulong_sat_add( imm_low_offset, 4UL /* BYTE_LENGTH_IMMEDIATE */ )>elf_sz ) ) {
      return FD_SBPF_ELF_ERR_VALUE_OUT_OF_BOUNDS;
    }
    uint va_low = FD_LOAD( uint, rodata+imm_low_offset );

    /* Read the high side of the address. Perform a bounds check first.
       https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1174-L1180 */
    if( FD_UNLIKELY( fd_ulong_sat_add( imm_high_offset, 4UL /* BYTE_LENGTH_IMMEDIATE */ )>elf_sz ) ) {
      return FD_SBPF_ELF_ERR_VALUE_OUT_OF_BOUNDS;
    }
    uint va_high = FD_LOAD( uint, rodata+imm_high_offset );

    /* Put the address back together.
       https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1182-L1187 */
    ulong refd_addr = ( (ulong)va_high<<32UL ) | va_low;
    if( FD_UNLIKELY( refd_addr==0UL ) ) {
      return FD_SBPF_ELF_ERR_INVALID_VIRTUAL_ADDRESS;
    }

    /* We need to normalize the address into the VM's memory space, which
       is rooted at 0x1_0000_0000 (the program ro-data region). If the
       linker hasn't normalized the addresses already, we treat addr as
       a relative offset into the program ro-data region.
       https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1189-L1193 */
    if( refd_addr<FD_SBPF_MM_PROGRAM_ADDR ) {
      refd_addr = fd_ulong_sat_add( refd_addr, FD_SBPF_MM_PROGRAM_ADDR );
    }

    /* Write back the low half. Perform a bounds check first.
       https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1195-L1202 */
    if( FD_UNLIKELY( fd_ulong_sat_add( imm_low_offset, 4UL /* BYTE_LENGTH_IMMEDIATE */ )>elf_sz ) ) {
      return FD_SBPF_ELF_ERR_VALUE_OUT_OF_BOUNDS;
    }
    FD_STORE( uint, rodata+imm_low_offset, (uint)refd_addr );

    /* Write back the high half. Perform a bounds check first.
       https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1205-L1214 */
    if( FD_UNLIKELY( fd_ulong_sat_add( imm_high_offset, 4UL /* BYTE_LENGTH_IMMEDIATE */ )>elf_sz ) ) {
      return FD_SBPF_ELF_ERR_VALUE_OUT_OF_BOUNDS;
    }
    FD_STORE( uint, rodata+imm_high_offset, (uint)(refd_addr>>32UL) );
  } else {
    /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1216-L1228 */
    ulong refd_addr = 0UL;

    /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1230-L1239 */
    if( FD_UNLIKELY( fd_ulong_sat_add( imm_offset, 4UL /* BYTE_LENGTH_IMMEDIATE */ )>elf_sz ) ) {
      return FD_SBPF_ELF_ERR_VALUE_OUT_OF_BOUNDS;
    }
    refd_addr = FD_LOAD( uint, rodata+imm_offset );
    refd_addr = fd_ulong_sat_add( refd_addr, FD_SBPF_MM_PROGRAM_ADDR );

    /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1242-L1245 */
    if( FD_UNLIKELY( fd_ulong_sat_add( r_offset, sizeof(ulong) )>elf_sz ) ) {
      return FD_SBPF_ELF_ERR_VALUE_OUT_OF_BOUNDS;
    }

    FD_STORE( ulong, rodata+r_offset, refd_addr );
  }

  return FD_SBPF_ELF_SUCCESS;
}

/* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1248-L1301 */
static int
fd_sbpf_r_bpf_64_32( fd_sbpf_loader_t *              loader,
                     fd_sbpf_program_t *             prog,
                     fd_sbpf_elf_t const *           elf,
                     ulong                           elf_sz,
                     uchar *                         rodata,
                     fd_sbpf_elf_info_t const *      info,
                     fd_elf64_rel const *            dt_rel,
                     ulong                           r_offset,
                     fd_sbpf_loader_config_t const * config ) {

  fd_elf64_shdr const * shdrs                  = (fd_elf64_shdr const *)( elf->bin + elf->ehdr.e_shoff );
  fd_elf64_shdr const * sh_text                = &shdrs[ info->shndx_text ];
  fd_elf64_shdr const * dyn_section_names_shdr = &shdrs[ info->shndx_dynstr ];

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1253-L1254 */
  ulong imm_offset = fd_ulong_sat_add( r_offset, 4UL /* BYTE_OFFSET_IMMEDIATE */ );

  /* Get the symbol entry from the dynamic symbol table.
     https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1256-L1259 */
  fd_elf64_sym const * symbol = NULL;

  /* Ensure the dynamic symbol table exists. */
  if( FD_UNLIKELY( info->shndx_dynsymtab<0 ) ) {
    return FD_SBPF_ELF_ERR_UNKNOWN_SYMBOL;
  }

  /* Get the dynamic symbol table section header. The section header
     was already validated in fd_sbpf_lenient_elf_parse() so we can
     directly get the symbol table. */
  fd_elf64_shdr const * sh_dynsym    = &shdrs[ info->shndx_dynsymtab ];
  fd_elf64_sym const *  dynsym_table = (fd_elf64_sym const *)( elf->bin + sh_dynsym->sh_offset );
  ulong                 dynsym_cnt   = (ulong)(sh_dynsym->sh_size / sizeof(fd_elf64_sym));

  /* The symbol table index is stored in the lower 4 bytes of r_info.
     Check the bounds of the symbol table index. */
  ulong r_sym = FD_ELF64_R_SYM( dt_rel->r_info );
  if( FD_UNLIKELY( r_sym>=dynsym_cnt ) ) {
    return FD_SBPF_ELF_ERR_UNKNOWN_SYMBOL;
  }
  symbol = &dynsym_table[ r_sym ];

  /* Verify symbol name.
     https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1261-L1263 */
  uchar const * name;
  ulong         name_len;
  if( FD_UNLIKELY( fd_sbpf_lenient_get_string_in_section( elf->bin, elf_sz, dyn_section_names_shdr, symbol->st_name, FD_SBPF_SYMBOL_NAME_SZ_MAX, &name, &name_len ) ) ) {
    return FD_SBPF_ELF_ERR_UNKNOWN_SYMBOL;
  }

  /* If the symbol is defined, this is a bpf-to-bpf call.
     https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1265-L1295 */
  uint key = 0U;
  int symbol_is_function = ( FD_ELF64_ST_TYPE( symbol->st_info )==FD_ELF_STT_FUNC );
  {
    if( symbol_is_function && symbol->st_value!=0UL ) {
      /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1267-L1269 */
      fd_sbpf_range_t text_section_range = (fd_sbpf_range_t) {
          .lo = sh_text->sh_addr,
          .hi = fd_ulong_sat_add( sh_text->sh_addr, sh_text->sh_size ) };
      if( FD_UNLIKELY( !fd_sbpf_range_contains( &text_section_range, symbol->st_value ) ) ) {
        return FD_SBPF_ELF_ERR_VALUE_OUT_OF_BOUNDS;
      }

      /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1270-L1279 */
      ulong target_pc = fd_ulong_sat_sub( symbol->st_value, sh_text->sh_addr ) / 8UL;
      int err = fd_sbpf_register_function_hashed_legacy( loader, prog, name, name_len, target_pc, &key );
      if( FD_UNLIKELY( err!=FD_SBPF_ELF_SUCCESS ) ) {
        return err;
      }
    } else {
      /* Else, it's a syscall. Ensure that the syscall can be resolved.
         https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1281-L1294 */
      key = fd_murmur3_32(name, name_len, 0UL );
      if( FD_UNLIKELY( config->reject_broken_elfs &&
                       fd_sbpf_syscalls_query( loader->syscalls, key, NULL )==NULL ) ) {
        return FD_SBPF_ELF_ERR_UNRESOLVED_SYMBOL;
      }
    }
  }

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1297-L1300 */
  if( FD_UNLIKELY( fd_ulong_sat_add( imm_offset, 4UL /* BYTE_LENGTH_IMMEDIATE */ )>elf_sz ) ) {
    return FD_SBPF_ELF_ERR_VALUE_OUT_OF_BOUNDS;
  }

  FD_STORE( uint, rodata+imm_offset, key );

  return FD_SBPF_ELF_SUCCESS;
}

static int
fd_sbpf_elf_peek_strict( fd_sbpf_elf_info_t * info,
                         void const *         bin,
                         ulong                bin_sz ) {

  /* Parse file header */

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L425
     https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L278
     (Agave does some extra checks on alignment, but they don't seem necessary) */
  if( FD_UNLIKELY( bin_sz<sizeof(fd_elf64_ehdr) ) ) {
    return FD_SBPF_ELF_PARSER_ERR_OUT_OF_BOUNDS;
  }

  fd_elf64_ehdr ehdr = FD_LOAD( fd_elf64_ehdr, bin );

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L430-L453 */
  ulong program_header_table_end = fd_ulong_sat_add( sizeof(fd_elf64_ehdr), fd_ulong_sat_mul( ehdr.e_phnum, sizeof(fd_elf64_phdr) ) );

  int parse_ehdr_err =
      ( fd_uint_load_4( ehdr.e_ident )    != FD_ELF_MAG_LE         )
    | ( ehdr.e_ident[ FD_ELF_EI_CLASS   ] != FD_ELF_CLASS_64       )
    | ( ehdr.e_ident[ FD_ELF_EI_DATA    ] != FD_ELF_DATA_LE        )
    | ( ehdr.e_ident[ FD_ELF_EI_VERSION ] != 1                     )
    | ( ehdr.e_ident[ FD_ELF_EI_OSABI   ] != FD_ELF_OSABI_NONE     )
    | ( fd_ulong_load_8( ehdr.e_ident+8 ) != 0UL                   )
    | ( ehdr.e_type                       != FD_ELF_ET_DYN         )
    | ( ehdr.e_machine                    != FD_ELF_EM_SBPF        )
    | ( ehdr.e_version                    != 1                     )
    // | ( ehdr.e_entry )
    | ( ehdr.e_phoff                      != sizeof(fd_elf64_ehdr) )
    // | ( ehdr.e_shoff )
    // | ( ehdr.e_flags )
    | ( ehdr.e_ehsize                     != sizeof(fd_elf64_ehdr) )
    | ( ehdr.e_phentsize                  != sizeof(fd_elf64_phdr) )
    | ( ehdr.e_phnum                      <  EXPECTED_PHDR_CNT     ) /* SIMD-0189 says < instead of != */
    | ( program_header_table_end          >= bin_sz                )
    | ( ehdr.e_shentsize                  != sizeof(fd_elf64_shdr) )
    // | ( ehdr.e_shnum )
    | ( ehdr.e_shstrndx                   >= ehdr.e_shnum          )
  ;
  if( FD_UNLIKELY( parse_ehdr_err ) ) {
    return FD_SBPF_ELF_PARSER_ERR_INVALID_FILE_HEADER;
  }

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L462 */
  if( FD_UNLIKELY( (program_header_table_end-sizeof(fd_elf64_ehdr))%sizeof(fd_elf64_phdr) ) ) {
    return FD_SBPF_ELF_PARSER_ERR_INVALID_SIZE;
  }
  if( FD_UNLIKELY( program_header_table_end>bin_sz ) ) {
    return FD_SBPF_ELF_PARSER_ERR_OUT_OF_BOUNDS;
  }
  /* This is always true ... */
  // if( FD_UNLIKELY( !fd_ulong_is_aligned( sizeof(fd_elf64_ehdr), 8UL ) ) ) {
  //   return FD_SBPF_ELF_PARSER_ERR_INVALID_ALIGNMENT;
  // }

  /* Parse program headers (expecting 4 segments) */

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L455-L487
     Note: Agave iterates with a zip, i.e. it cuts the loop to 4, even
           though the number of phdrs is allowed to be higher. */
  ulong expected_p_vaddr[ EXPECTED_PHDR_CNT ] = { FD_SBPF_MM_BYTECODE_ADDR, FD_SBPF_MM_RODATA_ADDR, FD_SBPF_MM_STACK_ADDR, FD_SBPF_MM_HEAP_ADDR };
  uint  expected_p_flags[ EXPECTED_PHDR_CNT ] = { FD_SBPF_PF_X,             FD_SBPF_PF_R,           FD_SBPF_PF_RW,         FD_SBPF_PF_RW        };
  fd_elf64_phdr     phdr[ EXPECTED_PHDR_CNT ];
  for( uint i=0; i<EXPECTED_PHDR_CNT; i++ ) {
    ulong phdr_off = sizeof(fd_elf64_ehdr) + i*sizeof(fd_elf64_phdr);
    phdr[ i ] = FD_LOAD( fd_elf64_phdr, bin+phdr_off );

    ulong p_filesz = ( expected_p_flags[ i ] & FD_SBPF_PF_W ) ? 0UL : phdr[ i ].p_memsz;
    int parse_phdr_err =
        ( phdr[ i ].p_type         != FD_ELF_PT_LOAD              )
      | ( phdr[ i ].p_flags        != expected_p_flags[ i ]       )
      | ( phdr[ i ].p_offset       <  program_header_table_end    )
      | ( phdr[ i ].p_offset       >= bin_sz                      )
      | ( phdr[ i ].p_offset % 8UL != 0UL                         )
      | ( phdr[ i ].p_vaddr        != expected_p_vaddr[ i ]       )
      | ( phdr[ i ].p_paddr        != expected_p_vaddr[ i ]       )
      | ( phdr[ i ].p_filesz       != p_filesz                    )
      | ( phdr[ i ].p_filesz       >  bin_sz - phdr[ i ].p_offset )
      | ( phdr[ i ].p_filesz % 8UL != 0UL                         )
      | ( phdr[ i ].p_memsz        >= FD_SBPF_MM_REGION_SZ        )
    ;
    if( FD_UNLIKELY( parse_phdr_err ) ) {
      return FD_SBPF_ELF_PARSER_ERR_INVALID_PROGRAM_HEADER;
    }
  }

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L489-L506 */
  ulong vm_range_start = phdr[ 0 ].p_vaddr;
  ulong vm_range_end = phdr[ 0 ].p_vaddr + phdr[ 0 ].p_memsz;
  ulong entry_chk = ehdr.e_entry + 7UL;
  int parse_e_entry_err =
     !( vm_range_start <= entry_chk && entry_chk < vm_range_end ) /* rust contains includes min, excludes max*/
    | ( ehdr.e_entry % 8UL != 0UL                               )
  ;
  if( FD_UNLIKELY( parse_e_entry_err ) ) {
    return FD_SBPF_ELF_PARSER_ERR_INVALID_FILE_HEADER;
  }

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L507-L515 */
  ulong entry_pc = ( ehdr.e_entry - phdr[ 0 ].p_vaddr ) / 8UL;
  ulong insn = fd_ulong_load_8( (uchar const *) bin + phdr[ 0 ].p_offset + entry_pc*8UL );
  /* Entrypoint must be a valid function start (ADD64_IMM with dst=r10)
     https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/ebpf.rs#L588 */
  if( FD_UNLIKELY( !fd_sbpf_is_function_start( fd_sbpf_instr( insn ) ) ) ) {
    return FD_SBPF_ELF_PARSER_ERR_INVALID_FILE_HEADER;
  }

  /* config.enable_symbol_and_section_labels is false in production,
     so there's nothing else to do.
     https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L519 */

  info->bin_sz   = bin_sz;
  info->text_off = (uint)phdr[ 0 ].p_offset;
  info->text_sz  = (uint)phdr[ 0 ].p_memsz;
  info->text_cnt = (uint)( phdr[ 0 ].p_memsz / 8UL );

  return FD_SBPF_ELF_SUCCESS;
}

static inline int
fd_sbpf_check_overlap( ulong a_start, ulong a_end, ulong b_start, ulong b_end ) {
  return !( ( a_end <= b_start || b_end <= a_start ) );
}

/* Mirrors Elf64::parse() in Agave. Returns an ElfParserError code on
   failure and 0 on success.
   https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L148 */
int
fd_sbpf_lenient_elf_parse( fd_sbpf_elf_info_t * info,
                           void const *         bin,
                           ulong                bin_sz ) {

  /* This documents the values that will be set in this function */
  info->bin_sz          = bin_sz;
  info->phndx_dyn       = -1;
  info->shndx_dyn       = -1;
  info->shndx_symtab    = -1;
  info->shndx_strtab    = -1;
  info->shndx_dynstr    = -1;
  info->shndx_dynsymtab = -1;

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L149 */
  if( FD_UNLIKELY( bin_sz<sizeof(fd_elf64_ehdr) ) ) {
    return FD_SBPF_ELF_PARSER_ERR_OUT_OF_BOUNDS;
  }

  fd_elf64_ehdr ehdr = FD_LOAD( fd_elf64_ehdr, bin );
  ulong ehdr_start = 0;
  ulong ehdr_end = sizeof(fd_elf64_ehdr);

  /* ELF header
     https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L151-L162 */
  int parse_ehdr_err =
      ( fd_uint_load_4( ehdr.e_ident )    != FD_ELF_MAG_LE         )
    | ( ehdr.e_ident[ FD_ELF_EI_CLASS   ] != FD_ELF_CLASS_64       )
    | ( ehdr.e_ident[ FD_ELF_EI_DATA    ] != FD_ELF_DATA_LE        )
    | ( ehdr.e_ident[ FD_ELF_EI_VERSION ] != 1                     )
    | ( ehdr.e_version                    != 1                     )
    | ( ehdr.e_ehsize                     != sizeof(fd_elf64_ehdr) )
    | ( ehdr.e_phentsize                  != sizeof(fd_elf64_phdr) )
    | ( ehdr.e_shentsize                  != sizeof(fd_elf64_shdr) )
    | ( ehdr.e_shstrndx                   >= ehdr.e_shnum          )
  ;
  if( FD_UNLIKELY( parse_ehdr_err ) ) {
    return FD_SBPF_ELF_PARSER_ERR_INVALID_FILE_HEADER;
  }

  /* Program headers
     https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L164-L165 */
  ulong phdr_start = ehdr.e_phoff;
  ulong phdr_end, phdr_sz;
  /* Elf64::parse_program_header_table() */
  {
    if( FD_UNLIKELY( __builtin_umull_overflow( ehdr.e_phnum, sizeof(fd_elf64_phdr), &phdr_sz ) ) ) {
      return FD_SBPF_ELF_PARSER_ERR_OUT_OF_BOUNDS;
    }

    if( FD_UNLIKELY( __builtin_uaddl_overflow( ehdr.e_phoff, phdr_sz, &phdr_end ) ) ) {
      /* ArithmeticOverflow -> ElfParserError::OutOfBounds
        https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L671-L675 */
      return FD_SBPF_ELF_PARSER_ERR_OUT_OF_BOUNDS;
    }

    /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L301 */
    if( FD_UNLIKELY( fd_sbpf_check_overlap( ehdr_start, ehdr_end, phdr_start, phdr_end ) ) ) {
      return FD_SBPF_ELF_PARSER_ERR_OVERLAP;
    }

    /* Ensure program header table range lies within the file, like
       slice_from_bytes. Unfortunately the checks have to be split up
       because Agave throws different error codes depending on which
       condition fails...
       https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L302-L303 */
    if( FD_UNLIKELY( phdr_sz%sizeof(fd_elf64_phdr)!=0UL ) ) {
      return FD_SBPF_ELF_PARSER_ERR_INVALID_SIZE;
    }

    if( FD_UNLIKELY( phdr_end>bin_sz ) ) {
      return FD_SBPF_ELF_PARSER_ERR_OUT_OF_BOUNDS;
    }

    if( FD_UNLIKELY( !fd_ulong_is_aligned( phdr_start, 8UL ) ) ) {
      return FD_SBPF_ELF_PARSER_ERR_INVALID_ALIGNMENT;
    }
  }

  /* Section headers
     https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L167-L172 */

  ulong shdr_start = ehdr.e_shoff;
  ulong shdr_end, shdr_sz;
  /* Elf64::parse_section_header_table() */
  {
    if( FD_UNLIKELY( __builtin_umull_overflow( ehdr.e_shnum, sizeof(fd_elf64_shdr), &shdr_sz ) ) ) {
      return FD_SBPF_ELF_PARSER_ERR_OUT_OF_BOUNDS;
    }

    /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L314-L317 */
    if( FD_UNLIKELY( __builtin_uaddl_overflow( ehdr.e_shoff, shdr_sz, &shdr_end ) ) ) {
      /* ArithmeticOverflow -> ElfParserError::OutOfBounds
        https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L671-L675 */
      return FD_SBPF_ELF_PARSER_ERR_OUT_OF_BOUNDS;
    }

    /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L318 */
    if( FD_UNLIKELY( fd_sbpf_check_overlap( ehdr_start, ehdr_end, shdr_start, shdr_end ) ) ) {
      return FD_SBPF_ELF_PARSER_ERR_OVERLAP;
    }

    /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L319 */
    if( FD_UNLIKELY( fd_sbpf_check_overlap( phdr_start, phdr_end, shdr_start, shdr_end ) ) ) {
      return FD_SBPF_ELF_PARSER_ERR_OVERLAP;
    }

    /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L321 */
    if( FD_UNLIKELY( (shdr_end-ehdr.e_shoff)%sizeof(fd_elf64_shdr) ) ) {
      return FD_SBPF_ELF_PARSER_ERR_INVALID_SIZE;
    }

    /* Ensure section header table range lies within the file, like slice_from_bytes */
    if( FD_UNLIKELY( shdr_end > bin_sz ) ) {
      return FD_SBPF_ELF_PARSER_ERR_OUT_OF_BOUNDS;
    }

    if( FD_UNLIKELY( !fd_ulong_is_aligned( ehdr.e_shoff, 8UL ) ) ) {
      return FD_SBPF_ELF_PARSER_ERR_INVALID_ALIGNMENT;
    }
  }

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L174-L177 */
  fd_elf64_shdr shdr = FD_LOAD( fd_elf64_shdr, bin + ehdr.e_shoff );
  if( FD_UNLIKELY( shdr.sh_type != FD_ELF_SHT_NULL ) ) {
    return FD_SBPF_ELF_PARSER_ERR_INVALID_SECTION_HEADER;
  }

  /* Parse each program header
     https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L179-L196 */
  ulong vaddr = 0UL;
  for( ulong i=0; i<ehdr.e_phnum; i++ ) {
    fd_elf64_phdr phdr = FD_LOAD( fd_elf64_phdr, bin + phdr_start + i*sizeof(fd_elf64_phdr) );
    if( FD_UNLIKELY( phdr.p_type != FD_ELF_PT_LOAD ) ) {
      /* Remember first PT_DYNAMIC program header for dynamic parsing */
      if( phdr.p_type==FD_ELF_PT_DYNAMIC && info->phndx_dyn == -1 ) {
        info->phndx_dyn = (int)i;
      }
      continue;
    }
    if( FD_UNLIKELY( phdr.p_vaddr<vaddr ) ) {
      return FD_SBPF_ELF_PARSER_ERR_INVALID_PROGRAM_HEADER;
    }
    ulong _offset_plus_size;
    if( FD_UNLIKELY( __builtin_uaddl_overflow( phdr.p_offset, phdr.p_filesz, &_offset_plus_size ) ) ) {
      return FD_SBPF_ELF_PARSER_ERR_OUT_OF_BOUNDS;
    }
    if( FD_UNLIKELY( phdr.p_offset + phdr.p_filesz > bin_sz ) ) {
      return FD_SBPF_ELF_PARSER_ERR_OUT_OF_BOUNDS;
    }
    vaddr = phdr.p_vaddr;
  }

  /* Parse each section header
     https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L198-L216 */
  ulong offset = 0UL;
  for( ulong i=0; i<ehdr.e_shnum; i++ ) {
    /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L200-L205 */
    fd_elf64_shdr shdr = FD_LOAD( fd_elf64_shdr, bin + shdr_start + i*sizeof(fd_elf64_shdr) );
    if( FD_UNLIKELY( shdr.sh_type==FD_ELF_SHT_NOBITS ) ) {
      continue;
    }

    /* Remember first SHT_DYNAMIC section header for dynamic parsing */
    if( shdr.sh_type==FD_ELF_SHT_DYNAMIC && info->shndx_dyn == -1 ) {
      info->shndx_dyn = (int)i;
    }

    ulong sh_start = shdr.sh_offset;
    ulong sh_end;
    if( FD_UNLIKELY( __builtin_uaddl_overflow( shdr.sh_offset, shdr.sh_size, &sh_end ) ) ) {
      return FD_SBPF_ELF_PARSER_ERR_OUT_OF_BOUNDS;
    }

    /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L206-L208 */
    if( FD_UNLIKELY( fd_sbpf_check_overlap( sh_start, sh_end, ehdr_start, ehdr_end ) ) ) {
      return FD_SBPF_ELF_PARSER_ERR_OVERLAP;
    }
    if( FD_UNLIKELY( fd_sbpf_check_overlap( sh_start, sh_end, phdr_start, phdr_end ) ) ) {
      return FD_SBPF_ELF_PARSER_ERR_OVERLAP;
    }
    if( FD_UNLIKELY( fd_sbpf_check_overlap( sh_start, sh_end, shdr_start, shdr_end ) ) ) {
      return FD_SBPF_ELF_PARSER_ERR_OVERLAP;
    }

    /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L209-L215 */
    if( FD_UNLIKELY( sh_start < offset ) ) {
      return FD_SBPF_ELF_PARSER_ERR_SECTION_NOT_IN_ORDER;
    }
    offset = sh_end;
    if( FD_UNLIKELY( sh_end > bin_sz ) ) {
      return FD_SBPF_ELF_PARSER_ERR_OUT_OF_BOUNDS;
    }
  }

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L218-L224
     section_header_table.get() returning ok is equivalent to ehdr.e_shstrndx < ehdr.e_shnum,
     and this is already checked above. So, nothing to do here. */

  /* Parse sections
     https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L240 */
  {
    /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L340-L342 */
    if( FD_UNLIKELY( ehdr.e_shstrndx == 0 ) ) {
      return FD_SBPF_ELF_PARSER_ERR_NO_SECTION_NAME_STRING_TABLE;
    }

    /* Use section name string table to identify well-known sections */
    ulong section_names_shdr_idx = ehdr.e_shstrndx;
    fd_elf64_shdr section_names_shdr = FD_LOAD( fd_elf64_shdr, bin + shdr_start + section_names_shdr_idx*sizeof(fd_elf64_shdr) );
    /* Agave repeats the following validation all the times, we can do it once here
       https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L474-L476 */
    if( FD_UNLIKELY( section_names_shdr.sh_type != FD_ELF_SHT_STRTAB ) ) {
      return FD_SBPF_ELF_PARSER_ERR_INVALID_SECTION_HEADER;
    }

    /* Iterate sections and record indices for .text, .symtab, .strtab, .dyn, .dynstr */
    for( ulong i=0; i<ehdr.e_shnum; i++ ) {
      /* Again... */
      fd_elf64_shdr shdr = FD_LOAD( fd_elf64_shdr, bin + shdr_start + i*sizeof(fd_elf64_shdr) );

      uchar const * name;
      ulong         name_len;
      int res = fd_sbpf_lenient_get_string_in_section( bin, bin_sz, &section_names_shdr, shdr.sh_name, FD_SBPF_SECTION_NAME_SZ_MAX, &name, &name_len );
      if( FD_UNLIKELY( res < 0 ) ) {
        return res;
      }

      /* Store the first section by name:
         https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L350-L355
         The rust code expands in:
            match section_name {
                b".symtab" => {
                    if self.symbol_section_header.is_some() {
                        return Err(ElfParserError::InvalidSectionHeader);
                    }
                    self.symbol_section_header = Some(section_header);
                }
                ...
                _ => {}
            }
         Note that the number of bytes compared should not include the
         null-terminator.
        */
      if( fd_sbpf_slice_cstr_eq( name, name_len, ".symtab" ) ) {
        if( FD_UNLIKELY( info->shndx_symtab != -1 ) ) {
          return FD_SBPF_ELF_PARSER_ERR_INVALID_SECTION_HEADER;
        }
        info->shndx_symtab = (int)i;
      } else if( fd_sbpf_slice_cstr_eq( name, name_len, ".strtab" ) ) {
        if( FD_UNLIKELY( info->shndx_strtab != -1 ) ) {
          return FD_SBPF_ELF_PARSER_ERR_INVALID_SECTION_HEADER;
        }
        info->shndx_strtab = (int)i;
      } else if( fd_sbpf_slice_cstr_eq( name, name_len, ".dynstr" ) ) {
        if( FD_UNLIKELY( info->shndx_dynstr != -1 ) ) {
          return FD_SBPF_ELF_PARSER_ERR_INVALID_SECTION_HEADER;
        }
        info->shndx_dynstr = (int)i;
      }
    }
  }

  /* Parse dynamic
     https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L241 */
  {
    /* Try PT_DYNAMIC first; if invalid or absent, fall back to SHT_DYNAMIC.
       Note that only the first PT_DYNAMIC and SHT_DYNAMIC are used because of Rust iter().find().
       Mirrors Rust logic:
         - Try PT_DYNAMIC: https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L364-L372
         - Fallback to SHT_DYNAMIC if PT missing/invalid: https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L374-L387
       If neither exists, return OK (static file). If SHT_DYNAMIC exists but is invalid, error. */

    ulong dynamic_table_start = ULONG_MAX;
    ulong dynamic_table_end = ULONG_MAX;

    /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L364-L372 */
    if( info->phndx_dyn >= 0 ) {
      fd_elf64_phdr dyn_ph = FD_LOAD( fd_elf64_phdr, bin + phdr_start + (ulong)info->phndx_dyn*sizeof(fd_elf64_phdr) );
      dynamic_table_start = dyn_ph.p_offset;
      dynamic_table_end = dyn_ph.p_offset + dyn_ph.p_filesz;

      /* slice_from_program_header also checks that the size of the
         slice is a multiple of the type size and that the alignment is
         correct. */
      if( FD_UNLIKELY( dynamic_table_end<dynamic_table_start ||
                       dynamic_table_end>bin_sz ||
                       dyn_ph.p_filesz%sizeof(fd_elf64_dyn)!=0UL ||
                       !fd_ulong_is_aligned( dynamic_table_start, 8UL ) ) ) {
        /* skip - try SHT_DYNAMIC instead */
        dynamic_table_start = ULONG_MAX;
        dynamic_table_end = ULONG_MAX;
      }
    }

    /* If PT_DYNAMIC did not validate, try SHT_DYNAMIC
       https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L376-L387 */
    if( dynamic_table_start==ULONG_MAX && info->shndx_dyn >= 0 ) {
      fd_elf64_shdr dyn_sh = FD_LOAD( fd_elf64_shdr, bin + shdr_start + (ulong)info->shndx_dyn*sizeof(fd_elf64_shdr) );
      dynamic_table_start = dyn_sh.sh_offset;
      if( FD_UNLIKELY( ( __builtin_uaddl_overflow( dyn_sh.sh_offset, dyn_sh.sh_size, &dynamic_table_end ) ) || /* checked_add */
                       ( dyn_sh.sh_size % sizeof(fd_elf64_dyn) != 0UL ) || /* slice_from_bytes InvalidSize */
                       ( dynamic_table_end > bin_sz )                   || /* slice_from_bytes OutOfBounds */
                       !fd_ulong_is_aligned( dynamic_table_start, 8UL )    /* slice_from_bytes InvalidAlignment */ ) ) {
        /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L382-L385 */
        return FD_SBPF_ELF_PARSER_ERR_INVALID_DYNAMIC_SECTION_TABLE;
      }
    }

    /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L393 */
    if( dynamic_table_start==ULONG_MAX ) {
      return FD_SBPF_ELF_SUCCESS;
    }

    /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L396-L407 */
    ulong dynamic_table[ FD_ELF_DT_NUM ] = { 0UL };
    ulong dyn_cnt = (dynamic_table_end - dynamic_table_start) / (ulong)sizeof(fd_elf64_dyn);
    for( ulong i = 0UL; i<dyn_cnt; i++ ) {
      fd_elf64_dyn dyn = FD_LOAD( fd_elf64_dyn, bin + dynamic_table_start + i*sizeof(fd_elf64_dyn) );

      if( FD_UNLIKELY( dyn.d_tag==FD_ELF_DT_NULL ) ) {
        break;
      }
      if( FD_UNLIKELY( dyn.d_tag>=FD_ELF_DT_NUM ) ) {
        continue;
      }

      dynamic_table[ dyn.d_tag ] = dyn.d_un.d_val;
    }

    /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L409 */
    do {
      ulong vaddr = dynamic_table[ FD_ELF_DT_REL ];
      if( FD_UNLIKELY( vaddr==0UL ) ) {
        break; /* from this do-while */
      }

      if ( FD_UNLIKELY( dynamic_table[ FD_ELF_DT_RELENT ] != sizeof(fd_elf64_rel) ) ) {
        return FD_SBPF_ELF_PARSER_ERR_INVALID_DYNAMIC_SECTION_TABLE;
      }

      ulong size = dynamic_table[ FD_ELF_DT_RELSZ ];
      if( FD_UNLIKELY( size==0UL ) ) {
        return FD_SBPF_ELF_PARSER_ERR_INVALID_DYNAMIC_SECTION_TABLE;
      }

      /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L430-L444 */
      ulong offset = ULONG_MAX;
      for( ulong i=0; i<ehdr.e_phnum; i++ ) {
        /* Again... */
        fd_elf64_phdr phdr = FD_LOAD( fd_elf64_phdr, bin + phdr_start + i*sizeof(fd_elf64_phdr) );
        if( FD_UNLIKELY( phdr.p_vaddr+phdr.p_memsz<phdr.p_vaddr ) ) {
          return FD_SBPF_ELF_PARSER_ERR_OUT_OF_BOUNDS;
        }
        if( phdr.p_vaddr<=vaddr && vaddr<phdr.p_vaddr+phdr.p_memsz ) {
          /* vaddr - phdr.p_vaddr is guaranteed to be non-negative */
          offset = vaddr-phdr.p_vaddr+phdr.p_offset;
          if( FD_UNLIKELY( offset<phdr.p_offset ) ) {
            return FD_SBPF_ELF_PARSER_ERR_OUT_OF_BOUNDS;
          }
          break;
        }
      }
      if( FD_UNLIKELY( offset==ULONG_MAX ) ) {
        for( ulong i=0; i<ehdr.e_shnum; i++ ) {
          /* Again... */
          fd_elf64_shdr shdr = FD_LOAD( fd_elf64_shdr, bin + shdr_start + i*sizeof(fd_elf64_shdr) );
          if( shdr.sh_addr == vaddr ) {
            offset = shdr.sh_offset;
            break;
          }
        }
      }
      if( FD_UNLIKELY( offset==ULONG_MAX ) ) {
        return FD_SBPF_ELF_PARSER_ERR_INVALID_DYNAMIC_SECTION_TABLE;
      }
      /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L446-L448 */
      ulong _offset_plus_size;
      if( FD_UNLIKELY( __builtin_uaddl_overflow( offset, size, &_offset_plus_size ) ) ) {
        return FD_SBPF_ELF_PARSER_ERR_OUT_OF_BOUNDS;
      }

      /* slice_from_bytes checks that size is a multiple of the type
         size and that the alignment of the bytes + offset is correct. */
      if( FD_UNLIKELY( ( size%sizeof(fd_elf64_rel)!=0UL ) ||
                       ( offset+size>bin_sz ) ||
                       ( !fd_ulong_is_aligned( offset, 8UL ) ) ) ) {
        return FD_SBPF_ELF_PARSER_ERR_INVALID_DYNAMIC_SECTION_TABLE;
      }

      /* Save the dynamic relocation table info */
      info->dt_rel_off = (uint)offset;
      info->dt_rel_sz  = (uint)size;
    } while( 0 ); /* so we can break out */

    /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L410 */
    do {
      /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L452-L455 */
      ulong vaddr = dynamic_table[ FD_ELF_DT_SYMTAB ];
      if( FD_UNLIKELY( vaddr==0UL ) ) {
        break; /* from this do-while */
      }

      fd_elf64_shdr shdr_sym = { 0 };
      for( ulong i=0; i<ehdr.e_shnum; i++ ) {
        /* Again... */
        shdr_sym = FD_LOAD( fd_elf64_shdr, bin + shdr_start + i*sizeof(fd_elf64_shdr) );
        if( shdr_sym.sh_addr == vaddr ) {
          info->shndx_dynsymtab = (int)i;
          break;
        }
      }

      /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L457-L461 */
      if( FD_UNLIKELY( info->shndx_dynsymtab==-1 ) ) {
        return FD_SBPF_ELF_PARSER_ERR_INVALID_DYNAMIC_SECTION_TABLE;
      }

      /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L463-L464 */
      {
        if( FD_UNLIKELY( shdr_sym.sh_type != FD_ELF_SHT_SYMTAB && shdr_sym.sh_type != FD_ELF_SHT_DYNSYM ) ) {
          return FD_SBPF_ELF_PARSER_ERR_INVALID_SECTION_HEADER;
        }
        ulong shdr_sym_start = shdr_sym.sh_offset;
        ulong shdr_sym_end;
        /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L574
           https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L671 */
        if( FD_UNLIKELY( __builtin_uaddl_overflow( shdr_sym.sh_offset, shdr_sym.sh_size, &shdr_sym_end ) ) ) {
          return FD_SBPF_ELF_PARSER_ERR_OUT_OF_BOUNDS;
        }
        /* slice_from_bytes InvalidSize */
        if( FD_UNLIKELY( shdr_sym.sh_size%sizeof(fd_elf64_sym) ) ) {
          return FD_SBPF_ELF_PARSER_ERR_INVALID_SIZE;
        }
        /* slice_from_bytes OutOfBounds */
        if( FD_UNLIKELY( shdr_sym_end>bin_sz ) ) {
          return FD_SBPF_ELF_PARSER_ERR_OUT_OF_BOUNDS;
        }
        /* slice_from_bytes InvalidAlignment */
        if( FD_UNLIKELY( !fd_ulong_is_aligned( shdr_sym_start, 8UL ) ) ) {
          return FD_SBPF_ELF_PARSER_ERR_INVALID_ALIGNMENT;
        }
      }
    } while( 0 ); /* so we can break out */
  }

  return FD_SBPF_ELF_SUCCESS;
}

/* Performs validation checks on the ELF. Returns an ElfError on failure
   and 0 on success.
   https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L719-L809 */
static int
fd_sbpf_lenient_elf_validate( fd_sbpf_elf_info_t * info,
                              void const *         bin,
                              ulong                bin_sz,
                              fd_elf64_shdr *      text_shdr ) {

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L721-L736 */
  fd_elf64_ehdr ehdr = FD_LOAD( fd_elf64_ehdr, bin );
  if( FD_UNLIKELY( ehdr.e_ident[ FD_ELF_EI_CLASS ] != FD_ELF_CLASS_64 ) ) {
    return FD_SBPF_ELF_ERR_WRONG_CLASS;
  }
  if( FD_UNLIKELY( ehdr.e_ident[ FD_ELF_EI_DATA  ] != FD_ELF_DATA_LE ) ) {
    return FD_SBPF_ELF_ERR_WRONG_ENDIANNESS;
  }
  if( FD_UNLIKELY( ehdr.e_ident[ FD_ELF_EI_OSABI ] != FD_ELF_OSABI_NONE ) ) {
    return FD_SBPF_ELF_ERR_WRONG_ABI;
  }
  if( FD_UNLIKELY( ehdr.e_machine != FD_ELF_EM_BPF && ehdr.e_machine != FD_ELF_EM_SBPF ) ) {
    return FD_SBPF_ELF_ERR_WRONG_MACHINE;
  }
  if( FD_UNLIKELY( ehdr.e_type != FD_ELF_ET_DYN ) ) {
    return FD_SBPF_ELF_ERR_WRONG_TYPE;
  }

  /* This code doesn't do anything:
     1. version is already checked at the very beginning of elf_peek
     2. the if condition is never true because sbpf_version is always v0
     https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L738-L763 */

  ulong shdr_start = ehdr.e_shoff;
  ulong section_names_shdr_idx = ehdr.e_shstrndx;
  fd_elf64_shdr section_names_shdr = FD_LOAD( fd_elf64_shdr, bin + shdr_start + section_names_shdr_idx*sizeof(fd_elf64_shdr) );

  /* We do a single iteration over the section header table, collect all info
     we need and return the errors later to match Agave. */

  int shndx_text    = -1;
  int writeable_err = 0;
  int oob_err       = 0;
  for( ulong i=0UL; i<ehdr.e_shnum; i++ ) {
    /* Again... */
    fd_elf64_shdr shdr = FD_LOAD( fd_elf64_shdr, bin + ehdr.e_shoff + i*sizeof(fd_elf64_shdr) );

    uchar const * name;
    ulong         name_len;
    int res = fd_sbpf_lenient_get_string_in_section( bin, bin_sz, &section_names_shdr, shdr.sh_name, FD_SBPF_SECTION_NAME_SZ_MAX, &name, &name_len );
    if( FD_UNLIKELY( res ) ) {
      /* this can never fail because it was checked above, but safer to keep it */
      return fd_sbpf_elf_parser_err_to_elf_err( res );
    }

    /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L765-L775 */
    if( FD_UNLIKELY( fd_sbpf_slice_cstr_eq( name, name_len, ".text" ) ) ) {
      if( FD_LIKELY( shndx_text==-1 ) ) {
        *text_shdr = shdr;  /* Store the text section header */
        shndx_text = (int)i;
      } else {
        return FD_SBPF_ELF_ERR_NOT_ONE_TEXT_SECTION;
      }
    }

    /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L780-L791 */
    if( FD_UNLIKELY( fd_sbpf_slice_cstr_start_with( name, name_len, ".bss" ) ||
                     ( ( ( shdr.sh_flags & (FD_ELF_SHF_ALLOC | FD_ELF_SHF_WRITE) ) == (FD_ELF_SHF_ALLOC | FD_ELF_SHF_WRITE) ) &&
                           fd_sbpf_slice_cstr_start_with( name, name_len, ".data" ) &&
                           !fd_sbpf_slice_cstr_start_with( name, name_len, ".data.rel" ) ) ) ) {
      /* to match Agave return error we can't fail here */
      writeable_err = 1;
    }

    /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L793-L802 */
    ulong shdr_end;
    if( FD_UNLIKELY( __builtin_uaddl_overflow( shdr.sh_offset, shdr.sh_size, &shdr_end ) ||
                     shdr_end>bin_sz ) ) {
      oob_err = 1;
    }
  }

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L776-L778 */
  if( FD_UNLIKELY( shndx_text==-1 ) ) {
    return FD_SBPF_ELF_ERR_NOT_ONE_TEXT_SECTION;
  }

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L786-L788 */
  if( FD_UNLIKELY( writeable_err ) ) {
    return FD_SBPF_ELF_ERR_WRITABLE_SECTION_NOT_SUPPORTED;
  }

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L798 */
  if( FD_UNLIKELY( oob_err ) ) {
    return FD_SBPF_ELF_ERR_VALUE_OUT_OF_BOUNDS;
  }

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L804-L806 */
  if( FD_UNLIKELY( !(
    text_shdr->sh_addr <= ehdr.e_entry && ehdr.e_entry < fd_ulong_sat_add( text_shdr->sh_addr, text_shdr->sh_size )
  ) ) ) {
    return FD_SBPF_ELF_ERR_ENTRYPOINT_OUT_OF_BOUNDS;
  }

  /* Get text section file ranges to calculate the size. */
  fd_sbpf_range_t text_section_range;
  fd_shdr_get_file_range( text_shdr, &text_section_range );

  info->text_off   = (uint)text_shdr->sh_addr;
  info->text_sz    = text_section_range.hi-text_section_range.lo;
  info->text_cnt   = (uint)( info->text_sz/8UL );
  info->shndx_text = shndx_text;

  return FD_SBPF_ELF_SUCCESS;
}

/* First part of Agave's load_with_lenient_parser(). We split up this
   function into two parts so we know how much memory we need to
   allocate for the loading step. Returns an ElfError on failure and 0
   on success.
   https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L593-L638 */
static int
fd_sbpf_elf_peek_lenient( fd_sbpf_elf_info_t *            info,
                          void const *                    bin,
                          ulong                           bin_sz,
                          fd_sbpf_loader_config_t const * config ) {

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L607 */
  int res = fd_sbpf_lenient_elf_parse( info, bin, bin_sz );
  if( FD_UNLIKELY( res<0 ) ) {
    return fd_sbpf_elf_parser_err_to_elf_err( res );
  }

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L617 */
  fd_elf64_shdr text_shdr = { 0 };
  res = fd_sbpf_lenient_elf_validate( info, bin, bin_sz, &text_shdr );
  if( FD_UNLIKELY( res<0 ) ) {
    return res;
  }

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L620-L638 */
  {
    ulong text_section_vaddr = fd_ulong_sat_add( text_shdr.sh_addr, FD_SBPF_MM_RODATA_ADDR );
    ulong vaddr_end          = text_section_vaddr;

    /* Validate bounds and text section addrs / offsets.
       https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L632-L638 */
    if( FD_UNLIKELY( ( config->reject_broken_elfs && text_shdr.sh_addr!=text_shdr.sh_offset ) ||
                       vaddr_end>FD_SBPF_MM_STACK_ADDR ) ) {
      return FD_SBPF_ELF_ERR_VALUE_OUT_OF_BOUNDS;
    }
  }

  /* Peek (vs load) stops here
     https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L638 */

  return FD_SBPF_ELF_SUCCESS;
}

static int
fd_sbpf_program_get_sbpf_version_or_err( void const *                    bin,
                                         ulong                           bin_sz,
                                         fd_sbpf_loader_config_t const * config ) {
  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L376-L381 */
  const ulong E_FLAGS_OFFSET = 48UL;

  if( FD_UNLIKELY( bin_sz<E_FLAGS_OFFSET+sizeof(uint) ) ) {
    return FD_SBPF_ELF_ERR_VALUE_OUT_OF_BOUNDS;
  }
  uint e_flags = FD_LOAD( uint, bin+E_FLAGS_OFFSET );

  uint sbpf_version = 0U;
  if( FD_UNLIKELY( config->sbpf_max_version==FD_SBPF_V0 ) ) {
    /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L384-L388 */
    sbpf_version = e_flags==E_FLAGS_SBPF_V2 ? FD_SBPF_RESERVED : FD_SBPF_V0;
  } else {
    /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L390-L396 */
    sbpf_version = e_flags < FD_SBPF_VERSION_COUNT ? e_flags : FD_SBPF_RESERVED;
  }

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L399-L401 */
  if( FD_UNLIKELY( !( config->sbpf_min_version <= sbpf_version && sbpf_version <= config->sbpf_max_version ) ) ) {
    return FD_SBPF_ELF_ERR_UNSUPPORTED_SBPF_VERSION;
  }

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L403-L407 */
  return (int)sbpf_version;
}

int
fd_sbpf_elf_peek( fd_sbpf_elf_info_t *            info,
                  void const *                    bin,
                  ulong                           bin_sz,
                  fd_sbpf_loader_config_t const * config ) {
  /* Extract sbpf_version (or error)
     https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L376-L401 */
  int maybe_sbpf_version = fd_sbpf_program_get_sbpf_version_or_err( bin, bin_sz, config );
  if( FD_UNLIKELY( maybe_sbpf_version<0 ) ) {
    return maybe_sbpf_version;
  }

  /* Initialize info struct */
  *info = (fd_sbpf_elf_info_t) {
    .bin_sz          = 0U,
    .text_off        = 0U,
    .text_cnt        = 0U,
    .text_sz         = 0UL,
    .shndx_text      = -1,
    .shndx_symtab    = -1,
    .shndx_strtab    = -1,
    .shndx_dyn       = -1,
    .shndx_dynstr    = -1,
    .shndx_dynsymtab = -1,
    .phndx_dyn       = -1,
    .dt_rel_off      = 0UL,
    .dt_rel_sz       = 0UL,
    .sbpf_version    = (uint)maybe_sbpf_version,
    /* !!! Keep this in sync with -Werror=missing-field-initializers */
  };

  /* Invoke strict vs lenient parser. The strict parser is used for
     SBPF version >= 3. The strict parser also returns an ElfParserError
     while the lenient parser returns an ElfError, so we have to map
     the strict parser's error code.
     https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L403-L407 */
  if( FD_UNLIKELY( fd_sbpf_enable_stricter_elf_headers_enabled( info->sbpf_version ) ) ) {
    return fd_sbpf_elf_parser_err_to_elf_err( fd_sbpf_elf_peek_strict( info, bin, bin_sz ) );
  }
  return fd_sbpf_elf_peek_lenient( info, bin, bin_sz, config );
}

/* Parses and concatenates the readonly data sections.  This function
   also computes and sets the rodata_sz field inside the SBPF program
   struct.  scratch is a pointer to a scratch area with size scratch_sz,
   used to allocate a temporary buffer for the parsed rodata sections
   before copying it back into the rodata (recommended size is bin_sz).
   Returns 0 on success and an ElfError error code on failure.  On
   success, the rodata and rodata_sz fields in the sbpf program struct
   are updated.
   https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L812-L987 */
static int
fd_sbpf_parse_ro_sections( fd_sbpf_program_t *             prog,
                           void const *                    bin,
                           ulong                           bin_sz,
                           fd_sbpf_loader_config_t const * config,
                           void *                          scratch,
                           ulong                           scratch_sz ) {

  fd_sbpf_elf_t const * elf                = (fd_sbpf_elf_t const *)bin;
  fd_elf64_shdr const * shdrs              = (fd_elf64_shdr const *)( elf->bin + elf->ehdr.e_shoff );
  fd_elf64_shdr const * section_names_shdr = &shdrs[ elf->ehdr.e_shstrndx ];
  uchar *               rodata             = prog->rodata;

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L818-L834 */
  ulong lowest_addr          = ULONG_MAX; /* Lowest section address */
  ulong highest_addr         = 0UL;       /* Highest section address */
  ulong ro_fill_length       = 0UL;       /* Aggregated section length, excluding gaps between sections */
  uchar invalid_offsets      = 0;         /* Whether the section has invalid offsets */

  /* Store the section header indices of ro slices to fill later. */
  ulong ro_slices_shidxs[ elf->ehdr.e_shnum ];
  ulong ro_slices_cnt = 0UL;

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L837-L909 */
  for( uint i=0U; i<elf->ehdr.e_shnum; i++ ) {
    fd_elf64_shdr const * section_header = &shdrs[ i ];

    /* Match the section name.
       https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L838-L845 */
    uchar const * name;
    ulong         name_len;
    if( FD_UNLIKELY( fd_sbpf_lenient_get_string_in_section( bin, bin_sz, section_names_shdr, section_header->sh_name, FD_SBPF_SECTION_NAME_SZ_MAX, &name, &name_len ) ) ) {
      continue;
    }

    if( FD_UNLIKELY( !fd_sbpf_slice_cstr_eq( name, name_len, ".text" ) &&
                     !fd_sbpf_slice_cstr_eq( name, name_len, ".rodata" ) &&
                     !fd_sbpf_slice_cstr_eq( name, name_len, ".data.rel.ro" ) &&
                     !fd_sbpf_slice_cstr_eq( name, name_len, ".eh_frame" ) ) ) {
      continue;
    }

    ulong section_addr = section_header->sh_addr;

    /* Handling for the section header offsets. If ELF vaddrs are
       enabled, the section header addresses are allowed to be > the
       section header offsets, as long as address - offset is constant
       across all sections. Otherwise, the section header addresses
       and offsets must match.
       https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L865-L884 */
    if( FD_LIKELY( !invalid_offsets ) ) {
      /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L866-L880 */
      if( FD_UNLIKELY( section_addr!=section_header->sh_offset ) ) {
        invalid_offsets = 1;
      }
    }

    /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L886-L897 */
    ulong vaddr_end = section_addr;
    if( section_addr<FD_SBPF_MM_RODATA_ADDR ) {
      vaddr_end = fd_ulong_sat_add( section_addr, FD_SBPF_MM_RODATA_ADDR );
    }

    if( FD_UNLIKELY( ( config->reject_broken_elfs && invalid_offsets ) ||
                       vaddr_end>FD_SBPF_MM_STACK_ADDR ) ) {
      return FD_SBPF_ELF_ERR_VALUE_OUT_OF_BOUNDS;
    }

    /* Append the ro slices vector and update the lowest / highest addr
       and ro_fill_length variables. Agave stores three fields in the
       ro slices array that can all be derived from the section header,
       so we just need to store the indices.

       The call to fd_shdr_get_file_range() is allowed to fail (Agave's
       unwrap_or_default() call returns a range of 0..0 in this case).
       https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L899-L908 */
    fd_sbpf_range_t section_header_range;
    fd_shdr_get_file_range( section_header, &section_header_range );
    if( FD_UNLIKELY( section_header_range.hi>bin_sz ) ) {
      return FD_SBPF_ELF_ERR_VALUE_OUT_OF_BOUNDS;
    }
    ulong section_data_len = section_header_range.hi-section_header_range.lo;

    lowest_addr    = fd_ulong_min( lowest_addr, section_addr );
    highest_addr   = fd_ulong_max( highest_addr, fd_ulong_sat_add( section_addr, section_data_len ) );
    ro_fill_length = fd_ulong_sat_add( ro_fill_length, section_data_len );
    ro_slices_shidxs[ ro_slices_cnt++ ] = i;
  }

  /* This checks that the ro sections are not overlapping. This check
     is incomplete, however, because it does not account for the
     existence of gaps between sections in calculations.
     https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L910-L913 */
  if( FD_UNLIKELY( config->reject_broken_elfs &&
                   fd_ulong_sat_add( lowest_addr, ro_fill_length )>highest_addr ) ) {
    return FD_SBPF_ELF_ERR_VALUE_OUT_OF_BOUNDS;
  }

  /* Note that optimize_rodata is always false.
     https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L923-L984 */
 {
    /* Readonly / non-readonly sections are mixed, so non-readonly
       sections must be zeroed and the readonly sections must be copied
       at their respective offsets.
       https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L950-L983 */
    lowest_addr = 0UL;

    /* Bounds check. */
    ulong buf_len = highest_addr;
    if( FD_UNLIKELY( buf_len>bin_sz ) ) {
      return FD_SBPF_ELF_ERR_VALUE_OUT_OF_BOUNDS;
    }

    /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L971-L976 */
    if( FD_UNLIKELY( buf_len>scratch_sz ) ) {
      FD_LOG_CRIT(( "scratch_sz is too small: %lu, required: %lu", scratch_sz, buf_len ));
    }
    uchar * ro_section = scratch;
    fd_memset( ro_section, 0, buf_len );

    for( ulong i=0UL; i<ro_slices_cnt; i++ ) {
      ulong sh_idx                       = ro_slices_shidxs[ i ];
      fd_elf64_shdr const * shdr         = &shdrs[ sh_idx ];
      ulong                 section_addr = shdr->sh_addr;

      /* This was checked above and should never fail. */
      fd_sbpf_range_t slice_range;
      fd_shdr_get_file_range( shdr, &slice_range );
      if( FD_UNLIKELY( slice_range.hi>bin_sz ) ) {
        return FD_SBPF_ELF_ERR_VALUE_OUT_OF_BOUNDS;
      }

      ulong buf_offset_start = fd_ulong_sat_sub( section_addr, lowest_addr );
      ulong slice_len        = slice_range.hi-slice_range.lo;
      if( FD_UNLIKELY( slice_len>buf_len ) ) {
        return FD_SBPF_ELF_ERR_VALUE_OUT_OF_BOUNDS;
      }

      fd_memcpy( ro_section+buf_offset_start, rodata+slice_range.lo, slice_len );
    }

    /* Copy the rodata section back in. */
    prog->rodata_sz = buf_len;
    fd_memcpy( rodata, ro_section, buf_len );
  }

  return FD_SBPF_ELF_SUCCESS;
}

/* Applies ELF relocations in-place. Returns 0 on success and an
   ElfError error code on failure.
   https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L990-L1331 */
static int
fd_sbpf_program_relocate( fd_sbpf_program_t *             prog,
                          void const *                    bin,
                          ulong                           bin_sz,
                          fd_sbpf_loader_config_t const * config,
                          fd_sbpf_loader_t *              loader ) {
  fd_sbpf_elf_info_t const * elf_info = &prog->info;
  fd_sbpf_elf_t const *      elf      = (fd_sbpf_elf_t const *)bin;
  uchar *                    rodata   = prog->rodata;
  fd_elf64_shdr const *      shdrs    = (fd_elf64_shdr const *)( elf->bin + elf->ehdr.e_shoff );
  fd_elf64_shdr const *      shtext   = &shdrs[ elf_info->shndx_text ];

  /* Copy rodata segment */
  fd_memcpy( rodata, elf->bin, elf_info->bin_sz );

  /* Fixup all program counter relative call instructions
     https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1005-L1041 */
  {
    /* Validate the bytes range of the text section.
       https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1006-L1008 */
    fd_sbpf_range_t text_section_range;
    fd_shdr_get_file_range( shtext, &text_section_range );

    ulong insn_cnt = (text_section_range.hi-text_section_range.lo)/8UL;
    if( FD_UNLIKELY( shtext->sh_size+shtext->sh_offset>bin_sz ) ) {
      return FD_SBPF_ELF_ERR_VALUE_OUT_OF_BOUNDS;
    }

    uchar * ptr = rodata + shtext->sh_offset;

    for( ulong i=0UL; i<insn_cnt; i++, ptr+=8UL ) {
      ulong insn = FD_LOAD( ulong, ptr );

      /* Check for call instruction.  If immediate is UINT_MAX, assume
         that compiler generated a relocation instead.
         https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1015 */
      ulong opc  = insn & 0xFF;
      int   imm  = (int)(insn >> 32UL);
      if( (opc!=FD_SBPF_OP_CALL_IMM) || (imm==-1) ) continue;

      /* Calculate and check the target PC
         https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1016-L1021 */
      long target_pc = fd_long_sat_add( fd_long_sat_add( (long)i, 1L ), imm);
      if( FD_UNLIKELY( target_pc<0L || target_pc>=(long)insn_cnt ) ) {
        return FD_SBPF_ELF_ERR_RELATIVE_JUMP_OUT_OF_BOUNDS;
      }

      /* Update the calldests
         https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1027-L1032 */
      uint pc_hash;
      int err = fd_sbpf_register_function_hashed_legacy( loader, prog, NULL, 0UL, (ulong)target_pc, &pc_hash );
      if( FD_UNLIKELY( err!=FD_SBPF_ELF_SUCCESS ) ) {
        return err;
      }

      /* Store PC hash in text section. Check for writes outside the
         text section.
         https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1034-L1038 */
      ulong offset = fd_ulong_sat_add( fd_ulong_sat_mul( i, 8UL ), 4UL ); // offset in text section
      if( FD_UNLIKELY( offset+4UL>shtext->sh_size ) ) {
        return FD_SBPF_ELF_ERR_VALUE_OUT_OF_BOUNDS;
      }

      FD_STORE( uint, ptr+4UL, pc_hash );
    }
  }

  /* Fixup all the relocations in the relocation section if exists. The
     dynamic relocations table was already parsed and validated in
     fd_sbpf_lenient_elf_parse().
     https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1046-L1304 */
  {
    fd_elf64_rel const *  dt_rels    = (fd_elf64_rel const *)( elf->bin + elf_info->dt_rel_off );
    uint                  dt_rel_cnt = elf_info->dt_rel_sz / sizeof(fd_elf64_rel);

    for( uint i=0U; i<dt_rel_cnt; i++ ) {
      fd_elf64_rel const * dt_rel   = &dt_rels[ i ];
      ulong                r_offset = dt_rel->r_offset;

      /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1068-L1303 */
      int err;
      switch( FD_ELF64_R_TYPE( dt_rel->r_info ) ) {
        case FD_ELF_R_BPF_64_64:
          err = fd_sbpf_r_bpf_64_64( elf, bin_sz, rodata, elf_info, dt_rel, r_offset );
          break;
        case FD_ELF_R_BPF_64_RELATIVE:
          err = fd_sbpf_r_bpf_64_relative(elf, bin_sz, rodata, elf_info, r_offset );
          break;
        case FD_ELF_R_BPF_64_32:
          err = fd_sbpf_r_bpf_64_32( loader, prog, elf, bin_sz, rodata, elf_info, dt_rel, r_offset, config );
          break;
        default:
          return FD_SBPF_ELF_ERR_UNKNOWN_RELOCATION;
      }

      if( FD_UNLIKELY( err!=FD_SBPF_ELF_SUCCESS ) ) {
        return err;
      }
    }
  }

  /* ...rest of this function is a no-op because
     enable_symbol_and_section_labels is disabled in production. */

  return FD_SBPF_ELF_SUCCESS;
}

/* Second part of load_with_lenient_parser().

   This function is responsible for "loading" an sBPF program. This
   means...
   1. Applies any relocations in-place to the rodata section.
   2. Registers the program entrypoint and other valid calldests.
   3. Parses and validates the rodata sections, zeroing out any gaps
      between sections.

   Returns 0 on success and an ElfError error code on failure.

   https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L640-L689
 */
static int
fd_sbpf_program_load_lenient( fd_sbpf_program_t *             prog,
                              void const *                    bin,
                              ulong                           bin_sz,
                              fd_sbpf_loader_t *              loader,
                              fd_sbpf_loader_config_t const * config,
                              void *                          scratch,
                              ulong                           scratch_sz ) {

  /* Load (vs peek) starts here
     https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L641 */

  fd_sbpf_elf_t const * elf      = (fd_sbpf_elf_t const *)bin;
  fd_sbpf_elf_info_t *  elf_info = &prog->info;
  fd_elf64_shdr const * shdrs    = (fd_elf64_shdr const *)( elf->bin + elf->ehdr.e_shoff );
  fd_elf64_shdr const * sh_text  = &shdrs[ elf_info->shndx_text ];

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L642-L647 */
  int err = fd_sbpf_program_relocate( prog, bin, bin_sz, config, loader );
  if( FD_UNLIKELY( err ) ) return err;

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L649-L653 */
  ulong offset = fd_ulong_sat_sub( elf->ehdr.e_entry, sh_text->sh_addr );
  if( FD_UNLIKELY( offset&0x7UL ) ) { /* offset % 8 != 0 */
    return FD_SBPF_ELF_ERR_INVALID_ENTRYPOINT;
  }

  /* Unregister the entrypoint from the calldests, and register the
     entry_pc. Our behavior slightly diverges from Agave's because we
     rely on an explicit entry_pc field within the elf_info struct
     to handle the b"entrypoint" symbol, and rely on PC hash inverses
     for any other CALL_IMM targets.

     Note that even though we won't use the calldests value for the
     entry pc, we still need to "register" it to check for any potential
     symbol collisions and report errors accordingly. We unregister it
     first by setting it to ULONG_MAX.

     TODO: Add special casing for static syscalls enabled. For now, it
     is not implemented.
     https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L654-L667 */
  prog->entry_pc = ULONG_MAX;
  ulong entry_pc = offset/8UL;
  err = fd_sbpf_register_function_hashed_legacy(
      loader,
      prog,
      (uchar const *)"entrypoint",
      strlen( "entrypoint" ),
      entry_pc,
      NULL );
  if( FD_UNLIKELY( err!=FD_SBPF_ELF_SUCCESS ) ) {
    return err;
  }

  /* Parse the ro sections.
     https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L669-L676 */
  err = fd_sbpf_parse_ro_sections( prog, bin, bin_sz, config, scratch, scratch_sz );
  if( FD_UNLIKELY( err!=FD_SBPF_ELF_SUCCESS ) ) {
    return err;
  }

  return FD_SBPF_ELF_SUCCESS;
}

int
fd_sbpf_program_load( fd_sbpf_program_t *             prog,
                      void const *                    bin,
                      ulong                           bin_sz,
                      fd_sbpf_syscalls_t *            syscalls,
                      fd_sbpf_loader_config_t const * config,
                      void *                          scratch,
                      ulong                           scratch_sz ) {
  fd_sbpf_loader_t loader = {
    .calldests = prog->calldests,
    .syscalls  = syscalls,
  };

  /* Invoke strict vs lenient loader
     Note: info.sbpf_version is already set by fd_sbpf_program_parse()
     https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L403-L409 */
  if( FD_UNLIKELY( fd_sbpf_enable_stricter_elf_headers_enabled( prog->info.sbpf_version ) ) ) {
    /* There is nothing else to do in the strict case except updating
       the prog->rodata_sz field from phdr[ 1 ].p_memsz, and setting
       the entry_pc. */
    fd_elf64_ehdr ehdr     = FD_LOAD( fd_elf64_ehdr, bin );
    fd_elf64_phdr phdr_0   = FD_LOAD( fd_elf64_phdr, bin+sizeof(fd_elf64_ehdr) );
    fd_elf64_phdr phdr_1   = FD_LOAD( fd_elf64_phdr, bin+sizeof(fd_elf64_ehdr)+sizeof(fd_elf64_phdr) );
    prog->rodata_sz        = phdr_1.p_memsz;
    prog->entry_pc         = ( ehdr.e_entry-phdr_0.p_vaddr )/8UL;
    return FD_SBPF_ELF_SUCCESS;
  }
  int res = fd_sbpf_program_load_lenient( prog, bin, bin_sz, &loader, config, scratch, scratch_sz );
  if( FD_UNLIKELY( res!=FD_SBPF_ELF_SUCCESS ) ) {
    return res;
  }

  return FD_SBPF_ELF_SUCCESS;
}

#undef ERR
#undef FAIL
#undef REQUIRE
