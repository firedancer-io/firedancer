#include "fd_sbpf_loader.h"
#include "fd_sbpf_opcodes.h"
#include "../../util/fd_util.h"
#include "../../util/bits/fd_sat.h"
#include "../murmur3/fd_murmur3.h"

#include <stdio.h>

#include "fd_sbpf_maps.c"

/* Error handling *****************************************************/

/* Thread local storage last error value */

static FD_TLS int ldr_errno     =  0;
static FD_TLS int ldr_err_srcln = -1;
#define FD_SBPF_ERRBUF_SZ (128UL)
static FD_TLS char fd_sbpf_errbuf[ FD_SBPF_ERRBUF_SZ ] = {0};

/* fd_sbpf_loader_seterr remembers the error ID and line number of the
   current file at which the last error occurred. */

int
fd_sbpf_loader_seterr( int err,
                       int srcln ) {
  ldr_errno     = err;
  ldr_err_srcln = srcln;
  return err;
}

/* Macros for returning an error from the current function while also
   remembering the error code. */

#define ERR( err ) return fd_sbpf_loader_seterr( (err), __LINE__ )
#define FAIL()  ERR( FD_SBPF_ERR_INVALID_ELF )
#define REQUIRE(x) if( FD_UNLIKELY( !(x) ) ) FAIL()

char const *
fd_sbpf_strerror( void ) {
  if( FD_UNLIKELY( ldr_errno==0 ) )
    strcpy( fd_sbpf_errbuf, "ok" );
  else
    snprintf( fd_sbpf_errbuf, FD_SBPF_ERRBUF_SZ,
              "code %d at %s(%d)", ldr_errno, __FILE__, ldr_err_srcln );
  return fd_sbpf_errbuf;
}

/* fd_sbpf_program ****************************************************/

FD_FN_CONST ulong
fd_sbpf_program_align( void ) {
  return alignof( fd_sbpf_program_info_t );
}

FD_FN_CONST ulong
fd_sbpf_program_footprint( void ) {
  return FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_INIT,
    alignof(fd_sbpf_program_info_t), sizeof(fd_sbpf_program_info_t) ),
    fd_sbpf_calldests_align(),       fd_sbpf_calldests_footprint()  ),
    alignof(fd_sbpf_program_info_t) );
}

fd_sbpf_program_t *
fd_sbpf_program_new( void * mem ) {

  if( FD_UNLIKELY( !mem ) ) return NULL;

  ulong laddr = (ulong)mem;
  laddr+=FD_LAYOUT_INIT;
  memset( (void *)laddr, 0, sizeof(fd_sbpf_program_info_t) );
  fd_sbpf_program_info_t * info = (fd_sbpf_program_info_t *)laddr;

  laddr=FD_LAYOUT_APPEND( laddr, alignof( fd_sbpf_program_info_t ),
                                 sizeof ( fd_sbpf_program_info_t ) );
  /* fd_sbpf_calldests_align() < alignof( fd_sbpf_program_info_t ) */
  info->calldests = fd_sbpf_calldests_new( (void *)laddr );

  return (fd_sbpf_program_t *)fd_type_pun( mem );
}


void *
fd_sbpf_program_delete( fd_sbpf_program_t * mem ) {
  ulong laddr = (ulong)fd_type_pun( mem );
  laddr+=FD_LAYOUT_INIT;
  memset( (void *)laddr, 0, sizeof(fd_sbpf_program_info_t) );

  laddr=FD_LAYOUT_APPEND( laddr, alignof( fd_sbpf_program_info_t ),
                                 sizeof ( fd_sbpf_program_info_t ) );
  /* fd_sbpf_calldests_align() < alignof( fd_sbpf_program_info_t ) */
  fd_sbpf_calldests_delete( (void *)laddr );

  return (void *)mem;
}

/* ELF loader **********************************************************

   ### Logic

   See the comments in fd_sbpf_prog_load below.

   ### Code Style

   This source follows common ELF naming practices.

     section:  a named data region present in the ELF file
     segment:  a contiguous memory region containing sections
               (not necessarily contiguous in the ELF file)

     physical address (paddr): Byte offset into ELF file (uchar * bin)
     virtual  address (vaddr): VM memory address

   In relocations:

     S: Symbol value (typically an ELF physical address)
     A: Implicit addend, i.e. the original value of the field that the
        relocation handler is about to write to
     V: Virtual address, i.e. the target value that the relocation
        handler is about to write into where the implicit addend was
        previously stored */

/* fd_sbpf_elf_t contains various temporary state during loading */

struct fd_sbpf_elf {
  /* External objects */
  fd_sbpf_calldests_t * calldests;  /* owned by program */
  fd_sbpf_syscalls_t  * syscalls;   /* owned by caller */

  /* File header */
  fd_elf64_ehdr ehdr;

  /* Segments */
  fd_elf64_phdr const * phdrs;
  ulong phndx_dyn;

  /* Section table */
  fd_elf64_shdr const * shdrs;
  /* Read-only section headers */
  fd_elf64_shdr const * shdr_text;
  fd_elf64_shdr const * shdr_rodata;
  fd_elf64_shdr const * shdr_data_rel_ro;
  fd_elf64_shdr const * shdr_eh_frame;
  /* Dynamic loading section headers */
  fd_elf64_shdr const * shdr_dyn;
  fd_elf64_shdr const * shdr_dynstr;
  /* FIXME replace shdr pointers with ushort indices */

  /* Dynamic table */
  fd_elf64_dyn const * dyn;
  ulong                dyn_cnt;

  /* Dynamic table entries */
  ulong dt_rel;
  ulong dt_relent;
  ulong dt_relsz;
  ulong dt_symtab;

  /* Dynamic symbol table */
  fd_elf64_sym const * dynsym;
  ulong                dynsym_cnt;
  char const *         dynstr;
  ulong                dynstr_sz;
};
typedef struct fd_sbpf_elf fd_sbpf_elf_t;

/* FD_SBPF_PHNDX_UNDEF: placeholder for undefined program header index */
#define FD_SBPF_PHNDX_UNDEF (ULONG_MAX)

/* FD_SBPF_MM_{...}_ADDR are hardcoded virtual addresses of segments
   in the sBPF virtual machine.

   FIXME: These should be defined elsewhere */

#define FD_SBPF_MM_PROGRAM_ADDR (0x100000000UL) /* readonly program data */
#define FD_SBPF_MM_STACK_ADDR   (0x200000000UL) /* stack (with gaps) */

/* FD_SBPF_SYM_NAME_SZ_MAX is the maximum length of a symbol name cstr
   including zero terminator. */

#define FD_SBPF_SYM_NAME_SZ_MAX (1024UL)

/* fd_sbpf_check_ehdr verifies the ELF file header. */

static int
fd_sbpf_check_ehdr( fd_elf64_ehdr const * ehdr,
                    ulong                 bin_sz ) {

  /* Validate ELF magic */
  REQUIRE( fd_uint_load_4( ehdr->e_ident )==0x464c457fU );

  /* Validate file type/target identification */
  REQUIRE( ehdr->e_ident[ FD_ELF_EI_CLASS      ]==FD_ELF_CLASS_64   );
  REQUIRE( ehdr->e_ident[ FD_ELF_EI_DATA       ]==FD_ELF_DATA_LE    );
  REQUIRE( ehdr->e_ident[ FD_ELF_EI_VERSION    ]==1                 );
  REQUIRE( ehdr->e_ident[ FD_ELF_EI_OSABI      ]==FD_ELF_OSABI_NONE );

  /* Validate ... */
  REQUIRE( ehdr->e_type     ==FD_ELF_ET_DYN         );
  REQUIRE( ehdr->e_machine  ==FD_ELF_EM_BPF         );
  REQUIRE( ehdr->e_ehsize   ==sizeof(fd_elf64_ehdr) );
  REQUIRE( ehdr->e_phentsize==sizeof(fd_elf64_phdr) );
  REQUIRE( ehdr->e_shentsize==sizeof(fd_elf64_shdr) );
  REQUIRE( ehdr->e_shstrndx < ehdr->e_shnum         );

  /* Bounds check program header table */

  ulong const phoff = ehdr->e_phoff;
  ulong const phnum = ehdr->e_phnum;
  REQUIRE( fd_ulong_is_aligned( phoff, 8UL ) );
  REQUIRE( phoff>=sizeof(fd_elf64_ehdr) ); /* overlaps file header */
  REQUIRE( phoff< bin_sz ); /* out of bounds */

  REQUIRE( phnum<=(ULONG_MAX/sizeof(fd_elf64_phdr)) ); /* overflow */
  ulong const phsz = phnum*sizeof(fd_elf64_phdr);

  ulong const phoff_end = phoff+phsz;
  REQUIRE( phoff_end>=phoff  ); /* overflow */
  REQUIRE( phoff_end<=bin_sz ); /* out of bounds */

  /* Bounds check section header table */

  ulong const shoff = ehdr->e_shoff;
  ulong const shnum = ehdr->e_shnum;
  REQUIRE( fd_ulong_is_aligned( shoff, 8UL ) );
  REQUIRE( shoff>=sizeof(fd_elf64_ehdr) ); /* overlaps file header */
  REQUIRE( shoff< bin_sz ); /* out of bounds */
  REQUIRE( shnum> 0UL    ); /* not enough sections */

  REQUIRE( shoff<=(ULONG_MAX/sizeof(fd_elf64_shdr)) ); /* overflow */
  ulong const shsz = shnum*sizeof(fd_elf64_shdr);

  ulong const shoff_end = shoff+shsz;
  REQUIRE( shoff_end>=shoff  ); /* overflow */
  REQUIRE( shoff_end<=bin_sz ); /* out of bounds */

  /* Overlap checks */

  REQUIRE( (phoff>shoff_end) | (shoff>phoff_end) ); /* overlap shdrs<>phdrs */

  return 0;
}

/* fd_sbpf_load_shdrs parses the program header table.

   Assumes that ...
   - table does not overlap with file header or section header table and
     is within bounds
   - offset of program header table is 8 byte aligned */

static int
fd_sbpf_load_phdrs( fd_sbpf_elf_t * prog,
                    uchar *         bin,
                    ulong           bin_sz ) {

  /* Fill in placeholders */
  prog->phndx_dyn  = FD_SBPF_PHNDX_UNDEF;

  ulong const pht_offset = prog->ehdr.e_phoff;
  ulong const pht_cnt    = prog->ehdr.e_phnum;

  /* Read program header table */

  fd_elf64_phdr * const phdr = (fd_elf64_phdr *)(bin+pht_offset);
  prog->phdrs = phdr;

  /* Virtual address of last seen program header */
  ulong p_load_vaddr = 0UL;

  for( ulong i=0; i<pht_cnt; i++ ) {
    switch( phdr[i].p_type ) {
    case FD_ELF_PT_DYNAMIC:
      /* Remember first PT_DYNAMIC segment */
      if( FD_LIKELY( prog->phndx_dyn==FD_SBPF_PHNDX_UNDEF ) )
        prog->phndx_dyn = i;
      break;
    case FD_ELF_PT_LOAD:
      /* LOAD segments must be ordered */
      REQUIRE( phdr[ i ].p_vaddr >= p_load_vaddr );
      p_load_vaddr = phdr[ i ].p_vaddr;
      /* Segment must be within bounds */
      REQUIRE( phdr[ i ].p_offset + phdr[ i ].p_filesz >= phdr[ i ].p_offset );
      REQUIRE( phdr[ i ].p_offset + phdr[ i ].p_filesz <= bin_sz             );
      /* No overlap checks */
      break;
    default:
      /* Ignore other segment types */
      break;
    }
  }

  return 0;
}

/* fd_sbpf_load_shdrs parses the section header table.

   Assumes that ...
   - table does not overlap with file header or program header table and
     is within bounds
   - offset of section header table is 8 byte aligned
   - section header table has at least one entry */

static int
fd_sbpf_load_shdrs( fd_sbpf_elf_t * prog,
                    uchar *         bin,
                    ulong           bin_sz ) {

  /* File Header */
  ulong const eh_offset = 0UL;
  ulong const eh_offend = sizeof(fd_elf64_ehdr);

  /* Section Header Table */
  ulong const sht_offset = prog->ehdr.e_shoff;
  ulong const sht_cnt    = prog->ehdr.e_shnum;
  ulong const sht_sz     = sht_cnt*sizeof(fd_elf64_shdr);
  ulong const sht_offend = sht_offset + sht_sz;

  fd_elf64_shdr * const shdr = (fd_elf64_shdr *)(bin+sht_offset);
  prog->shdrs = shdr;

  /* Program Header Table */
  ulong const pht_offset = prog->ehdr.e_phoff;
  ulong const pht_cnt    = prog->ehdr.e_phnum;
  ulong const pht_offend = pht_offset + (pht_cnt*sizeof(fd_elf64_phdr));

  /* Require SHT_NULL at index 0 */

  REQUIRE( shdr[ 0 ].sh_type==FD_ELF_SHT_NULL );

  /* Require SHT_STRTAB for section name table */

  REQUIRE( prog->ehdr.e_shstrndx < sht_cnt ); /* out of bounds */
  REQUIRE( shdr[ prog->ehdr.e_shstrndx ].sh_type==FD_ELF_SHT_STRTAB );

  ulong shstr_off = shdr[ prog->ehdr.e_shstrndx ].sh_offset;
  REQUIRE( shstr_off<bin_sz );

  /* Validate section header table.
     Check that all sections are in bounds, ordered, and don't overlap. */

  ulong min_sh_offset = 0UL;  /* lowest permitted section offset */

  for( ulong i=0UL; i<sht_cnt; i++ ) {
    uint  sh_type   = shdr[ i ].sh_type;
    uint  sh_name   = shdr[ i ].sh_name;
    ulong sh_offset = shdr[ i ].sh_offset;
    ulong sh_size   = shdr[ i ].sh_size;
    ulong sh_offend = sh_offset + sh_size;

    /* check that physical range has no overflow and is within bounds */
    REQUIRE( sh_offend >= sh_offset );
    REQUIRE( sh_offend <= bin_sz    );

    if( sh_type!=FD_ELF_SHT_NOBITS ) {
      /* Overlap checks */
      REQUIRE( (sh_offset>=eh_offend ) | (sh_offend<=eh_offset ) ); /* overlaps ELF file header */
      REQUIRE( (sh_offset>=pht_offend) | (sh_offend<=pht_offset) ); /* overlaps program header table */
      REQUIRE( (sh_offset>=sht_offend) | (sh_offend<=sht_offset) ); /* overlaps section header table */
      /* Ordering and overlap check */
      REQUIRE( sh_offset >= min_sh_offset );
      min_sh_offset = sh_offend;
    }

    if( sh_type==FD_ELF_SHT_DYNAMIC ) {
      /* Remember first SHT_DYNAMIC segment */
      if( FD_LIKELY( !prog->shdr_dyn ) )
        prog->shdr_dyn = &shdr[ i ];
    }

    ulong name_off = shstr_off + (ulong)sh_name;
    REQUIRE( name_off<=bin_sz ); /* out of bounds */
    /* TODO Is it okay to create a zero-sz string at EOF? */

    /* Create name cstr */

    char __attribute__((aligned(8UL))) name[ 17UL ]={0};
    fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( name ),
                                            (char const *)(bin+name_off), 16UL ) );

    /* Check name */
    /* TODO switch table for this? */
    /* TODO reject duplicate sections */

    /**/ if( 0==strcmp ( name, ".text"          ) ) {
      REQUIRE( !prog->shdr_text ); /* check for duplicate */
                                                    prog->shdr_text        = &shdr[ i ]; }
    else if( 0==strcmp ( name, ".rodata"        ) ) prog->shdr_rodata      = &shdr[ i ];
    else if( 0==strcmp ( name, ".data.rel.ro"   ) ) prog->shdr_data_rel_ro = &shdr[ i ];
    else if( 0==strcmp ( name, ".eh_frame"      ) ) prog->shdr_eh_frame    = &shdr[ i ];
    else if( 0==strcmp ( name, ".dynstr"        ) ) prog->shdr_dynstr      = &shdr[ i ];
    else if( 0==strncmp( name, ".bss",      4UL ) ) FAIL();
    else if( 0==strncmp( name, ".data.rel", 9UL ) ) {} /* ignore */
    else if( 0==strncmp( name, ".data",     5UL ) && (shdr[ i ].sh_flags & FD_ELF_SHF_WRITE) ) FAIL();
    else                                            {} /* ignore */
    /* else ignore */
  }

  /* FIXME SHT_NULL implies zero size in the Rust ELF loader, which seems to be permitted for .text */
  REQUIRE( (!!prog->shdr_text) && (prog->shdr_text->sh_type != FD_ELF_SHT_NULL) ); /* check for missing text section */
  REQUIRE( (prog->shdr_text->sh_addr <= prog->ehdr.e_entry) & /* check that entrypoint is in text VM range */
           (prog->ehdr.e_entry       <  fd_ulong_sat_add( prog->shdr_text->sh_addr, prog->shdr_text->sh_size ) ) );

  if( prog->shdr_dynstr ) {
    ulong sh_offset = prog->shdr_dynstr->sh_offset;
    ulong sh_size   = prog->shdr_dynstr->sh_size;
    REQUIRE( (sh_offset+sh_size>=sh_offset) & (sh_offset+sh_size<=bin_sz) );
    prog->dynstr = (char *)( bin+sh_offset );
    /* FIXME alignment check? */
    prog->dynstr_sz = sh_size;
  }

  return 0;
}

static int
fd_sbpf_find_dynamic( fd_sbpf_elf_t * prog,
                      uchar const *   bin,
                      ulong           bin_sz ) {

  /* Try first PT_DYNAMIC in program header table */

  if( prog->phndx_dyn!=FD_SBPF_PHNDX_UNDEF ) {
    ulong dyn_off = prog->phdrs[ prog->phndx_dyn ].p_offset;
    ulong dyn_sz  = prog->phdrs[ prog->phndx_dyn ].p_filesz;
    ulong dyn_end = dyn_off+dyn_sz;

    /* Fall through to SHT_DYNAMIC if invalid */

    if( FD_LIKELY(   ( dyn_end>=dyn_off )                /* overflow      */
                   & ( dyn_end<=bin_sz  )                /* out of bounds */
                   & fd_ulong_is_aligned( dyn_off, 8UL ) /* misaligned    */
                   & fd_ulong_is_aligned( dyn_sz,  8UL ) /* misaligned sz */ ) ) {

      prog->dyn     = (fd_elf64_dyn const *)(bin+dyn_off);
      prog->dyn_cnt = dyn_sz / sizeof(fd_elf64_dyn);
      return 0;
    }
  }

  /* Try first SHT_DYNAMIC in section header table */

  if( prog->shdr_dyn ) {
    ulong dyn_off = prog->shdr_dyn->sh_offset;
    ulong dyn_sz  = prog->shdr_dyn->sh_size;
    ulong dyn_end = dyn_off+dyn_sz;

    /* This time, don't tolerate errors */

    REQUIRE( ( dyn_end>=dyn_off )                /* overflow      */
           & ( dyn_end<=bin_sz  )                /* out of bounds */
           & fd_ulong_is_aligned( dyn_off, 8UL ) /* misaligned    */
           & fd_ulong_is_aligned( dyn_sz,  8UL ) /* misaligned sz */ );

    prog->dyn     = (fd_elf64_dyn const *)(bin+dyn_off);
    prog->dyn_cnt = dyn_sz / sizeof(fd_elf64_dyn);
    return 0;
  }

  /* Missing or invalid PT_DYNAMIC and missing SHT_DYNAMIC, skip. */
  return 0;
}

static int
fd_sbpf_load_dynamic( fd_sbpf_elf_t * prog,
                      uchar const *   bin,
                      ulong           bin_sz ) {

  /* Skip if no dynamic table was fonud */

  if( !prog->dyn_cnt ) return 0;

  /* Walk dynamic table */

  fd_elf64_dyn const * dyn     = prog->dyn;
  ulong const          dyn_cnt = prog->dyn_cnt;

  for( ulong i=0; i<dyn_cnt; i++ ) {
    if( FD_UNLIKELY( dyn[i].d_tag==FD_ELF_DT_NULL ) ) break;

    ulong d_val = dyn[i].d_un.d_val;
    switch( dyn[i].d_tag ) {
    case FD_ELF_DT_REL:    prog->dt_rel   =d_val; break;
    case FD_ELF_DT_RELENT: prog->dt_relent=d_val; break;
    case FD_ELF_DT_RELSZ:  prog->dt_relsz =d_val; break;
    case FD_ELF_DT_SYMTAB: prog->dt_symtab=d_val; break;
    }
  }

  /* Load dynamic symbol table */

  if( prog->dt_symtab ) {
    /* Search for dynamic symbol table
       FIXME unfortunate bounded O(n^2) -- could convert to binary search */

    /* FIXME this could be clobbered by relocations, causing strict
             aliasing violations */

    fd_elf64_shdr const * shdr_dynsym = NULL;

    for( ulong i=0; i<prog->ehdr.e_shnum; i++ ) {
      if( prog->shdrs[ i ].sh_addr == prog->dt_symtab ) {
        shdr_dynsym = &prog->shdrs[ i ];
        break;
      }
    }
    REQUIRE( shdr_dynsym );

    /* Check section type */

    uint sh_type = shdr_dynsym->sh_type;
    REQUIRE( (sh_type==FD_ELF_SHT_SYMTAB) | (sh_type==FD_ELF_SHT_DYNSYM) );

    /* Check if out of bounds or misaligned */

    ulong sh_offset = shdr_dynsym->sh_offset;
    ulong sh_size   = shdr_dynsym->sh_size;

    REQUIRE( ( sh_offset+sh_size>=sh_offset )
           & ( sh_offset+sh_size<=bin_sz    )
           & fd_ulong_is_aligned( sh_offset, alignof(fd_elf64_sym) ) );

    prog->dynsym = (fd_elf64_sym const *)( bin+sh_offset );
    prog->dynsym_cnt = sh_size/sizeof(fd_elf64_sym);
  }

  return 0;
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
   position-dependent binaries without any dynamic relocations.

   ### Memory Management

   The solana-labs/rbpf v0.3.0 loader makes no restrictions on
   relocation targets.  It even permits and applies relocations that
   would corrupt ELF data structures (sections, relocs, etc).  No such
   corruption is actually taking place in this other loader because it
   creates a "shadow" copy of the ELF binary being loaded.  Any would-be
   corruption is not visible to the loader as it is walking the reloc
   table.

   This code operates only on a single copy and thus needs to ensure
   that maliciously crafted ELFs do not cause corruption or aliasing
   violations (U.B.).

   Thus, relocations are only applied when their side effects are
   visible in VM memory.  Specifically, this includes all of the program
   content mapped at MM_PROGRAM_START:  .text, .rodata, .eh_frame, and
   .data.rel.ro.  Relocation writes outside of these sections are
   silently discarded.

   FIXME are there other sections for which writes are supported? */

/* fd_sbpf_reloc_mask returns a mask for relocation writes at given ELF
   file offset.  Each return value byte i in [0,8) is 0xFF is off+i is
   writable and 0x00 if it isn't.  Assumes that off+8 <= ULONG_MAX. */

static inline ulong
fd_sbpf_reloc_submask( fd_elf64_shdr const * shdr,
                       ulong                 off ) {

  ulong end    = off+8UL;
  ulong sh_off = shdr->sh_offset;
  ulong sh_end = shdr->sh_size + sh_off;

  /* 0 if relocation target is entirely out-of-bounds,
     ULONG_MAX otherwise */
  ulong oob_mask = (ulong)( (end<sh_off) | (off>sh_end) )-1UL;

  /* Mask off low and high out-of-bounds areas */
  ulong mask_lo = ULONG_MAX >> fd_ulong_if( off>=sh_off, 0UL, ((sh_off-off)<<3)&63 );
  ulong mask_hi = ULONG_MAX << fd_ulong_if( end<=sh_end, 0UL, ((end-sh_end)<<3)&63 );

  return oob_mask & mask_lo & mask_hi;
}

static ulong
fd_sbpf_reloc_mask( fd_sbpf_elf_t const * elf,
                    ulong                 off ) {
  /* The following four sections is the only content exported to the
     VM memory map.  Thus, discard relocations to all other parts of the
     ELF file.
     This assumes that these four sections do not overlap with any other
     data structures in this ELF. */
  return                          fd_sbpf_reloc_submask( elf->shdr_text,        off )
       | (elf->shdr_rodata      ? fd_sbpf_reloc_submask( elf->shdr_rodata,      off ) : 0UL)
       | (elf->shdr_eh_frame    ? fd_sbpf_reloc_submask( elf->shdr_eh_frame,    off ) : 0UL)
       | (elf->shdr_data_rel_ro ? fd_sbpf_reloc_submask( elf->shdr_data_rel_ro, off ) : 0UL);
}

/* R_BPF_64_64 relocates an absolute address into the extended imm field
   of an lddw-form instruction.  (Two instruction slots, low 32 bits in
   first immediate field, high 32 bits in second immediate field)

    Bits  0..32    32..64   64..96   96..128
         [ ... ] [ IMM_LO ] [ ... ] [ IMM_HI ] */

static int
fd_sbpf_r_bpf_64_64( fd_sbpf_elf_t *      elf,
                     uchar *              bin,
                     ulong                bin_sz,
                     fd_elf64_rel const * rel ) {

  uint  r_sym    = FD_ELF64_R_SYM( rel->r_info );
  ulong r_offset = rel->r_offset;
  REQUIRE( r_offset+16UL>r_offset );
  REQUIRE( r_offset+16UL<bin_sz   );

  /* Offsets of implicit addend (immediate fields) */
  ulong A_off_lo = r_offset+ 4UL;
  ulong A_off_hi = r_offset+12UL;

  /* Read implicit addend (imm field of first insn slot) */
  // SBF_V2: ulong A_off = is_text ? r_offset+4UL : r_offset;
  REQUIRE( A_off_lo+4UL<bin_sz );
  ulong A = *(uint *)( bin+A_off_lo );

  /* Lookup symbol */
  REQUIRE( r_sym < elf->dynsym_cnt );
  fd_elf64_sym const * sym = &elf->dynsym[ r_sym ];
  ulong S = sym->st_value;

  /* Relocate */
  if( S<FD_SBPF_MM_PROGRAM_ADDR ) S+=FD_SBPF_MM_PROGRAM_ADDR;
  ulong V = S+A;

  /* Write back */
  uint mask_lo = (uint)fd_sbpf_reloc_mask( elf, A_off_lo );
  uint mask_hi = (uint)fd_sbpf_reloc_mask( elf, A_off_hi );
  FD_STORE( uint, bin+A_off_lo, ( FD_LOAD( uint, bin+A_off_lo ) & ~mask_lo ) | ( (uint)(V      ) & mask_lo ) );
  FD_STORE( uint, bin+A_off_hi, ( FD_LOAD( uint, bin+A_off_hi ) & ~mask_hi ) | ( (uint)(V>>32UL) & mask_hi ) );

  return 0;
}

/* R_BPF_64_RELATIVE is almost entirely Solana specific. */

static int
fd_sbpf_r_bpf_64_relative( fd_sbpf_elf_t *      elf,
                           uchar *              bin,
                           ulong                bin_sz,
                           fd_elf64_rel const * rel ) {

  ulong r_offset = rel->r_offset;

  int is_text = ( ( !!elf->shdr_text                      ) &
                  ( r_offset >= elf->shdr_text->sh_offset ) &
                  ( r_offset <  elf->shdr_text->sh_offset +
                                elf->shdr_text->sh_size   ) );
  if( is_text ) {
    /* If reloc target is in .text, behave like R_BPF_64_64, except:
       - R_SYM(r_info) is ignored
       - If implicit addend looks like a physical address, make it
         a virtual address (by adding a constant offset)

       This relocation type seems to make little sense but is required
       for most programs. */

    REQUIRE( r_offset+16UL<=bin_sz );
    ulong imm_lo_off = r_offset+ 4UL;
    ulong imm_hi_off = r_offset+12UL;

    /* Read implicit addend */
    uint  va_lo = *(uint *)( bin + imm_lo_off );
    uint  va_hi = *(uint *)( bin + imm_hi_off );
    ulong va    = ( (ulong)va_hi<<32UL ) | va_lo;

    REQUIRE( va!=0UL );
    va = va<FD_SBPF_MM_PROGRAM_ADDR ? va+FD_SBPF_MM_PROGRAM_ADDR : va;

    /* Write back
       Skip bounds check as .text is guaranteed to be writable */
    *(uint *)( bin + imm_lo_off ) = (uint)( va       );
    *(uint *)( bin + imm_hi_off ) = (uint)( va>>32UL );
  } else {
    /* Outside .text do a 64-bit write */

    /* Bounds checks */
    REQUIRE( (r_offset+12UL>r_offset) & (r_offset+12UL<=bin_sz) );
    ulong mask = fd_sbpf_reloc_mask( elf, r_offset );
    if( FD_UNLIKELY( mask==0UL ) ) return 0;  /* skip */

    /* Read implicit addend
       FIXME: Special case for EF_SBF_V2 currently not handled here. */
    ulong va = *(uint *)( bin+r_offset+4UL );

    /* Relocate */
    va = fd_ulong_sat_add( va, FD_SBPF_MM_PROGRAM_ADDR );

    /* Write back */
    void * target = bin+r_offset;
    FD_STORE( ulong, target, ( FD_LOAD( ulong, target ) & ~mask ) | ( va & mask ) );
  }

  return 0;
}

static int
fd_sbpf_r_bpf_64_32( fd_sbpf_elf_t *      elf,
                     uchar *              bin,
                     ulong                bin_sz,
                     fd_elf64_rel const * rel ) {

  uint  r_sym    = FD_ELF64_R_SYM( rel->r_info );
  ulong r_offset = rel->r_offset;

  /* Lookup symbol */
  REQUIRE( r_sym < elf->dynsym_cnt );
  fd_elf64_sym const * sym = &elf->dynsym[ r_sym ];
  ulong S = sym->st_value;

  /* Lookup symbol name */
  REQUIRE( sym->st_name < elf->dynstr_sz );
  char const * name = elf->dynstr + sym->st_name;
  ulong max_len  = fd_ulong_min( elf->dynstr_sz - sym->st_name, FD_SBPF_SYM_NAME_SZ_MAX );
  ulong name_len = strnlen( name, max_len );
  REQUIRE( name_len<max_len );
  /* FIXME missing UTF-8 validation */

  /* Value to write into relocated field */
  uint V;

  int is_func_call = ( FD_ELF64_ST_TYPE( sym->st_info ) == FD_ELF_STT_FUNC )
                   & ( S!=0UL );
  if( is_func_call ) {
    /* Check whether function call is in
       virtual memory range of text section */
    REQUIRE( elf->shdr_text );
    ulong sh_addr = elf->shdr_text->sh_addr;
    ulong sh_size = elf->shdr_text->sh_size;
    REQUIRE( (S>=sh_addr) & (S<sh_addr+sh_size) );

    /* Register function call */
    ulong target_pc = (S-sh_addr) / 8UL;

    /* Check for collision with syscall ID */
    REQUIRE( !fd_sbpf_syscalls_query( elf->syscalls, (uint)target_pc, NULL ) );

    /* Register new entry */
    uint hash = fd_murmur3_32( &target_pc, 8UL, 0U );
    REQUIRE( fd_sbpf_calldests_upsert( elf->calldests, hash, target_pc ) );

    V = (uint)hash;
  } else {
    /* FIXME Should cache Murmur hashes.
             If max ELF size is 10MB, can fit about 640k relocs.
             Each reloc could point to a symbol with the same st_name,
             which results in 640MB hash input data without caching.  */
    uint hash = fd_murmur3_32( name, name_len, 0UL );
    /* Ensure that requested syscall ID exists */
    REQUIRE( fd_sbpf_syscalls_query( elf->syscalls, hash, NULL ) );

    V = hash;
  }

  /* Bounds checks */
  REQUIRE( (r_offset+8UL>r_offset) & (r_offset+8UL<=bin_sz) );
  ulong A_off = r_offset+4UL;
  uint  mask  = (uint)fd_sbpf_reloc_mask( elf, A_off );

  /* Apply relocation */
  void * target = bin+A_off;
  FD_STORE( uint, target, ( FD_LOAD( uint, target ) & ~mask ) | ( V & mask ) );

  return 0;
}

static int
fd_sbpf_apply_reloc( fd_sbpf_elf_t *      prog,
                     uchar *              bin,
                     ulong                bin_sz,
                     fd_elf64_rel const * rel ) {
  switch( FD_ELF64_R_TYPE( rel->r_info ) ) {
  case FD_ELF_R_BPF_64_64:
    return fd_sbpf_r_bpf_64_64      ( prog, bin, bin_sz, rel );
  case FD_ELF_R_BPF_64_RELATIVE:
    return fd_sbpf_r_bpf_64_relative( prog, bin, bin_sz, rel );
  case FD_ELF_R_BPF_64_32:
    return fd_sbpf_r_bpf_64_32      ( prog, bin, bin_sz, rel );
  default:
    ERR( FD_SBPF_ERR_INVALID_ELF );
  }
}

/* fd_sbpf_hash_calls converts local call instructions in the "LLVM
   form" (immediate is a program counter offset) to eBPF form (immediate
   is a hash of the target program counter).  Corresponds to
   fixup_relative calls in solana-labs/rbpf.

   Assumes that the text section range exists, is within bounds, and
   does not overlap with the ELF file header, program header table, or
   section header table. */

static int
fd_sbpf_hash_calls( fd_sbpf_elf_t * prog,
                    uchar *         bin ) {

  fd_elf64_shdr const * shtext    = prog->shdr_text;
  fd_sbpf_calldests_t * calldests = prog->calldests;

  uchar * ptr      = bin + shtext->sh_offset;
  ulong   insn_cnt = shtext->sh_type!=FD_ELF_SHT_NULL ? shtext->sh_size / 8UL : 0UL;

  for( ulong i=0; i<insn_cnt; i++, ptr+=8UL ) {
    ulong insn = FD_LOAD( ulong, ptr );

    /* Check for call instruction.  If immediate is UINT_MAX, assume
       that compiler generated a relocation instead. */
    ulong opc = insn & 0xFF;
    int   imm = (int)(insn >> 32UL);
    if( (opc!=FD_SBPF_OP_CALL_IMM) | (imm==-1) )
      continue;

    /* Mark function call destination */
    long target_pc_s;
    REQUIRE( 0==__builtin_saddl_overflow( (long)i+1L, imm, &target_pc_s ) );
    ulong target_pc = (ulong)target_pc_s;
    REQUIRE( target_pc<insn_cnt );  /* bounds check target */

    /* Derive hash and insert */
    /* FIXME encrypt target_pc before insert */
    uint hash = fd_murmur3_32( &target_pc, 8UL, 0U );
    REQUIRE( fd_sbpf_calldests_upsert( calldests, hash, target_pc ) );

    /* Replace immediate with hash */
    FD_STORE( uint, ptr+4UL, hash );
  }

  return 0;
}

static int
fd_sbpf_relocate( fd_sbpf_elf_t * prog,
                  uchar *         bin,
                  ulong           bin_sz ) {

  /* Skip relocation if DT_REL is missing */

  if( prog->dt_rel == 0UL ) return 0;

  /* Validate reloc table params */

  REQUIRE(  prog->dt_relent==sizeof(fd_elf64_rel)       );
  REQUIRE(  prog->dt_relsz !=0UL                        );
  REQUIRE( (prog->dt_relsz % sizeof(fd_elf64_rel))==0UL );

  /* Find section matching DT_REL, assuming section header table is
     already validated.

     FIXME The physical address matching DT_REL can be discovered by
           bounds checking it against segments.  This is currently the
           default behavior, falling back to section matching for ELFs
           where DT_REL is not in a segment. */

  ulong rel_shnum;
  for( rel_shnum=0; rel_shnum < prog->ehdr.e_shnum; rel_shnum++ )
    if( prog->shdrs[ rel_shnum ].sh_addr==prog->dt_rel )
      break;
  REQUIRE( rel_shnum < prog->ehdr.e_shnum );

  /* Translate virtual address to file offset */

  ulong rel_off = prog->shdrs[ rel_shnum ].sh_offset;
  REQUIRE( fd_ulong_is_aligned( rel_off, alignof(fd_elf64_rel) ) );
  REQUIRE( (rel_off<bin_sz) & (prog->dt_relsz <= bin_sz) & ((rel_off+prog->dt_relsz) <= bin_sz) );

  /* Load section and reloc tables
     Assume section header already validated at this point */

  fd_elf64_rel const * rel     = (fd_elf64_rel const *)(bin+rel_off);
  ulong                rel_cnt = prog->dt_relsz/sizeof(fd_elf64_rel);

  /* Apply each reloc */

  for( ulong i=0; i<rel_cnt; i++ ) {
    int res = fd_sbpf_apply_reloc( prog, bin, bin_sz, &rel[ i ] );
    if( res!=0 ) return res;
  }

  return 0;
}

/* fd_sbpf_make_rodata prepares the read-only sections to be mapped into
   memory into a single segment. */

static int
fd_sbpf_make_rodata( fd_sbpf_elf_t *          elf,
                     fd_sbpf_program_info_t * info,
                     uchar *                  bin,
                     ulong                    bin_sz ) {

  fd_elf64_shdr const * shdrs = elf->shdrs;

  /* Indices of sections part of readonly segment.
     TODO store section indices in fd_sbpf_elf_t instead. */
# define INVALID_SECTION (0x100000)
  uint shidx[ 4 ] = {
    elf->shdr_text        ? (uint)( elf->shdr_text        - shdrs ) : INVALID_SECTION,
    elf->shdr_rodata      ? (uint)( elf->shdr_rodata      - shdrs ) : INVALID_SECTION,
    elf->shdr_data_rel_ro ? (uint)( elf->shdr_data_rel_ro - shdrs ) : INVALID_SECTION,
    elf->shdr_eh_frame    ? (uint)( elf->shdr_eh_frame    - shdrs ) : INVALID_SECTION
  };

  /* Sort indices (optimal sorting network for 4 ints) */
  { /* from fd_sort.c */
    uint _k[2]; ulong _c;
#   define ORDER(k0,k1) _k[0]=(k0); _k[1]=(k1); _c=(ulong)((k1)<(k0)); (k0)=_k[_c]; (k1)=_k[_c^1UL];
    ORDER( shidx[ 0 ], shidx[ 1 ] ); /* O O | | */
    ORDER( shidx[ 2 ], shidx[ 3 ] ); /* | | O O */
    ORDER( shidx[ 0 ], shidx[ 2 ] ); /* O | O | */
    ORDER( shidx[ 1 ], shidx[ 3 ] ); /* | O | O */
    ORDER( shidx[ 1 ], shidx[ 2 ] ); /* | O O | */
#   undef ORDER
  }

  /* Coherence check: .text section must exist
     (This is already verified elsewhere) */
  REQUIRE( shidx[ 0 ]!=INVALID_SECTION );

  /* Virtual address range of segment */
  ulong segment_end = 0UL;

  /* Derive segment VA range by spanning all sections */
  ulong tot_section_sz = 0UL;  /* Size of all sections */
  ulong ro_section_cnt;        /* Number of sections in rodata segment */
  for( ro_section_cnt=0UL; ro_section_cnt<4UL; ro_section_cnt++ ) {
    uint idx = shidx[ ro_section_cnt ];
    if( idx==INVALID_SECTION ) break;

    fd_elf64_shdr const * shdr = &shdrs[ idx ];
    ulong sh_size = fd_ulong_if( shdr->sh_type!=FD_ELF_SHT_NOBITS, shdr->sh_size, 0UL );

    /* Check that virtual address range is in MM_PROGRAM bounds */
    ulong sh_end = shdr->sh_addr + sh_size;
    REQUIRE( shdr->sh_addr == shdr->sh_offset         );
    REQUIRE( shdr->sh_addr <  FD_SBPF_MM_PROGRAM_ADDR ); /* overflow check */
    REQUIRE(       sh_size <  FD_SBPF_MM_PROGRAM_ADDR ); /* overflow check */
    REQUIRE( sh_end        <= FD_SBPF_MM_STACK_ADDR-FD_SBPF_MM_PROGRAM_ADDR ); /* check overlap with stack */

    /* Check that physical address range is in bounds */
    ulong paddr_end = shdr->sh_offset + sh_size;
    REQUIRE( paddr_end >= shdr->sh_offset );
    REQUIRE( paddr_end <= bin_sz          );

    /* Expand range to fit section */
    segment_end = fd_ulong_max( segment_end, sh_end );

    /* Bounds check total section size */
    REQUIRE( tot_section_sz + sh_size >= tot_section_sz ); /* overflow check */
    tot_section_sz += sh_size;
  }

  /* More coherence checks ... these should never fail */
  REQUIRE( ro_section_cnt>0UL    );
  REQUIRE( segment_end  <=bin_sz );

  /* More overlap checks */
  REQUIRE( tot_section_sz <= segment_end ); /* overlap check */

  /* Create segment */
  uchar * rodata    = bin;
  ulong   rodata_sz = segment_end;

  /* memset gaps between sections to zero.
      Assume section sh_addrs are monotonically increasing.
      Assume section virtual address ranges equal physical address ranges.
      Assume ranges are not overflowing. */
  /* FIXME match Solana more closely here */

  ulong cursor = 0UL;
  for( uint i=0; i<ro_section_cnt; i++ ) {
    fd_elf64_shdr const * shdr = &shdrs[ shidx[ i ] ];
    if( FD_UNLIKELY( shdr->sh_type == FD_ELF_SHT_NOBITS ) ) continue;
    fd_memset( rodata+cursor, 0, shdr->sh_addr - cursor );
    cursor = shdr->sh_addr + shdr->sh_size;
  }

  /* Convert entrypoint offset to program counter */

  ulong entry_off = fd_ulong_sat_sub( elf->ehdr.e_entry, elf->shdr_text->sh_addr );
  ulong entry_pc = entry_off / 8UL;
  REQUIRE( fd_ulong_is_aligned( entry_off, 8UL ) );
  /* TODO remove "entrypoint" from function registry */
  REQUIRE( fd_sbpf_calldests_upsert( elf->calldests, 0x71e3cf81, entry_pc ) );

  /* Write info */

  info->rodata    = rodata;
  info->rodata_sz = rodata_sz;

  info->text     = (ulong const *)( rodata + elf->shdr_text->sh_offset );
  info->text_cnt = elf->shdr_text->sh_size / 8UL;
  info->entry_pc = entry_pc;

# undef INVALID_SECTION
  return 0;
}

int
fd_sbpf_program_load( fd_sbpf_program_t *  prog,
                      void *               _bin,
                      ulong                bin_sz,
                      fd_sbpf_syscalls_t * syscalls ) {
  int err;
  uchar * bin = (uchar *)_bin;

  fd_sbpf_program_info_t * info = (fd_sbpf_program_info_t *)prog;
  fd_sbpf_elf_t elf = { .calldests=info->calldests,
                        .syscalls =syscalls };

  /* Read file header */
  if( FD_UNLIKELY( bin_sz<sizeof(fd_elf64_ehdr) ) ) FAIL();
  memcpy( &elf.ehdr, bin, sizeof(fd_elf64_ehdr) );

  /* Validate file header */
  if( FD_UNLIKELY( (err=fd_sbpf_check_ehdr  ( &elf.ehdr, bin_sz ))!=0 ) )
    return err;

  /* Program headers */
  if( FD_UNLIKELY( (err=fd_sbpf_load_phdrs  ( &elf, bin, bin_sz ))!=0 ) )
    return err;

  /* Section headers */
  if( FD_UNLIKELY( (err=fd_sbpf_load_shdrs  ( &elf, bin, bin_sz ))!=0 ) )
    return err;

  /* Find dynamic section */
  if( FD_UNLIKELY( (err=fd_sbpf_find_dynamic( &elf, bin, bin_sz ))!=0 ) )
    return err;

  /* Load dynamic section */
  if( FD_UNLIKELY( (err=fd_sbpf_load_dynamic( &elf, bin, bin_sz ))!=0 ) )
    return err;

  /* Convert calls with PC relative immediate to hashes */
  if( FD_UNLIKELY( (err=fd_sbpf_hash_calls  ( &elf, bin         ))!=0 ) )
    return err;

  /* Apply relocations */
  if( FD_UNLIKELY( (err=fd_sbpf_relocate    ( &elf, bin, bin_sz ))!=0 ) )
    return err;

  /* Create read-only segment
     This mangles the ELF file */
  if( FD_UNLIKELY( (err=fd_sbpf_make_rodata ( &elf, info, bin, bin_sz ))!=0 ) )
    return err;

  return 0;
}

#undef ERR
#undef FAIL
#undef REQUIRE

/* Declare extern symbol definitions for inlines */

FD_FN_CONST extern inline fd_sbpf_program_info_t const *
fd_sbpf_program_get_info( fd_sbpf_program_t const * program );

