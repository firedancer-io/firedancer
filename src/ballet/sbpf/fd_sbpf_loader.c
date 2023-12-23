#include "fd_sbpf_loader.h"
#include "fd_sbpf_opcodes.h"
#include "../../util/fd_util.h"
#include "../../util/bits/fd_sat.h"
#include "../murmur3/fd_murmur3.h"

#include <assert.h>
#include <stdio.h>

#include "fd_sbpf_maps.c"

/* Error handling *****************************************************/

/* Thread local storage last error value */

static FD_TL int ldr_errno     =  0;
static FD_TL int ldr_err_srcln = -1;
#define FD_SBPF_ERRBUF_SZ (128UL)
static FD_TL char fd_sbpf_errbuf[ FD_SBPF_ERRBUF_SZ ] = {0};

/* fd_sbpf_loader_seterr remembers the error ID and line number of the
   current file at which the last error occurred. */

__attribute__((cold,noinline)) int
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

#define FD_SBPF_MM_PROGRAM_ADDR (0x100000000UL) /* readonly program data */
#define FD_SBPF_MM_STACK_ADDR   (0x200000000UL) /* stack (with gaps) */

/* _fd_int_store_if_negative stores x to *p if *p is negative (branchless) */

static inline int
_fd_int_store_if_negative( int * p,
                      int   x ) {
  return (*p = fd_int_if( (*p)<0, x, *p ));
}

/* fd_sbpf_check_ehdr verifies the ELF file header. */

static int
fd_sbpf_check_ehdr( fd_elf64_ehdr const * ehdr,
                    ulong                 elf_sz ) {

  /* Validate ELF magic */
  REQUIRE( ( fd_uint_load_4( ehdr->e_ident )==0x464c457fU          )
  /* Validate file type/target identification */
         & ( ehdr->e_ident[ FD_ELF_EI_CLASS   ]==FD_ELF_CLASS_64   )
         & ( ehdr->e_ident[ FD_ELF_EI_DATA    ]==FD_ELF_DATA_LE    )
         & ( ehdr->e_ident[ FD_ELF_EI_VERSION ]==1                 )
         & ( ehdr->e_ident[ FD_ELF_EI_OSABI   ]==FD_ELF_OSABI_NONE )
         & ( ehdr->e_type                      ==FD_ELF_ET_DYN     )
         & ( ( ehdr->e_machine                 ==FD_ELF_EM_BPF   )
           | ( ehdr->e_machine                 ==FD_ELF_EM_SBPF  ) )
         & ( ehdr->e_version                   ==1                 )
  /* Coherence checks */
         & ( ehdr->e_ehsize   ==sizeof(fd_elf64_ehdr)              )
         & ( ehdr->e_phentsize==sizeof(fd_elf64_phdr)              )
         & ( ehdr->e_shentsize==sizeof(fd_elf64_shdr)              )
         & ( ehdr->e_shstrndx < ehdr->e_shnum                      )
         & ( ehdr->e_flags    !=FD_ELF_EF_SBPF_V2                  ) );

  /* Bounds check program header table */

  ulong const phoff = ehdr->e_phoff;
  ulong const phnum = ehdr->e_phnum;
  REQUIRE( ( fd_ulong_is_aligned( phoff, 8UL ) )
         & ( phoff<=elf_sz ) ); /* out of bounds */

  REQUIRE( phnum<=(ULONG_MAX/sizeof(fd_elf64_phdr)) ); /* overflow */
  ulong const phsz = phnum*sizeof(fd_elf64_phdr);

  ulong const phoff_end = phoff+phsz;
  REQUIRE( ( phoff_end>=phoff  )    /* overflow */
         & ( phoff_end<=elf_sz )    /* out of bounds */
         & ( (phoff_end==0UL)       /* overlaps file header */
           | (phoff>=sizeof(fd_elf64_ehdr)) ) );

  /* Bounds check section header table */

  ulong const shoff = ehdr->e_shoff;
  ulong const shnum = ehdr->e_shnum;
  REQUIRE( ( fd_ulong_is_aligned( shoff, 8UL ) )
         & ( shoff>=sizeof(fd_elf64_ehdr)      )    /* overlaps file header */
         & ( shoff< elf_sz                     )    /* out of bounds */
         & ( shnum> 0UL                        ) ); /* not enough sections */

  REQUIRE( shoff<=(ULONG_MAX/sizeof(fd_elf64_shdr)) ); /* overflow */
  ulong const shsz = shnum*sizeof(fd_elf64_shdr);

  ulong const shoff_end = shoff+shsz;
  REQUIRE( ( shoff_end>=shoff  )    /* overflow */
         & ( shoff_end<=elf_sz ) ); /* out of bounds */

  /* Overlap checks */

  REQUIRE( (phoff>=shoff_end) | (shoff>=phoff_end) ); /* overlap shdrs<>phdrs */

  return 0;
}

/* shdr_get_loaded_size returns the loaded size of a section, i.e. the
   number of bytes loaded into the rodata segment.  sBPF ELFs grossly
   misuse the sh_size parameter.  When SHT_NOBITS is set, the actual
   section size is zero, and the section size is ignored. */

static ulong
shdr_get_loaded_size( fd_elf64_shdr const * shdr ) {
  return fd_ulong_if( shdr->sh_type==FD_ELF_SHT_NOBITS, 0UL, shdr->sh_size );
}

/* check_cstr verifies a string in a string table.  Returns non-NULL if
   the string is null terminated and contains at most max non-NULL
   characters.  Returns NULL if the off is out of bounds, or if the max
   or EOF are reached before the null terminator. */

static char const *
check_cstr( uchar const * bin,
            ulong         bin_sz,
            ulong         off,
            ulong         max,
            ulong *       opt_sz ) {
  if( FD_UNLIKELY( off>=bin_sz ) ) return NULL;
  max += 1UL;                              /* include NULL terminator */
  max  = fd_ulong_min( max, bin_sz-off );  /* truncate to available size */
  char const * cstr = (char const *)( bin+off );
  ulong len = strnlen( cstr, max );
  if( opt_sz ) *opt_sz = len;
  return len<max ? cstr : NULL;
}

/* fd_sbpf_load_shdrs walks the program header table.  Remembers info
   along the way, and performs various validations.

   Assumes that ...
   - table does not overlap with file header or section header table and
     is within bounds
   - offset of program header table is 8 byte aligned */

static int
fd_sbpf_load_phdrs( fd_sbpf_elf_info_t *  info,
                    fd_sbpf_elf_t const * elf,
                    ulong                 elf_sz ) {

  ulong const pht_offset = elf->ehdr.e_phoff;
  ulong const pht_cnt    = elf->ehdr.e_phnum;

  /* Virtual address of last seen program header */
  ulong p_load_vaddr = 0UL;

  /* Read program header table */
  fd_elf64_phdr const * phdr = (fd_elf64_phdr const *)( elf->bin + pht_offset );
  for( ulong i=0; i<pht_cnt; i++ ) {
    switch( phdr[i].p_type ) {
    case FD_ELF_PT_DYNAMIC:
      /* Remember first PT_DYNAMIC segment */
      _fd_int_store_if_negative( &info->phndx_dyn, (int)i );
      break;
    case FD_ELF_PT_LOAD:
      /* LOAD segments must be ordered */
      REQUIRE( phdr[ i ].p_vaddr >= p_load_vaddr );
      p_load_vaddr = phdr[ i ].p_vaddr;
      /* Segment must be within bounds */
      REQUIRE( ( phdr[ i ].p_offset + phdr[ i ].p_filesz >= phdr[ i ].p_offset )
             & ( phdr[ i ].p_offset + phdr[ i ].p_filesz <= elf_sz             ) );
      /* No overlap checks */
      break;
    default:
      /* Ignore other segment types */
      break;
    }
  }

  return 0;
}

/* fd_sbpf_load_shdrs walks the section header table.  Remembers info
   along the way, and performs various validations.

   Assumes that ...
   - table does not overlap with file header or program header table and
     is within bounds
   - offset of section header table is 8 byte aligned
   - section header table has at least one entry */

static int
fd_sbpf_load_shdrs( fd_sbpf_elf_info_t *  info,
                    fd_sbpf_elf_t const * elf,
                    ulong                 elf_sz ) {

  /* File Header */
  ulong const eh_offset = 0UL;
  ulong const eh_offend = sizeof(fd_elf64_ehdr);

  /* Section Header Table */
  ulong const sht_offset = elf->ehdr.e_shoff;
  ulong const sht_cnt    = elf->ehdr.e_shnum;
  ulong const sht_sz     = sht_cnt*sizeof(fd_elf64_shdr);
  ulong const sht_offend = sht_offset + sht_sz;

  fd_elf64_shdr const * shdr = (fd_elf64_shdr const *)( elf->bin + sht_offset );

  /* Program Header Table */
  ulong const pht_offset = elf->ehdr.e_phoff;
  ulong const pht_cnt    = elf->ehdr.e_phnum;
  ulong const pht_offend = pht_offset + (pht_cnt*sizeof(fd_elf64_phdr));

  /* Require SHT_STRTAB for section name table */

  REQUIRE( elf->ehdr.e_shstrndx < sht_cnt ); /* out of bounds */
  REQUIRE( shdr[ elf->ehdr.e_shstrndx ].sh_type==FD_ELF_SHT_STRTAB );

  ulong shstr_off = shdr[ elf->ehdr.e_shstrndx ].sh_offset;
  ulong shstr_sz  = shdr[ elf->ehdr.e_shstrndx ].sh_size;
  REQUIRE( shstr_off<elf_sz );
  shstr_sz = fd_ulong_min( shstr_sz, elf_sz-shstr_off );

  /* Clear the "loaded sections" bitmap */

  fd_memset( info->loaded_sections, 0, sizeof(info->loaded_sections) );

  /* Validate section header table.
     Check that all sections are in bounds, ordered, and don't overlap. */

  ulong min_sh_offset = 0UL;  /* lowest permitted section offset */

  /* While validating section header table, also figure out size
     of the rodata segment.  This is the minimal virtual address range
     that spans all sections.  The offset of each section in virtual
     addressing and file addressing is guaranteed to be the same. */
  ulong segment_end    = 0UL;  /* Upper bound of segment virtual address */
  ulong tot_section_sz = 0UL;  /* Size of all sections */

  for( ulong i=0UL; i<sht_cnt; i++ ) {
    uint  sh_type   = shdr[ i ].sh_type;
    uint  sh_name   = shdr[ i ].sh_name;
    ulong sh_addr   = shdr[ i ].sh_addr;
    ulong sh_offset = shdr[ i ].sh_offset;
    ulong sh_size   = shdr[ i ].sh_size;
    ulong sh_offend = sh_offset + sh_size;

    /* First section must be SHT_NULL */
    REQUIRE( i>0UL || sh_type==FD_ELF_SHT_NULL );

    /* check that physical range has no overflow and is within bounds */
    REQUIRE( sh_offend >= sh_offset );
    REQUIRE( sh_offend <= elf_sz    );

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
      _fd_int_store_if_negative( &info->shndx_dyn, (int)i );
    }

    ulong name_off = shstr_off + (ulong)sh_name;
    REQUIRE( ( name_off<elf_sz   ) /* out of bounds */
           & ( sh_name <shstr_sz ) );

    /* Create name cstr */

    char const * name_ptr = check_cstr( elf->bin + shstr_off, shstr_sz, sh_name, 15UL, NULL );
    REQUIRE( name_ptr );
    char __attribute__((aligned(16UL))) name[ 16UL ] = {0};
    strncpy( name, name_ptr, 15UL );

    /* Check name */
    /* TODO switch table for this? */
    /* TODO reject duplicate sections */

    int load = 0;  /* should section be loaded? */

    /**/ if( 0==memcmp( name, ".text", 6UL /* equals */ ) ) {
      REQUIRE( (info->shndx_text)<0 ); /* check for duplicate */
      info->shndx_text = (int)i;
      load = 1;
    }
    else if( (0==memcmp( name, ".rodata",       8UL /* equals */ ) )
           | (0==memcmp( name, ".data.rel.ro", 13UL /* equals */ ) )
           | (0==memcmp( name, ".eh_frame",    10UL /* equals */ ) ) ) {
      load = 1;
    }
    else if( 0==memcmp( name, ".symtab",   8UL /* equals     */ ) ) {
      REQUIRE( (info->shndx_symtab)<0 );
      info->shndx_symtab = (int)i;
    }
    else if( 0==memcmp( name, ".strtab",   8UL /* equals     */ ) ) {
      REQUIRE( (info->shndx_strtab)<0 );
      info->shndx_strtab = (int)i;
    }
    else if( 0==memcmp( name, ".dynstr",   8UL /* equals     */ ) ) {
      REQUIRE( (info->shndx_dynstr)<0 );
      info->shndx_dynstr = (int)i;
    }
    else if( 0==memcmp( name, ".bss",      4UL /* has prefix */ ) ) {
      FAIL();
    }
    else if( 0==memcmp( name, ".data.rel", 9UL  /* has prefix */ ) ) {} /* ignore */
    else if( (0==memcmp( name, ".data",    5UL  /* has prefix */ ) )
           & ( ( shdr[ i ].sh_flags & (FD_ELF_SHF_ALLOC|FD_ELF_SHF_WRITE) )
                                    ==(FD_ELF_SHF_ALLOC|FD_ELF_SHF_WRITE)   ) ) {
      FAIL();
    }
    else                                            {} /* ignore */
    /* else ignore */

    if( load ) {
      /* Remember that section should be loaded */

      info->loaded_sections[ i>>6UL ] |= (1UL)<<(i&63UL);

      /* Check that virtual address range is in MM_PROGRAM bounds */

      ulong sh_actual_size = shdr_get_loaded_size( &shdr[ i ] );
      ulong sh_virtual_end = sh_addr + sh_actual_size;
      REQUIRE( sh_addr        == sh_offset               );
      REQUIRE( sh_addr        <  FD_SBPF_MM_PROGRAM_ADDR ); /* overflow check */
      REQUIRE( sh_actual_size <  FD_SBPF_MM_PROGRAM_ADDR ); /* overflow check */
      REQUIRE( sh_virtual_end <= FD_SBPF_MM_STACK_ADDR-FD_SBPF_MM_PROGRAM_ADDR ); /* check overlap with stack */

      /* Check that physical address range is in bounds
        (Seems redundant?) */
      ulong paddr_end = sh_offset + sh_actual_size;
      REQUIRE( paddr_end >= sh_offset );
      REQUIRE( paddr_end <= elf_sz    );

      /* Expand range to fit section */
      segment_end = fd_ulong_max( segment_end, sh_virtual_end );

      /* Coherence check sum of section sizes (used to detect overlap) */
      REQUIRE( tot_section_sz + sh_actual_size >= tot_section_sz ); /* overflow check */
      tot_section_sz += sh_actual_size;
    }
  }

  /* More coherence checks ... these should never fail */
  REQUIRE( segment_end   <=elf_sz );
  REQUIRE( tot_section_sz <= segment_end );

  /* Require .text section */

  REQUIRE( (info->shndx_text)>=0 );
  fd_elf64_shdr const * shdr_text = &shdr[ info->shndx_text ];
  REQUIRE( (shdr_text->sh_addr <= elf->ehdr.e_entry)
           /* check that entrypoint is in text VM range */
         & (elf->ehdr.e_entry  <  fd_ulong_sat_add( shdr_text->sh_addr, shdr_text->sh_size ) ) );
  /* NOTE: Does NOT check that the entrypoint is in text section file
           range (which may be 0 sz if SHT_NOBITS).  This check is
           separately done in the sBPF verifier. */

  info->text_off = (uint)shdr_text->sh_offset;
  info->text_cnt = (uint)shdr_get_loaded_size( shdr_text ) / 8U;

  /* Convert entrypoint offset to program counter */

  ulong entry_off = fd_ulong_sat_sub( elf->ehdr.e_entry, shdr_text->sh_addr );
  ulong entry_pc = entry_off / 8UL;
  REQUIRE( fd_ulong_is_aligned( entry_off, 8UL ) );
  info->entry_pc = (uint)entry_pc;

  if( (info->shndx_dynstr)>=0 ) {
    fd_elf64_shdr const * shdr_dynstr = &shdr[ info->shndx_dynstr ];
    ulong sh_offset = shdr_dynstr->sh_offset;
    ulong sh_size   = shdr_dynstr->sh_size;
    REQUIRE( (sh_offset+sh_size>=sh_offset) & (sh_offset+sh_size<=elf_sz) );
    info->dynstr_off = (uint)sh_offset;
    info->dynstr_sz  = (uint)sh_size;
  }

  info->rodata_sz        = (uint)segment_end;
  info->rodata_footprint = (uint)elf_sz;

  return 0;
}

static int
_fd_sbpf_elf_peek( fd_sbpf_elf_info_t * info,
                   void const *         bin,
                   ulong                elf_sz ) {

  /* ELFs must have a file header */
  REQUIRE( elf_sz>sizeof(fd_elf64_ehdr) );

  /* Reject overlong ELFs (using uint addressing internally).
     This is well beyond Solana's max account size of 10 MB. */
  REQUIRE( elf_sz<=UINT_MAX );

  /* Initialize info struct */
  *info = (fd_sbpf_elf_info_t) {
    .text_off         = 0U,
    .text_cnt         = 0U,
    .dynstr_off       = 0U,
    .dynstr_sz        = 0U,
    .rodata_footprint = 0U,
    .rodata_sz        = 0U,
    .shndx_text       = -1,
    .shndx_symtab     = -1,
    .shndx_strtab     = -1,
    .shndx_dyn        = -1,
    .shndx_dynstr     = -1,
    .phndx_dyn        = -1,
    /* !!! Keep this in sync with -Werror=missing-field-initializers */
  };

  fd_sbpf_elf_t const * elf = (fd_sbpf_elf_t const *)bin;
  int err;

  /* Validate file header */
  if( FD_UNLIKELY( (err=fd_sbpf_check_ehdr( &elf->ehdr, elf_sz ))!=0 ) )
    return err;

  /* Program headers */
  if( FD_UNLIKELY( (err=fd_sbpf_load_phdrs( info, elf,  elf_sz ))!=0 ) )
    return err;

  /* Section headers */
  if( FD_UNLIKELY( (err=fd_sbpf_load_shdrs( info, elf,  elf_sz ))!=0 ) )
    return err;

  return 0;
}

fd_sbpf_elf_info_t *
fd_sbpf_elf_peek( fd_sbpf_elf_info_t * info,
                  void const *         bin,
                  ulong                elf_sz ) {
  return _fd_sbpf_elf_peek( info, bin, elf_sz )==0 ? info : NULL;
}

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
  return FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_INIT,
    alignof(fd_sbpf_program_t), sizeof(fd_sbpf_program_t) ),
    fd_sbpf_calldests_align(),  fd_sbpf_calldests_footprint() ),
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

  if( FD_UNLIKELY( ((elf_info->rodata_footprint)>0U) & (!rodata)) ) {
    FD_LOG_WARNING(( "NULL rodata" ));
    return NULL;
  }

  /* Initialize program struct */

  ulong laddr = (ulong)prog_mem;
  laddr+=FD_LAYOUT_INIT;
  memset( (void *)laddr, 0, sizeof(fd_sbpf_program_t) );
  fd_sbpf_program_t * prog = (fd_sbpf_program_t *)fd_type_pun( (void *)laddr );

  memcpy( &prog->info, elf_info, sizeof(fd_sbpf_elf_info_t) );
  prog->rodata    = rodata;
  prog->rodata_sz = elf_info->rodata_sz;
  prog->text      = (ulong *)((ulong)rodata + elf_info->text_off);
  prog->text_cnt  = elf_info->text_cnt;
  prog->entry_pc  = elf_info->entry_pc;

  /* Initialize calldests map */

  laddr=FD_LAYOUT_APPEND( laddr, alignof( fd_sbpf_program_t ),
                                 sizeof ( fd_sbpf_program_t ) );
  /* fd_sbpf_calldests_align() < alignof( fd_sbpf_program_t ) */
  prog->calldests = fd_sbpf_calldests_join( fd_sbpf_calldests_new( (void *)laddr ) );

  return prog;
}

void *
fd_sbpf_program_delete( fd_sbpf_program_t * mem ) {

  ulong laddr = (ulong)fd_type_pun( mem );
  laddr+=FD_LAYOUT_INIT;
  memset( (void *)laddr, 0, sizeof(fd_sbpf_program_t) );

  fd_sbpf_calldests_delete( fd_sbpf_calldests_leave( mem->calldests ) );

  return (void *)mem;
}

/* fd_sbpf_loader_t contains various temporary state during loading */

struct fd_sbpf_loader {
  /* External objects */
  fd_sbpf_calldests_t * calldests;  /* owned by program */
  fd_sbpf_syscalls_t  * syscalls;   /* owned by caller */

  /* Dynamic table */
  uint dyn_off;  /* File offset of dynamic table (UINT_MAX=missing) */
  uint dyn_cnt;  /* Number of dynamic table entries */

  /* Dynamic table entries */
  ulong dt_rel;
  ulong dt_relent;
  ulong dt_relsz;
  ulong dt_symtab;

  /* Dynamic symbols */
  uint dynsym_off;  /* File offset of .dynsym section (0=missing) */
  uint dynsym_cnt;  /* Symbol count */
};
typedef struct fd_sbpf_loader fd_sbpf_loader_t;

/* FD_SBPF_SYM_NAME_SZ_MAX is the maximum length of a symbol name cstr
   including zero terminator. */

#define FD_SBPF_SYM_NAME_SZ_MAX (64UL)

static int
fd_sbpf_find_dynamic( fd_sbpf_loader_t *         loader,
                      fd_sbpf_elf_t const *      elf,
                      ulong                      elf_sz,
                      fd_sbpf_elf_info_t const * info ) {

  fd_elf64_shdr const * shdrs = (fd_elf64_shdr const *)( elf->bin + elf->ehdr.e_shoff );
  fd_elf64_phdr const * phdrs = (fd_elf64_phdr const *)( elf->bin + elf->ehdr.e_phoff );

  /* Try first PT_DYNAMIC in program header table */

  if( (info->phndx_dyn)>=0 ) {
    ulong dyn_off = phdrs[ info->phndx_dyn ].p_offset;
    ulong dyn_sz  = phdrs[ info->phndx_dyn ].p_filesz;
    ulong dyn_end = dyn_off+dyn_sz;

    /* Fall through to SHT_DYNAMIC if invalid */

    if( FD_LIKELY(   ( dyn_end>=dyn_off )                /* overflow      */
                   & ( dyn_end<=elf_sz  )                /* out of bounds */
                   & fd_ulong_is_aligned( dyn_off, 8UL ) /* misaligned    */
                   & fd_ulong_is_aligned( dyn_sz, sizeof(fd_elf64_dyn) ) /* misaligned sz */ ) ) {
      loader->dyn_off = (uint)dyn_off;
      loader->dyn_cnt = (uint)(dyn_sz / sizeof(fd_elf64_dyn));
      return 0;
    }
  }

  /* Try first SHT_DYNAMIC in section header table */

  if( (info->shndx_dyn)>0 ) {
    ulong dyn_off = shdrs[ info->shndx_dyn ].sh_offset;
    ulong dyn_sz  = shdrs[ info->shndx_dyn ].sh_size;
    ulong dyn_end = dyn_off+dyn_sz;

    /* This time, don't tolerate errors */

    REQUIRE( ( dyn_end>=dyn_off )                /* overflow      */
           & ( dyn_end<=elf_sz  )                /* out of bounds */
           & fd_ulong_is_aligned( dyn_off, 8UL ) /* misaligned    */
           & fd_ulong_is_aligned( dyn_sz, sizeof(fd_elf64_dyn) ) /* misaligned sz */ );

    loader->dyn_off = (uint)dyn_off;
    loader->dyn_cnt = (uint)(dyn_sz / sizeof(fd_elf64_dyn));
    return 0;
  }

  /* Missing or invalid PT_DYNAMIC and missing SHT_DYNAMIC, skip. */
  return 0;
}

static int
fd_sbpf_load_dynamic( fd_sbpf_loader_t *         loader,
                      fd_sbpf_elf_t const *      elf,
                      ulong                      elf_sz ) {

  fd_elf64_shdr const * shdrs = (fd_elf64_shdr const *)( elf->bin + elf->ehdr.e_shoff );

  /* Skip if no dynamic table was found */

  if( !loader->dyn_cnt ) return 0;

  /* Walk dynamic table */

  fd_elf64_dyn const * dyn     = (fd_elf64_dyn const *)( elf->bin + loader->dyn_off );
  ulong const          dyn_cnt = loader->dyn_cnt;

  for( ulong i=0; i<dyn_cnt; i++ ) {
    if( FD_UNLIKELY( dyn[i].d_tag==FD_ELF_DT_NULL ) ) break;

    ulong d_val = dyn[i].d_un.d_val;
    switch( dyn[i].d_tag ) {
    case FD_ELF_DT_REL:    loader->dt_rel   =d_val; break;
    case FD_ELF_DT_RELENT: loader->dt_relent=d_val; break;
    case FD_ELF_DT_RELSZ:  loader->dt_relsz =d_val; break;
    case FD_ELF_DT_SYMTAB: loader->dt_symtab=d_val; break;
    }
  }

  /* Load dynamic symbol table */

  if( loader->dt_symtab ) {
    /* Search for dynamic symbol table
      FIXME unfortunate bounded O(n^2) -- could convert to binary search */

    /* FIXME this could be clobbered by relocations, causing strict
             aliasing violations */

    fd_elf64_shdr const * shdr_dynsym = NULL;

    for( ulong i=0; i<elf->ehdr.e_shnum; i++ ) {
      if( shdrs[ i ].sh_addr == loader->dt_symtab ) {
        shdr_dynsym = &shdrs[ i ];
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

    REQUIRE( ( sh_offset+sh_size>=sh_offset           )
           & ( sh_offset+sh_size<=elf_sz              )
           & ( fd_ulong_is_aligned( sh_offset, 8UL )  )
           & ( sh_size % sizeof (fd_elf64_sym) == 0UL ) );

    loader->dynsym_off = (uint)sh_offset;
    loader->dynsym_cnt = (uint)(sh_size/sizeof(fd_elf64_sym));
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
   position-dependent binaries without any dynamic relocations. */

/* R_BPF_64_64 relocates an absolute address into the extended imm field
   of an lddw-form instruction.  (Two instruction slots, low 32 bits in
   first immediate field, high 32 bits in second immediate field)

    Bits  0..32    32..64   64..96   96..128
         [ ... ] [ IMM_LO ] [ ... ] [ IMM_HI ] */

static int
fd_sbpf_r_bpf_64_64( fd_sbpf_loader_t   const * loader,
                     fd_sbpf_elf_t      const * elf,
                     ulong                      elf_sz,
                     uchar                    * rodata,
                     fd_sbpf_elf_info_t const * info,
                     fd_elf64_rel       const * rel ) {

  (void)info;

  uint  r_sym    = FD_ELF64_R_SYM( rel->r_info );
  ulong r_offset = rel->r_offset;

  /* Bounds check */
  REQUIRE( ( r_offset+16UL> r_offset )
         & ( r_offset+16UL<=elf_sz   ) );

  /* Offsets of implicit addend (immediate fields) */
  ulong A_off_lo = r_offset+ 4UL;
  ulong A_off_hi = r_offset+12UL;

  /* Read implicit addend (imm field of first insn slot) */
  // SBF_V2: ulong A_off = is_text ? r_offset+4UL : r_offset;
  REQUIRE( A_off_lo+4UL<elf_sz );

  /* Lookup symbol */
  REQUIRE( r_sym < loader->dynsym_cnt );
  fd_elf64_sym const * dynsyms = (fd_elf64_sym const *)( elf->bin + loader->dynsym_off );
  fd_elf64_sym const * sym     = &dynsyms[ r_sym ];
  ulong S = sym->st_value;

  /* Relocate */
  ulong A = FD_LOAD( uint, &rodata[ A_off_lo ] );
  ulong V = fd_ulong_sat_add( S, A );
  if( V<FD_SBPF_MM_PROGRAM_ADDR ) V+=FD_SBPF_MM_PROGRAM_ADDR;

  /* Write back */
  FD_STORE( uint, &rodata[ A_off_lo ], (uint)(V      ) );
  FD_STORE( uint, &rodata[ A_off_hi ], (uint)(V>>32UL) );

  return 0;
}

/* R_BPF_64_RELATIVE is almost entirely Solana specific. */

static int
fd_sbpf_r_bpf_64_relative( fd_sbpf_elf_t      const * elf,
                           ulong                      elf_sz,
                           uchar                    * rodata,
                           fd_sbpf_elf_info_t const * info,
                           fd_elf64_rel       const * rel ) {

  ulong r_offset = rel->r_offset;

  /* Is reloc target in .text section? */
  fd_elf64_shdr const * shdrs     = (fd_elf64_shdr const *)( elf->bin + elf->ehdr.e_shoff );
  fd_elf64_shdr const * shdr_text = &shdrs[ info->shndx_text ];
  int is_text = ( ( r_offset >= shdr_text->sh_offset ) &
                  ( r_offset <  shdr_text->sh_offset +
                                shdr_get_loaded_size( shdr_text ) ) );

  if( is_text ) {
    /* If reloc target is in .text, behave like R_BPF_64_64, except:
       - R_SYM(r_info) is ignored
       - If implicit addend looks like a physical address, make it
         a virtual address (by adding a constant offset)

       This relocation type seems to make little sense but is required
       for most programs. */

    REQUIRE( (r_offset+16UL>r_offset) & (r_offset+16UL<=elf_sz) );
    ulong imm_lo_off = r_offset+ 4UL;
    ulong imm_hi_off = r_offset+12UL;

    /* Read implicit addend */
    uint  va_lo = FD_LOAD( uint, rodata+imm_lo_off );
    uint  va_hi = FD_LOAD( uint, rodata+imm_hi_off );
    ulong va    = ( (ulong)va_hi<<32UL ) | va_lo;

    REQUIRE( va!=0UL );
    va = va<FD_SBPF_MM_PROGRAM_ADDR ? va+FD_SBPF_MM_PROGRAM_ADDR : va;

    /* Write back
       Skip bounds check as .text is guaranteed to be writable */
    FD_STORE( uint, rodata+imm_lo_off, (uint)( va       ) );
    FD_STORE( uint, rodata+imm_hi_off, (uint)( va>>32UL ) );
  } else {
    /* Outside .text do a 64-bit write */

    /* Bounds checks */
    REQUIRE( (r_offset+8UL>r_offset) & (r_offset+8UL<=elf_sz) );

    /* Read implicit addend */
    ulong va = FD_LOAD( uint, rodata+r_offset+4UL );

    /* Relocate */
    va = fd_ulong_sat_add( va, FD_SBPF_MM_PROGRAM_ADDR );

    /* Write back */
    FD_STORE( ulong, rodata+r_offset, va );
  }

  return 0;
}

static int
fd_sbpf_r_bpf_64_32( fd_sbpf_loader_t   const * loader,
                     fd_sbpf_elf_t      const * elf,
                     ulong                      elf_sz,
                     uchar                    * rodata,
                     fd_sbpf_elf_info_t const * info,
                     fd_elf64_rel       const * rel ) {

  uint  r_sym    = FD_ELF64_R_SYM( rel->r_info );
  ulong r_offset = rel->r_offset;

  /* Lookup symbol */
  REQUIRE( r_sym < loader->dynsym_cnt );
  fd_elf64_shdr const * shdrs   = (fd_elf64_shdr const *)( elf->bin + elf->ehdr.e_shoff );
  fd_elf64_sym  const * dynsyms = (fd_elf64_sym const *)( elf->bin + loader->dynsym_off );
  fd_elf64_sym  const * sym     = &dynsyms[ r_sym ];
  ulong S = sym->st_value;

  /* Verify .dynstr (TODO can we lift this out of the reloc handler?) */
  REQUIRE( info->shndx_dynstr > 0 );
  REQUIRE( shdrs[ info->shndx_dynstr ].sh_type == FD_ELF_SHT_STRTAB );

  /* Verify symbol name */
  ulong name_len;
  char const * name = check_cstr( elf->bin + info->dynstr_off, info->dynstr_sz, sym->st_name, FD_SBPF_SYM_NAME_SZ_MAX-1UL, &name_len );
  REQUIRE( name );

  /* Value to write into relocated field */
  uint V;

  int is_func_call = ( FD_ELF64_ST_TYPE( sym->st_info ) == FD_ELF_STT_FUNC )
                   & ( S!=0UL );
  if( is_func_call ) {
    /* Check whether function call is in virtual memory range of text section. */
    fd_elf64_shdr const * shdr_text = &shdrs[ info->shndx_text ];
    ulong sh_addr = shdr_text->sh_addr;
    ulong sh_size = shdr_text->sh_size;
    REQUIRE( (S>=sh_addr) & (S<sh_addr+sh_size) );

    /* Note: The above check is broken, as sh_size is interpreted as 0
       for SHT_NOBITS section. Yet, this is the "correct" loading
       behavior according to protocol rules. */

    /* Register function call */
    ulong target_pc = (S-sh_addr) / 8UL;

    /* Check for collision with syscall ID */
    REQUIRE( !fd_sbpf_syscalls_query( loader->syscalls, (uint)target_pc, NULL ) );

    /* Register new entry */
    uint hash;
    if( name_len >= 10UL && 0==strncmp( name, "entrypoint", name_len ) ) {
      hash = 0x71e3cf81;
    } else {
      hash = fd_murmur3_32( &target_pc, 8UL, 0U );
    }
    REQUIRE( fd_sbpf_calldests_upsert( loader->calldests, hash, target_pc ) );

    V = (uint)hash;
  } else {
    /* FIXME Should cache Murmur hashes.
             If max ELF size is 10MB, can fit about 640k relocs.
             Each reloc could point to a symbol with the same st_name,
             which results in 640MB hash input data without caching.  */
    uint hash = fd_murmur3_32( name, name_len, 0UL );
    /* Ensure that requested syscall ID exists */
    REQUIRE( fd_sbpf_syscalls_query( loader->syscalls, hash, NULL ) );

    V = hash;
  }

  /* Bounds checks */
  REQUIRE( (r_offset+8UL>r_offset) & (r_offset+8UL<=elf_sz) );
  ulong A_off = r_offset+4UL;

  /* Apply relocation */
  FD_STORE( uint, rodata+A_off, V );

  return 0;
}

static int
fd_sbpf_apply_reloc( fd_sbpf_loader_t   const * loader,
                     fd_sbpf_elf_t      const * elf,
                     ulong                      elf_sz,
                     uchar                    * rodata,
                     fd_sbpf_elf_info_t const * info,
                     fd_elf64_rel       const * rel ) {
  switch( FD_ELF64_R_TYPE( rel->r_info ) ) {
  case FD_ELF_R_BPF_64_64:
    return fd_sbpf_r_bpf_64_64      ( loader, elf, elf_sz, rodata, info, rel );
  case FD_ELF_R_BPF_64_RELATIVE:
    return fd_sbpf_r_bpf_64_relative(         elf, elf_sz, rodata, info, rel );
  case FD_ELF_R_BPF_64_32:
    return fd_sbpf_r_bpf_64_32      ( loader, elf, elf_sz, rodata, info, rel );
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
fd_sbpf_hash_calls( fd_sbpf_loader_t *    loader,
                    fd_sbpf_program_t *   prog,
                    fd_sbpf_elf_t const * elf ) {

  fd_elf64_shdr const * shdrs  = (fd_elf64_shdr const *)( elf->bin + elf->ehdr.e_shoff );
  fd_sbpf_elf_info_t *  info   = &prog->info;
  uchar *               rodata = prog->rodata;

  fd_elf64_shdr const * shtext    = &shdrs[ info->shndx_text ];
  fd_sbpf_calldests_t * calldests = loader->calldests;

  uchar * ptr      = rodata + shtext->sh_offset;
  ulong   insn_cnt = shdr_get_loaded_size( shtext ) / 8UL;

  for( ulong i=0; i<insn_cnt; i++, ptr+=8UL ) {
    ulong insn = FD_LOAD( ulong, ptr );

    /* Check for call instruction.  If immediate is UINT_MAX, assume
       that compiler generated a relocation instead. */
    ulong opc  = insn & 0xFF;
    int   imm  = (int)(insn >> 32UL);
    if( (opc!=0x85) | (imm==-1) )
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
fd_sbpf_relocate( fd_sbpf_loader_t   const * loader,
                  fd_sbpf_elf_t      const * elf,
                  ulong                      elf_sz,
                  uchar                    * rodata,
                  fd_sbpf_elf_info_t const * info ) {

  ulong const dt_rel    = loader->dt_rel;
  ulong const dt_relent = loader->dt_relent;
  ulong const dt_relsz  = loader->dt_relsz;

  /* Skip relocation if DT_REL is missing */

  if( dt_rel == 0UL ) return 0;

  /* Validate reloc table params */

  REQUIRE(  dt_relent==sizeof(fd_elf64_rel)       );
  REQUIRE(  dt_relsz !=0UL                        );
  REQUIRE( (dt_relsz % sizeof(fd_elf64_rel))==0UL );

  /* Resolve DT_REL virtual address to file offset
     First, attempt to find segment containing DT_REL */

  ulong rel_off = ULONG_MAX;

  fd_elf64_phdr const * phdrs = (fd_elf64_phdr const *)( elf->bin + elf->ehdr.e_phoff );
  ulong rel_phnum;
  for( rel_phnum=0; rel_phnum < elf->ehdr.e_phnum; rel_phnum++ ) {
    ulong va_lo = phdrs[ rel_phnum ].p_vaddr;
    ulong va_hi = phdrs[ rel_phnum ].p_memsz + va_lo;
    REQUIRE( va_hi>=va_lo );
    if( (dt_rel>=va_lo) & (dt_rel<va_hi) ) {
      /* Found */
      ulong va_off = dt_rel - va_lo;
      ulong pa_lo  = phdrs[ rel_phnum ].p_offset + va_off;
      /* Overflow checks */
      REQUIRE( (va_off<=dt_rel)
             & (pa_lo >=va_off)
             & (pa_lo < elf_sz) );
      rel_off = pa_lo;
      break;
    }
  }

  /* DT_REL not contained in any segment.  Fallback to section header
     table for finding first dynamic reloc section. */

  if( rel_phnum == elf->ehdr.e_phnum ) {
    fd_elf64_shdr const * shdrs = (fd_elf64_shdr const *)( elf->bin + elf->ehdr.e_shoff );
    ulong rel_shnum;
    for( rel_shnum=0; rel_shnum < elf->ehdr.e_shnum; rel_shnum++ )
      if( shdrs[ rel_shnum ].sh_addr==dt_rel )
        break;
    REQUIRE( rel_shnum < elf->ehdr.e_shnum );
    rel_off = shdrs[ rel_shnum ].sh_offset;
  }

  REQUIRE( fd_ulong_is_aligned( rel_off, 8UL ) );
  REQUIRE( (rel_off            <  elf_sz)
         & (dt_relsz           <= elf_sz)
         & ((rel_off+dt_relsz) <= elf_sz) );

  /* Load section and reloc tables
     Assume section header already validated at this point */

  fd_elf64_rel const * rel     = (fd_elf64_rel const *)( elf->bin + rel_off );
  ulong                rel_cnt = dt_relsz/sizeof(fd_elf64_rel);

  /* Apply each reloc */

  for( ulong i=0; i<rel_cnt; i++ ) {
    int res = fd_sbpf_apply_reloc( loader, elf, elf_sz, rodata, info, &rel[ i ] );
    if( res!=0 ) return res;
  }

  return 0;
}

static int
fd_sbpf_zero_rodata( fd_sbpf_elf_t *            elf,
                     uchar *                    rodata,
                     fd_sbpf_elf_info_t const * info ) {

  fd_elf64_shdr const * shdrs = (fd_elf64_shdr const *)( elf->bin + elf->ehdr.e_shoff );

  /* memset gaps between sections to zero.
      Assume section sh_addrs are monotonically increasing.
      Assume section virtual address ranges equal physical address ranges.
      Assume ranges are not overflowing. */
  /* FIXME match Solana more closely here */

  ulong cursor = 0UL;
  for( ulong i=0; i<elf->ehdr.e_shnum; i++ ) {
    if( !( info->loaded_sections[ i>>6UL ] & (1UL<<(i&63UL)) ) ) continue;

    fd_elf64_shdr const * shdr = &shdrs[ i ];

    /* NOBITS sections are included in rodata, but may have invalid
       offsets, thus we can't trust the shdr->sh_offset field. */
    if( FD_UNLIKELY( shdr->sh_type==FD_ELF_SHT_NOBITS ) ) continue;

    ulong off = shdr->sh_offset;
    ulong sz  = shdr->sh_size;
    assert( cursor<=off             );  /* Invariant: Monotonically increasing offsets */
    assert( off+sz>=off             );  /* Invariant: No integer overflow */
    assert( off+sz<=info->rodata_sz );  /* Invariant: No buffer overflow */

    /* Fill gap with zeros */
    ulong gap = off - cursor;
    fd_memset( rodata+cursor, 0, gap );

    cursor = off+sz;
  }

  fd_memset( rodata+cursor, 0, info->rodata_sz - cursor );

  return 0;
}

int
fd_sbpf_program_load( fd_sbpf_program_t *  prog,
                      void const *         _bin,
                      ulong                elf_sz,
                      fd_sbpf_syscalls_t * syscalls ) {
  int err;
  fd_sbpf_elf_t * elf = (fd_sbpf_elf_t *)_bin;

  fd_sbpf_loader_t loader = {
    .calldests = prog->calldests,
    .syscalls  = syscalls,

    .dyn_off   = 0U,
    .dyn_cnt   = 0U,

    .dt_rel    = 0UL,
    .dt_relent = 0UL,
    .dt_relsz  = 0UL,
    .dt_symtab = 0UL,

    .dynsym_off = 0U,
    .dynsym_cnt = 0U,
  };

  /* Find dynamic section */
  if( FD_UNLIKELY( (err=fd_sbpf_find_dynamic( &loader, elf, elf_sz, &prog->info ))!=0 ) )
    return err;

  /* Load dynamic section */
  if( FD_UNLIKELY( (err=fd_sbpf_load_dynamic( &loader, elf, elf_sz ))!=0 ) )
    return err;

  /* Copy rodata segment */
  fd_memcpy( prog->rodata, elf->bin, prog->info.rodata_footprint );

  /* Convert calls with PC relative immediate to hashes */
  if( FD_UNLIKELY( (err=fd_sbpf_hash_calls  ( &loader, prog, elf ))!=0 ) )
    return err;

  /* Apply relocations */
  if( FD_UNLIKELY( (err=fd_sbpf_relocate    ( &loader, elf, elf_sz, prog->rodata, &prog->info ))!=0 ) )
    return err;

  /* Override entrypoint */
  do {
    fd_sbpf_calldests_t * entry = fd_sbpf_calldests_query( prog->calldests, 0x71e3cf81, NULL );
    if( !entry )
      entry = fd_sbpf_calldests_insert( prog->calldests, 0x71e3cf81 );
    REQUIRE( entry );
    entry->pc = prog->entry_pc;
  } while(0);

  /* Create read-only segment */
  if( FD_UNLIKELY( (err=fd_sbpf_zero_rodata( elf, prog->rodata, &prog->info ))!=0 ) )
    return err;

  return 0;
}

#undef ERR
#undef FAIL
#undef REQUIRE
