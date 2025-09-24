#include "fd_sbpf_loader.h"
#include "fd_sbpf_instr.h"
#include "fd_sbpf_opcodes.h"
#include "../../util/fd_util.h"
#include "../../util/bits/fd_sat.h"
#include "../murmur3/fd_murmur3.h"

#include <assert.h>
#include <stdio.h>

/* Error handling *****************************************************/

/* Thread local storage last error value */

static FD_TL int ldr_errno     =  0;
static FD_TL int ldr_err_srcln = -1;
#define FD_SBPF_ERRBUF_SZ (128UL)
static FD_TL char fd_sbpf_errbuf[ FD_SBPF_ERRBUF_SZ ] = {0};

/* fd_sbpf_loader_seterr remembers the error ID and line number of the
   current file at which the last error occurred. */

__attribute__((cold,noinline)) static int
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
#define REQUIRE(x) do { if ( FD_UNLIKELY( !(x) ) ) FAIL(); } while (0)

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

/* _fd_int_store_if_negative stores x to *p if *p is negative (branchless) */

static inline int
_fd_int_store_if_negative( int * p,
                      int   x ) {
  return (*p = fd_int_if( (*p)<0, x, *p ));
}

/* fd_sbpf_check_ehdr verifies the ELF file header. */

static int
fd_sbpf_check_ehdr( fd_elf64_ehdr const * ehdr,
                    ulong                 elf_sz,
                    uint                  min_version,
                    uint                  max_version ) {

  /* Validate ELF magic */
  REQUIRE( ( fd_uint_load_4( ehdr->e_ident )==0x464c457fU          )
  /* Validate file type/target identification
     Solana/Agave performs header checks across two places:
      - Elf64::parse https://github.com/solana-labs/rbpf/blob/v0.8.0/src/elf_parser/mod.rs#L108
      - Executable::validate https://github.com/solana-labs/rbpf/blob/v0.8.0/src/elf.rs#L518
     These two sections are executed in close proximity, with no modifications to the header in between.
     We can therefore consolidate the checks in one place.
  */
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
         & ( ehdr->e_flags >= min_version                          )
         & ( max_version
             ? ( ehdr->e_flags <= max_version )
             : ( ehdr->e_flags != FD_ELF_EF_SBPF_V2 )
           )
  );

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
   section size is zero, and the section size is ignored. Sets *is_some
   to 0 and returns 0 if SHT_NOBITS is set. Otherwise, sets *is_some to
   1 and returns the section size. */

static ulong
shdr_get_loaded_size( fd_elf64_shdr const * shdr, uchar * is_some ) {
  if( shdr->sh_type==FD_ELF_SHT_NOBITS ) {
    *is_some = 0;
    return 0UL;
  } else {
    *is_some = 1;
    return shdr->sh_size;
  }
}

/* Mimics Elf64Shdr::file_range(). Returns 1 (Some) if the section
   header type is not SHT_NOBITS, and sets (lo, hi) to the section
   header offset and offset + size respectively. Returns 0 (None)
   otherwise, and sets both (lo, hi) to 0.

   https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L87-L93 */

static uchar
fd_shdr_get_file_range( fd_elf64_shdr const * shdr,
                        ulong *               lo,
                        ulong *               hi ) {
  if( shdr->sh_type==FD_ELF_SHT_NOBITS ) {
    *lo = 0UL;
    *hi = 0UL;
    return 0;
  } else {
    *lo = shdr->sh_offset;
    *hi = fd_ulong_sat_add( shdr->sh_offset, shdr->sh_size );
    return 1;
  }
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

/* fd_sbpf_load_phdrs walks the program header table.  Remembers info
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

/* FD_SBPF_SECTION_NAME_SZ_MAX is the maximum length of a symbol name cstr
   including zero terminator.
   https://github.com/solana-labs/rbpf/blob/c168a8715da668a71584ea46696d85f25c8918f6/src/elf_parser/mod.rs#L12 */
#define FD_SBPF_SECTION_NAME_SZ_MAX (16UL)

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
                    ulong                 elf_sz,
                    int                   elf_deploy_checks ) {

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

  /* Overlap checks */
  REQUIRE( (sht_offset>=eh_offend ) | (sht_offend<=eh_offset ) ); /* overlaps ELF file header */
  REQUIRE( (sht_offset>=pht_offend) | (sht_offend<=pht_offset) ); /* overlaps program header table */

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

  /* Keep track of the physical (file address) end of all relevant
     sections to determine rodata_sz */
  ulong psegment_end          = 0UL;     /* Upper bound of physical (file) addressing  */

  /* While validating section header table, also figure out size
     of the rodata segment.  This is the minimal virtual address range
     that spans all sections. */
  ulong vsegment_start  = FD_SBPF_MM_PROGRAM_ADDR;  /* Lower bound of segment virtual address */
  ulong vsegment_end    = 0UL;  /* Upper bound of segment virtual address */

  ulong tot_section_sz = 0UL;  /* Size of all sections */
  ulong lowest_addr    = 0UL;
  ulong highest_addr   = 0UL;

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
    REQUIRE( sh_offend <= elf_sz    ); // https://github.com/solana-labs/rbpf/blob/v0.8.0/src/elf_parser/mod.rs#L180

    if( sh_type!=FD_ELF_SHT_NOBITS ) {
      /* Overlap checks */
      REQUIRE( (sh_offset>=eh_offend ) | (sh_offend<=eh_offset ) ); /* overlaps ELF file header */
      REQUIRE( (sh_offset>=pht_offend) | (sh_offend<=pht_offset) ); /* overlaps program header table */
      REQUIRE( (sh_offset>=sht_offend) | (sh_offend<=sht_offset) ); /* overlaps section header table */

      /* Ordering and overlap check
         https://github.com/solana-labs/rbpf/blob/v0.8.0/src/elf_parser/mod.rs#L177
      */
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

    char const * name_ptr = check_cstr( elf->bin + shstr_off, shstr_sz, sh_name, FD_SBPF_SECTION_NAME_SZ_MAX-1UL, NULL );
    REQUIRE( name_ptr );
    char __attribute__((aligned(16UL))) name[ FD_SBPF_SECTION_NAME_SZ_MAX ] = {0};
    strncpy( name, name_ptr, FD_SBPF_SECTION_NAME_SZ_MAX-1UL );

    /* Check name */
    /* TODO switch table for this? */
    /* TODO reject duplicate sections */

    /* https://github.com/firedancer-io/sbpf/blob/sbpf-v0.11.1-patches/src/elf.rs#L855 */
    if( FD_LIKELY( strncmp( name, ".text", sizeof(".text") )==0 ||
                   strncmp( name, ".rodata", sizeof(".rodata") )==0 ||
                   strncmp( name, ".data.rel.ro", sizeof(".data.rel.ro") )==0 ||
                   strncmp( name, ".eh_frame", sizeof(".eh_frame") )==0 ) ) {
      lowest_addr  = fd_ulong_min( lowest_addr, sh_addr );
      highest_addr = fd_ulong_max( highest_addr, fd_ulong_sat_add( sh_addr, sh_size ) );
    }

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

      /* https://github.com/solana-labs/rbpf/blob/v0.8.0/src/elf.rs#L426 */
      if ( FD_UNLIKELY( elf_deploy_checks ) ){
        REQUIRE( sh_addr == sh_offset );
      }
      REQUIRE( sh_addr        <  FD_SBPF_MM_PROGRAM_ADDR ); /* overflow check */
      REQUIRE( sh_actual_size <  FD_SBPF_MM_PROGRAM_ADDR ); /* overflow check */
      REQUIRE( sh_virtual_end <= FD_SBPF_MM_STACK_ADDR-FD_SBPF_MM_PROGRAM_ADDR ); /* check overlap with stack */

      /* Check that physical address range is in bounds
        (Seems redundant?) */
      ulong paddr_end = sh_offset + sh_actual_size;
      REQUIRE( paddr_end >= sh_offset );
      REQUIRE( paddr_end <= elf_sz    );

      vsegment_start = fd_ulong_min( vsegment_start, sh_addr );
      /* Expand range to fit section */
      psegment_end = fd_ulong_max( psegment_end, paddr_end );
      vsegment_end = fd_ulong_max( vsegment_end, sh_virtual_end );

      /* Coherence check sum of section sizes */
      REQUIRE( tot_section_sz + sh_actual_size >= tot_section_sz ); /* overflow check */
      tot_section_sz += sh_actual_size;
    }
  }

  /* https://github.com/firedancer-io/sbpf/blob/sbpf-v0.11.1-patches/src/elf.rs#L982 */
  REQUIRE( fd_ulong_sat_sub( highest_addr, lowest_addr ) <= elf_sz ); /* addr out of bounds */

  /* More coherence checks */
  REQUIRE( psegment_end <= elf_sz ); // https://github.com/solana-labs/rbpf/blob/v0.8.0/src/elf.rs#L782


  /* Check that the rodata segment is within bounds
     https://github.com/solana-labs/rbpf/blob/v0.8.0/src/elf.rs#L725 */
  if ( FD_UNLIKELY( elf_deploy_checks ) ){
    REQUIRE( fd_ulong_sat_add( vsegment_start, tot_section_sz) <= vsegment_end );
  }

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
  ulong text_size = shdr_get_loaded_size( shdr_text );
  info->text_sz = text_size;
  info->text_cnt = (uint) text_size / 8U;


  /* Convert entrypoint offset to program counter */

  info->rodata_sz        = (uint)psegment_end;
  info->rodata_footprint = (uint)elf_sz;

  ulong entry_off = fd_ulong_sat_sub( elf->ehdr.e_entry, shdr_text->sh_addr );
  ulong entry_pc = entry_off / 8UL;

  /* Follows https://github.com/solana-labs/rbpf/blob/v0.8.0/src/elf.rs#L443 */
  REQUIRE( fd_ulong_is_aligned( entry_off, 8UL ) );
  REQUIRE( entry_pc < ( info->rodata_sz / 8UL ) );
  info->entry_pc = (uint)entry_pc;

  if( (info->shndx_dynstr)>=0 ) {
    fd_elf64_shdr const * shdr_dynstr = &shdr[ info->shndx_dynstr ];
    ulong sh_offset = shdr_dynstr->sh_offset;
    ulong sh_size   = shdr_dynstr->sh_size;
    REQUIRE( (sh_offset+sh_size>=sh_offset) & (sh_offset+sh_size<=info->rodata_footprint) );
    info->dynstr_off = (uint)sh_offset;
    info->dynstr_sz  = (uint)sh_size;
  }

  return 0;
}

fd_sbpf_elf_info_t *
fd_sbpf_elf_peek_old( fd_sbpf_elf_info_t * info,
                      void const *         bin,
                      ulong                elf_sz,
                      int                  elf_deploy_checks,
                      uint                 sbpf_min_version,
                      uint                 sbpf_max_version ) {

  /* Reject overlong ELFs (using uint addressing internally).
     This is well beyond Solana's max account size of 10 MB. */
  if( FD_UNLIKELY( elf_sz>UINT_MAX ) )
    return NULL;

  fd_sbpf_elf_t const * elf = (fd_sbpf_elf_t const *)bin;
  int err;

  /* Validate file header */
  if( FD_UNLIKELY( (err=fd_sbpf_check_ehdr( &elf->ehdr, elf_sz, sbpf_min_version, sbpf_max_version ))!=0 ) )
    return NULL;

  /* Program headers */
  if( FD_UNLIKELY( (err=fd_sbpf_load_phdrs( info, elf,  elf_sz ))!=0 ) )
    return NULL;

  /* Section headers */
  if( FD_UNLIKELY( (err=fd_sbpf_load_shdrs( info, elf,  elf_sz, elf_deploy_checks ))!=0 ) )
    return NULL;

  /* Set SBPF version from ELF e_flags */
  info->sbpf_version = sbpf_max_version ? elf->ehdr.e_flags : 0UL;

  return info;
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
  if( FD_UNLIKELY( fd_sbpf_enable_stricter_elf_headers( info->sbpf_version ) ) ) {
    /* SBPF v3+ no longer neeeds calldests bitmap */
    return FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_INIT,
      alignof(fd_sbpf_program_t), sizeof(fd_sbpf_program_t) ),
      alignof(fd_sbpf_program_t) );
  }
  return FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_INIT,
    alignof(fd_sbpf_program_t), sizeof(fd_sbpf_program_t) ),
    fd_sbpf_calldests_align(), fd_sbpf_calldests_footprint( info->rodata_sz / 8UL ) ),  /* calldests bitmap */
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

  /* https://github.com/solana-labs/rbpf/blob/v0.8.0/src/elf_parser/mod.rs#L99 */
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong) rodata, FD_SBPF_PROG_RODATA_ALIGN ) ) ){
    FD_LOG_WARNING(( "rodata is not 8-byte aligned" ));
    return NULL;
  }

  /* Initialize program struct */

  FD_SCRATCH_ALLOC_INIT( laddr, prog_mem );
  fd_sbpf_program_t * prog = FD_SCRATCH_ALLOC_APPEND( laddr, alignof(fd_sbpf_program_t), sizeof(fd_sbpf_program_t) );

  *prog = (fd_sbpf_program_t) {
    .info      = *elf_info,
    .rodata    = rodata,
    .rodata_sz = elf_info->rodata_sz,
    .text      = (ulong *)((ulong)rodata + elf_info->text_off), /* FIXME: WHAT IF MISALIGNED */
    .text_off  = elf_info->text_off,
    .text_cnt  = elf_info->text_cnt,
    .text_sz   = elf_info->text_sz,
    .entry_pc  = elf_info->entry_pc
  };

  if( FD_UNLIKELY( fd_sbpf_enable_stricter_elf_headers( elf_info->sbpf_version ) ) ) {
    /* No calldests map in SBPF v3+ */
    prog->calldests_shmem = NULL;
    prog->calldests = NULL;
  } else {
    /* Initialize calldests map */
    ulong pc_max = elf_info->rodata_sz / 8UL;
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

  fd_sbpf_calldests_delete( fd_sbpf_calldests_leave( mem->calldests ) );
  fd_memset( mem, 0, sizeof(fd_sbpf_program_t) );

  return (void *)mem;
}

/* fd_sbpf_loader_t contains various temporary state during loading */

struct fd_sbpf_loader {
  /* External objects */
  ulong *              calldests;  /* owned by program */
  fd_sbpf_syscalls_t * syscalls;   /* owned by caller */

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

  int elf_deploy_checks;
};
typedef struct fd_sbpf_loader fd_sbpf_loader_t;

/* FD_SBPF_SYM_NAME_SZ_MAX is the maximum length of a symbol name cstr
   including zero terminator.
   https://github.com/solana-labs/rbpf/blob/c168a8715da668a71584ea46696d85f25c8918f6/src/elf_parser/mod.rs#L13 */
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
        /* TODO: verify this ... */
        /* Check section type */
        uint sh_type = shdrs[ i ].sh_type;
        // https://github.com/solana-labs/rbpf/blob/v0.8.5/src/elf_parser/mod.rs#L500
        REQUIRE( (sh_type==FD_ELF_SHT_SYMTAB) | (sh_type==FD_ELF_SHT_DYNSYM) );

        shdr_dynsym = &shdrs[ i ];
        break;
      }
    }
    REQUIRE( shdr_dynsym );

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
                     fd_elf64_rel       const * rel,
                     fd_elf64_shdr const *      sh_text,
                     ulong                      r_offset ) {

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1070-L1080 */
  ulong imm_offset = r_offset;
  {
    ulong text_section_lo, text_section_hi;
    if( info->sbpf_version==FD_SBPF_V0 ||
        ( fd_shdr_get_file_range( sh_text, &text_section_lo, &text_section_hi ) &&
          r_offset>=text_section_lo &&
          r_offset<text_section_hi ) ) {
      imm_offset = fd_ulong_sat_add( r_offset, 4UL /* BYTE_OFFSET_IMMEDIATE */ );
    }
  }

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1084-L1086 */


  uint  r_sym    = FD_ELF64_R_SYM( rel->r_info );

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

    /* TODO bounds check the target? */

    /* Register new entry */
    uint hash;
    if( name_len >= 10UL && 0==strncmp( name, "entrypoint", name_len ) ) {
      /* Skip insertion of "entrypoint" relocation entries to calldests. This
         emulates Solana/Agave's behavior of unregistering these entries before
         registering the entrypoint manually.
         Entrypoint is registered in fd_sbpf_program_load.
         Hash is still applied. */
      hash = 0x71e3cf81;
    } else {
      hash = fd_pchash( (uint)target_pc );
      if( FD_LIKELY( target_pc < (info->rodata_sz / 8UL ) ) )
        fd_sbpf_calldests_insert( loader->calldests, target_pc );
    }

    /* Check for collision with syscall ID
       https://github.com/solana-labs/rbpf/blob/57139e9e1fca4f01155f7d99bc55cdcc25b0bc04/src/program.rs#L142-L146 */
    REQUIRE( !fd_sbpf_syscalls_query( loader->syscalls, (ulong)hash, NULL ) );
    V = (uint)hash;
  } else {
    /* FIXME Should cache Murmur hashes.
             If max ELF size is 10MB, can fit about 640k relocs.
             Each reloc could point to a symbol with the same st_name,
             which results in 640MB hash input data without caching.  */
    uint hash = fd_murmur3_32( name, name_len, 0UL );
    /* Ensure that requested syscall ID exists only when deploying
       https://github.com/solana-labs/rbpf/blob/v0.8.0/src/elf.rs#L1097 */
    if ( FD_UNLIKELY( loader->elf_deploy_checks ) ) {
      REQUIRE( fd_sbpf_syscalls_query( loader->syscalls, (ulong)hash, NULL ) );
    }

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
    ulong insn = *((ulong *) ptr);

    /* Check for call instruction.  If immediate is UINT_MAX, assume
       that compiler generated a relocation instead. */
    ulong opc  = insn & 0xFF;
    int   imm  = (int)(insn >> 32UL);
    if( (opc!=FD_SBPF_OP_CALL_IMM) | (imm==-1) )
      continue;

    /* Mark function call destination */
    long target_pc_s;
    REQUIRE( 0==__builtin_saddl_overflow( (long)i+1L, imm, &target_pc_s ) );
    ulong target_pc = (ulong)target_pc_s;
    REQUIRE( target_pc<insn_cnt );  /* bounds check target */

    fd_sbpf_calldests_insert( calldests, target_pc );

    /* Replace immediate with hash */
    uint pc_hash = fd_pchash( (uint)target_pc );
    /* Check for collision with syscall ID
       https://github.com/solana-labs/rbpf/blob/57139e9e1fca4f01155f7d99bc55cdcc25b0bc04/src/program.rs#L142-L146 */
    REQUIRE( !fd_sbpf_syscalls_query( loader->syscalls, (ulong)pc_hash, NULL ) );

    FD_STORE( uint, ptr+4UL, pc_hash );
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
fd_sbpf_program_load_old( fd_sbpf_program_t *  prog,
                          void const *         _bin,
                          ulong                elf_sz,
                          fd_sbpf_syscalls_t * syscalls,
                          int                  elf_deploy_checks ) {
  fd_sbpf_loader_seterr( 0, 0 );

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
    .elf_deploy_checks = elf_deploy_checks
  };

  // /* Find dynamic section */
  // if( FD_UNLIKELY( (err=fd_sbpf_find_dynamic( &loader, elf, elf_sz, &prog->info ))!=0 ) )
  //   return err;

  // /* Load dynamic section */
  // if( FD_UNLIKELY( (err=fd_sbpf_load_dynamic( &loader, elf, elf_sz ))!=0 ) )
  //   return err;

  /* Register entrypoint to calldests. */
  fd_sbpf_calldests_insert( prog->calldests, prog->entry_pc );

  /* Copy rodata segment */
  // fd_memcpy( prog->rodata, elf->bin, prog->info.rodata_footprint );

  // /* Convert calls with PC relative immediate to hashes */
  // if( FD_UNLIKELY( (err=fd_sbpf_hash_calls  ( &loader, prog, elf ))!=0 ) )
  //   return err;

  /* Apply relocations */
  if( FD_UNLIKELY( (err=fd_sbpf_relocate    ( &loader, elf, elf_sz, prog->rodata, &prog->info ))!=0 ) )
    return err;

  /* Create read-only segment */
  if( FD_UNLIKELY( (err=fd_sbpf_zero_rodata( elf, prog->rodata, &prog->info ))!=0 ) )
    return err;

  return 0;
}

int
fd_sbpf_program_get_sbpf_version_or_err( void const *                    bin,
                                         ulong                           bin_sz,
                                         fd_sbpf_loader_config_t const * config ) {
  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L376-L381 */
  const ulong E_FLAGS_OFFSET = 48UL;
  const uint  E_FLAGS_SBPF_V2 = 0x20;

  if( FD_UNLIKELY( bin_sz < E_FLAGS_OFFSET+sizeof(uint) ) ) {
    return FD_SBPF_ELF_PARSER_ERR_OUT_OF_BOUNDS;
  }
  uint e_flags = fd_uint_load_4( (uchar const *)bin + E_FLAGS_OFFSET );

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

static int
fd_sbpf_elf_peek_strict( fd_sbpf_elf_info_t *            info,
                         void const *                    bin,
                         ulong                           bin_sz,
                         fd_sbpf_loader_config_t const * config ) {
  (void)config;

  /* Parse file header */

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L425
     https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L278
     (Agave does some extra checks on alignment, but they don't seem necessary) */
  if( FD_UNLIKELY( bin_sz<sizeof(fd_elf64_ehdr) ) ) {
    return FD_SBPF_ELF_PARSER_ERR_OUT_OF_BOUNDS;
  }

  fd_elf64_ehdr ehdr = FD_LOAD( fd_elf64_ehdr, bin );

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L430-L453 */
  ulong program_header_table_end = sizeof(fd_elf64_ehdr) + ehdr.e_phnum*sizeof(fd_elf64_phdr);

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

  info->rodata_sz        = (uint)phdr[ 1 ].p_memsz;
  info->rodata_footprint = (uint)bin_sz;
  info->entry_pc         = (uint)entry_pc;
  info->text_off         = (uint)phdr[ 0 ].p_offset;
  info->text_sz          = (uint)phdr[ 0 ].p_memsz;
  info->text_cnt         = (uint)( phdr[ 0 ].p_memsz / 8UL );

  return 0;
}

static inline int
fd_sbpf_check_overlap( ulong a_start, ulong a_end, ulong b_start, ulong b_end ) {
  return !( ( a_end <= b_start || b_end <= a_start ) );
}

int
fd_sbpf_lenient_get_string_in_section( char *                string,
                                       fd_elf64_shdr const * section_header,
                                       uint                  offset_in_section,
                                       ulong                 maximum_length,
                                       void const *          bin,
                                       ulong                 bin_sz ) {
  /* This could be checked only once outside the loop, but to keep the code the same...
     https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L474-L476 */
  if( FD_UNLIKELY( section_header->sh_type != FD_ELF_SHT_STRTAB ) ) {
    return FD_SBPF_ELF_PARSER_ERR_INVALID_SECTION_HEADER;
  }

  /* default to -1 because length check is done checking for 0... */
  memset( string, -1, maximum_length );

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L477-L482 */
  ulong offset_in_file = section_header->sh_offset + (ulong)offset_in_section; /* can't overflow */
  ulong offset_in_file_plus_maximum_length = offset_in_file + FD_SBPF_SECTION_NAME_SZ_MAX; /* can't overflow */
  ulong sh_end = section_header->sh_offset + section_header->sh_size; /* already checked */
  ulong string_range_start = offset_in_file;
  ulong string_range_end = fd_ulong_min( offset_in_file_plus_maximum_length, sh_end );
  if( FD_UNLIKELY( string_range_end > bin_sz ) ) {
    return FD_SBPF_ELF_PARSER_ERR_OUT_OF_BOUNDS;
  }
  /* In rust vec.get([n..n]) returns [], so this is accepted.
      vec.get([n..m]) with m<n returns None, so it throws ElfParserError::OutOfBounds. */
  if( FD_UNLIKELY( string_range_end < string_range_start ) ) {
    return FD_SBPF_ELF_PARSER_ERR_OUT_OF_BOUNDS;
  }

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L483-L485 */
  memcpy( string, (uchar const *)bin + string_range_start, string_range_end - string_range_start );

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L486-L495 */
  int found = 0;
  for( ulong j=0; j<FD_SBPF_SECTION_NAME_SZ_MAX; j++ ) {
    if( string[ j ] == 0x00 ) {
      found = 1;
      break;
    }
  }
  if( FD_UNLIKELY( !found ) ) {
    return FD_SBPF_ELF_PARSER_ERR_STRING_TOO_LONG;
  }
  return 0;
}

/* TODO: Normalize the error codes.
   Elf64::parse()
   https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L148 */
int
fd_sbpf_lenient_elf_parse( fd_sbpf_elf_info_t *            info,
                           void const *                    bin,
                           ulong                           bin_sz,
                           fd_sbpf_loader_config_t const * config ) {
  (void)config;

  /* This documents the values that will be set in this function */
  info->rodata_sz        = (uint)bin_sz; // FIXME
  info->rodata_footprint = (uint)bin_sz;
  info->dynstr_off       = 0U;
  info->dynstr_sz        = 0U;
  info->phndx_dyn        = -1;
  info->shndx_dyn        = -1;
  info->shndx_symtab     = -1;
  info->shndx_strtab     = -1;
  info->shndx_dynstr     = -1;
  info->dt_symtab        = -1;

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L149 */
  if( FD_UNLIKELY( bin_sz<sizeof(fd_elf64_ehdr) ) ) {
    return FD_SBPF_ELF_PARSER_ERR_OUT_OF_BOUNDS;
  }
  /* TODO: decide whether we want to enforce that bin is aligned,
           in which case we can simply cast pointers to the various
           table entries, or if we want to allow misaligned bin,
           in which case we have to keep the FD_LOAD calls. */
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)bin, 8UL ) ) ) {
    return FD_SBPF_ELF_PARSER_ERR_INVALID_ALIGNMENT;
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

  ulong phdr_sz = sizeof(fd_elf64_phdr) * (ulong)( ehdr.e_phnum ); /* this can't overflow */
  ulong phdr_start = ehdr.e_phoff;
  ulong phdr_end = phdr_sz + ehdr.e_phoff;
  /* Elf64::parse_program_header_table() */
  {
    if( FD_UNLIKELY( phdr_end < phdr_sz ) ) { /* add overflow */
      /* ArithmeticOverflow -> ElfParserError::OutOfBounds
        https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L671-L675 */
      return FD_SBPF_ELF_PARSER_ERR_OUT_OF_BOUNDS;
    }

    /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L301 */
    if( FD_UNLIKELY( fd_sbpf_check_overlap( ehdr_start, ehdr_end, phdr_start, phdr_end ) ) ) {
      return FD_SBPF_ELF_PARSER_ERR_OVERLAP;
    }

    /* Ensure program header table range lies within the file, like slice_from_bytes */
    if( FD_UNLIKELY( phdr_end > bin_sz ) ) {
      return FD_SBPF_ELF_PARSER_ERR_OUT_OF_BOUNDS;
    }
  }

  /* Section headers
     https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L167-L172 */

  ulong shdr_sz = sizeof(fd_elf64_shdr) * (ulong)( ehdr.e_shnum ); /* this can't overflow */
  ulong shdr_start = ehdr.e_shoff;
  ulong shdr_end = shdr_sz + ehdr.e_shoff;
  /* Elf64::parse_section_header_table() */
  {
    /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L314-L317 */
    if( FD_UNLIKELY( shdr_end < shdr_sz ) ) { /* add overflow */
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

    /* Ensure section header table range lies within the file, like slice_from_bytes */
    if( FD_UNLIKELY( shdr_end > bin_sz ) ) {
      return FD_SBPF_ELF_PARSER_ERR_OUT_OF_BOUNDS;
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
    if( FD_UNLIKELY( phdr.p_vaddr < vaddr ) ) {
      return FD_SBPF_ELF_PARSER_ERR_INVALID_PROGRAM_HEADER;
    }
    if( FD_UNLIKELY( phdr.p_offset + phdr.p_filesz < phdr.p_offset ) ) { /* add overflow */
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
    if( FD_UNLIKELY( shdr.sh_type == FD_ELF_SHT_NOBITS ) ) {
      continue;
    }

    /* Remember first SHT_DYNAMIC section header for dynamic parsing */
    if( shdr.sh_type==FD_ELF_SHT_DYNAMIC && info->shndx_dyn == -1 ) {
      info->shndx_dyn = (int)i;
    }

    ulong sh_start = shdr.sh_offset;
    ulong sh_end = shdr.sh_offset + shdr.sh_size;
    if( FD_UNLIKELY( sh_end < sh_start ) ) { /* add overflow */
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

      char name[ FD_SBPF_SECTION_NAME_SZ_MAX ];
      int res = fd_sbpf_lenient_get_string_in_section( name, &section_names_shdr, shdr.sh_name, FD_SBPF_SECTION_NAME_SZ_MAX, bin, bin_sz );
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
        */
      if(        fd_memeq( name, ".symtab", sizeof(".symtab") ) ) {
        if( FD_UNLIKELY( info->shndx_symtab != -1 ) ) {
          return FD_SBPF_ELF_PARSER_ERR_INVALID_SECTION_HEADER;
        }
        info->shndx_symtab = (int)i;
      } else if( fd_memeq( name, ".strtab", sizeof(".strtab") ) ) {
        if( FD_UNLIKELY( info->shndx_strtab != -1 ) ) {
          return FD_SBPF_ELF_PARSER_ERR_INVALID_SECTION_HEADER;
        }
        info->shndx_strtab = (int)i;
      } else if( fd_memeq( name, ".dynstr", sizeof(".dynstr") ) ) {
        if( FD_UNLIKELY( info->shndx_dynstr != -1 ) ) {
          return FD_SBPF_ELF_PARSER_ERR_INVALID_SECTION_HEADER;
        }
        info->shndx_dynstr = (int)i;
        info->dynstr_off   = (uint)shdr.sh_offset;
        info->dynstr_sz    = (uint)shdr.sh_size;
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

      /* slice_from_program_header also checks that the size of the slice is a multiple of the type size */
      if( FD_UNLIKELY( ( dynamic_table_end < dynamic_table_start )
                    |  ( dynamic_table_end > bin_sz )
                    |  ( dyn_ph.p_filesz % sizeof(fd_elf64_dyn) != 0UL ) ) ) {
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
      dynamic_table_end = dyn_sh.sh_offset + dyn_sh.sh_size;
      if( FD_UNLIKELY( ( dynamic_table_end < dynamic_table_start )
                    |  ( dynamic_table_end > bin_sz )
                    |  ( dyn_sh.sh_size % sizeof(fd_elf64_dyn) != 0UL ) ) ) {
        /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L382-L385 */
        return FD_SBPF_ELF_PARSER_ERR_INVALID_DYNAMIC_SECTION_TABLE;
      }
    }

    /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L393 */
    if( dynamic_table_start==ULONG_MAX ) {
      return 0;
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
        if( FD_UNLIKELY( phdr.p_vaddr + phdr.p_memsz < phdr.p_vaddr ) ) {
          return FD_SBPF_ELF_PARSER_ERR_OUT_OF_BOUNDS;
        }
        if( phdr.p_vaddr <= vaddr && vaddr < phdr.p_vaddr + phdr.p_memsz ) {
          /* vaddr - phdr.p_vaddr is guaranteed to be non-negative */
          offset = vaddr - phdr.p_vaddr + phdr.p_offset;
          if( FD_UNLIKELY( offset < phdr.p_offset ) ) {
            return FD_SBPF_ELF_PARSER_ERR_OUT_OF_BOUNDS;
          }
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
      if( FD_UNLIKELY( ( ( size % sizeof(fd_elf64_rel) ) != 0UL )
                       | ( offset + size < offset )
                       | ( offset + size > bin_sz ) ) ) {
        return FD_SBPF_ELF_PARSER_ERR_INVALID_DYNAMIC_SECTION_TABLE;
      }

      /* Save the dynamic relocation table info */
      info->dt_reloff = (uint)offset;
      info->dt_relsz  = (uint)size;
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
          info->dt_symtab = (int)i;
          break;
        }
      }

      /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L457-L461 */
      if( FD_UNLIKELY( info->dt_symtab==-1 ) ) {
        return FD_SBPF_ELF_PARSER_ERR_INVALID_DYNAMIC_SECTION_TABLE;
      }

      /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L463-L464 */
      {
        if( FD_UNLIKELY( shdr_sym.sh_type != FD_ELF_SHT_SYMTAB && shdr_sym.sh_type != FD_ELF_SHT_DYNSYM ) ) {
          return FD_SBPF_ELF_PARSER_ERR_INVALID_SECTION_HEADER;
        }
        ulong shdr_sym_start = shdr_sym.sh_offset;
        ulong shdr_sym_end = shdr_sym.sh_offset + shdr_sym.sh_size;
        if( FD_UNLIKELY( ( shdr_sym_end < shdr_sym_start )
                      |  ( shdr_sym_end > bin_sz )
                      |  ( shdr_sym.sh_size % sizeof(fd_elf64_sym) != 0UL ) ) ) {
          return FD_SBPF_ELF_PARSER_ERR_INVALID_SIZE;
        }
      }
    } while( 0 ); /* so we can break out */
  }

  return 0;
}

/* TODO: Document this function.
   TODO: Normalize the error codes.
   TODO: Convert ElfParserError error codes to ElfError. */
int
fd_sbpf_lenient_elf_validate( fd_sbpf_elf_info_t *            info,
                              void const *                    bin,
                              ulong                           bin_sz,
                              fd_sbpf_loader_config_t const * config,
                              fd_elf64_shdr *                 text_shdr ) {
  (void)config;

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

  int shndx_text = -1;
  int writeable_err = 0;
  for( ulong i=0; i<ehdr.e_shnum; i++ ) {
    /* Again... */
    fd_elf64_shdr shdr = FD_LOAD( fd_elf64_shdr, bin + ehdr.e_shoff + i*sizeof(fd_elf64_shdr) );

    char name[ FD_SBPF_SECTION_NAME_SZ_MAX ];
    int res = fd_sbpf_lenient_get_string_in_section( name, &section_names_shdr, shdr.sh_name, FD_SBPF_SECTION_NAME_SZ_MAX, bin, bin_sz );
    if( FD_UNLIKELY( res < 0 ) ) {
      /* this can never fail because it was checked above, but safer to keep it */
      return res;
    }

    /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L765-L775 */
    if( FD_UNLIKELY( fd_memeq( name, ".text", sizeof(".text") ) ) ) {
      if( FD_UNLIKELY( shndx_text==-1 ) ) {
        *text_shdr = shdr;  /* Store the text section header */
        shndx_text = (int)i;
      } else {
        return FD_SBPF_ELF_ERR_NOT_ONE_TEXT_SECTION;
      }
    }

    /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L780-L791 */
    if( FD_UNLIKELY(
      fd_memeq( name, ".bss", sizeof(".bss")-1UL ) /* starts with */
      || (
        ( ( shdr.sh_flags & (FD_ELF_SHF_ALLOC | FD_ELF_SHF_WRITE) ) == (FD_ELF_SHF_ALLOC | FD_ELF_SHF_WRITE) )
        &&  fd_memeq( name, ".data", sizeof(".data")-1UL ) /* starts with */
        && !fd_memeq( name, ".data.rel", sizeof(".data.rel")-1UL ) /* starts with */
      )
    ) ) {
      /* to match Agave return error we can't fail here */
      writeable_err = 1;
    }

    /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L793-L802
       Out of bound checkes were already done during elf_parse, so nothing to do here. */
  }

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L786-L788 */
  if( FD_UNLIKELY( writeable_err ) ) {
    return FD_SBPF_ELF_ERR_WRITABLE_SECTION_NOT_SUPPORTED;
  }

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L804-L806 */
  if( FD_UNLIKELY( !(
    text_shdr->sh_addr <= ehdr.e_entry && ehdr.e_entry < fd_ulong_sat_add( text_shdr->sh_addr, text_shdr->sh_size )
  ) ) ) {
    return FD_SBPF_ELF_ERR_ENTRYPOINT_OUT_OF_BOUNDS;
  }

  ulong entry_off = fd_ulong_sat_sub( ehdr.e_entry, text_shdr->sh_addr );
  info->entry_pc         = (uint)( entry_off / 8UL );
  info->text_off         = (uint)text_shdr->sh_offset;
  info->text_sz          = (uint)text_shdr->sh_size;
  info->text_cnt         = (uint)( text_shdr->sh_size / 8UL );
  info->shndx_text       = shndx_text;

  return 0;
}

/* TODO: Document this function.

   TODO: Convert ElfParserError error codes to ElfError. */
static int
fd_sbpf_elf_peek_lenient( fd_sbpf_elf_info_t *            info,
                          void const *                    bin,
                          ulong                           bin_sz,
                          fd_sbpf_loader_config_t const * config ) {
//FIXME
#if 0
  fd_sbpf_elf_info_t * res = fd_sbpf_elf_peek_old( info, bin, bin_sz, config->elf_deploy_checks, config->sbpf_min_version, config->sbpf_max_version );
  return res==NULL ? FD_SBPF_ELF_PARSER_ERR_INVALID_FILE_HEADER : 0;
#else
  (void)config;
  int res;

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L607 */
  if( FD_UNLIKELY( res=fd_sbpf_lenient_elf_parse( info, bin, bin_sz, config )<0 ) ) {
    return res;
  }

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L617 */
  fd_elf64_shdr text_shdr = { 0 };
  if( FD_UNLIKELY( res=fd_sbpf_lenient_elf_validate( info, bin, bin_sz, config, &text_shdr )<0 ) ) {
    return res;
  }

  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L620-L638 */
  {
    ulong sbpf_version = info->sbpf_version;
    ulong text_section_vaddr;
    if( fd_sbpf_enable_elf_vaddr( sbpf_version ) && text_shdr.sh_addr >= FD_SBPF_MM_RODATA_ADDR ) {
      text_section_vaddr = text_shdr.sh_addr;
    } else {
      text_section_vaddr = fd_ulong_sat_add( text_shdr.sh_addr, FD_SBPF_MM_RODATA_ADDR );
    }

    ulong vaddr_end;
    if( fd_sbpf_reject_rodata_stack_overlap( sbpf_version ) ) {
      vaddr_end = fd_ulong_sat_add( text_section_vaddr, text_shdr.sh_size );
    } else {
      vaddr_end = text_section_vaddr;
    }

    /* Validate bounds - reject broken ELFs */
    if( FD_UNLIKELY(
        (
          config->reject_broken_elfs
          && !fd_sbpf_enable_elf_vaddr( sbpf_version )
          && text_shdr.sh_addr != text_shdr.sh_offset
        )
        || ( vaddr_end > FD_SBPF_MM_STACK_ADDR )
    ) ) {
      return FD_SBPF_ELF_PARSER_ERR_OUT_OF_BOUNDS;
    }
  }

  /* Peek (vs load) stops here
     https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L638 */

  return 0;
#endif
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
    .text_off         = 0U,
    .text_cnt         = 0U,
    .text_sz          = 0UL,
    .dynstr_off       = 0U,
    .dynstr_sz        = 0U,
    .rodata_sz        = 0U,
    .rodata_footprint = 0U,
    .shndx_text       = -1,
    .shndx_symtab     = -1,
    .shndx_strtab     = -1,
    .shndx_dyn        = -1,
    .shndx_dynstr     = -1,
    .phndx_dyn        = -1,
    .dt_rel           = -1,
    .dt_relent        = -1,
    .dt_relsz         = -1,
    .dt_symtab        = -1,
    .dyn_off          = UINT_MAX,
    .dyn_cnt          = 0U,
    .entry_pc         = 0U,
    .sbpf_version     = (uint)maybe_sbpf_version,
    /* !!! Keep this in sync with -Werror=missing-field-initializers */
  };

  /* Invoke strict vs lenient parser. The strict parser is used for
     SBPF version >= 3.
     https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L403-L407 */
  if( FD_UNLIKELY( fd_sbpf_enable_stricter_elf_headers( info->sbpf_version ) ) ) {
    return fd_sbpf_elf_peek_strict( info, bin, bin_sz, config );
  }
  return fd_sbpf_elf_peek_lenient( info, bin, bin_sz, config );
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
  fd_sbpf_elf_info_t const * elf_info  = &prog->info;
  fd_sbpf_elf_t const *      elf       = fd_type_pun_const( bin );
  uchar *                    rodata    = prog->rodata;
  fd_elf64_shdr const *      shdrs     = (fd_elf64_shdr const *)( elf->bin + elf->ehdr.e_shoff );
  fd_elf64_shdr const *      shtext    = &shdrs[ elf_info->shndx_text ];
  fd_sbpf_calldests_t *      calldests = loader->calldests;

  /* Copy rodata segment */
  fd_memcpy( rodata, elf->bin, prog->info.rodata_sz );

  /* Fixup all program counter relative call instructions
     https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1005-L1041 */
  {
    /* Validate the bytes range of the text section.
       https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1006-L1008 */
    ulong lo, hi;
    uchar is_some = fd_shdr_get_file_range( shtext, &lo, &hi );
    if( FD_UNLIKELY( !is_some ) ) {
      return FD_SBPF_ELF_ERR_VALUE_OUT_OF_BOUNDS;
    }

    ulong insn_cnt = (lo - hi) / 8UL;
    if( FD_UNLIKELY( shtext->sh_size+shtext->sh_offset>bin_sz ) ) {
      return FD_SBPF_ELF_ERR_VALUE_OUT_OF_BOUNDS;
    }

    uchar * ptr = rodata + shtext->sh_offset;

    for( ulong i=0; i<insn_cnt; i++, ptr+=8UL ) {
      ulong insn = *((ulong *) ptr);

      /* Check for call instruction.  If immediate is UINT_MAX, assume
         that compiler generated a relocation instead.
         https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1015 */
      ulong opc  = insn & 0xFF;
      int   imm  = (int)(insn >> 32UL);
      if( (opc!=FD_SBPF_OP_CALL_IMM) | (imm==-1) ) continue;

      /* Calculate and check the target PC
         https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1016-L1021 */
      long target_pc = fd_long_sat_add( fd_long_sat_add( (long)i, 1L ), imm);
      if( FD_UNLIKELY( target_pc<0L || target_pc>=(long)insn_cnt ) ) {
        return FD_SBPF_ELF_ERR_RELATIVE_JUMP_OUT_OF_BOUNDS;
      }

      /* register_function_hashed_legacy() */
      {
        /* Update the calldests
           https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1027-L1032 */
        fd_sbpf_calldests_insert( calldests, (ulong)target_pc );

        /* Check for collision with syscall ID
           https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/program.rs#L161-L163 */
        uint pc_hash = fd_pchash( (uint)target_pc );
        if( FD_UNLIKELY( fd_sbpf_syscalls_query( loader->syscalls, (ulong)pc_hash, NULL ) ) ) {
          return FD_SBPF_ELF_ERR_SYMBOL_HASH_COLLISION;
        }

        if( !fd_sbpf_static_syscalls( elf_info->sbpf_version ) ) {
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
    }
  }

  /* Fixup all the relocations in the relocation section if exists
     https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1046-L1304 */
  {
    fd_elf64_phdr const * phdr           = (fd_elf64_phdr const *)( elf->bin + elf->ehdr.e_phoff );
    ushort                pht_cnt        = elf->ehdr.e_phnum;
    fd_elf64_phdr const * program_header = NULL;
    fd_elf64_rel const *  dt_rel         = (fd_elf64_rel const *)( elf->bin + elf_info->dt_reloff );
    uint                  dt_rel_cnt     = elf_info->dt_relsz / sizeof(fd_elf64_rel);

    for( uint i=0U; i<dt_rel_cnt; i++ ) {
      fd_elf64_rel const * rel      = &dt_rel[ i ];
      ulong                r_offset = rel->r_offset;

      /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1052-L1066 */
      if( fd_sbpf_enable_elf_vaddr( elf_info->sbpf_version ) ) {

        /* Inverting this condition for readability...
           https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1053-L1061 */
        if( !( program_header &&
               program_header->p_vaddr<=r_offset &&
               r_offset<fd_ulong_sat_add( program_header->p_vaddr, program_header->p_memsz ) ) ) {

          /* Iterate through the program header table to find the header
             https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1056-L1059 */
          for( ushort j=0; j<pht_cnt; j++ ) {
            fd_elf64_phdr const * header = &phdr[ j ];
            if( header->p_vaddr<=r_offset &&
                r_offset<fd_ulong_sat_add( header->p_vaddr, header->p_memsz ) ) {
              program_header = header;
              break;
            }
          }
        }

        /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1062-L1065 */
        if( FD_UNLIKELY( !program_header ) ) {
          return FD_SBPF_ELF_ERR_VALUE_OUT_OF_BOUNDS;
        }
        r_offset = fd_ulong_sat_add( fd_ulong_sat_sub( r_offset, program_header->p_vaddr ),
                                     program_header->p_offset );
      }

      /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L1068-L1303 */
      switch( FD_ELF64_R_TYPE( rel->r_info ) ) {
        case FD_ELF_R_BPF_64_64:
          return fd_sbpf_r_bpf_64_64      ( loader, elf, bin_sz, rodata, elf_info, rel );
        case FD_ELF_R_BPF_64_RELATIVE:
          return fd_sbpf_r_bpf_64_relative(         elf, bin_sz, rodata, elf_info, rel );
        case FD_ELF_R_BPF_64_32:
          return fd_sbpf_r_bpf_64_32      ( loader, elf, bin_sz, rodata, elf_info, rel );
        default:
          ERR( FD_SBPF_ERR_INVALID_ELF );
      }
    }
  }

  return FD_SBPF_ELF_SUCCESS;
}

/* Second part of load_with_lenient_parser().

   TODO: Explain what this function does.

   Returns 0 on success and an ElfError error code on failure.

   https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L640-L689
 */
static int
fd_sbpf_program_load_lenient( fd_sbpf_program_t *             prog,
                              void const *                    bin,
                              ulong                           bin_sz,
                              fd_sbpf_loader_t *              loader,
                              fd_sbpf_loader_config_t const * config ) {
  /* Load (vs peek) starts here
     https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L641 */
#if 0
  return fd_sbpf_program_load_old( prog, bin, bin_sz, syscalls, config->elf_deploy_checks );
#else
  /* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L642-L647 */
  int err = fd_sbpf_program_relocate( prog, bin, bin_sz, config, loader );
  if( FD_UNLIKELY( err ) ) return err;

  return FD_SBPF_ELF_SUCCESS;
#endif
}

int
fd_sbpf_program_load( fd_sbpf_program_t *             prog,
                      void const *                    bin,
                      ulong                           bin_sz,
                      fd_sbpf_syscalls_t *            syscalls,
                      fd_sbpf_loader_config_t const * config ) {
  /* TODO: a lot of these fields seem redundant... */
  fd_sbpf_loader_t loader = {
    .calldests         = prog->calldests,
    .syscalls          = syscalls,

    .dyn_off           = 0U,
    .dyn_cnt           = 0U,

    .dt_rel            = 0UL,
    .dt_relent         = 0UL,
    .dt_relsz          = 0UL,
    .dt_symtab         = 0UL,

    .dynsym_off        = 0U,
    .dynsym_cnt        = 0U,
    .elf_deploy_checks = config->elf_deploy_checks
  };

  /* Invoke strict vs lenient loader
     Note: info.sbpf_version is already set by fd_sbpf_program_parse()
     https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L403-L409 */
  if( FD_UNLIKELY( fd_sbpf_enable_stricter_elf_headers( prog->info.sbpf_version ) ) ) {
    /* There is nothing else to do in the strict case*/
    return FD_SBPF_ELF_SUCCESS;
  }
  return fd_sbpf_program_load_lenient( prog, bin, bin_sz, &loader, config );
}

#undef ERR
#undef FAIL
#undef REQUIRE
