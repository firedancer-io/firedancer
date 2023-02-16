#include "fd_sbpf_loader.h"

#include "../../util/fd_util.h"

#include <stdio.h>

/* Thread-local error storage *****************************************/

static FD_TLS int ldr_errno     =  0;
static FD_TLS int ldr_err_srcln = -1;

int
fd_sbpf_loader_seterr( int err,
                       int srcln ) {
  ldr_errno     = err;
  ldr_err_srcln = srcln;
  return err;
}

#define ERR( err ) return fd_sbpf_loader_seterr( (err), __LINE__ )
#define FAIL()  ERR( FD_SBPF_ERR_INVALID_ELF )
#define REQUIRE(x) if( FD_UNLIKELY( !(x) ) ) FAIL()

#define FD_SBPF_ERRBUF_SZ (128UL)
static FD_TLS char fd_sbpf_errbuf[ FD_SBPF_ERRBUF_SZ ] = {0};

char const *
fd_sbpf_strerror( void ) {
  if( FD_UNLIKELY( ldr_errno==0 ) )
    strcpy( fd_sbpf_errbuf, "ok" );
  else
    snprintf( fd_sbpf_errbuf, FD_SBPF_ERRBUF_SZ,
              "code %d at %s(%d)", ldr_errno, __FILE__, ldr_err_srcln );
  return fd_sbpf_errbuf;
}

/* ELF loader *********************************************************/

static int
fd_sbpf_check_ehdr( fd_elf64_ehdr * ehdr
                    /*ulong           bin_sz*/ ) {

  /* Validate ELF magic: "\x7fELF" */
  REQUIRE( ehdr->e_ident[ EI_MAG0 ]==ELFMAG0 &&
           ehdr->e_ident[ EI_MAG1 ]==ELFMAG1 &&
           ehdr->e_ident[ EI_MAG2 ]==ELFMAG2 &&
           ehdr->e_ident[ EI_MAG3 ]==ELFMAG3 );

  /* Validate file type/target identification */
  REQUIRE( ehdr->e_ident[ EI_CLASS      ]==ELFCLASS64    );
  REQUIRE( ehdr->e_ident[ EI_DATA       ]==ELFDATA2LSB   );
  REQUIRE( ehdr->e_ident[ EI_VERSION    ]==1             );
  REQUIRE( ehdr->e_ident[ EI_OSABI      ]==ELFOSABI_NONE );
  REQUIRE( ehdr->e_ident[ EI_ABIVERSION ]==0             );

  /* Validate ... */
  REQUIRE( ehdr->e_type     ==ET_DYN                );
  REQUIRE( ehdr->e_machine  ==EM_BPF                );
  REQUIRE( ehdr->e_ehsize   ==sizeof(fd_elf64_ehdr) );
  REQUIRE( ehdr->e_phentsize==sizeof(fd_elf64_phdr) );
  REQUIRE( ehdr->e_shentsize==sizeof(fd_elf64_shdr) );

  /* TODO overlap checks */

  return 0;
}

static int
fd_sbpf_load_phdrs( fd_sbpf_program_t * prog,
                    uchar * bin,
                    ulong   bin_sz ) {

  /* Fill in placeholders */
  prog->phndx_load = FD_SBPF_PHNDX_UNDEF;
  prog->phndx_dyn  = FD_SBPF_PHNDX_UNDEF;

  /* Bounds check program header table */

  ulong const phoff = prog->ehdr.e_phoff;
  ulong const phnum = prog->ehdr.e_phnum;
  REQUIRE( phoff<bin_sz ); /* out of bounds */

  REQUIRE( phnum<=(ULONG_MAX/sizeof(fd_elf64_phdr)) ); /* overflow */
  ulong const phsz = phnum*sizeof(fd_elf64_phdr);

  ulong const phoff_end = phoff+phsz;
  REQUIRE( phoff_end>=phoff  ); /* overflow */
  REQUIRE( phoff_end<=bin_sz ); /* out of bounds */

  /* TODO ALIGNMENT CHECK? */

  /* Read program header table */

  fd_elf64_phdr * const phdr = (fd_elf64_phdr *)(bin+phoff);
  prog->phdrs = phdr;

  for( ulong i=0; i<phnum; i++ ) {
    switch( phdr[i].p_type ) {
    case PT_DYNAMIC:
      /* Remember first PT_DYNAMIC segment */
      /* TODO: Fail on duplicate? */
      if( FD_LIKELY( prog->phndx_dyn==FD_SBPF_PHNDX_UNDEF ) )
        prog->phndx_dyn = i;
      break;
    case PT_LOAD:
      /* Remember last PT_LOAD segment */
      /* TODO: Solana's loader currently parses PT_LOAD but then does
               nothing with that data. */
      /* TODO: Why are we "loading" the first segment for PT_DYNAMIC and
               the last segment for PT_LOAD? */
      prog->phndx_load = i;
      FD_LOG_WARNING(( "Unhandled PT_LOAD" ));
      break;
    default:
      /* Ignore other segment types */
      break;
    }
  }

  return 0;
}

static int
fd_sbpf_load_shdrs( fd_sbpf_program_t * prog,
                    uchar * bin,
                    ulong   bin_sz ) {

  /* TODO */
  (void)bin;

  /* Bounds check section header table */

  ulong const shoff = prog->ehdr.e_shoff;
  ulong const shnum = prog->ehdr.e_shnum;
  REQUIRE( shoff<bin_sz ); /* out of bounds */
  REQUIRE( shnum>0UL    ); /* not enough sections */

  REQUIRE( shoff<=(ULONG_MAX/sizeof(fd_elf64_shdr)) ); /* overflow */
  ulong const shsz = shnum*sizeof(fd_elf64_shdr);

  ulong const shoff_end = shoff+shsz;
  REQUIRE( shoff_end>=shoff  ); /* overflow */
  REQUIRE( shoff_end<=bin_sz ); /* out of bounds */

  /* Start to walk section header table */

  fd_elf64_shdr * const shdr = (fd_elf64_shdr *)(bin+shoff);
  prog->shdrs = shdr;

  /* Require SHT_NULL at index 0 */

  REQUIRE( shdr[ 0 ].sh_type==SHT_NULL );

  /* Require SHT_STRTAB for section name table */

  REQUIRE( prog->ehdr.e_shstrndx < shnum ); /* out of bounds */
  REQUIRE( shdr[ prog->ehdr.e_shstrndx ].sh_type==SHT_STRTAB );

  ulong shstr_off = shdr[ prog->ehdr.e_shstrndx ].sh_offset;
  REQUIRE( shstr_off<bin_sz );

  /* Read section header table */

  for( ulong i=1; i<shnum; i++ ) {
    if( shdr[ i ].sh_type==SHT_DYNAMIC ) {
      /* Remember first SHT_DYNAMIC segment */
      /* TODO: Fail on duplicate? */
      if( FD_LIKELY( prog->shndx_dyn==i ) )
        prog->shndx_dyn = i;
    }

    /* TODO overlap checks */
    /* TODO check section offset order */
    /* TODO check section bounds */

    ulong name_off = shstr_off + (ulong)shdr[i].sh_name;
    REQUIRE( name_off<=bin_sz ); /* out of bounds */
    /* TODO Is it okay to create a zero-sz string at EOF? */

    /* Create name cstr */

    char __attribute__((aligned(8UL))) name[ 16UL ]={0};
    ulong name_sz = fd_ulong_min( bin_sz-name_off, 15UL );
    strncpy( name, (char const *)(bin+name_off), name_sz );

    /* Check name */
    /* TODO switch table for this? */

         if( 0==strcmp( name, ".bss"    ) )
      prog->shndx_bss    = i;
    else if( 0==strcmp( name, ".text"   ) )
      prog->shndx_text   = i;
    else if( 0==strcmp( name, ".symtab" ) )
      prog->shndx_symtab = i;
    else if( 0==strcmp( name, ".strtab" ) )
      prog->shndx_strtab = i;
    else if( 0==strcmp( name, ".dynstr" ) )
      prog->shndx_dynstr = i;
  }

  /* Various other arbitrary checks */

  return 0;
}

static int
fd_sbpf_load_dynamic( fd_sbpf_program_t * prog,
                      uchar * bin,
                      ulong   bin_sz ) {
  (void)bin;

  ulong dyn_off;
  ulong dyn_sz;

  if( prog->phndx_dyn!=FD_SBPF_PHNDX_UNDEF ) {
    dyn_off = prog->phdrs[ prog->phndx_dyn ].p_offset;
    dyn_sz  = prog->phdrs[ prog->phndx_dyn ].p_filesz;
    FD_LOG_NOTICE(( "Using dynamic segment (phndx=%lu off=%lu sz=%lu)",
                    prog->phndx_dyn, dyn_off, dyn_sz ));
  } else if( prog->shndx_dyn!=0UL ) {
    /* TODO this is obviously wrong */
    dyn_off = prog->shdrs[ prog->shndx_dyn ].sh_offset;
    dyn_sz  = prog->shdrs[ prog->shndx_dyn ].sh_size;
    FD_LOG_NOTICE(( "Using dynamic section (deprecated behavior) (shndx=%lu off=%lu sz=%lu)",
                    prog->shndx_dyn, dyn_off, dyn_sz ));
  } else {
    FD_LOG_ERR(( "TODO: ELF has neither dynamic segment nor section. What do we do?" ));
  }

  ulong const dyn_end = dyn_off+dyn_sz;

  REQUIRE( dyn_end>=dyn_off ); /* overflow */
  REQUIRE( dyn_off< bin_sz  ); /* out of bounds */
  REQUIRE( dyn_end<=bin_sz  ); /* out of bounds */
  REQUIRE( (dyn_sz%sizeof(fd_elf64_dyn))==0UL ); /* unaligned sz */

  /* Walk dynamic table */

  fd_elf64_dyn * dyns    = (fd_elf64_dyn *)(bin+dyn_off);
  ulong const    dyn_cnt = dyn_sz/sizeof(fd_elf64_dyn);

  for( ulong i=0; i<dyn_cnt; i++ ) {
    if( FD_UNLIKELY( dyns[i].d_tag==DT_NULL ) ) break;

    ulong d_val = dyns[i].d_un.d_val;
    switch( dyns[i].d_tag ) {
    case DT_REL:    prog->dt_rel   =d_val; break;
    case DT_RELENT: prog->dt_relent=d_val; break;
    case DT_RELSZ:  prog->dt_relsz =d_val; break;
    case DT_SYMTAB: prog->dt_symtab=d_val; break;
    }
  }

  return 0;
}

static int
fd_sbpf_relocate( fd_sbpf_program_t * prog,
                  uchar * bin,
                  ulong   bin_sz ) {
  /* Validate reloc table params */

  REQUIRE(  prog->dt_rel   !=0UL                        );
  REQUIRE(  prog->dt_relent==sizeof(fd_elf64_rel)       );
  REQUIRE(  prog->dt_relsz !=0UL                        );
  REQUIRE( (prog->dt_relsz % sizeof(fd_elf64_rel))==0UL );

  /* Virtual bounds check */

  ulong dyn_vaddr     = prog->phdrs[ prog->phndx_dyn ].p_vaddr;
  ulong dyn_end_vaddr = prog->phdrs[ prog->phndx_dyn ].p_memsz + dyn_vaddr;

  REQUIRE( prog->phndx_dyn!=FD_SBPF_PHNDX_UNDEF           );
  REQUIRE( prog->dt_rel                   >=dyn_vaddr     );
  REQUIRE( (prog->dt_rel + prog->dt_relsz)<=dyn_end_vaddr );

  /* Translate virtual address to file offset */

  ulong rel_off = prog->dt_rel - dyn_vaddr;
  ulong rel_cnt = prog->dt_relsz/sizeof(fd_elf64_rel);

  (void)rel_off;
  (void)rel_cnt;
  (void)bin;
  (void)bin_sz;

  /* !!! O(n*m) where n=rel_cnt m=sh_cnt */
  //fd_elf64_rel * rel = (fd_elf64_rel *)(bin+rel_off);
  //for( ulong i=0; i<rel_cnt; i++ ) {
  //
  //}

  return 0;
}

int
fd_sbpf_program_load( fd_sbpf_program_t * prog,
                      uchar * bin,
                      ulong   bin_sz ) {
  int err;

  /* Bounds check file header (starting at offset 0UL) */
  if( FD_UNLIKELY( bin_sz<sizeof(fd_elf64_ehdr) ) ) FAIL();

  /* Read file header */
  memcpy( &prog->ehdr, bin, sizeof(fd_elf64_ehdr) );

  /* Validate file header */
  if( FD_UNLIKELY( (err=fd_sbpf_check_ehdr( &prog->ehdr ))!=0 ) )
    return err;

  /* Program headers */
  if( FD_UNLIKELY( (err=fd_sbpf_load_phdrs  ( prog, bin, bin_sz ))!=0 ) )
    return err;

  /* Section headers */
  if( FD_UNLIKELY( (err=fd_sbpf_load_shdrs  ( prog, bin, bin_sz ))!=0 ) )
    return err;

  /* Dynamic section */
  if( FD_UNLIKELY( (err=fd_sbpf_load_dynamic( prog, bin, bin_sz ))!=0 ) )
    return err;

  /* Apply relocations */
  if( FD_UNLIKELY( (err=fd_sbpf_relocate    ( prog, bin, bin_sz ))!=0 ) )
    return err;

  return 0;
}
