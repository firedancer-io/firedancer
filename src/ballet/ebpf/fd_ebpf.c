#define _DEFAULT_SOURCE
#include "fd_ebpf.h"

#include "../elf/fd_elf.h"
#include "../../util/fd_util.h"

/* TODO this needs fuzzing + cbmc */

struct __attribute__((aligned(16UL))) fd_ebpf_known_sym {
  ulong value;
  uchar known;
};
typedef struct fd_ebpf_known_sym fd_ebpf_known_sym_t;

fd_ebpf_link_opts_t *
fd_ebpf_static_link( fd_ebpf_link_opts_t * opts,
                     void * elf,
                     ulong  elf_sz ) {

# define FD_ELF_REQUIRE(c) do { if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: %s", #c )); return NULL; } } while(0)

  FD_ELF_REQUIRE( opts->section );
  FD_ELF_REQUIRE( opts->sym_cnt==0 || opts->sym );
  FD_ELF_REQUIRE( opts );
  FD_ELF_REQUIRE( elf  );
  FD_ELF_REQUIRE( fd_ulong_is_aligned( (ulong)elf, 8UL ) );

  /* Load file header */

  FD_ELF_REQUIRE( elf_sz>=sizeof(fd_elf64_ehdr) );
  fd_elf64_ehdr const * eh = (fd_elf64_ehdr *)elf;

  FD_ELF_REQUIRE( eh->e_type == FD_ELF_ET_REL );

  /* Check file type */

  FD_ELF_REQUIRE( fd_uint_load_4( eh->e_ident ) == 0x464c457fU     );

  FD_ELF_REQUIRE( eh->e_ident[ FD_ELF_EI_CLASS   ] == FD_ELF_CLASS_64 );
  FD_ELF_REQUIRE( eh->e_ident[ FD_ELF_EI_DATA    ] == FD_ELF_DATA_LE  );
  FD_ELF_REQUIRE( eh->e_ident[ FD_ELF_EI_VERSION ] == 1               );

  FD_ELF_REQUIRE( eh->e_type    == FD_ELF_ET_REL );
  FD_ELF_REQUIRE( eh->e_machine == FD_ELF_EM_BPF );

  /* Load section header table */

  FD_ELF_REQUIRE( eh->e_shentsize == sizeof(fd_elf64_shdr) );

  FD_ELF_REQUIRE( eh->e_shoff  < elf_sz );
  FD_ELF_REQUIRE( eh->e_shnum  < 128    );
  ulong shoff_end = eh->e_shoff + eh->e_shnum*sizeof(fd_elf64_shdr);
  FD_ELF_REQUIRE( shoff_end    <= elf_sz );

  fd_elf64_shdr const * shdr = (fd_elf64_shdr *)( (ulong)elf + eh->e_shoff );

  /* Load section header string table */

  FD_ELF_REQUIRE( eh->e_shstrndx < eh->e_shnum );
  fd_elf64_shdr const * shstrtab = &shdr[ eh->e_shstrndx ];

  /* Walk section header table */

  fd_elf64_shdr const * prog     = NULL; ulong prog_shndx   = ULONG_MAX;
  fd_elf64_shdr const * rel_prog = NULL;
  fd_elf64_shdr const * symtab   = NULL; ulong symtab_shndx = ULONG_MAX;
  fd_elf64_shdr const * strtab   = NULL; ulong strtab_shndx = ULONG_MAX;

  for( ulong i=0; i < eh->e_shnum; i++ ) {
    ulong sh_name_off = shstrtab->sh_offset + shdr[ i ].sh_name;
    char const * sh_name = fd_elf_read_cstr( elf, elf_sz, sh_name_off, 128UL );
    if( !sh_name ) continue;

    switch( shdr[ i ].sh_type ) {
    case FD_ELF_SHT_PROGBITS:
      if( 0==strcmp( sh_name, opts->section ) ) {
        prog_shndx = i;
        prog       = &shdr[ i ];
      }
      break;
    case FD_ELF_SHT_REL:
      if( 0==strncmp( sh_name, ".rel", 4UL ) &&
          0== strcmp( sh_name+4, opts->section ) )
        rel_prog = &shdr[ i ];
      break;
    case FD_ELF_SHT_SYMTAB:
      if( 0==strcmp( sh_name, ".symtab" ) ) {
        symtab_shndx = i;
        symtab     = &shdr[ i ];
      }
      break;
    case FD_ELF_SHT_STRTAB:
      if( 0==strcmp( sh_name, ".strtab" ) ) {
        strtab_shndx = i;
        strtab     = &shdr[ i ];
      }
      break;
    default:
      continue;
    }
  }

  FD_ELF_REQUIRE( prog     );
  FD_ELF_REQUIRE( rel_prog );
  FD_ELF_REQUIRE( symtab   );
  FD_ELF_REQUIRE( strtab   );

  /* Load bytecode */

  FD_ELF_REQUIRE( prog->sh_offset                 < elf_sz );
  FD_ELF_REQUIRE( prog->sh_size                   < elf_sz );
  FD_ELF_REQUIRE( prog->sh_offset + prog->sh_size < elf_sz );
  ulong * code = (ulong *)( (ulong)elf + prog->sh_offset );
  FD_ELF_REQUIRE( fd_ulong_is_aligned( (ulong)code, 8UL ) );

  /* Load symbol table */

  FD_ELF_REQUIRE( symtab->sh_entsize == sizeof(fd_elf64_sym) );
  FD_ELF_REQUIRE( symtab->sh_offset                   < elf_sz );
  FD_ELF_REQUIRE( symtab->sh_size                     < elf_sz );
  FD_ELF_REQUIRE( symtab->sh_offset + symtab->sh_size < elf_sz );

  ulong sym_cnt = symtab->sh_size / sizeof(fd_elf64_sym);
  fd_elf64_sym const * sym = (fd_elf64_sym *)( (ulong)elf + symtab->sh_offset );

  /* Load string table */

  FD_ELF_REQUIRE( strtab->sh_offset                   < elf_sz );
  FD_ELF_REQUIRE( strtab->sh_size                     < elf_sz );
  FD_ELF_REQUIRE( strtab->sh_offset + strtab->sh_size < elf_sz );
  FD_ELF_REQUIRE( symtab->sh_link == strtab_shndx );

  /* Load relocation table */

  FD_ELF_REQUIRE( rel_prog->sh_entsize == sizeof(fd_elf64_rel) );
  FD_ELF_REQUIRE( rel_prog->sh_offset                     < elf_sz );
  FD_ELF_REQUIRE( rel_prog->sh_size                       < elf_sz );
  FD_ELF_REQUIRE( rel_prog->sh_offset + rel_prog->sh_size < elf_sz );
  FD_ELF_REQUIRE( rel_prog->sh_link == symtab_shndx );
  FD_ELF_REQUIRE( rel_prog->sh_info == prog_shndx   );

  ulong rel_cnt = rel_prog->sh_size / sizeof(fd_elf64_rel);
  fd_elf64_rel const * rel = (fd_elf64_rel *)( (ulong)elf + rel_prog->sh_offset );

  /* Create symbol mapping table */

  fd_ebpf_known_sym_t * sym_mapping = fd_alloca( alignof(fd_ebpf_known_sym_t), sizeof(fd_ebpf_known_sym_t)*sym_cnt );
  if( FD_UNLIKELY( !sym_mapping ) ) {
    FD_LOG_WARNING(( "fd_alloca failed" ));
    return NULL;
  }

  /* Walk symbol table */

  for( ulong i=0; i<sym_cnt; i++ ) {
    char const * sym_name = fd_elf_read_cstr( elf, elf_sz, strtab->sh_offset + sym[ i ].st_name, 128UL );
    if( !sym_name ) continue;

    /* TODO: O(n^2) complexity -- fine for now as factors are small */

    for( ulong j=0; j<opts->sym_cnt; j++ ) {
      if( 0==strcmp( sym_name, opts->sym[ j ].name ) ) {
        sym_mapping[ i ] = (fd_ebpf_known_sym_t) {
          .known = 1,
          .value = (ulong)(uint)opts->sym[ j ].value
        };
      }
    }
  }

  /* Apply relocations */

  for( ulong i=0; i<rel_cnt; i++ ) {
    FD_ELF_REQUIRE( rel[ i ].r_offset     < prog->sh_size );
    FD_ELF_REQUIRE( rel[ i ].r_offset+8UL < prog->sh_size );

    ulong r_sym  = FD_ELF64_R_SYM(  rel[ i ].r_info );
    ulong r_type = FD_ELF64_R_TYPE( rel[ i ].r_info );
    FD_ELF_REQUIRE( r_sym < sym_cnt );

    ulong S = sym_mapping[ r_sym ].value;

    /* TODO another bounds check? */

    switch( r_type ) {
    case FD_ELF_R_BPF_64_64: {
      ulong r_lo_off = prog->sh_offset + rel[ i ].r_offset +  4UL;
      ulong r_hi_off = prog->sh_offset + rel[ i ].r_offset + 12UL;

      FD_ELF_REQUIRE( fd_ulong_is_aligned( r_lo_off, 4UL ) );
      FD_ELF_REQUIRE( fd_ulong_is_aligned( r_hi_off, 4UL ) );
      FD_ELF_REQUIRE( r_hi_off+4UL < elf_sz );
      ulong * insn = (ulong *)( (ulong)elf + prog->sh_offset + rel[ i ].r_offset );

      ulong   insn0_pre  = insn[ 0 ];
      ulong   insn1_pre  = insn[ 1 ];

      ulong A     = insn0_pre>>32; /* implicit addend */
      ulong value = S + A;

      ulong   insn0_post = ( (insn0_pre&0xFFFFFFFF) | (value<<32               ) );
      ulong   insn1_post = ( (insn1_pre&0xFFFFFFFF) | (value&0xFFFFFFFF00000000) );

      /* FIXME: clang bug? relocations against eBPF map require
                src_reg==1 (BPF_PSEUDO_MAP_FD).  This is obviously
                not the intended behavior of R_BPF_64_64, which just
                relocates the imm, not src_reg field.  However, the
                eBPF code generated by clang has src_reg==0. */
      insn0_post |= 0x1000;

      insn[ 0 ] = insn0_post;
      insn[ 1 ] = insn1_post;

      FD_LOG_DEBUG(( "reloc %lu at insn %lu\n"
                     "  S: %#lx\tA: %#lx\n"
                     "  pre:  %016lx %016lx\n"
                     "  post: %016lx %016lx",
                     i, rel[ i ].r_offset / 8UL,
                     S, A,
                     insn0_pre,  insn1_pre,
                     insn0_post, insn1_post ));
      break;
    }
    default:
      FD_LOG_WARNING(( "reloc %lu: Unsupported relocation type %#lx", i, r_type ));
      return NULL;
    }
  }

  /* Save bytecode slice */

  opts->bpf    = (void *)( (ulong)elf + prog->sh_offset );
  opts->bpf_sz = prog->sh_size;

  return opts;

# undef FD_ELF_REQUIRE
}
