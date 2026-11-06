#include "fd_transpile_obj.h"
#include "../../../util/fd_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
write_file( char const * path,
            ulong        sz ) {
  FILE * f = fopen( path, "wb" );
  FD_TEST( f );
  for( ulong i=0UL; i<sz; i++ ) FD_TEST( fputc( 'x', f )=='x' );
  FD_TEST( !fclose( f ) );
}

/* check_hdr verifies a member header at p and returns its size */

static ulong
check_hdr( uchar const * p,
           char const *  name ) {
  FD_TEST( !memcmp( p+58, "`\n", 2UL ) );
  ulong name_len = strlen( name );
  FD_TEST( !memcmp( p, name, name_len ) );
  for( ulong i=name_len; i<16UL; i++ ) FD_TEST( p[i]==' ' );
  char sz_cstr[ 11 ] = {0};
  memcpy( sz_cstr, p+48, 10UL );
  return strtoul( sz_cstr, NULL, 10 );
}

static void
test_export_obj( void ) {
  fd_transpiler_t * t = aligned_alloc( 64UL, sizeof(fd_transpiler_t) );
  FD_TEST( t );

  ulong bpf_text[ 2 ] = {
    0x0000002a000000b7UL, /* mov64 r0, 42 */
    0x0000000000000095UL  /* exit */
  };

  FD_TEST( !fd_vm_transpile_code( t, FD_SBPF_V0, (uchar const *)bpf_text, 2UL, 0UL, NULL, NULL, NULL, 0UL, 0UL ) );

  memset( t->meta.prog_id, 1, 32UL );

  static uchar elf_buf[ 65536 ];
  ulong elf_sz = fd_transpiler_export_obj( t, NULL, elf_buf, sizeof(elf_buf) );
  FD_TEST( elf_sz > 0UL );

  /* Validate ELF Header */
  fd_elf64_ehdr const * ehdr = (fd_elf64_ehdr const *)elf_buf;
  FD_TEST( ehdr->e_ident[ FD_ELF_EI_MAG0 ] == 0x7f );
  FD_TEST( ehdr->e_ident[ FD_ELF_EI_MAG1 ] == 'E' );
  FD_TEST( ehdr->e_ident[ FD_ELF_EI_MAG2 ] == 'L' );
  FD_TEST( ehdr->e_ident[ FD_ELF_EI_MAG3 ] == 'F' );
  FD_TEST( ehdr->e_type == FD_ELF_ET_REL );
  FD_TEST( ehdr->e_machine == FD_ELF_EM_X86_64 );
  FD_TEST( ehdr->e_shnum > 0 );

  /* Find .symtab and .strtab */
  fd_elf64_shdr const * shdrs = (fd_elf64_shdr const *)( elf_buf + ehdr->e_shoff );
  fd_elf64_shdr const * shstrtab_shdr = &shdrs[ ehdr->e_shstrndx ];
  char const * shstrtab = (char const *)( elf_buf + shstrtab_shdr->sh_offset );

  fd_elf64_shdr const * symtab_shdr = NULL;
  fd_elf64_shdr const * strtab_shdr = NULL;
  for( ulong i=0UL; i<(ulong)ehdr->e_shnum; i++ ) {
    char const * sname = shstrtab + shdrs[ i ].sh_name;
    if( !strcmp( sname, ".symtab" ) ) symtab_shdr = &shdrs[ i ];
    else if( !strcmp( sname, ".strtab" ) ) strtab_shdr = &shdrs[ i ];
  }
  FD_TEST( symtab_shdr && strtab_shdr );

  /* Verify the global export symbol */
  char const * strtab = (char const *)( elf_buf + strtab_shdr->sh_offset );
  fd_elf64_sym const * syms = (fd_elf64_sym const *)( elf_buf + symtab_shdr->sh_offset );
  ulong sym_cnt = symtab_shdr->sh_size / sizeof(fd_elf64_sym);

  int found_export = 0;
  int found_entry  = 0;
  int found_helper = 0;
  for( ulong i=0UL; i<sym_cnt; i++ ) {
    char const * sym_name = strtab + syms[ i ].st_name;
    if( !strncmp( sym_name, "fd_transpiled_ext_", 18UL ) ) {
      FD_TEST( FD_ELF64_ST_BIND( syms[ i ].st_info ) == FD_ELF_STB_GLOBAL );
      FD_TEST( FD_ELF64_ST_TYPE( syms[ i ].st_info ) == FD_ELF_STT_OBJECT );
      FD_TEST( syms[ i ].st_size == sizeof(fd_transpile_export_t) );
      found_export = 1;
    } else if( !strcmp( sym_name, "sbpf_entrypoint" ) ) {
      FD_TEST( FD_ELF64_ST_BIND( syms[ i ].st_info ) == FD_ELF_STB_LOCAL );
      FD_TEST( FD_ELF64_ST_TYPE( syms[ i ].st_info ) == FD_ELF_STT_FUNC );
      FD_TEST( syms[ i ].st_size > 0UL );
      found_entry = 1;
    } else if( !strcmp( sym_name, "fd_xlat_unwind" ) ) {
      FD_TEST( FD_ELF64_ST_BIND( syms[ i ].st_info ) == FD_ELF_STB_LOCAL );
      FD_TEST( syms[ i ].st_size > 0UL );
      found_helper = 1;
    }
    /* locals precede globals (sh_info) */
    if( FD_ELF64_ST_BIND( syms[ i ].st_info ) == FD_ELF_STB_LOCAL ) FD_TEST( i < symtab_shdr->sh_info );
    else                                                            FD_TEST( i >= symtab_shdr->sh_info );
  }
  FD_TEST( found_export );
  FD_TEST( found_entry );
  FD_TEST( found_helper );

  /* Test failure conditions */
  FD_TEST( !fd_transpiler_export_obj( NULL, NULL, elf_buf, sizeof(elf_buf) ) );
  FD_TEST( !fd_transpiler_export_obj( t, NULL, NULL, sizeof(elf_buf) ) );
  FD_TEST( !fd_transpiler_export_obj( t, NULL, elf_buf, 0UL ) );
  FD_TEST( !fd_transpiler_export_obj( t, NULL, elf_buf, 10UL ) ); /* Buffer too small */

  free( t );
}

static void
test_export_archive( void ) {
  char dir[] = "/tmp/test_transpile_archive.XXXXXX";
  FD_TEST( mkdtemp( dir ) );

  /* Create dummy transpiled object files with expected naming pattern:
     fd_transpiled_<base58(prog_id)>.o */
  char path[ 256 ];
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL,
    "%s/fd_transpiled_11111111111111111111111111111111.o", dir ) );
  write_file( path, 100UL );

  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL,
    "%s/fd_transpiled_33333333333333333333333333333333.o", dir ) );
  write_file( path, 200UL );

  /* Test fd_transpiler_export_archive */
  FD_TEST( !fd_transpiler_export_archive( dir ) );

  /* Verify fd_transpiled_export.o exists */
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "%s/fd_transpiled_export.o", dir ) );
  FD_TEST( access( path, F_OK ) == 0 );

  /* Verify libfd_transpiled.a exists and is a valid thin archive */
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "%s/libfd_transpiled.a", dir ) );
  FILE * f = fopen( path, "rb" );
  FD_TEST( f );
  static uchar ar_buf[ 4096 ];
  ulong ar_sz = fread( ar_buf, 1UL, sizeof(ar_buf), f );
  FD_TEST( !fclose( f ) );
  FD_TEST( ar_sz > 8UL && !memcmp( ar_buf, "!<thin>\n", 8UL ) );

  /* Test invalid dir */
  FD_TEST( fd_transpiler_export_archive( NULL ) == -1 );
  FD_TEST( fd_transpiler_export_archive( "" ) == -1 );
  FD_TEST( fd_transpiler_export_archive( "/nonexistent/dir/12345" ) == -1 );

  /* Clean up */
  unlink( path );
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "%s/fd_transpiled_export.o", dir ) );
  unlink( path );
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL,
    "%s/fd_transpiled_11111111111111111111111111111111.o", dir ) );
  unlink( path );
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL,
    "%s/fd_transpiled_33333333333333333333333333333333.o", dir ) );
  unlink( path );
  FD_TEST( !rmdir( dir ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char dir[] = "/tmp/test_transpile_obj.XXXXXX";
  FD_TEST( mkdtemp( dir ) );

  char path[ 256 ];
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "%s/a.o",       dir ) ); write_file( path, 3UL  );
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "%s/prog-bb.o", dir ) ); write_file( path, 42UL );
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "%s/c.o",       dir ) ); write_file( path, 0UL  );

  char const * names[3] = { "a.o", "prog-bb.o", "c.o" };
  char const * syms [3] = { "sym_a", "sym_bb", NULL };
  FD_TEST( !fd_transpile_export_ar( dir, "lib.a", names, syms, 3UL ) );

  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "%s/lib.a", dir ) );
  static uchar buf[ 4096 ];
  FILE * f = fopen( path, "rb" );
  FD_TEST( f );
  ulong sz = fread( buf, 1UL, sizeof(buf), f );
  FD_TEST( !fclose( f ) );

  FD_TEST( sz>8UL && !memcmp( buf, "!<thin>\n", 8UL ) );
  ulong off = 8UL;

  /* symbol index */
  ulong symtab_sz = check_hdr( buf+off, "/" );
  uchar const * symtab = buf+off+60UL;
  FD_TEST( fd_uint_bswap( FD_LOAD( uint, symtab ) )==2U );
  ulong sym_off[2] = { fd_uint_bswap( FD_LOAD( uint, symtab+4UL ) ), fd_uint_bswap( FD_LOAD( uint, symtab+8UL ) ) };
  FD_TEST( !memcmp( symtab+12, "sym_a\0sym_bb\0", 13UL ) );
  FD_TEST( symtab_sz==25UL );
  off += 60UL + fd_ulong_align_up( symtab_sz, 2UL );

  /* long name table */
  ulong names_sz = check_hdr( buf+off, "//" );
  char const * strtab = (char const *)buf+off+60UL;
  FD_TEST( names_sz==strlen( "a.o/\nprog-bb.o/\nc.o/\n" ) );
  FD_TEST( !memcmp( strtab, "a.o/\nprog-bb.o/\nc.o/\n", names_sz ) );
  off += 60UL + fd_ulong_align_up( names_sz, 2UL );

  /* members (headers only) */
  FD_TEST( sym_off[0]==off       );
  FD_TEST( sym_off[1]==off+60UL  );
  FD_TEST( check_hdr( buf+off, "/0"  )==3UL  ); off += 60UL;
  FD_TEST( check_hdr( buf+off, "/5"  )==42UL ); off += 60UL;
  FD_TEST( check_hdr( buf+off, "/16" )==0UL  ); off += 60UL;
  FD_TEST( off==sz );

  /* missing member fails and leaves no temp file behind */
  char const * bad[1] = { "missing.o" };
  FD_TEST( fd_transpile_export_ar( dir, "bad.a", bad, syms, 1UL )==-1 );
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "%s/bad.a.tmp", dir ) );
  FD_TEST( access( path, F_OK )!=0 );

  for( ulong i=0UL; i<3UL; i++ ) {
    FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "%s/%s", dir, names[i] ) );
    FD_TEST( !unlink( path ) );
  }
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "%s/lib.a", dir ) );
  FD_TEST( !unlink( path ) );
  FD_TEST( !rmdir( dir ) );

  test_export_obj();
  test_export_archive();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
