#include "../fd_util.h"
#include "fd_ar.h"

#if FD_HAS_HOSTED

#include <stdio.h>
#include <errno.h>

FD_IMPORT_BINARY( test_ar, "src/ballet/shred/fixtures/localnet-shreds-0.ar" );

/* test_valid_ar: Read all files from archive. */

static void
test_valid_ar( void ) {

  /* Open a valid AR file */

  FILE * file = fmemopen( (void *)test_ar, test_ar_sz, "rb" );
  FD_TEST( file );
  FD_TEST( !fd_ar_read_init( file ) );

  /* Read a few entries */

  fd_ar_meta_t meta[1];
  uchar buf[1500];

# define CHECK_NEXT_AR(name, sz, off, val )         \
  FD_TEST( !fd_ar_read_next( file, meta )        ); \
  FD_TEST( meta->mtime              ==0L         ); \
  FD_TEST( meta->uid                ==0L         ); \
  FD_TEST( meta->gid                ==0L         ); \
  FD_TEST( meta->mode               ==0644L      ); \
  FD_TEST( meta->filesz             ==(long)sz   ); \
  FD_TEST( fread( buf, 1, sz, file )==sz         ); \
  FD_TEST( buf[ off ]               ==(uchar)val )

  CHECK_NEXT_AR( "d0000/", 1203, 0x49, 0x00 );
  CHECK_NEXT_AR( "d0001/", 1203, 0x49, 0x01 );
  CHECK_NEXT_AR( "d0002/", 1203, 0x49, 0x02 );
  CHECK_NEXT_AR( "d0003/", 1203, 0x49, 0x03 );

# undef CHECK_NEXT_AR

  /* Reached end of archive, expecting ENOENT */

  FD_TEST( fd_ar_read_next( file, meta )==ENOENT );
  FD_TEST( !fclose( file ) );
}

/* test_empty_ar: Gracefully handle empty archives */

static void
test_empty_ar( void ) {
  char buf[ 8 ];
  FILE * file = fmemopen( fd_memcpy( buf, "!<arch>\n", 8UL ), 8UL, "rb" );
  FD_TEST( file );
  FD_TEST( !fd_ar_read_init( file ) );
  fd_ar_meta_t meta[1];
  FD_TEST( fd_ar_read_next( file, meta )==ENOENT );
  FD_TEST( !fclose( file ) );
}

/* test_invalid_ar_magic: Refuse to open files that are clearly not AR */

static void
test_invalid_ar_magic( void ) {
  char buf[ 128 ];
  FILE * file = fmemopen( fd_memset( buf, 0, 128UL ), 128UL, "rb" );
  FD_TEST( file );
  FD_TEST( fd_ar_read_init( file )==EPROTO );
  FD_TEST( !fclose( file ) );
}

/* test_invalid_entry_magic: Abort stream on invalid file header magic */

static void
test_invalid_entry_magic( void ) {
  char buf[ 128 ];
  FILE * file = fmemopen( fd_memcpy( fd_memset( buf, 0, 128UL ), "!<arch>\n", 8UL ), 128UL, "rb" );
  FD_TEST( file );
  FD_TEST( !fd_ar_read_init( file ) );
  fd_ar_meta_t meta[1];
  FD_TEST( fd_ar_read_next( file, meta )==EPROTO );
  FD_TEST( !fclose( file ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_valid_ar();
  test_empty_ar();
  test_invalid_ar_magic();
  test_invalid_entry_magic();

  FD_LOG_NOTICE(( "pass" ));

  fd_halt();
  return 0;
}

#else

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_LOG_WARNING(( "skip: unit test requires FD_HAS_HOSTED" ));
  fd_halt();
  return 0;
}

#endif
