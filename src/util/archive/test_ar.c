#include "../fd_util.h"
#include "fd_ar.h"

#include <errno.h>

FD_IMPORT_BINARY(test_ar, "src/ballet/shred/fixtures/localnet-shreds-0.ar");

/* test_valid_ar: Read all files from archive. */
void
test_valid_ar( void ) {
  /* Open a valid AR file */

  FILE * file = fmemopen( (void *)test_ar, test_ar_sz, "rb" );
  FD_TEST( file );
  FD_TEST( fd_ar_open( file ) );

  fd_ar_t hdr;
  uchar buf[ 1500 ];

# define CHECK_NEXT_AR(name, sz)                                               \
  FD_TEST( fd_ar_next( file, &hdr ) );                                         \
  FD_TEST( hdr.magic==FD_AR_FILE_MAGIC );                                      \
  FD_TEST( 0==strncmp( hdr.ident,      name,           strlen(name)       ) ); \
  FD_TEST( 0==strncmp( hdr.filesz_dec, #sz "  ",       strlen( #sz "  " ) ) ); \
  FD_TEST( 0==memcmp ( hdr.mtime_dec,  "0           ", FD_AR_MTIME_SZ     ) ); \
  FD_TEST( 0==memcmp ( hdr.uid_dec,    "0     ",       FD_AR_UID_SZ       ) ); \
  FD_TEST( 0==memcmp ( hdr.gid_dec,    "0     ",       FD_AR_GID_SZ       ) ); \
  FD_TEST( 0==memcmp ( hdr.mode_oct,   "644     ",     FD_AR_MODE_SZ      ) ); \
  FD_TEST( (long)sz==fd_ar_filesz( &hdr )      );                              \
  FD_TEST(       sz==fread( buf, 1, sz, file ) );

  /* Read a few entries */

  CHECK_NEXT_AR( "d0000/", 1203 );
  FD_TEST( buf[ 0x49 ]==0x00 ); /* arbitrary byte in file payload */

  CHECK_NEXT_AR( "d0001/", 1203 );
  FD_TEST( buf[ 0x49 ]==0x01 );

  CHECK_NEXT_AR( "d0002/", 1203 );
  FD_TEST( buf[ 0x49 ]==0x02 );

  CHECK_NEXT_AR( "d0003/", 1203 );
  FD_TEST( buf[ 0x49 ]==0x03 );

  /* Reached end of archive, expecting ENOENT */

  FD_TEST( !fd_ar_next( file, &hdr ) );
  FD_TEST( errno==ENOENT );

  FD_TEST( 0==fclose( file ) );
}

/* test_empty_ar: Gracefully handle empty archives */
void
test_empty_ar( void ) {
  char empty[ 8 ] = { '!', '<', 'a', 'r', 'c', 'h', '>', '\n' };

  FILE * file = fmemopen( (void *)empty, sizeof(empty), "rb" );
  FD_TEST( file );
  FD_TEST( fd_ar_open( file ) );

  fd_ar_t hdr;
  FD_TEST( !fd_ar_next( file, &hdr ) );
  FD_TEST( errno==ENOENT );

  FD_TEST( 0==fclose( file ) );
}

/* test_invalid_ar_magic: Refuse to open files that are clearly not AR */
void
test_invalid_ar_magic( void ) {
  char zeros[ 128 ] = {0};

  FILE * file = fmemopen( (void *)zeros, sizeof(zeros), "rb" );
  FD_TEST( file );
  FD_TEST( !fd_ar_open( file ) );
  FD_TEST( errno==EPROTO );
  FD_TEST( 0==fclose( file ) );
}

/* test_invalid_entry_magic: Abort stream on invalid file header magic */
void
test_invalid_entry_magic( void ) {
  char zeros[ 128 ] = {
    '!', '<', 'a', 'r', 'c', 'h', '>', '\n', /* archive header */
    0, /* file header expected */
  };

  FILE * file = fmemopen( (void *)zeros, sizeof(zeros), "rb" );
  FD_TEST( file );
  FD_TEST( fd_ar_open( file ) );

  fd_ar_t hdr;
  FD_TEST( !fd_ar_next( file, &hdr ) );
  FD_TEST( errno==EPROTO );

  FD_TEST( 0==fclose( file ) );
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
