#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdio.h>
#include <stdlib.h>

#include "../../util/fd_util.h"
#include "fd_tar.h"

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_stderr_set(4);
  return 0;
}

static int
tar_file( void *                cb_arg,
          fd_tar_meta_t const * meta,
          ulong FD_FN_UNUSED    sz ) {
  FD_TEST( (ulong)cb_arg == 0x1234UL );

  /* Read meta to ensure it is accessible */
  fd_tar_meta_t meta2;
  meta2 = *meta;
  void * meta_ptr = &meta2;
  FD_COMPILER_FORGET( meta_ptr );

  return 0;
}

static int
tar_read( void *       cb_arg,
          void const * buf,
          ulong        bufsz ) {
  FD_TEST( (ulong)cb_arg == 0x1234UL );

  /* Read buf to ensure it is accessible */
  int x = 0;
  for( ulong i=0UL; i<bufsz; i++ )
    x ^= ((uchar const *)buf)[i];
  FD_COMPILER_FORGET( x );

  return 0;
}

static const fd_tar_read_vtable_t tar_read_vt = {
  .file = tar_file,
  .read = tar_read
};


int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {

  fd_tar_reader_t _reader[1];

  fd_tar_reader_t * reader = fd_tar_reader_new( _reader, &tar_read_vt, (void *)0x1234UL );
  FD_TEST( reader );

  /* Read all in one */
  int err1 = fd_tar_read( reader, data, size );

  FD_TEST( _reader==fd_tar_reader_delete( reader ) );

  reader = fd_tar_reader_new( _reader, &tar_read_vt, (void *)0x1234UL );
  FD_TEST( reader );

  /* Read byte by byte */
  int err2 = 0;
  for( ulong i=0UL; i<size; i++ ) {
    err2 = fd_tar_read( reader, data+i, 1UL );
    if( err2!=0 ) break;
  }

  FD_TEST( _reader==fd_tar_reader_delete( reader ) );

  /* Errors should be the same */
  if( FD_UNLIKELY( err1!=err2 ) )
    FD_LOG_ERR(( "err1=%d err2=%d", err1, err2 ));

  return 0;
}
