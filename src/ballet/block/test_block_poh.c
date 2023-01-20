#include "fd_microblock.h"

#if FD_HAS_HOSTED

/* Reads an AR file containing shreds, derives blocks, and verifies
   the Proof-of-History hash chain.

   Usage: `./test_poh --shreds shreds.ar` */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "../../util/archive/fd_ar.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* Command-line handling */

  char const * shreds_path = fd_env_strip_cmdline_cstr ( &argc, &argv, "--shreds",      NULL, NULL    );
  ulong        txn_max_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--txn-max-cnt", NULL, 16384UL );

  if( FD_UNLIKELY( !shreds_path ) ) FD_LOG_ERR(( "--shreds not specified" ));

  /* Allocate entry buffer */

  ulong footprint = fd_microblock_footprint( txn_max_cnt );
  void * entry_mem = aligned_alloc( fd_microblock_align(), footprint );
  FD_TEST( entry_mem );

  void * shentry = fd_microblock_new( entry_mem, txn_max_cnt );
  FD_TEST( shentry );

  fd_microblock_t * entry = fd_microblock_join( shentry );
  FD_TEST( entry );

  /* Open archive */

  FILE * shreds_file = fopen( shreds_path, "r" );
  if( FD_UNLIKELY( !shreds_file ) ) FD_LOG_ERR(( "Failed to open shreds file: %s", strerror( errno ) ));

  int ar_err = fd_ar_read_init( shreds_file );
  if( FD_UNLIKELY( ar_err!=0    ) ) FD_LOG_ERR(( "Failed to read shreds file: %s", strerror( errno ) ));

  /* Read each shred */

  for(;;) {
    fd_ar_meta_t meta;
    ar_err = fd_ar_read_next( shreds_file, &meta );
    if( FD_UNLIKELY( ar_err=ENOENT ) ) break;
    if( FD_UNLIKELY( ar_err!=0     ) ) FD_LOG_ERR(( "Error while reading shreds file: %s", strerror( errno ) ));

    FD_LOG_NOTICE(( "Reading file %s", meta.ident ));
  }

  /* Cleanup */

  fd_microblock_delete( fd_microblock_leave( entry ) );

  free( entry_mem );
  fclose( shreds_file );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

#else

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_LOG_WARNING(( "skip: unit test requires FD_HAS_HOSTED capabilities" ));
  fd_halt();
  return 0;
}

#endif
