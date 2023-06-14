#include "fd_shred.h"

#include <errno.h>
#include <stdio.h>
#include "../../util/archive/fd_ar.h"

FD_IMPORT_BINARY( localnet_shreds_0,  "src/ballet/shred/fixtures/localnet-slot0-shreds.ar"  );
FD_IMPORT_BINARY( localnet_batch_0_0, "src/ballet/shred/fixtures/localnet-slot0-batch0.bin" );

FD_IMPORT_BINARY( localnet_v14_shreds_0,  "src/ballet/shred/fixtures/localnet-v14-slot0-shreds.ar"  );
FD_IMPORT_BINARY( localnet_v14_shreds_1,  "src/ballet/shred/fixtures/localnet-v14-slot1-shreds.ar"  );

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* Open shreds for reading */
  FD_LOG_NOTICE(( "v13 slot 0" ));
  FILE * file = fmemopen( (void *)localnet_shreds_0, localnet_shreds_0_sz, "r" );
  FD_TEST( file );
  FD_TEST( 0==fd_ar_read_init( file ) );

  /* Concatenate shreds with `fd_deshredder_t` */
  char batch[ 6000 ];      /* Deserialized shred batch */
  fd_deshredder_t deshred; /* Deshredder intermediate state */

  /* Initialize deshredder with empty list of shreds */
  fd_deshredder_init( &deshred, &batch, sizeof(batch), NULL, 0 );

  /* Feed deshredder one-by-one.
     Production code would feed it multiple shreds in batches. */
  fd_ar_meta_t hdr;
  int ar_err;
  while( (ar_err = fd_ar_read_next( file, &hdr ))==0 ) {
    uchar shred_buf[ FD_SHRED_SZ ];

    /* Read next file from archive */
    FD_TEST(( hdr.filesz>=0 && hdr.filesz < (long)sizeof(shred_buf) ));

    size_t n = fread( shred_buf, 1, (ulong)hdr.filesz, file );
    FD_TEST(( n==(ulong)hdr.filesz ));

    /* Parse shred */
    fd_shred_t const * shred = fd_shred_parse( shred_buf, (ulong)hdr.filesz );

    /* Refill deshredder with shred */
    fd_shred_t const * const shred_list[1] = { shred };
    deshred.shreds    = shred_list;
    deshred.shred_cnt = 1U;

    fd_deshredder_next( &deshred );
  }

  /* Did we gracefully finish consuming the archive? */
  FD_TEST( ar_err==ENOENT );

  /* Check size of defragmented batch */
  ulong batch_sz = sizeof(batch) - deshred.bufsz;
  /* fwrite( batch, batch_sz, 1, stdout ); */
  FD_TEST( batch_sz==3080UL                );
  FD_TEST( batch_sz==localnet_batch_0_0_sz );

  /* Check number of shreds */
  ulong shred_cnt = *(ulong *)batch;
  FD_TEST( shred_cnt==64UL );

  /* Verify deshredded content */
  FD_TEST( 0==memcmp( batch, localnet_batch_0_0, localnet_batch_0_0_sz ) );

  FD_LOG_NOTICE(( "v14 slot 0" ));
  file = fmemopen( (void *)localnet_v14_shreds_0, localnet_v14_shreds_0_sz, "r" );
  FD_TEST( file );
  FD_TEST( 0==fd_ar_read_init( file ) );

  fd_deshredder_init( &deshred, &batch, sizeof(batch), NULL, 0 );

  while( (ar_err = fd_ar_read_next( file, &hdr ))==0 ) {
    uchar shred_buf[ FD_SHRED_SZ ];

    /* Read next file from archive */
    FD_TEST(( hdr.filesz>=0 && hdr.filesz < (long)sizeof(shred_buf) ));

    size_t n = fread( shred_buf, 1, (ulong)hdr.filesz, file );
    FD_TEST(( n==(ulong)hdr.filesz ));

    /* Parse shred */
    fd_shred_t const * shred = fd_shred_parse( shred_buf, (ulong)hdr.filesz );

    /* Refill deshredder with shred */
    fd_shred_t const * const shred_list[1] = { shred };
    deshred.shreds    = shred_list;
    deshred.shred_cnt = 1U;

    fd_deshredder_next( &deshred );
  }

  /* Did we gracefully finish consuming the archive? */
  FD_TEST( ar_err==ENOENT );

  FD_LOG_NOTICE(( "v14 slot 1" ));
  file = fmemopen( (void *)localnet_v14_shreds_1, localnet_v14_shreds_1_sz, "r" );
  FD_TEST( file );
  FD_TEST( 0==fd_ar_read_init( file ) );

  fd_deshredder_init( &deshred, &batch, sizeof(batch), NULL, 0 );

  while( (ar_err = fd_ar_read_next( file, &hdr ))==0 ) {
    uchar shred_buf[ FD_SHRED_SZ ];

    /* Read next file from archive */
    FD_TEST(( hdr.filesz>=0 && hdr.filesz < (long)sizeof(shred_buf) ));

    size_t n = fread( shred_buf, 1, (ulong)hdr.filesz, file );
    FD_TEST(( n==(ulong)hdr.filesz ));

    /* Parse shred */
    fd_shred_t const * shred = fd_shred_parse( shred_buf, (ulong)hdr.filesz );
    FD_TEST( shred );

    /* Refill deshredder with shred */
    fd_shred_t const * const shred_list[1] = { shred };
    deshred.shreds    = shred_list;
    deshred.shred_cnt = 1U;

    fd_deshredder_next( &deshred );
  }

  /* Did we gracefully finish consuming the archive? */
  FD_TEST( ar_err==ENOENT );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
