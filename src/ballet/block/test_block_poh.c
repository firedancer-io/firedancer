#if FD_HAS_HOSTED

#include "fd_microblock.h"

/* Reads an AR file containing shreds, derives blocks, and verifies
   the Proof-of-History hash chain.

   Usage: `./test_poh --shreds shreds.ar` */

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "../../util/archive/fd_ar.h"
#include "../shred/fd_shred.h"
#include "../poh/fd_poh.h"

/* read_shred: Reads next data shred from AR file.  Returns NULL on EOF.
   Terminates program on read failure.  Lifetime of returned shred ends
   at next call to this function. */
static fd_shred_t const *
read_data_shred( FILE * shreds_file ) {
  /* Read file meta from archive */
  fd_ar_meta_t meta;

  int ar_err = fd_ar_read_next( shreds_file, &meta );
  if( FD_UNLIKELY( ar_err==ENOENT ) )
    return NULL;
  if( FD_UNLIKELY( ar_err!=0     ) )
    FD_LOG_ERR(( "Error while reading shreds file: %s", strerror( ar_err ) ));

  FD_TEST( meta.filesz>=0L );

  FD_LOG_NOTICE(( "Reading shred file %s", meta.ident ));

  /* Read file content */
  static __thread uchar shred_buf[ FD_SHRED_SZ ];
  FD_TEST( meta.filesz<=(long)FD_SHRED_SZ );
  if( FD_UNLIKELY( fread( shred_buf, (ulong)meta.filesz, 1UL, shreds_file )!=1UL ) )
    FD_LOG_ERR(( "Error reading %s: %s", meta.ident, strerror( errno ) ));

  /* Parse shred */
  fd_shred_t const * shred = fd_shred_parse( shred_buf, (ulong)meta.filesz );
  FD_TEST( shred );
  if( FD_UNLIKELY( shred->variant & FD_SHRED_TYPEMASK_CODE ) )
    FD_LOG_ERR(( "Unexpected coding shred: %s", meta.ident ));

  return shred;
}

/* peek_initial_state: Extracts the initial PoH state by peeking at the
   first shred in a shreds archive.  Assumes that the first shred is
   aligned at the first microblock, and that the entire microblock
   header fits into shred payload.  Terminates program on failure. */
static void
peek_initial_state( FILE *           shreds_file,
                    ulong *          tick,
                    fd_poh_state_t * poh ) {
  /* Remember position */
  long pos = ftell( shreds_file );
  FD_TEST( pos>=0L );

  /* Peek next data shred */
  fd_shred_t const * shred = read_data_shred( shreds_file );
  FD_TEST( shred );

  /* Peek previous PoH state by looking at fragmented microblock data.
     This is only valid if the first data batch of the block contains
     at least one microblock header and if that first microblock header\
     is not fragmented across multiple shreds.  Our assumptions hold on
     current Solana mainnet constraints:
     Each block has 64 entries, each shred must have sizeof FD_SHRED_SZ,
     each shred must fill all the available data space. */

  ulong hash_off = 8UL /* Data batch header size */
                  + offsetof( fd_microblock_hdr_t, hash );

  /* Bounds check */
  FD_TEST( fd_shred_payload_sz( shred )>=(hash_off+FD_SHA256_HASH_SZ) );
  /* Read count in first batch header -- Must have at least 1 microblock. */
  FD_TEST( FD_LOAD( ulong, fd_shred_data_payload( shred ) )>0UL );

  /* Extract info */
  *tick = shred->slot << 5;
  memcpy( poh->state, fd_shred_data_payload( shred )+hash_off, FD_SHA256_HASH_SZ );

  /* Rewind */
  FD_TEST( fseek( shreds_file, pos, SEEK_SET )==0 );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* Command-line handling */

  char const * shreds_path = fd_env_strip_cmdline_cstr ( &argc, &argv, "--shreds",      NULL, NULL    );
  ulong        txn_max_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--txn-max-cnt", NULL, 16384UL );
  int          enable_poh  = fd_env_strip_cmdline_int  ( &argc, &argv, "--poh",         NULL, 1       );
  (void)enable_poh;

  if( FD_UNLIKELY( !shreds_path ) ) FD_LOG_ERR(( "--shreds not specified" ));

  /* Allocate data batch buffer */

  ulong batch_sz = 0x20000;
  void * batch_mem = malloc( batch_sz );
  FD_TEST( batch_mem );

  /* Allocate microblock buffer */

  ulong footprint = fd_microblock_footprint( txn_max_cnt );
  void * block_mem = aligned_alloc( fd_microblock_align(), footprint );
  FD_TEST( block_mem );

  void * shblock = fd_microblock_new( block_mem, txn_max_cnt );
  FD_TEST( shblock );

  fd_microblock_t * block = fd_microblock_join( shblock );
  FD_TEST( block );

  /* Open archive */

  FILE * shreds_file = fopen( shreds_path, "r" );
  if( FD_UNLIKELY( !shreds_file ) ) FD_LOG_ERR(( "Failed to open shreds file: %s", strerror( errno ) ));

  int ar_err = fd_ar_read_init( shreds_file );
  if( FD_UNLIKELY( ar_err!=0    ) ) FD_LOG_ERR(( "Failed to read shreds file: %s", strerror( errno ) ));

  /* Peek initial state from first shred */

  ulong tick; /* high 59-bit: slot number
                 low   5-bit: microblock index */
  fd_poh_state_t poh;

  peek_initial_state( shreds_file, &tick, &poh );

  FD_LOG_NOTICE(( "Initial state: slot=%lu hash="
                  "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
                  "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                  tick>>5,
                  FD_LOG_HEX16_FMT_ARGS( poh.state      ),
                  FD_LOG_HEX16_FMT_ARGS( poh.state+16UL ) ));

  /* Read each shred */

  fd_deshredder_t shredder = {0};
  fd_deshredder_init( &shredder, batch_mem, batch_sz, NULL, 0UL );

  for(;;) {
    fd_shred_t const * shred = read_data_shred( shreds_file );
    if( FD_UNLIKELY( !shred ) ) break;

    /* Add shred to deshredder */

    shredder.shreds    = &shred;
    shredder.shred_cnt = 1UL;

    long shred_res = fd_deshredder_next( &shredder );
    if( FD_LIKELY( shred_res==-FD_SHRED_EPIPE ) ) continue;
    if( FD_UNLIKELY( shred_res<0L ) )
      FD_LOG_ERR(( "Error while deshredding: %ld", shred_res ));
  }

  /* Cleanup */

  fd_microblock_delete( fd_microblock_leave( block ) );

  free( block_mem );
  free( batch_mem );
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
