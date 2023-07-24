#include "../fd_flamenco.h"
#include "fd_solcap_proto.h"

#include <errno.h>
#include <stdio.h>

static int
usage( void ) {
  fprintf( stderr,
    "Usage: fd_solcap_yaml [options] {FILE}\n"
    "\n"
    "Print a runtime capture file as YAML.\n"
    "\n"
    "Options:\n"
    "  --page-sz      {gigantic|huge|normal}    Page size\n"
    "  --page-cnt     {count}                   Page count\n"
    "  --scratch-mb   1024                      Scratch mem MiB\n"
    "  -v             {level}                   YAML verbosity\n"
    "\n" );
  return 0;
}

static void
process_accounts_delta( fd_solcap_bank_preimage_t * preimage,
                        long                        block_off,
                        FILE *                      file,
                        int                         verbose ) {

  /* Seek to accounts */

  int err = fseek( file, block_off + (long)preimage->account_off, SEEK_SET );
  if( FD_UNLIKELY( err<0L ) ) {
    FD_LOG_ERR(( "fseek accounts failed (%d-%s)", errno, strerror( errno ) ));
    return;
  }

  /* Read accounts */

  ulong account_cnt = preimage->account_cnt;
  for( ulong i=0UL; i<account_cnt; i++ ) {

    /* Read header */

    fd_solcap_account_t account[1];
    ulong n = fread( account, sizeof(fd_solcap_account_t), 1UL, file );
    if( FD_UNLIKELY( n!=1UL ) ) {
      FD_LOG_ERR(( "fread account header failed (%d-%s)", errno, strerror( errno ) ));
      return;
    }

    ulong footprint = account->footprint;
    ulong overhead;
    FD_TEST( !__builtin_usubl_overflow( footprint, sizeof(fd_solcap_account_t), &overhead ) );
    FD_TEST( overhead<LONG_MAX );

    /* Skip content */

    err = fseek( file, (long)overhead, SEEK_CUR );
    if( FD_UNLIKELY( err<0L ) ) {
      FD_LOG_ERR(( "fseek account content failed (%d-%s)", errno, strerror( errno ) ));
      return;
    }

    /* Write to YAML */

    printf(
      "    - pubkey: %32J\n"
      "      hash:   %32J\n",
      account->key,
      account->hash );

    if( verbose>=3 ) {
      printf(
        "      lamports:   %lu\n"
        "      slot:       %lu\n"
        "      rent_epoch: %lu\n"
        "      executable: %s\n",
        account->lamports,
        account->slot,
        account->rent_epoch,
        account->executable ? "true" : "false" );
    }

  }

}

static void
process_block( fd_solcap_fhdr_t * hdr,
               long               block_off,
               FILE *             file,
               int                verbose ) {

  (void)verbose;

  ulong slot0    = hdr->v0.slot0;
  ulong slot_cnt = hdr->v0.slot_cnt;

  /* Read bank hashes */

  fd_hash_t * bank_hash = fd_scratch_alloc( 16UL, slot_cnt * sizeof(fd_hash_t) );
  FD_TEST( bank_hash );

  int err = fseek( file, block_off + (long)hdr->v0.bank_hash_off, SEEK_SET );
  if( FD_UNLIKELY( err<0L ) ) {
    FD_LOG_ERR(( "fseek bank hash table failed (%d-%s)", errno, strerror( errno ) ));
    return;
  }

  ulong n = fread( bank_hash, sizeof(fd_hash_t), slot_cnt, file );
  if( FD_UNLIKELY( n!=slot_cnt ) ) {
    FD_LOG_ERR(( "fread bank hash table failed (%d-%s)", errno, strerror( errno ) ));
    return;
  }

  /* Read preimages */

  fd_solcap_bank_preimage_t * preimage = NULL;

  if( verbose >= 1 ) {
    preimage = fd_scratch_alloc( alignof(fd_solcap_bank_preimage_t),
                                 slot_cnt * sizeof(fd_solcap_bank_preimage_t) );

    err = fseek( file, block_off + (long)hdr->v0.bank_preimage_off, SEEK_SET );
    if( FD_UNLIKELY( err<0L ) ) {
      FD_LOG_ERR(( "fseek bank preimage table failed (%d-%s)", errno, strerror( errno ) ));
      return;
    }

    n = fread( preimage, sizeof(fd_solcap_bank_preimage_t), slot_cnt, file );
    if( FD_UNLIKELY( n!=slot_cnt ) ) {
      FD_LOG_ERR(( "fread bank preimage table failed (%d-%s)", errno, strerror( errno ) ));
      return;
    }
  }

  /* Write YAML */

  for( ulong i=0UL; i<slot_cnt; i++ ) {

    /* Slot Entry */

    ulong slot = slot0+i;
    printf(
      "- slot: %lu\n"
      "  bank_hash: %32J\n",
      slot,
      bank_hash[ i ].hash );

    if( verbose>=1 ) {
      printf(
        "  prev_bank_hash:     %32J\n"
        "  account_delta_hash: %32J\n"
        "  poh_hash:           %32J\n",
        preimage[ i ].prev_bank_hash,
        preimage[ i ].account_delta_hash,
        preimage[ i ].poh_hash );
    }

    /* Accounts */

    if( verbose >= 2 ) {
      printf( "  accounts_delta:\n" );
      process_accounts_delta( &preimage[ i ], block_off, file, verbose );
    }

  }

}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_flamenco_boot( &argc, &argv );

  /* Command line handling */

  for( int i=1; i<argc; i++ )
    if( 0==strcmp( argv[i], "--help" ) ) return usage();

  char const * _page_sz   = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",    NULL, "gigantic" );
  ulong        page_cnt   = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",   NULL, 2UL        );
  ulong        scratch_mb = fd_env_strip_cmdline_ulong( &argc, &argv, "--scratch-mb", NULL, 1024UL     );
  int          verbose    = fd_env_strip_cmdline_int  ( &argc, &argv, "-v",           NULL, 0          );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  if( argc!=2 ) {
    fprintf( stderr, "ERROR: expected 1 argument, got %d\n", argc-1 );
    usage();
    return 1;
  }

  /* Create workspace and scratch allocator */

  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_log_cpu_id(), "wksp", 0UL );
  if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "fd_wksp_new_anonymous() failed" ));

  ulong  smax = scratch_mb << 20;
  void * smem = fd_wksp_alloc_laddr( wksp, fd_scratch_smem_align(), smax, 1UL );
  if( FD_UNLIKELY( !smem ) ) FD_LOG_ERR(( "Failed to alloc scratch mem" ));
  ulong  scratch_depth = 4UL;
  void * fmem = fd_wksp_alloc_laddr( wksp, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( scratch_depth ), 2UL );
  if( FD_UNLIKELY( !fmem ) ) FD_LOG_ERR(( "Failed to alloc scratch frames" ));

  fd_scratch_attach( smem, fmem, smax, scratch_depth );

  /* Open file */

  char const * path = argv[ 1 ];
  FILE * file = fopen( path, "rb" );
  if( FD_UNLIKELY( !file ) )
    FD_LOG_ERR(( "fopen(%s) failed (%d-%s)", path, errno, strerror( errno ) ));

  while( !feof( file ) ) {

    long block_off = ftell( file );
    FD_TEST( block_off>=0L );

    /* Read block header */

    fd_solcap_fhdr_t hdr[1];
    ulong n = fread( &hdr, sizeof(fd_solcap_fhdr_t), 1UL, file );
    if( FD_UNLIKELY( n!=1UL ) ) {
      if( feof( file ) ) break;
      FD_LOG_ERR(( "fread failed (%d-%s)", errno, strerror( errno ) ));
      break;
    }

    FD_TEST( hdr->magic    == FD_SOLCAP_MAGIC          );
    FD_TEST( hdr->version  == 0UL                      );
    FD_TEST( hdr->total_sz >= sizeof(fd_solcap_fhdr_t) );
    FD_TEST( hdr->v0.slot0    <  (1UL<<32UL)           );
    FD_TEST( hdr->v0.slot_cnt <  (1UL<<32UL)           );

    FD_LOG_DEBUG(( "slot=%lu..%lu block_off=%#lx block_sz=%#lx",
                   hdr->v0.slot0, hdr->v0.slot0 + hdr->v0.slot_cnt,
                   block_off, hdr->total_sz ));

    /* Process block */

    fd_scratch_push();
    process_block( hdr, block_off, file, verbose );
    fd_scratch_pop();

    /* Seek to end of block */

    ulong block_end;
    FD_TEST( !__builtin_uaddl_overflow( (ulong)block_off, hdr->total_sz, &block_end ) );
    FD_TEST( block_end<LONG_MAX );

    int err = fseek( file, (long)block_end, SEEK_SET );
    if( FD_UNLIKELY( err<0L ) ) {
      FD_LOG_ERR(( "fseek failed (%d-%s)", errno, strerror( errno ) ));
      break;
    }

  }

  /* Cleanup */

  FD_LOG_NOTICE(( "Done" ));
  FD_TEST( fd_scratch_frame_used()==0UL );
  fd_wksp_free_laddr( fd_scratch_detach( NULL ) );
  fd_wksp_free_laddr( fmem                      );
  fclose( file );
  fd_halt();
  return 0;
}
