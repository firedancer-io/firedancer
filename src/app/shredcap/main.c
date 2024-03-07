#include "../../flamenco/shredcap/fd_shredcap.h"

/* fd_shredcap is a tool to ingest and verify rocksdb into a fd_shredcap capture.
   The main commands are "--cmd ingest and --cmd verify". By default, "ingest" 
   will perform a verify. An example command is:
   
   build/native/clang/bin/fd_shred_cap --pages 10 --rocksdb  /data/ibhatt/hash/rocksdb/ 
   --capturepath ~/bigcap/ --cmd ingest --startslot 250553925 --endslot 250558000.
   
   The --capturepath must be terminated with a '/' char and must be a path to a
   directory which does not yet exist. The tool will not overwrite exisiting 
   directories.
   
   The "populate" command populates a blockstore with a specified block range. It
   will also contain the bank hash information for each slot. frank_ledger can be 
   used to generate checkpoints using a shredstore.  */

#define DEFAULT_SHREDCAP_FILE_SIZE (1737418240UL)
#define DEFAULT_SLOT_HISTORY_MAX   (10000000UL)

int
main( int argc, char ** argv ) {

  fd_boot( &argc, &argv );
  fd_flamenco_boot( &argc, &argv );

  char const * wkspname     = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp",        NULL, NULL                       );
  ulong pages               = fd_env_strip_cmdline_ulong( &argc, &argv, "--pages",       NULL, 5                          );
  char const * reset        = fd_env_strip_cmdline_cstr ( &argc, &argv, "--reset",       NULL, "false"                    );
  char const * rocksdb_dir  = fd_env_strip_cmdline_cstr ( &argc, &argv, "--rocksdb",     NULL, NULL                       );
  ulong shred_max           = fd_env_strip_cmdline_ulong( &argc, &argv, "--shredmax",    NULL, 1UL << 17                  );
  char const * capture_path = fd_env_strip_cmdline_cstr ( &argc, &argv, "--capturepath", NULL, NULL                       );
  char const * cmd          = fd_env_strip_cmdline_cstr ( &argc, &argv, "--cmd",         NULL, NULL                       );
  ulong start_slot          = fd_env_strip_cmdline_ulong( &argc, &argv, "--startslot",   NULL, 0                          );
  ulong end_slot            = fd_env_strip_cmdline_ulong( &argc, &argv, "--endslot",     NULL, ULONG_MAX                  );
  ulong max_file_sz         = fd_env_strip_cmdline_ulong( &argc, &argv, "--maxfilesz",   NULL, DEFAULT_SHREDCAP_FILE_SIZE );
  ulong slot_history_max    = fd_env_strip_cmdline_ulong( &argc, &argv, "--slothistory", NULL, DEFAULT_SLOT_HISTORY_MAX   );
  char const * do_verify    = fd_env_strip_cmdline_cstr ( &argc, &argv, "--doverify",    NULL, "true"                     );

  fd_wksp_t * wksp;
  if ( wkspname == NULL ) {
    FD_LOG_NOTICE(( "--wksp not specified, using an anonymous local workspace" ));
    wksp = fd_wksp_new_anonymous( FD_SHMEM_GIGANTIC_PAGE_SZ, pages, 0, "wksp", 0UL );
  } else {
    fd_shmem_info_t shmem_info[ 1UL ];
    if ( FD_UNLIKELY( fd_shmem_info( wkspname, 0UL, shmem_info ) ) ) {
      FD_LOG_ERR(( "unable to query region \"%s\"\n\tprobably does not exist or bad permissions", wkspname ));
    }
    wksp = fd_wksp_attach( wkspname );
  }
  if ( wksp == NULL ) {
    FD_LOG_ERR(( "failed to attach to workspace %s", wkspname ));
  }

  char hostname[ 64UL ];
  gethostname( hostname, sizeof(hostname) );
  ulong hashseed = fd_hash( 0, hostname, strnlen( hostname, sizeof(hostname) ) );

  if( strcmp( reset, "true" ) == 0 ) {
    fd_wksp_reset( wksp, (uint)hashseed );
  }

  /* Create scratch region */
  ulong  smax   = 1024UL << 21 /* MiB */;
  ulong  sdepth = 128;         /* 128 scratch frames */
  void * smem   = fd_wksp_alloc_laddr( wksp, fd_scratch_smem_align(), fd_scratch_smem_footprint( smax   ), 421UL );
  void * fmem   = fd_wksp_alloc_laddr( wksp, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( sdepth ), 421UL );
  FD_TEST( (!!smem) & (!!fmem) );
  fd_scratch_attach( smem, fmem, smax, sdepth );

  void * shmem;
  fd_blockstore_t * blockstore;
  ulong tag = FD_BLOCKSTORE_MAGIC;
  fd_wksp_tag_query_info_t info;
  if ( fd_wksp_tag_query( wksp, &tag, 1, &info, 1 ) > 0) {
    shmem = fd_wksp_laddr_fast( wksp, info.gaddr_lo );
    blockstore = fd_blockstore_join( shmem );
    if ( blockstore == NULL ) {
      FD_LOG_ERR(( "failed to join a blockstore" )); 
    }
  } else {
    shmem = fd_wksp_alloc_laddr( wksp, fd_blockstore_align(), fd_blockstore_footprint(), FD_BLOCKSTORE_MAGIC );
    if ( shmem == NULL ) {
      FD_LOG_ERR(( "failed to allocate a blockstore" ));
    }
    int lg_txn_max = fd_ulong_find_msb( shred_max ) + 1;

    blockstore = fd_blockstore_join( fd_blockstore_new( shmem, 1, hashseed, shred_max, slot_history_max, lg_txn_max ) );
    if ( blockstore == NULL ) {
      fd_wksp_free_laddr( shmem );
      FD_LOG_ERR(( "failed to allocate a blockstore" ));
    }
  }

  FD_LOG_NOTICE(( "blockstore at global address 0x%016lx", fd_wksp_gaddr_fast( wksp, shmem ) ));

  if ( FD_UNLIKELY( cmd == NULL ) ) {
    FD_LOG_ERR(( "no command specified" ));
  }

  if ( strcmp( cmd, "ingest" ) == 0 ) {
    if( rocksdb_dir ) {
      fd_shredcap_ingest_rocksdb_to_capture( rocksdb_dir, capture_path,
                                               max_file_sz, start_slot, end_slot );
      if ( strcmp( do_verify, "true" ) == 0 ) {
        fd_shredcap_verify( capture_path, blockstore );
      }
    }
  }
  else if ( strcmp( cmd, "verify" ) == 0 ) {
    fd_shredcap_verify( capture_path, blockstore );
  }
  else if ( strcmp( cmd, "populate" ) == 0 ) {
    fd_shredcap_populate_blockstore( capture_path, blockstore, start_slot, end_slot );
    // TODO: This should eventually extend to checkpointing just the blockstore 
    // such that it can be loaded in.
  } 
  else {
    FD_LOG_ERR(( "unknown command=%s", cmd ));
  }
  fd_scratch_detach( NULL );
  fd_wksp_free_laddr( smem );
  fd_wksp_free_laddr( fmem );

  fd_log_flush();
  fd_flamenco_halt();
  fd_halt();
  return 0;
}
