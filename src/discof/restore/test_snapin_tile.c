#define FD_TILE_TEST
#include "fd_snapin_tile.c"
#include "stream/fd_stream_writer.h"

static ulong
mock_stream_align( void ) {
  return fd_ulong_max( fd_ulong_max( fd_stream_writer_align(), fd_mcache_align() ), fd_dcache_align() );
}

static ulong
mock_stream_footprint( ulong depth,
                       ulong dcache_data_sz ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_stream_writer_align(), fd_stream_writer_footprint( 0UL )          );
  l = FD_LAYOUT_APPEND( l, fd_mcache_align(),        fd_mcache_footprint( depth, 0uL          ) );
  l = FD_LAYOUT_APPEND( l, fd_dcache_align(),        fd_dcache_footprint( dcache_data_sz, 0UL ) );
  return l;
}

static fd_stream_writer_t *
mock_stream_init( void * mem,
                  ulong  depth,
                  ulong  dcache_data_sz ) {
  if( FD_UNLIKELY( !mem ) ) return NULL;
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, mock_stream_align() ) ) ) return NULL;

  FD_SCRATCH_ALLOC_INIT( l, mem );
  void * writer_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_stream_writer_align(), fd_stream_writer_footprint( 0UL )          );
  void * mcache_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_mcache_align(),        fd_mcache_footprint( depth, 0uL          ) );
  void * dcache_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_dcache_align(),        fd_dcache_footprint( dcache_data_sz, 0UL ) );

  fd_frag_meta_t * mcache = fd_mcache_join( fd_mcache_new( mcache_mem, depth, 0UL, 0UL ) );
  uchar *          dcache = fd_dcache_join( fd_dcache_new( dcache_mem, dcache_data_sz, 0UL ) );

  return fd_stream_writer_new( writer_mem, 0UL, fd_type_pun( mcache ), dcache );
}

static void *
mock_stream_delete( fd_stream_writer_t * writer ) {
  fd_dcache_delete( fd_dcache_leave( writer->data ) );
  fd_mcache_delete( fd_mcache_leave( fd_type_pun( writer->mcache ) ) );
  return fd_stream_writer_delete( writer );
}

/* Feed in snapshot stream frags and validate the resulting account
   frags are sane.  This variant tests handwritten edge cases. */

static void
test_account_frags( fd_wksp_t * wksp ) {
  /* Create a snapin context */
  fd_topo_tile_t topo_tile = {
    .name = "snapin",
    .snapin = {
      .scratch_sz = 4096UL
    }
  };
  void * tile_scratch = fd_wksp_alloc_laddr( wksp, scratch_align(), scratch_footprint( &topo_tile ), 1UL );
  FD_TEST( tile_scratch );
  fd_snapin_tile_t * ctx = scratch_init( tile_scratch, &topo_tile );
  FD_TEST( ctx );

  void * out_mcache_mem = fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( 128UL, 0UL ), 1UL );
  ctx->out_mcache = fd_type_pun( fd_mcache_join( fd_mcache_new( out_mcache_mem, 128UL, 0UL, 0UL ) ) );
  FD_TEST( ctx->out_mcache );
  ctx->out_depth   = fd_mcache_depth( ctx->out_mcache->f );
  ctx->out_seq_max = UINT_MAX;

  ctx->tar_file_rem = ULONG_MAX;
  ctx->accv_sz      = ULONG_MAX;
  fd_snapshot_expect_account_hdr( ctx );
  uchar scratch_buf[ 256 ];
  ctx->buf     = scratch_buf;
  ctx->buf_max = sizeof(scratch_buf);

  /* Create an input */
  void * in_stream_mem = fd_wksp_alloc_laddr( wksp, mock_stream_align(), mock_stream_footprint( 128UL, 4096UL ), 1UL );
  fd_stream_writer_t * in_stream = mock_stream_init( in_stream_mem, 128UL, 4096UL );
  FD_TEST( in_stream );
  fd_snapin_in_t in = {
    .mcache = in_stream->mcache,
    .depth  = (uint)in_stream->depth,
    .idx    = 0U,
    .seq    = 0UL,
    .goff   = 0UL,
    .mline  = in_stream->mcache
  };
  ctx->in_base = (uchar *)wksp;

  /* An empty account */
  fd_solana_account_hdr_t const acc1 = { .hash={ .uc={ 1,2,3 } } };
  fd_stream_writer_copy( in_stream, &acc1, sizeof(fd_solana_account_hdr_t), fd_frag_meta_ctl( 0, 1, 1, 0 ) );
  ulong read_sz;
  FD_TEST( on_stream_frag( ctx, &in, in_stream->mcache+0, &read_sz )==1 );
  FD_TEST( ctx->out_mcache[ 0 ].seq==0UL );
  FD_TEST( ctx->out_mcache[ 0 ].sz==sizeof(fd_solana_account_hdr_t) );
  FD_TEST( ctx->out_mcache[ 0 ].ctl==fd_frag_meta_ctl( 0, 1, 1, 0 ) );
  FD_TEST( ctx->out_mcache[ 0 ].goff==0UL );
  FD_TEST( fd_memeq( ctx->in_base+ctx->out_mcache[ 0 ].loff, &acc1, sizeof(fd_solana_account_hdr_t) ) );

  fd_wksp_free_laddr( mock_stream_delete( in_stream ) );
  fd_wksp_free_laddr( tile_scratch );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL,      "gigantic" );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",  NULL,             1UL );
  ulong        near_cpu = fd_env_strip_cmdline_ulong( &argc, &argv, "--near-cpu",  NULL, fd_log_cpu_id() );
  uint         rng_seed = fd_env_strip_cmdline_uint ( &argc, &argv, "--rng-seed",  NULL,              0U );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, rng_seed, 0UL ) );

  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, near_cpu, "wksp", 0UL );
  if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "Unable to attach to wksp" ));

  test_account_frags( wksp );

  fd_wksp_delete_anonymous( wksp );
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
