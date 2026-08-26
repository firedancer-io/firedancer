#include "../../disco/stem/fd_stem.h"
#include "utils/fd_ssparse.h"

#include <stdlib.h>

static ulong test_pub_sig[ 64UL ];
static ulong test_pub_cnt;
static ulong test_parser_call_cnt;
static ulong test_parser_done_after;

static int
test_ssparse_advance( fd_ssparse_t *                parser,
                      uchar const *                 data,
                      ulong                         data_sz,
                      fd_ssparse_advance_result_t * result );

static ulong
test_stem_publish( fd_stem_context_t * stem,
                   ulong               out_idx,
                   ulong               sig,
                   ulong               chunk,
                   ulong               sz,
                   ulong               ctl,
                   ulong               tsorig,
                   ulong               tspub ) {
  (void)stem;
  (void)out_idx;
  (void)chunk;
  (void)sz;
  (void)ctl;
  (void)tsorig;
  (void)tspub;
  FD_TEST( test_pub_cnt<sizeof(test_pub_sig)/sizeof(test_pub_sig[0]) );
  test_pub_sig[ test_pub_cnt++ ] = sig;
  return test_pub_cnt-1UL;
}

#define fd_stem_publish test_stem_publish
#define fd_ssparse_advance test_ssparse_advance
#include "fd_snapwr_tile.c"
#undef fd_ssparse_advance
#undef fd_stem_publish

static int
test_ssparse_advance( fd_ssparse_t *                parser,
                      uchar const *                 data,
                      ulong                         data_sz,
                      fd_ssparse_advance_result_t * result ) {
  (void)parser;
  (void)data;
  FD_TEST( data_sz==1UL );
  FD_TEST( test_parser_done_after );
  fd_memset( result, 0, sizeof(*result) );
  result->bytes_consumed = 1UL;
  test_parser_call_cnt++;
  return test_parser_call_cnt>=test_parser_done_after ? FD_SSPARSE_ADVANCE_DONE : FD_SSPARSE_ADVANCE_AGAIN;
}

static void
sync_ctx_init( fd_snapwr_tile_t * ctx,
               ulong              lane_cnt,
               int                state ) {
  fd_memset( ctx, 0, sizeof(*ctx) );
  ctx->state           = state;
  ctx->full            = 1;
  ctx->lane_cnt        = lane_cnt;
  ctx->pending_control = ULONG_MAX;
  ctx->ct_out.idx      = 0UL;
}

static void
send_control( fd_snapwr_tile_t * ctx,
              ulong              lane,
              ulong              sig ) {
  FD_TEST( !returnable_frag( ctx, lane, 0UL, sig, 0UL, 0UL, 0UL, 0UL, 0UL,
                             (fd_stem_context_t *)1UL ) );
}

static void
send_data( fd_snapwr_tile_t * ctx,
           ulong              lane,
           int                eom ) {
  ulong sig = FD_SNAPSHOT_MSG_DATA;
  ulong ctl = fd_frag_meta_ctl( 0UL, 0, eom, 0 );
  FD_TEST( !before_frag( ctx, lane, 0UL, sig ) );
  FD_TEST( !returnable_frag( ctx, lane, 0UL, sig, 0UL, 0UL, ctl, 0UL, 0UL,
                             (fd_stem_context_t *)1UL ) );
}

static void
test_barriers_and_frames( void ) {
  ulong const lane_cnts[] = { 1UL, 2UL, 4UL };
  fd_snapwr_tile_t * ctx = aligned_alloc( alignof(fd_snapwr_tile_t), sizeof(fd_snapwr_tile_t) );
  FD_TEST( ctx );
  for( ulong n_idx=0UL; n_idx<sizeof(lane_cnts)/sizeof(lane_cnts[0]); n_idx++ ) {
    ulong lane_cnt = lane_cnts[ n_idx ];
    sync_ctx_init( ctx, lane_cnt, FD_SNAPSHOT_STATE_FINISHING );
    test_pub_cnt = 0UL;
    for( ulong lane=lane_cnt; lane; lane-- ) {
      send_control( ctx, lane-1UL, FD_SNAPSHOT_MSG_CTRL_FINI );
      FD_TEST( test_pub_cnt==(lane==1UL) );
    }

    sync_ctx_init( ctx, lane_cnt, FD_SNAPSHOT_STATE_PROCESSING );
    for( ulong frame=0UL; frame<2UL*lane_cnt; frame++ ) {
      if( lane_cnt>1UL && frame+1UL<2UL*lane_cnt ) {
        ulong future = frame+1UL;
        FD_TEST( before_frag( ctx, future%lane_cnt, 0UL, FD_SNAPSHOT_MSG_DATA )<0 );
      }
      send_data( ctx, frame%lane_cnt, 1 );
      FD_TEST( ctx->expected_frame==frame+1UL );
    }
  }
  free( ctx );
}

static void
test_pending_control_allows_lagging_data( void ) {
  fd_snapwr_tile_t * ctx = aligned_alloc( alignof(fd_snapwr_tile_t), sizeof(fd_snapwr_tile_t) );
  FD_TEST( ctx );
  sync_ctx_init( ctx, 2UL, FD_SNAPSHOT_STATE_PROCESSING );
  uchar lane_data[ 1UL ] __attribute__((aligned(FD_CHUNK_ALIGN))) = { 0U };
  ctx->expected_frame = 1UL;
  ctx->in[1].wksp     = (fd_wksp_t *)lane_data;
  ctx->in[1].chunk0   = 0UL;
  ctx->in[1].wmark    = 0UL;
  ctx->in[1].mtu      = 1UL;
  test_pub_cnt         = 0UL;
  test_parser_call_cnt = 0UL;
  test_parser_done_after = 1UL;

  send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_FINI );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING );
  FD_TEST( ctx->pending_control==FD_SNAPSHOT_MSG_CTRL_FINI );
  FD_TEST( ctx->control_seen[0] );
  FD_TEST( !ctx->control_seen[1] );
  FD_TEST( before_frag( ctx, 0UL, 1UL,
                        FD_SNAPSHOT_MSG_DATA )<0 );

  ulong sig = FD_SNAPSHOT_MSG_DATA;
  ulong ctl = fd_frag_meta_ctl( 0UL, 0, 1, 0 );
  FD_TEST( !before_frag( ctx, 1UL, 0UL, sig ) );
  FD_TEST( !returnable_frag( ctx, 1UL, 0UL, sig, 0UL, 1UL, ctl, 0UL, 0UL,
                             (fd_stem_context_t *)1UL ) );
  FD_TEST( test_parser_call_cnt==1UL );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_FINISHING );
  FD_TEST( ctx->expected_frame==2UL );
  FD_TEST( ctx->pending_control==FD_SNAPSHOT_MSG_CTRL_FINI );
  FD_TEST( ctx->control_seen[0] );
  FD_TEST( !ctx->control_seen[1] );

  send_control( ctx, 1UL, FD_SNAPSHOT_MSG_CTRL_FINI );
  FD_TEST( test_pub_cnt==1UL );
  FD_TEST( test_pub_sig[0]==FD_SNAPSHOT_MSG_CTRL_FINI );
  free( ctx );
}

static void
test_pending_control_keeps_frame_order( void ) {
  fd_snapwr_tile_t * ctx = aligned_alloc( alignof(fd_snapwr_tile_t), sizeof(fd_snapwr_tile_t) );
  FD_TEST( ctx );
  sync_ctx_init( ctx, 3UL, FD_SNAPSHOT_STATE_PROCESSING );
  uchar lane1_data[ 1UL ] __attribute__((aligned(FD_CHUNK_ALIGN))) = { 0U };
  uchar lane2_data[ 1UL ] __attribute__((aligned(FD_CHUNK_ALIGN))) = { 0U };
  ctx->expected_frame = 1UL;
  ctx->in[1].wksp     = (fd_wksp_t *)lane1_data;
  ctx->in[1].chunk0   = 0UL;
  ctx->in[1].wmark    = 0UL;
  ctx->in[1].mtu      = 1UL;
  ctx->in[2].wksp     = (fd_wksp_t *)lane2_data;
  ctx->in[2].chunk0   = 0UL;
  ctx->in[2].wmark    = 0UL;
  ctx->in[2].mtu      = 1UL;
  test_pub_cnt          = 0UL;
  test_parser_call_cnt  = 0UL;
  test_parser_done_after = 2UL;

  send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_FINI );
  ulong sig1 = FD_SNAPSHOT_MSG_DATA;
  ulong sig2 = FD_SNAPSHOT_MSG_DATA;
  ulong ctl  = fd_frag_meta_ctl( 0UL, 0, 1, 0 );
  FD_TEST( !before_frag( ctx, 1UL, 0UL, sig1 ) );
  FD_TEST( before_frag( ctx, 2UL, 0UL, sig2 )<0 );

  FD_TEST( !returnable_frag( ctx, 1UL, 0UL, sig1, 0UL, 1UL, ctl, 0UL, 0UL,
                             (fd_stem_context_t *)1UL ) );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING );
  FD_TEST( ctx->expected_frame==2UL );
  FD_TEST( !before_frag( ctx, 2UL, 0UL, sig2 ) );
  FD_TEST( !returnable_frag( ctx, 2UL, 0UL, sig2, 0UL, 1UL, ctl, 0UL, 0UL,
                             (fd_stem_context_t *)1UL ) );
  FD_TEST( test_parser_call_cnt==2UL );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_FINISHING );
  FD_TEST( ctx->expected_frame==3UL );
  send_control( ctx, 1UL, FD_SNAPSHOT_MSG_CTRL_FINI );
  send_control( ctx, 2UL, FD_SNAPSHOT_MSG_CTRL_FINI );
  FD_TEST( test_pub_cnt==1UL );
  FD_TEST( test_pub_sig[0]==FD_SNAPSHOT_MSG_CTRL_FINI );

  free( ctx );
}

static void
test_error_interrupts_incremental_init( void ) {
  fd_snapwr_tile_t * ctx = aligned_alloc( alignof(fd_snapwr_tile_t), sizeof(fd_snapwr_tile_t) );
  FD_TEST( ctx );
  sync_ctx_init( ctx, 2UL, FD_SNAPSHOT_STATE_IDLE );
  ctx->recovery.accounts_off = 4096UL;
  ctx->recovery.flush_off    = 3072UL;
  ctx->accounts_off          = ctx->recovery.accounts_off;
  ctx->flush_off             = ctx->recovery.flush_off;
  test_pub_cnt               = 0UL;

  FD_TEST( !before_frag( ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_CTRL_INIT_INCR ) );
  send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_INIT_INCR );
  FD_TEST( ctx->pending_control==FD_SNAPSHOT_MSG_CTRL_INIT_INCR );
  FD_TEST( ctx->control_seen[0] );
  FD_TEST( !ctx->control_seen[1] );
  FD_TEST( !ctx->full );

  FD_TEST( !before_frag( ctx, 0UL, 1UL, FD_SNAPSHOT_MSG_CTRL_ERROR ) );
  send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_ERROR );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_ERROR );
  FD_TEST( ctx->pending_control==FD_SNAPSHOT_MSG_CTRL_INIT_INCR );
  FD_TEST( ctx->control_seen[0] );
  FD_TEST( !ctx->control_seen[1] );
  FD_TEST( test_pub_cnt==1UL );
  FD_TEST( test_pub_sig[0]==FD_SNAPSHOT_MSG_CTRL_ERROR );
  FD_TEST( before_frag( ctx, 1UL, 0UL, FD_SNAPSHOT_MSG_CTRL_INIT_INCR )>0 );

  FD_TEST( !before_frag( ctx, 0UL, 2UL, FD_SNAPSHOT_MSG_CTRL_FAIL ) );
  send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
  FD_TEST( !before_frag( ctx, 1UL, 1UL, FD_SNAPSHOT_MSG_CTRL_FAIL ) );
  send_control( ctx, 1UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
  FD_TEST( !ctx->write_buf_used );
  FD_TEST( ctx->accounts_off==ctx->recovery.accounts_off );
  FD_TEST( ctx->flush_off==ctx->recovery.flush_off );
  FD_TEST( ctx->accounts_off==4096UL );
  FD_TEST( ctx->flush_off==3072UL );

  free( ctx );
}

static void
test_partial_fail_survives_error( void ) {
  fd_snapwr_tile_t * ctx = aligned_alloc( alignof(fd_snapwr_tile_t), sizeof(fd_snapwr_tile_t) );
  FD_TEST( ctx );
  sync_ctx_init( ctx, 4UL, FD_SNAPSHOT_STATE_PROCESSING );
  test_pub_cnt = 0UL;

  FD_TEST( !before_frag( ctx, 2UL, 0UL, FD_SNAPSHOT_MSG_CTRL_FAIL ) );
  send_control( ctx, 2UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
  FD_TEST( ctx->pending_control==FD_SNAPSHOT_MSG_CTRL_FAIL );
  FD_TEST( ctx->control_seen[2] );

  FD_TEST( !before_frag( ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_CTRL_ERROR ) );
  send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_ERROR );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_ERROR );
  FD_TEST( ctx->pending_control==FD_SNAPSHOT_MSG_CTRL_FAIL );
  FD_TEST( ctx->control_seen[2] );

  send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
  send_control( ctx, 1UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
  send_control( ctx, 3UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
  FD_TEST( ctx->pending_control==ULONG_MAX );
  FD_TEST( test_pub_cnt==2UL );
  FD_TEST( test_pub_sig[0]==FD_SNAPSHOT_MSG_CTRL_ERROR );
  FD_TEST( test_pub_sig[1]==FD_SNAPSHOT_MSG_CTRL_FAIL );

  sync_ctx_init( ctx, 4UL, FD_SNAPSHOT_STATE_PROCESSING );
  test_pub_cnt = 0UL;
  send_control( ctx, 2UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
  transition_malformed( ctx, (fd_stem_context_t *)1UL );
  FD_TEST( ctx->pending_control==FD_SNAPSHOT_MSG_CTRL_FAIL );
  FD_TEST( ctx->control_seen[2] );
  send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
  send_control( ctx, 1UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
  send_control( ctx, 3UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
  FD_TEST( ctx->pending_control==ULONG_MAX );
  free( ctx );
}

static void
test_fail_supersedes_pending_controls( void ) {
  struct {
    ulong sig;
    int   state;
  } const cases[] = {
    { FD_SNAPSHOT_MSG_META,           FD_SNAPSHOT_STATE_PROCESSING },
    { FD_SNAPSHOT_MSG_CTRL_INIT_FULL, FD_SNAPSHOT_STATE_IDLE       },
    { FD_SNAPSHOT_MSG_CTRL_INIT_INCR, FD_SNAPSHOT_STATE_IDLE       },
    { FD_SNAPSHOT_MSG_CTRL_FINI,      FD_SNAPSHOT_STATE_PROCESSING },
    { FD_SNAPSHOT_MSG_CTRL_NEXT,      FD_SNAPSHOT_STATE_FINISHING  },
    { FD_SNAPSHOT_MSG_CTRL_DONE,      FD_SNAPSHOT_STATE_FINISHING  },
  };

  for( ulong i=0UL; i<sizeof(cases)/sizeof(cases[0]); i++ ) {
    fd_snapwr_tile_t * ctx = aligned_alloc( alignof(fd_snapwr_tile_t), sizeof(fd_snapwr_tile_t) );
    FD_TEST( ctx );
    sync_ctx_init( ctx, 4UL, cases[i].state );
    test_pub_cnt = 0UL;

    FD_TEST( !before_frag( ctx, 0UL, 0UL, cases[i].sig ) );
    send_control( ctx, 0UL, cases[i].sig );
    FD_TEST( ctx->pending_control==cases[i].sig );
    FD_TEST( ctx->control_seen[0] );

    FD_TEST( !before_frag( ctx, 1UL, 0UL, FD_SNAPSHOT_MSG_CTRL_FAIL ) );
    send_control( ctx, 1UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
    FD_TEST( ctx->pending_control==FD_SNAPSHOT_MSG_CTRL_FAIL );
    FD_TEST( !ctx->control_seen[0] );
    FD_TEST( ctx->control_seen[1] );

    send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
    send_control( ctx, 2UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
    send_control( ctx, 3UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
    FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
    FD_TEST( ctx->pending_control==ULONG_MAX );
    FD_TEST( test_pub_cnt==1UL );
    FD_TEST( test_pub_sig[0]==FD_SNAPSHOT_MSG_CTRL_FAIL );
    free( ctx );
  }
}

static void
test_incremental_fail_rolls_back( void ) {
  fd_snapwr_tile_t * ctx = aligned_alloc( alignof(fd_snapwr_tile_t), sizeof(fd_snapwr_tile_t) );
  FD_TEST( ctx );
  void * parser_mem = aligned_alloc( fd_ssmanifest_parser_align(), fd_ssmanifest_parser_footprint() );
  FD_TEST( parser_mem );
  sync_ctx_init( ctx, 2UL, FD_SNAPSHOT_STATE_IDLE );
  ctx->manifest_parser       = fd_ssmanifest_parser_join( fd_ssmanifest_parser_new( parser_mem ) );
  ctx->recovery.accounts_off = 4096UL;
  ctx->recovery.flush_off    = 3072UL;
  ctx->accounts_off          = ctx->recovery.accounts_off;
  ctx->flush_off             = ctx->recovery.flush_off;
  test_pub_cnt                = 0UL;

  send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_INIT_INCR );
  send_control( ctx, 1UL, FD_SNAPSHOT_MSG_CTRL_INIT_INCR );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING );
  FD_TEST( !ctx->full );

  ctx->accounts_off   = 8192UL;
  ctx->flush_off      = 6144UL;
  ctx->write_buf_used = 128UL;
  send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_ERROR );
  send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
  send_control( ctx, 1UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
  FD_TEST( !ctx->write_buf_used );
  FD_TEST( ctx->accounts_off==ctx->recovery.accounts_off );
  FD_TEST( ctx->flush_off==ctx->recovery.flush_off );
  FD_TEST( ctx->accounts_off==4096UL );
  FD_TEST( ctx->flush_off==3072UL );

  free( parser_mem );
  free( ctx );
}

static void
test_error_and_fail( void ) {
  fd_snapwr_tile_t * ctx = aligned_alloc( alignof(fd_snapwr_tile_t), sizeof(fd_snapwr_tile_t) );
  FD_TEST( ctx );
  sync_ctx_init( ctx, 2UL, FD_SNAPSHOT_STATE_FINISHING );
  test_pub_cnt = 0UL;
  send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_ERROR );
  FD_TEST( test_pub_cnt==1UL );
  FD_TEST( before_frag( ctx, 1UL, 0UL, FD_SNAPSHOT_MSG_CTRL_DONE )>0 );
  send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_ERROR );
  send_control( ctx, 1UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
  FD_TEST( test_pub_cnt==2UL );
  free( ctx );
}

static void
test_raw_lane_and_zero_eom( void ) {
  fd_snapwr_tile_t * ctx = aligned_alloc( alignof(fd_snapwr_tile_t), sizeof(fd_snapwr_tile_t) );
  FD_TEST( ctx );
  sync_ctx_init( ctx, 4UL, FD_SNAPSHOT_STATE_PROCESSING );
  FD_TEST( before_frag( ctx, 1UL, 0UL, FD_SNAPSHOT_MSG_DATA )<0 );
  send_data( ctx, 0UL, 0 );
  FD_TEST( !ctx->expected_frame );

  ctx->state          = FD_SNAPSHOT_STATE_FINISHING;
  ctx->expected_frame = 1UL;
  send_data( ctx, 1UL, 1 );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_FINISHING );
  FD_TEST( ctx->expected_frame==2UL );
  free( ctx );
}

static void
test_malformed_stream_endings( void ) {
  fd_snapwr_tile_t * ctx = aligned_alloc( alignof(fd_snapwr_tile_t), sizeof(fd_snapwr_tile_t) );
  FD_TEST( ctx );
  sync_ctx_init( ctx, 2UL, FD_SNAPSHOT_STATE_PROCESSING );
  test_pub_cnt = 0UL;
  send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_FINI );
  send_control( ctx, 1UL, FD_SNAPSHOT_MSG_CTRL_FINI );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_ERROR );
  FD_TEST( test_pub_cnt==1UL );
  FD_TEST( test_pub_sig[0]==FD_SNAPSHOT_MSG_CTRL_ERROR );

  sync_ctx_init( ctx, 2UL, FD_SNAPSHOT_STATE_FINISHING );
  test_pub_cnt = 0UL;
  ulong ctl = fd_frag_meta_ctl( 0UL, 0, 1, 0 );
  FD_TEST( !before_frag( ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_DATA ) );
  FD_TEST( !returnable_frag( ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_DATA,
                             0UL, 1UL, ctl, 0UL, 0UL,
                             (fd_stem_context_t *)1UL ) );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_ERROR );
  FD_TEST( test_pub_cnt==1UL );
  FD_TEST( test_pub_sig[0]==FD_SNAPSHOT_MSG_CTRL_ERROR );
  free( ctx );
}

static void
test_init_resets_lane_state( void ) {
  fd_snapwr_tile_t * ctx = aligned_alloc( alignof(fd_snapwr_tile_t), sizeof(fd_snapwr_tile_t) );
  FD_TEST( ctx );
  void * parser_mem = aligned_alloc( fd_ssmanifest_parser_align(), fd_ssmanifest_parser_footprint() );
  FD_TEST( parser_mem );
  sync_ctx_init( ctx, 2UL, FD_SNAPSHOT_STATE_IDLE );
  ctx->manifest_parser = fd_ssmanifest_parser_join( fd_ssmanifest_parser_new( parser_mem ) );
  ctx->in[0].pos       = 5UL;
  ctx->in[1].pos       = 6UL;
  ctx->expected_frame  = 7UL;

  send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_INIT_INCR );
  FD_TEST( ctx->in[0].pos==5UL );
  FD_TEST( ctx->in[1].pos==6UL );
  FD_TEST( ctx->expected_frame==7UL );

  send_control( ctx, 1UL, FD_SNAPSHOT_MSG_CTRL_INIT_INCR );
  FD_TEST( !ctx->in[0].pos );
  FD_TEST( !ctx->in[1].pos );
  FD_TEST( !ctx->expected_frame );
  FD_TEST( !ctx->full );
  free( parser_mem );
  free( ctx );
}

static void
test_nonempty_raw_data( void ) {
  fd_snapwr_tile_t * ctx = aligned_alloc( alignof(fd_snapwr_tile_t), sizeof(fd_snapwr_tile_t) );
  FD_TEST( ctx );
  uchar lane_data[1] __attribute__((aligned(FD_CHUNK_ALIGN))) = { 0U };
  sync_ctx_init( ctx, 2UL, FD_SNAPSHOT_STATE_PROCESSING );
  ctx->in[0].wksp   = (fd_wksp_t *)lane_data;
  ctx->in[0].chunk0 = 0UL;
  ctx->in[0].wmark  = 0UL;
  ctx->in[0].mtu    = sizeof(lane_data);
  test_parser_call_cnt  = 0UL;
  test_parser_done_after = 1UL;

  FD_TEST( before_frag( ctx, 1UL, 0UL, FD_SNAPSHOT_MSG_DATA )<0 );
  ulong ctl = fd_frag_meta_ctl( 0UL, 0, 0, 0 );
  FD_TEST( !returnable_frag( ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_DATA,
                             0UL, sizeof(lane_data), ctl, 0UL, 0UL,
                             (fd_stem_context_t *)1UL ) );
  FD_TEST( test_parser_call_cnt==1UL );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_FINISHING );
  FD_TEST( !ctx->expected_frame );
  free( ctx );
}

static void
test_meta_barrier_is_swallowed( void ) {
  fd_snapwr_tile_t * ctx = aligned_alloc( alignof(fd_snapwr_tile_t), sizeof(fd_snapwr_tile_t) );
  FD_TEST( ctx );
  sync_ctx_init( ctx, 2UL, FD_SNAPSHOT_STATE_PROCESSING );
  test_pub_cnt = 0UL;
  send_control( ctx, 0UL, FD_SNAPSHOT_MSG_META );
  FD_TEST( ctx->pending_control==FD_SNAPSHOT_MSG_META );
  FD_TEST( !test_pub_cnt );
  send_control( ctx, 1UL, FD_SNAPSHOT_MSG_META );
  FD_TEST( ctx->pending_control==ULONG_MAX );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING );
  FD_TEST( !test_pub_cnt );
  free( ctx );
}

static void
test_control_rollback_lifecycle( void ) {
  fd_snapwr_tile_t * ctx = aligned_alloc( alignof(fd_snapwr_tile_t), sizeof(fd_snapwr_tile_t) );
  FD_TEST( ctx );
  sync_ctx_init( ctx, 2UL, FD_SNAPSHOT_STATE_FINISHING );
  ctx->accounts_off = 4096UL;
  ctx->flush_off    = 3072UL;
  test_pub_cnt      = 0UL;
  send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_NEXT );
  send_control( ctx, 1UL, FD_SNAPSHOT_MSG_CTRL_NEXT );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
  FD_TEST( ctx->recovery.accounts_off==4096UL );
  FD_TEST( ctx->recovery.flush_off==3072UL );

  send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
  send_control( ctx, 1UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
  FD_TEST( !ctx->accounts_off );
  FD_TEST( !ctx->flush_off );

  sync_ctx_init( ctx, 2UL, FD_SNAPSHOT_STATE_FINISHING );
  ctx->accounts_off = 4096UL;
  ctx->flush_off    = 3072UL;
  send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_NEXT );
  send_control( ctx, 1UL, FD_SNAPSHOT_MSG_CTRL_NEXT );
  send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_INIT_INCR );
  FD_TEST( !ctx->full );
  send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_ERROR );
  send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
  send_control( ctx, 1UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
  FD_TEST( ctx->accounts_off==4096UL );
  FD_TEST( ctx->flush_off==3072UL );

  sync_ctx_init( ctx, 2UL, FD_SNAPSHOT_STATE_FINISHING );
  send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_DONE );
  send_control( ctx, 1UL, FD_SNAPSHOT_MSG_CTRL_DONE );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
  send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_SHUTDOWN );
  send_control( ctx, 1UL, FD_SNAPSHOT_MSG_CTRL_SHUTDOWN );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_SHUTDOWN );
  free( ctx );
}

static void
test_full_fail_resets_offsets( void ) {
  fd_snapwr_tile_t * ctx = aligned_alloc( alignof(fd_snapwr_tile_t), sizeof(fd_snapwr_tile_t) );
  FD_TEST( ctx );
  sync_ctx_init( ctx, 2UL, FD_SNAPSHOT_STATE_ERROR );
  ctx->full           = 1;
  ctx->accounts_off   = 4096UL;
  ctx->flush_off      = 3072UL;
  ctx->write_buf_used = 128UL;
  send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
  send_control( ctx, 1UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
  FD_TEST( !ctx->accounts_off );
  FD_TEST( !ctx->flush_off );
  FD_TEST( !ctx->write_buf_used );
  free( ctx );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_barriers_and_frames();
  test_pending_control_allows_lagging_data();
  test_pending_control_keeps_frame_order();
  test_error_interrupts_incremental_init();
  test_partial_fail_survives_error();
  test_fail_supersedes_pending_controls();
  test_incremental_fail_rolls_back();
  test_error_and_fail();
  test_raw_lane_and_zero_eom();
  test_malformed_stream_endings();
  test_init_resets_lane_state();
  test_nonempty_raw_data();
  test_meta_barrier_is_swallowed();
  test_control_rollback_lifecycle();
  test_full_fail_resets_offsets();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
