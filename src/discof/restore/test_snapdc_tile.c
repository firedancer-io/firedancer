#include "../../disco/stem/fd_stem.h"
#include "utils/fd_ssctrl.h"

#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>
#include <zstd_errors.h>

#include <stdlib.h>

#define TEST_PUB_MAX  (512UL)
#define TEST_DATA_MAX (32UL*FD_SNAPSHOT_DATA_MTU)

typedef struct {
  ulong sig;
  ulong sz;
  ulong ctl;
  ulong data_off;
} test_pub_t;

static test_pub_t test_pub[ TEST_PUB_MAX ];
static ulong      test_pub_cnt;
static uchar      test_data[ TEST_DATA_MAX ];
static ulong      test_data_sz;
static void *     test_out_mem;
static int        test_decompress_script;
static int        test_decompress_phase;

static ulong
test_zstd_decompress_stream( ZSTD_DCtx * dctx,
                             void *      dst,
                             ulong       dst_capacity,
                             ulong *     dst_pos,
                             void const * src,
                             ulong        src_size,
                             ulong *      src_pos ) {
  if( FD_LIKELY( !test_decompress_script ) )
    return ZSTD_decompressStream_simpleArgs( dctx, dst, dst_capacity, dst_pos, src, src_size, src_pos );

  FD_TEST( dst_capacity>=64UL );
  int phase = test_decompress_phase++;
  if( !phase ) {
    FD_TEST( src_size );
    fd_memset( dst, 'a', 23UL );
    *dst_pos = 23UL;
    *src_pos = 0UL;
    return 1UL;
  }
  if( phase==1 ) {
    FD_TEST( src_size );
    fd_memset( dst, 'b', 64UL );
    *dst_pos = 64UL;
    *src_pos = src_size;
    return 1UL;
  }

  FD_TEST( !src_size );
  fd_memset( dst, 'c', 17UL );
  *dst_pos = 17UL;
  *src_pos = 0UL;
  return 0UL;
}

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
  (void)tsorig;
  (void)tspub;

  FD_TEST( test_pub_cnt<TEST_PUB_MAX );
  FD_TEST( test_data_sz+sz<=TEST_DATA_MAX );
  test_pub_t * pub = &test_pub[ test_pub_cnt++ ];
  pub->sig      = sig;
  pub->sz       = sz;
  pub->ctl      = ctl;
  pub->data_off = test_data_sz;
  if( sz ) fd_memcpy( test_data+test_data_sz, fd_chunk_to_laddr_const( test_out_mem, chunk ), sz );
  test_data_sz += sz;
  return test_pub_cnt-1UL;
}

#undef  fd_stem_publish
#define fd_stem_publish test_stem_publish
#define ZSTD_decompressStream_simpleArgs test_zstd_decompress_stream
#include "fd_snapdc_tile.c"
#undef ZSTD_decompressStream_simpleArgs
#undef fd_stem_publish

typedef struct {
  fd_snapdc_tile_t ctx[1];
  fd_ssctrl_init_t init[1];
  fd_ssctrl_meta_t meta[1];
  uchar in [ 2UL*FD_SNAPSHOT_DATA_MTU ] __attribute__((aligned(FD_CHUNK_ALIGN)));
  uchar out[ 8UL*FD_SNAPSHOT_DATA_MTU ] __attribute__((aligned(FD_CHUNK_ALIGN)));
} test_env_t;

static void
capture_reset( test_env_t * env ) {
  test_pub_cnt  = 0UL;
  test_data_sz  = 0UL;
  test_out_mem  = env->out;
}

static test_env_t *
test_env_new( ulong tile_idx,
              ulong tile_count ) {
  test_env_t * env = aligned_alloc( FD_CHUNK_ALIGN, sizeof(test_env_t) );
  FD_TEST( env );
  fd_memset( env, 0, sizeof(test_env_t) );

  env->ctx->state       = FD_SNAPSHOT_STATE_IDLE;
  env->ctx->tile_idx    = tile_idx;
  env->ctx->tile_count  = tile_count;
  env->ctx->zstd        = ZSTD_createDCtx();
  env->ctx->in.mem      = (fd_wksp_t *)env->in;
  env->ctx->in.chunk0   = 0UL;
  env->ctx->in.wmark    = sizeof(env->in)>>FD_CHUNK_LG_SZ;
  env->ctx->in.mtu      = FD_SNAPSHOT_DATA_MTU;
  env->ctx->out.mem     = (fd_wksp_t *)env->out;
  env->ctx->out.chunk0  = 0UL;
  env->ctx->out.wmark   = sizeof(env->out)>>FD_CHUNK_LG_SZ;
  env->ctx->out.chunk   = 0UL;
  env->ctx->out.mtu     = FD_SNAPSHOT_DATA_MTU;
  FD_TEST( env->ctx->zstd );
  FD_TEST( tile_count && tile_count<=FD_TOPO_MAX_TILE_IN_LINKS );
  FD_TEST( tile_idx<tile_count );

  capture_reset( env );
  return env;
}

static void
test_env_delete( test_env_t * env ) {
  FD_TEST( !ZSTD_isError( ZSTD_freeDCtx( env->ctx->zstd ) ) );
  free( env );
}

static int
data_call( test_env_t * env,
           ulong        sz ) {
  ulong sig = FD_SNAPSHOT_MSG_DATA;
  ulong pub_cnt = test_pub_cnt;
  int again = returnable_frag( env->ctx, 0UL, 0UL, sig, 0UL, sz,
                               0UL, 0UL, 0UL, (fd_stem_context_t *)1UL );
  FD_TEST( test_pub_cnt-pub_cnt<=1UL );
  return again;
}

static ulong
send_data( test_env_t * env,
           void const * data,
           ulong        data_sz ) {
  FD_TEST( data_sz<=env->ctx->in.mtu );
  if( data_sz ) fd_memcpy( env->in, data, data_sz );
  ulong call_cnt = 0UL;
  do {
    FD_TEST( call_cnt++<TEST_PUB_MAX );
  } while( data_call( env, data_sz ) );
  return call_cnt;
}

static void
send_control( test_env_t * env,
              ulong        sig ) {
  ulong pub_cnt = test_pub_cnt;
  FD_TEST( !returnable_frag( env->ctx, 0UL, 0UL, sig, 0UL, 0UL,
                             0UL, 0UL, 0UL, (fd_stem_context_t *)1UL ) );
  FD_TEST( test_pub_cnt-pub_cnt<=1UL );
}

static void
begin_load( test_env_t * env,
            int          full,
            int          zstd ) {
  fd_memset( env->init, 0, sizeof(fd_ssctrl_init_t) );
  env->init->zstd = zstd;
  fd_memcpy( env->in, env->init, sizeof(fd_ssctrl_init_t) );
  ulong sig = full ? FD_SNAPSHOT_MSG_CTRL_INIT_FULL : FD_SNAPSHOT_MSG_CTRL_INIT_INCR;
  ulong pub_cnt = test_pub_cnt;
  FD_TEST( !returnable_frag( env->ctx, 0UL, 0UL, sig, 0UL, sizeof(fd_ssctrl_init_t),
                             0UL, 0UL, 0UL, (fd_stem_context_t *)1UL ) );
  FD_TEST( test_pub_cnt==pub_cnt+1UL );
  FD_TEST( test_pub[ pub_cnt ].sig==sig );
  FD_TEST( test_pub[ pub_cnt ].sz==sizeof(fd_ssctrl_init_t) );
  FD_TEST( !memcmp( test_data+test_pub[ pub_cnt ].data_off, env->init, sizeof(fd_ssctrl_init_t) ) );
}

static ulong
make_frame( uchar *       out,
            ulong         out_max,
            void const *  src,
            ulong         src_sz,
            int           content_size,
            int           checksum ) {
  ZSTD_CCtx * cctx = ZSTD_createCCtx();
  FD_TEST( cctx );
  FD_TEST( !ZSTD_isError( ZSTD_CCtx_setParameter( cctx, ZSTD_c_contentSizeFlag, content_size ) ) );
  FD_TEST( !ZSTD_isError( ZSTD_CCtx_setParameter( cctx, ZSTD_c_checksumFlag,    checksum     ) ) );
  ulong frame_sz = ZSTD_compress2( cctx, out, out_max, src, src_sz );
  FD_TEST( !ZSTD_isError( frame_sz ) );
  FD_TEST( !ZSTD_isError( ZSTD_freeCCtx( cctx ) ) );
  return frame_sz;
}

static ulong
make_skippable( uchar * out,
                ulong   payload_sz,
                uchar   seed ) {
  FD_STORE( uint, out,     0x184d2a50U      );
  FD_STORE( uint, out+4UL, (uint)payload_sz );
  for( ulong i=0UL; i<payload_sz; i++ ) out[ 8UL+i ] = (uchar)(seed+(uchar)i);
  return 8UL+payload_sz;
}

static void
assert_output( ulong        pub_off,
               void const * expected,
               ulong        expected_sz,
               int          eom ) {
  ulong out_sz = 0UL;
  ulong data_cnt = 0UL;
  for( ulong i=pub_off; i<test_pub_cnt; i++ ) {
    FD_TEST( test_pub[i].sig==FD_SNAPSHOT_MSG_DATA );
    FD_TEST( out_sz+test_pub[i].sz<=expected_sz );
    if( test_pub[i].sz ) {
      FD_TEST( !memcmp( test_data+test_pub[i].data_off,
                        (uchar const *)expected+out_sz,
                        test_pub[i].sz ) );
    }
    out_sz += test_pub[i].sz;
    data_cnt++;
    FD_TEST( fd_frag_meta_ctl_eom( test_pub[i].ctl )==(eom && i+1UL==test_pub_cnt) );
  }
  FD_TEST( data_cnt );
  FD_TEST( out_sz==expected_sz );
}

static void
feed_frame( test_env_t * env,
            void const * frame,
            ulong        frame_sz,
            ulong        piece_sz ) {
  FD_TEST( piece_sz );
  ulong off = 0UL;
  while( off<frame_sz ) {
    ulong piece = fd_ulong_min( piece_sz, frame_sz-off );
    send_data( env, (uchar const *)frame+off, piece );
    off += piece;
  }
}

static void
test_owner_counts( void ) {
  static uchar const payload[] = "frame owner";
  uchar frame[4096];
  ulong frame_sz = make_frame( frame, sizeof(frame), payload, sizeof(payload)-1UL, 1, 0 );
  ulong const tile_counts[] = { 1UL, 2UL, 3UL, 4UL };

  for( ulong count_idx=0UL; count_idx<sizeof(tile_counts)/sizeof(tile_counts[0]); count_idx++ ) {
    ulong tile_count = tile_counts[ count_idx ];
    for( ulong tile_idx=0UL; tile_idx<tile_count; tile_idx++ ) {
      test_env_t * env = test_env_new( tile_idx, tile_count );
      begin_load( env, 1, 1 );
      capture_reset( env );

      for( ulong frame_idx=0UL; frame_idx<2UL*tile_count; frame_idx++ ) {
        ulong pub_off = test_pub_cnt;
        send_data( env, frame, frame_sz );
        if( frame_idx%tile_count==tile_idx ) {
          FD_TEST( test_pub_cnt==pub_off+1UL );
          assert_output( pub_off, payload, sizeof(payload)-1UL, 1 );
        } else {
          FD_TEST( test_pub_cnt==pub_off );
        }
        capture_reset( env );
      }
      FD_TEST( env->ctx->metrics.full.compressed_bytes_read==2UL*frame_sz );
      FD_TEST( env->ctx->metrics.full.decompressed_bytes_written==2UL*(sizeof(payload)-1UL) );
      test_env_delete( env );
    }
  }
}

static void
test_plain_multiframe_input( void ) {
  static char const * payload[] = { "frame zero", "frame one", "frame two", "frame three" };
  uchar stream[8192];
  ulong stream_sz = 0UL;
  for( ulong frame_idx=0UL; frame_idx<4UL; frame_idx++ ) {
    ulong payload_sz = strlen( payload[frame_idx] );
    stream_sz += make_frame( stream+stream_sz, sizeof(stream)-stream_sz, payload[frame_idx], payload_sz, 1, 0 );
  }

  for( ulong tile_idx=0UL; tile_idx<4UL; tile_idx++ ) {
    test_env_t * env = test_env_new( tile_idx, 4UL );
    begin_load( env, 1, 1 );
    capture_reset( env );
    send_data( env, stream, stream_sz );

    FD_TEST( env->ctx->state==FD_SNAPSHOT_STATE_PROCESSING );
    FD_TEST( test_pub_cnt==1UL );
    assert_output( 0UL, payload[tile_idx], strlen( payload[tile_idx] ), 1 );
    test_env_delete( env );
  }

  test_env_t * env = test_env_new( 3UL, 4UL );
  begin_load( env, 1, 1 );
  capture_reset( env );
  for( ulong off=0UL; off<stream_sz; off++ ) send_data( env, stream+off, 1UL );
  assert_output( 0UL, payload[3], strlen( payload[3] ), 1 );
  test_env_delete( env );
}

static void
test_fragmented_and_frame_shapes( void ) {
  static uchar const payload[] = "fragmented unknown-size frame";
  uchar frame[4096];
  test_env_t * env = test_env_new( 0UL, 1UL );
  begin_load( env, 1, 1 );
  capture_reset( env );

  ulong frame_sz = make_frame( frame, sizeof(frame), payload, sizeof(payload)-1UL, 0, 0 );
  feed_frame( env, frame, frame_sz, 1UL );
  assert_output( 0UL, payload, sizeof(payload)-1UL, 1 );

  capture_reset( env );
  frame_sz = make_frame( frame, sizeof(frame), payload, sizeof(payload)-1UL, 1, 1 );
  feed_frame( env, frame, frame_sz, 7UL );
  assert_output( 0UL, payload, sizeof(payload)-1UL, 1 );

  capture_reset( env );
  frame_sz = make_frame( frame, sizeof(frame), payload, 0UL, 1, 0 );
  send_data( env, frame, frame_sz );
  FD_TEST( test_pub_cnt==1UL );
  FD_TEST( !test_pub[0].sz );
  assert_output( 0UL, NULL, 0UL, 1 );

  capture_reset( env );
  frame_sz = make_skippable( frame, 0UL, 3U );
  send_data( env, frame, frame_sz );
  FD_TEST( test_pub_cnt==1UL );
  FD_TEST( !test_pub[0].sz );
  assert_output( 0UL, NULL, 0UL, 1 );

  capture_reset( env );
  frame_sz = make_skippable( frame, 31UL, 9U );
  feed_frame( env, frame, frame_sz, 3UL );
  FD_TEST( test_pub_cnt==1UL );
  FD_TEST( !test_pub[0].sz );
  assert_output( 0UL, NULL, 0UL, 1 );

  test_env_delete( env );
}

static void
test_exact_mtu_and_zero_input_drain( void ) {
  ulong payload_max = 3UL*FD_SNAPSHOT_DATA_MTU+17UL;
  uchar * payload = malloc( payload_max ); FD_TEST( payload );
  uchar * frame   = malloc( ZSTD_compressBound( payload_max ) ); FD_TEST( frame );
  fd_memset( payload, 0x5a, payload_max );

  test_env_t * env = test_env_new( 0UL, 1UL );
  begin_load( env, 1, 1 );
  capture_reset( env );

  ulong frame_sz = make_frame( frame, ZSTD_compressBound( payload_max ),
                               payload, FD_SNAPSHOT_DATA_MTU, 1, 0 );
  FD_TEST( frame_sz<FD_SNAPSHOT_DATA_MTU );
  send_data( env, frame, frame_sz );
  FD_TEST( test_pub_cnt==1UL );
  FD_TEST( test_pub[0].sz==FD_SNAPSHOT_DATA_MTU );
  assert_output( 0UL, payload, FD_SNAPSHOT_DATA_MTU, 1 );

  capture_reset( env );
  env->ctx->out.mtu = 64UL;
  test_decompress_script = 1;
  test_decompress_phase  = 0;
  uchar one_byte = 0U;
  send_data( env, &one_byte, 1UL );
  test_decompress_script = 0;
  FD_TEST( test_decompress_phase==3 );
  FD_TEST( test_pub_cnt==3UL );
  FD_TEST( test_pub[0].sz==23UL );
  FD_TEST( !fd_frag_meta_ctl_eom( test_pub[0].ctl ) );
  FD_TEST( test_pub[1].sz==64UL );
  FD_TEST( !fd_frag_meta_ctl_eom( test_pub[1].ctl ) );
  FD_TEST( test_pub[2].sz==17UL );
  FD_TEST( fd_frag_meta_ctl_eom( test_pub[2].ctl ) );
  for( ulong i=0UL;  i<23UL; i++ ) FD_TEST( test_data[i]=='a' );
  for( ulong i=23UL; i<87UL; i++ ) FD_TEST( test_data[i]=='b' );
  for( ulong i=87UL; i<104UL; i++ ) FD_TEST( test_data[i]=='c' );

  test_env_delete( env );
  free( frame );
  free( payload );
}

static void
test_truncated_and_malformed( void ) {
  static uchar const payload[] = "bad frame boundary";
  uchar frame[4096];
  ulong frame_sz = make_frame( frame, sizeof(frame), payload, sizeof(payload)-1UL, 1, 1 );

  test_env_t * env = test_env_new( 0UL, 1UL );
  begin_load( env, 1, 1 );
  capture_reset( env );
  send_data( env, frame, frame_sz-1UL );
  FD_TEST( env->ctx->state==FD_SNAPSHOT_STATE_PROCESSING );
  send_control( env, FD_SNAPSHOT_MSG_CTRL_FINI );
  FD_TEST( env->ctx->state==FD_SNAPSHOT_STATE_ERROR );
  FD_TEST( test_pub[ test_pub_cnt-1UL ].sig==FD_SNAPSHOT_MSG_CTRL_ERROR );
  test_env_delete( env );

  env = test_env_new( 1UL, 2UL );
  begin_load( env, 1, 1 );
  capture_reset( env );
  send_data( env, frame, frame_sz-1UL );
  FD_TEST( env->ctx->state==FD_SNAPSHOT_STATE_PROCESSING );
  send_control( env, FD_SNAPSHOT_MSG_CTRL_FINI );
  FD_TEST( env->ctx->state==FD_SNAPSHOT_STATE_ERROR );
  FD_TEST( test_pub[ test_pub_cnt-1UL ].sig==FD_SNAPSHOT_MSG_CTRL_ERROR );
  test_env_delete( env );

  uchar malformed[8] = { 0 };
  env = test_env_new( 0UL, 1UL );
  begin_load( env, 1, 1 );
  capture_reset( env );
  send_data( env, malformed, sizeof(malformed) );
  FD_TEST( env->ctx->state==FD_SNAPSHOT_STATE_ERROR );
  FD_TEST( test_pub_cnt==1UL );
  FD_TEST( test_pub[0].sig==FD_SNAPSHOT_MSG_CTRL_ERROR );
  test_env_delete( env );
}

static void
test_raw_tile_zero( void ) {
  uchar raw[257];
  for( ulong i=0UL; i<sizeof(raw); i++ ) raw[i] = (uchar)(i*29UL);

  for( ulong tile_count=1UL; tile_count<=FD_TOPO_MAX_TILE_IN_LINKS; tile_count++ ) {
    ulong compressed_sum   = 0UL;
    ulong decompressed_sum = 0UL;
    for( ulong tile_idx=0UL; tile_idx<tile_count; tile_idx++ ) {
      test_env_t * env = test_env_new( tile_idx, tile_count );
      begin_load( env, 1, 0 );
      capture_reset( env );
      env->ctx->out.mtu = 64UL;
      send_data( env, raw, sizeof(raw) );
      if( !tile_idx ) {
        FD_TEST( test_pub_cnt==5UL );
        assert_output( 0UL, raw, sizeof(raw), 0 );
        for( ulong i=0UL; i<test_pub_cnt; i++ )
          FD_TEST( !fd_frag_meta_ctl_eom( test_pub[i].ctl ) );
      } else {
        FD_TEST( !test_pub_cnt );
      }
      FD_TEST( env->ctx->state==FD_SNAPSHOT_STATE_PROCESSING );
      compressed_sum   += env->ctx->metrics.full.compressed_bytes_read;
      decompressed_sum += env->ctx->metrics.full.decompressed_bytes_written;
      test_env_delete( env );
    }
    FD_TEST( compressed_sum==sizeof(raw) );
    FD_TEST( decompressed_sum==sizeof(raw) );
  }
}

static void
test_controls_and_retry( void ) {
  static uchar const payload[] = "retry";
  uchar frame[4096];
  ulong frame_sz = make_frame( frame, sizeof(frame), payload, sizeof(payload)-1UL, 1, 0 );

  test_env_t * env = test_env_new( 0UL, 2UL );
  begin_load( env, 1, 1 );
  FD_TEST( env->ctx->state==FD_SNAPSHOT_STATE_PROCESSING );
  FD_TEST( env->ctx->full );

  fd_memset( env->meta, 0xa5, sizeof(fd_ssctrl_meta_t) );
  fd_memcpy( env->in, env->meta, sizeof(fd_ssctrl_meta_t) );
  ulong pub_cnt = test_pub_cnt;
  FD_TEST( !returnable_frag( env->ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_META,
                             0UL, sizeof(fd_ssctrl_meta_t), 0UL, 0UL, 0UL,
                             (fd_stem_context_t *)1UL ) );
  FD_TEST( test_pub_cnt==pub_cnt+1UL );
  FD_TEST( test_pub[pub_cnt].sig==FD_SNAPSHOT_MSG_META );
  FD_TEST( !memcmp( test_data+test_pub[pub_cnt].data_off, env->meta, sizeof(fd_ssctrl_meta_t) ) );

  send_data( env, frame, 3UL );
  send_control( env, FD_SNAPSHOT_MSG_CTRL_ERROR );
  FD_TEST( env->ctx->state==FD_SNAPSHOT_STATE_ERROR );
  pub_cnt = test_pub_cnt;
  send_control( env, FD_SNAPSHOT_MSG_CTRL_ERROR );
  FD_TEST( test_pub_cnt==pub_cnt );

  send_data( env, frame, frame_sz );
  FD_TEST( test_pub_cnt==pub_cnt );

  send_control( env, FD_SNAPSHOT_MSG_CTRL_FAIL );
  FD_TEST( env->ctx->state==FD_SNAPSHOT_STATE_IDLE );
  send_control( env, FD_SNAPSHOT_MSG_CTRL_FAIL );
  FD_TEST( env->ctx->state==FD_SNAPSHOT_STATE_IDLE );

  capture_reset( env );
  begin_load( env, 0, 1 );
  FD_TEST( !env->ctx->full );
  send_data( env, frame, frame_sz );
  assert_output( 1UL, payload, sizeof(payload)-1UL, 1 );

  send_control( env, FD_SNAPSHOT_MSG_LOAD_COMPLETE );
  send_control( env, FD_SNAPSHOT_MSG_CTRL_FINI );
  FD_TEST( env->ctx->state==FD_SNAPSHOT_STATE_FINISHING );
  send_control( env, FD_SNAPSHOT_MSG_CTRL_NEXT );
  FD_TEST( env->ctx->state==FD_SNAPSHOT_STATE_IDLE );

  begin_load( env, 1, 1 );
  send_control( env, FD_SNAPSHOT_MSG_CTRL_FINI );
  send_control( env, FD_SNAPSHOT_MSG_CTRL_DONE );
  FD_TEST( env->ctx->state==FD_SNAPSHOT_STATE_IDLE );
  send_control( env, FD_SNAPSHOT_MSG_CTRL_SHUTDOWN );
  FD_TEST( env->ctx->state==FD_SNAPSHOT_STATE_SHUTDOWN );
  test_env_delete( env );
}

static void
test_retry_resets_frame_state( void ) {
  static uchar const payload[] = "retry frame ownership";
  uchar frame[4096];
  ulong frame_sz = make_frame( frame, sizeof(frame), payload, sizeof(payload)-1UL, 1, 0 );

  test_env_t * env = test_env_new( 0UL, 2UL );
  begin_load( env, 1, 1 );
  capture_reset( env );

  send_data( env, frame, frame_sz );
  FD_TEST( env->ctx->frame_idx==1UL );
  send_data( env, frame, 3UL );
  FD_TEST( env->ctx->dirty );
  FD_TEST( env->ctx->frame_idx==1UL );

  send_control( env, FD_SNAPSHOT_MSG_CTRL_ERROR );
  send_control( env, FD_SNAPSHOT_MSG_CTRL_FAIL );
  begin_load( env, 1, 1 );
  FD_TEST( !env->ctx->dirty );
  FD_TEST( !env->ctx->frame_idx );
  FD_TEST( !env->ctx->in.frag_pos );
  FD_TEST( !env->ctx->zstd_frame->header_sz );
  FD_TEST( !env->ctx->zstd_frame->block_header_sz );
  FD_TEST( !env->ctx->zstd_frame->bytes_remaining );

  capture_reset( env );
  send_data( env, frame, frame_sz );
  assert_output( 0UL, payload, sizeof(payload)-1UL, 1 );
  test_env_delete( env );
}

static void
test_malformed_unowned_frame( void ) {
  uchar malformed[8] = { 0 };
  test_env_t * env = test_env_new( 1UL, 2UL );
  begin_load( env, 1, 1 );
  capture_reset( env );

  send_data( env, malformed, sizeof(malformed) );
  FD_TEST( env->ctx->state==FD_SNAPSHOT_STATE_ERROR );
  FD_TEST( test_pub_cnt==1UL );
  FD_TEST( test_pub[0].sig==FD_SNAPSHOT_MSG_CTRL_ERROR );

  send_control( env, FD_SNAPSHOT_MSG_CTRL_FAIL );

  static uchar const payload[] = "valid retry";
  uchar frame[4096];
  ulong frame_sz = make_frame( frame, sizeof(frame), payload, sizeof(payload)-1UL, 1, 0 );
  begin_load( env, 1, 1 );
  capture_reset( env );
  send_data( env, frame, frame_sz );
  FD_TEST( !test_pub_cnt );
  send_data( env, frame, frame_sz );
  assert_output( 0UL, payload, sizeof(payload)-1UL, 1 );
  test_env_delete( env );
}

static void
test_mixed_frame_rotation( void ) {
  static char const * payload[] = { "normal zero", NULL, NULL, "normal three" };
  uchar stream[8192];
  ulong stream_sz = 0UL;
  stream_sz += make_frame( stream+stream_sz, sizeof(stream)-stream_sz,
                           payload[0], strlen( payload[0] ), 1, 0 );
  stream_sz += make_skippable( stream+stream_sz, 7UL, 11U );
  stream_sz += make_frame( stream+stream_sz, sizeof(stream)-stream_sz,
                           "", 0UL, 1, 0 );
  stream_sz += make_frame( stream+stream_sz, sizeof(stream)-stream_sz,
                           payload[3], strlen( payload[3] ), 1, 1 );

  for( ulong tile_idx=0UL; tile_idx<4UL; tile_idx++ ) {
    test_env_t * env = test_env_new( tile_idx, 4UL );
    begin_load( env, 1, 1 );
    capture_reset( env );
    send_data( env, stream, stream_sz );

    if( payload[tile_idx] ) {
      assert_output( 0UL, payload[tile_idx], strlen( payload[tile_idx] ), 1 );
    } else {
      FD_TEST( test_pub_cnt==1UL );
      assert_output( 0UL, NULL, 0UL, 1 );
    }
    FD_TEST( env->ctx->frame_idx==4UL );
    test_env_delete( env );
  }
}

static void
test_control_publication_counts( void ) {
  test_env_t * env = test_env_new( 0UL, 2UL );
  begin_load( env, 1, 1 );
  capture_reset( env );

  send_control( env, FD_SNAPSHOT_MSG_LOAD_COMPLETE );
  FD_TEST( !test_pub_cnt );

  fd_memset( env->meta, 0, sizeof(fd_ssctrl_meta_t) );
  fd_memcpy( env->in, env->meta, sizeof(fd_ssctrl_meta_t) );
  send_control( env, FD_SNAPSHOT_MSG_META );
  FD_TEST( test_pub_cnt==1UL );
  FD_TEST( test_pub[0].sig==FD_SNAPSHOT_MSG_META );

  send_control( env, FD_SNAPSHOT_MSG_CTRL_ERROR );
  FD_TEST( test_pub_cnt==2UL );
  FD_TEST( test_pub[1].sig==FD_SNAPSHOT_MSG_CTRL_ERROR );
  send_control( env, FD_SNAPSHOT_MSG_CTRL_DONE );
  FD_TEST( test_pub_cnt==2UL );
  send_control( env, FD_SNAPSHOT_MSG_CTRL_FAIL );
  FD_TEST( test_pub_cnt==3UL );
  FD_TEST( test_pub[2].sig==FD_SNAPSHOT_MSG_CTRL_FAIL );
  test_env_delete( env );
}

static void
test_incremental_metrics( void ) {
  static uchar const payload[] = "incremental metrics";
  uchar frame[4096];
  ulong frame_sz = make_frame( frame, sizeof(frame), payload, sizeof(payload)-1UL, 1, 0 );

  test_env_t * env = test_env_new( 0UL, 2UL );
  env->ctx->metrics.full.compressed_bytes_read      = 11UL;
  env->ctx->metrics.full.decompressed_bytes_written = 13UL;
  begin_load( env, 0, 1 );
  capture_reset( env );
  send_data( env, frame, frame_sz );
  FD_TEST( env->ctx->metrics.full.compressed_bytes_read==11UL );
  FD_TEST( env->ctx->metrics.full.decompressed_bytes_written==13UL );
  FD_TEST( env->ctx->metrics.incremental.compressed_bytes_read==frame_sz );
  FD_TEST( env->ctx->metrics.incremental.decompressed_bytes_written==sizeof(payload)-1UL );
  test_env_delete( env );

  uchar raw[257];
  fd_memset( raw, 0x5a, sizeof(raw) );
  env = test_env_new( 0UL, 2UL );
  begin_load( env, 0, 0 );
  capture_reset( env );
  env->ctx->out.mtu = 64UL;
  send_data( env, raw, sizeof(raw) );
  FD_TEST( env->ctx->metrics.incremental.compressed_bytes_read==sizeof(raw) );
  FD_TEST( env->ctx->metrics.incremental.decompressed_bytes_written==sizeof(raw) );
  test_env_delete( env );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_plain_multiframe_input();
  test_owner_counts();
  test_fragmented_and_frame_shapes();
  test_exact_mtu_and_zero_input_drain();
  test_truncated_and_malformed();
  test_raw_tile_zero();
  test_controls_and_retry();
  test_retry_resets_frame_state();
  test_malformed_unowned_frame();
  test_mixed_frame_rotation();
  test_control_publication_counts();
  test_incremental_metrics();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
