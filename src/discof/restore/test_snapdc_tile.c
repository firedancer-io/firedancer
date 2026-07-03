#define FD_TILE_TEST
#include "fd_snapdc_tile.c"
#include <stdlib.h>
#include <string.h>

#define TEST_MCACHE_DEPTH 128UL
#define TEST_IN_BUF_SZ    (1UL<<20)
#define TEST_OUT_BUF_SZ   (1UL<<20)

struct test_env {
  fd_snapdc_tile_t ctx[1];

  uchar * zstd_mem;
  uchar * in_mem;
  uchar * out_mem;
  uchar * mcache_mem;

  fd_frag_meta_t * out_mcache;
  ulong            out_seq_rd;

  ulong              stem_seqs[1];
  ulong              stem_depths[1];
  int                stem_out_reliable[1];
  fd_stem_context_t  stem[1];
};
typedef struct test_env test_env_t;

static void
fill_pattern( uchar * buf,
              ulong   sz,
              ulong   seed ) {
  ulong x = seed | 1UL;
  for( ulong i=0UL; i<sz; i++ ) {
    x ^= x<<13; x ^= x>>7; x ^= x<<17;
    buf[ i ] = (uchar)x;
  }
}

static ulong
out_chunk_mtu( ulong out_mtu ) {
  return ((out_mtu + 2UL*FD_CHUNK_SZ-1UL) >> (1UL+FD_CHUNK_LG_SZ)) << 1UL;
}

static void
test_env_init( test_env_t * env,
               ulong        out_mtu ) {
  memset( env->ctx, 0, sizeof(fd_snapdc_tile_t) );
  env->ctx->state = FD_SNAPSHOT_STATE_IDLE;

  ulong zstd_sz = ZSTD_estimateDStreamSize( ZSTD_WINDOW_SZ );
  env->zstd_mem = aligned_alloc( 32UL, zstd_sz );
  FD_TEST( env->zstd_mem );
  env->ctx->zstd = ZSTD_initStaticDStream( env->zstd_mem, zstd_sz );
  FD_TEST( env->ctx->zstd );

  env->in_mem  = aligned_alloc( FD_CHUNK_ALIGN, TEST_IN_BUF_SZ  );
  env->out_mem = aligned_alloc( FD_CHUNK_ALIGN, TEST_OUT_BUF_SZ );
  FD_TEST( env->in_mem && env->out_mem );

  env->ctx->in.mem      = (fd_wksp_t *)env->in_mem;
  env->ctx->in.chunk0   = 0UL;
  env->ctx->in.wmark    = (TEST_IN_BUF_SZ>>FD_CHUNK_LG_SZ) - 1UL;
  env->ctx->in.mtu      = TEST_IN_BUF_SZ>>1UL;
  env->ctx->in.frag_pos = 0UL;

  ulong chunk_mtu = out_chunk_mtu( out_mtu );
  env->ctx->out.mem    = (fd_wksp_t *)env->out_mem;
  env->ctx->out.chunk0 = 0UL;
  env->ctx->out.wmark  = (TEST_OUT_BUF_SZ>>FD_CHUNK_LG_SZ) - chunk_mtu;
  env->ctx->out.chunk  = 0UL;
  env->ctx->out.mtu    = out_mtu;

  env->mcache_mem = aligned_alloc( fd_mcache_align(), fd_mcache_footprint( TEST_MCACHE_DEPTH, 0UL ) );
  FD_TEST( env->mcache_mem );
  FD_TEST( fd_mcache_new( env->mcache_mem, TEST_MCACHE_DEPTH, 0UL, 0UL ) );
  env->out_mcache = fd_mcache_join( env->mcache_mem );
  FD_TEST( env->out_mcache );
  env->out_seq_rd = 0UL;

  env->stem_seqs[0]         = 0UL;
  env->stem_depths[0]       = TEST_MCACHE_DEPTH;
  env->stem_out_reliable[0] = 0;

  env->stem->mcaches             = &env->out_mcache;
  env->stem->depths              = env->stem_depths;
  env->stem->seqs                = env->stem_seqs;
  env->stem->cr_avail            = NULL;
  env->stem->min_cr_avail        = NULL;
  env->stem->cr_decrement_amount = 0UL;
  env->stem->out_reliable        = env->stem_out_reliable;
}

static void
test_env_fini( test_env_t * env ) {
  fd_mcache_delete( fd_mcache_leave( env->out_mcache ) );
  free( env->mcache_mem );
  free( env->out_mem );
  free( env->in_mem );
  free( env->zstd_mem );
}

static void
write_init_msg( test_env_t * env,
                 int          zstd_flag ) {
  fd_ssctrl_init_t msg;
  memset( &msg, 0, sizeof(msg) );
  msg.zstd = zstd_flag;
  memcpy( env->in_mem, &msg, sizeof(msg) );
}

static void
send_ctrl( test_env_t * env,
           ulong        sig,
           ulong        chunk,
           ulong        sz ) {
  int more = returnable_frag( env->ctx, 0UL, 0UL, sig, chunk, sz, 0UL, 0UL, 0UL, env->stem );
  FD_TEST( !more );
}

static ulong
last_pub_sig( test_env_t * env ) {
  ulong seq = env->stem_seqs[0] - 1UL;
  fd_frag_meta_t const * line = env->out_mcache + fd_mcache_line_idx( seq, TEST_MCACHE_DEPTH );
  return line->sig;
}

/* feed_data injects a single incoming data frag of sz bytes at in.mem
   chunk 0, driving returnable_frag until the frag is fully consumed
   (mirroring how the stem re-polls the same mcache line while
   returnable_frag asks to be called again).  Every published
   FD_SNAPSHOT_MSG_DATA frag is appended to out_acc.  Returns the total
   bytes appended and, if requested, the number of frags that carried
   them. */
static ulong
feed_data( test_env_t *  env,
           uchar const * data,
           ulong         sz,
           uchar *       out_acc,
           ulong         out_acc_cap,
           ulong *       frag_cnt_out ) {
  FD_TEST( sz<=TEST_IN_BUF_SZ );
  memcpy( env->in_mem, data, sz );

  ulong copied   = 0UL;
  ulong frag_cnt = 0UL;
  int   more;
  do {
    more = returnable_frag( env->ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_DATA, 0UL, sz, 0UL, 0UL, 0UL, env->stem );
    while( fd_seq_lt( env->out_seq_rd, env->stem_seqs[0] ) ) {
      fd_frag_meta_t const * line = env->out_mcache + fd_mcache_line_idx( env->out_seq_rd, TEST_MCACHE_DEPTH );
      if( line->sig==FD_SNAPSHOT_MSG_DATA ) {
        FD_TEST( copied+line->sz<=out_acc_cap );
        memcpy( out_acc+copied, fd_chunk_to_laddr_const( env->out_mem, line->chunk ), line->sz );
        copied += line->sz;
        frag_cnt++;
      }
      env->out_seq_rd = fd_seq_inc( env->out_seq_rd, 1UL );
    }
  } while( more );

  if( frag_cnt_out ) *frag_cnt_out = frag_cnt;
  return copied;
}

static void
test_scratch_sizes( void ) {
  ulong align = scratch_align();
  FD_TEST( align>=alignof(fd_snapdc_tile_t) );
  FD_TEST( align>=32UL );

  ulong footprint = scratch_footprint( NULL );
  FD_TEST( footprint>=sizeof(fd_snapdc_tile_t) );
  FD_TEST( footprint>=ZSTD_estimateDStreamSize( ZSTD_WINDOW_SZ ) );
}

static void
test_uncompressed_passthrough_single_frag( void ) {
  test_env_t env[1];
  test_env_init( env, 4096UL );

  write_init_msg( env, 0 );
  send_ctrl( env, FD_SNAPSHOT_MSG_CTRL_INIT_FULL, 0UL, sizeof(fd_ssctrl_init_t) );
  FD_TEST( env->ctx->state==FD_SNAPSHOT_STATE_PROCESSING );
  FD_TEST( !env->ctx->is_zstd );
  FD_TEST( last_pub_sig( env )==FD_SNAPSHOT_MSG_CTRL_INIT_FULL );

  uchar plaintext[ 128 ];
  fill_pattern( plaintext, sizeof(plaintext), 0x1UL );

  uchar out_acc[ 256 ];
  ulong frag_cnt;
  ulong copied = feed_data( env, plaintext, sizeof(plaintext), out_acc, sizeof(out_acc), &frag_cnt );

  FD_TEST( copied==sizeof(plaintext) );
  FD_TEST( frag_cnt==1UL );
  FD_TEST( !memcmp( out_acc, plaintext, sizeof(plaintext) ) );
  FD_TEST( env->ctx->metrics.full.compressed_bytes_read==sizeof(plaintext) );
  FD_TEST( env->ctx->metrics.full.decompressed_bytes_written==sizeof(plaintext) );

  send_ctrl( env, FD_SNAPSHOT_MSG_CTRL_FINI, 0UL, 0UL );
  FD_TEST( env->ctx->state==FD_SNAPSHOT_STATE_FINISHING );
  send_ctrl( env, FD_SNAPSHOT_MSG_CTRL_DONE, 0UL, 0UL );
  FD_TEST( env->ctx->state==FD_SNAPSHOT_STATE_IDLE );

  test_env_fini( env );
}

static void
test_uncompressed_passthrough_multi_chunk_output( void ) {
  test_env_t env[1];
  ulong out_mtu = 16UL;
  test_env_init( env, out_mtu );

  write_init_msg( env, 0 );
  send_ctrl( env, FD_SNAPSHOT_MSG_CTRL_INIT_INCR, 0UL, sizeof(fd_ssctrl_init_t) );
  FD_TEST( !env->ctx->full );

  uchar plaintext[ 100 ];
  fill_pattern( plaintext, sizeof(plaintext), 0x2UL );

  uchar out_acc[ 256 ];
  ulong frag_cnt;
  ulong copied = feed_data( env, plaintext, sizeof(plaintext), out_acc, sizeof(out_acc), &frag_cnt );

  FD_TEST( copied==sizeof(plaintext) );
  FD_TEST( !memcmp( out_acc, plaintext, sizeof(plaintext) ) );
  FD_TEST( frag_cnt==(sizeof(plaintext)+out_mtu-1UL)/out_mtu );
  FD_TEST( env->ctx->metrics.incremental.compressed_bytes_read==sizeof(plaintext) );
  FD_TEST( env->ctx->metrics.incremental.decompressed_bytes_written==sizeof(plaintext) );

  test_env_fini( env );
}

static void
test_zstd_roundtrip_small_out_mtu( void ) {
  test_env_t env[1];
  ulong out_mtu = 37UL; /* deliberately not a divisor of plain_sz below, so the
                            final decompress call produces fewer than out_mtu
                            bytes and ctx->dirty reliably clears */
  test_env_init( env, out_mtu );

  write_init_msg( env, 1 );
  send_ctrl( env, FD_SNAPSHOT_MSG_CTRL_INIT_FULL, 0UL, sizeof(fd_ssctrl_init_t) );
  FD_TEST( env->ctx->is_zstd );

  ulong plain_sz = 4000UL;
  uchar * plaintext = malloc( plain_sz );
  FD_TEST( plaintext );
  fill_pattern( plaintext, plain_sz, 0x3UL );

  ulong bound = ZSTD_compressBound( plain_sz );
  uchar * comp = malloc( bound );
  FD_TEST( comp );
  ulong comp_sz = ZSTD_compress( comp, bound, plaintext, plain_sz, 3 );
  FD_TEST( !ZSTD_isError( comp_sz ) );

  uchar * out_acc = malloc( plain_sz+4096UL );
  FD_TEST( out_acc );
  ulong frag_cnt;
  ulong copied = feed_data( env, comp, comp_sz, out_acc, plain_sz+4096UL, &frag_cnt );

  FD_TEST( copied==plain_sz );
  FD_TEST( !memcmp( out_acc, plaintext, plain_sz ) );
  /* out.mtu is far smaller than the decompressed payload, so draining
     it must span many out_produced==out.mtu frags before the tile
     reports the input frag as fully consumed. */
  FD_TEST( frag_cnt>=plain_sz/out_mtu );
  FD_TEST( !env->ctx->dirty );
  FD_TEST( env->ctx->metrics.full.compressed_bytes_read==comp_sz );
  FD_TEST( env->ctx->metrics.full.decompressed_bytes_written==plain_sz );

  free( out_acc ); free( comp ); free( plaintext );
  test_env_fini( env );
}

static void
test_zstd_roundtrip_chunked_input( void ) {
  test_env_t env[1];
  ulong out_mtu = 4096UL;
  test_env_init( env, out_mtu );

  write_init_msg( env, 1 );
  send_ctrl( env, FD_SNAPSHOT_MSG_CTRL_INIT_INCR, 0UL, sizeof(fd_ssctrl_init_t) );

  ulong plain_sz = 20000UL;
  uchar * plaintext = malloc( plain_sz );
  FD_TEST( plaintext );
  fill_pattern( plaintext, plain_sz, 0x4UL );

  ulong bound = ZSTD_compressBound( plain_sz );
  uchar * comp = malloc( bound );
  FD_TEST( comp );
  ulong comp_sz = ZSTD_compress( comp, bound, plaintext, plain_sz, 3 );
  FD_TEST( !ZSTD_isError( comp_sz ) );

  uchar * out_acc = malloc( plain_sz+4096UL );
  FD_TEST( out_acc );
  ulong copied_total = 0UL;

  /* Cut the compressed byte stream at offsets that do not line up with
     zstd block or frame boundaries, mimicking arbitrarily sized network
     reads handed down by snapld. */
  ulong offsets[] = { 0UL, 137UL, 311UL, 1500UL, 1501UL, comp_sz };
  ulong n = sizeof(offsets)/sizeof(offsets[0]);
  for( ulong i=0UL; i+1UL<n; i++ ) {
    ulong lo = fd_ulong_min( offsets[ i   ], comp_sz );
    ulong hi = fd_ulong_min( offsets[ i+1 ], comp_sz );
    if( FD_UNLIKELY( hi<=lo ) ) continue;
    ulong frag_cnt;
    copied_total += feed_data( env, comp+lo, hi-lo, out_acc+copied_total, plain_sz+4096UL-copied_total, &frag_cnt );
  }

  FD_TEST( copied_total==plain_sz );
  FD_TEST( !memcmp( out_acc, plaintext, plain_sz ) );
  FD_TEST( !env->ctx->dirty );
  FD_TEST( env->ctx->metrics.incremental.compressed_bytes_read==comp_sz );
  FD_TEST( env->ctx->metrics.incremental.decompressed_bytes_written==plain_sz );

  free( out_acc ); free( comp ); free( plaintext );
  test_env_fini( env );
}

static void
test_zstd_malformed_input_transitions_to_error( void ) {
  test_env_t env[1];
  test_env_init( env, 4096UL );

  write_init_msg( env, 1 );
  send_ctrl( env, FD_SNAPSHOT_MSG_CTRL_INIT_FULL, 0UL, sizeof(fd_ssctrl_init_t) );

  uchar garbage[ 64 ];
  for( ulong i=0UL; i<sizeof(garbage); i++ ) garbage[ i ] = (uchar)(0xA5U ^ (uchar)i);
  memcpy( env->in_mem, garbage, sizeof(garbage) );

  int more = returnable_frag( env->ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_DATA, 0UL, sizeof(garbage), 0UL, 0UL, 0UL, env->stem );
  FD_TEST( !more );
  FD_TEST( env->ctx->state==FD_SNAPSHOT_STATE_ERROR );
  FD_TEST( last_pub_sig( env )==FD_SNAPSHOT_MSG_CTRL_ERROR );

  /* Once in the error state, further data frags are dropped with no
     new publishes until a FAIL control message arrives. */
  ulong seq_before = env->stem_seqs[0];
  more = returnable_frag( env->ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_DATA, 0UL, sizeof(garbage), 0UL, 0UL, 0UL, env->stem );
  FD_TEST( !more );
  FD_TEST( env->stem_seqs[0]==seq_before );

  send_ctrl( env, FD_SNAPSHOT_MSG_CTRL_FAIL, 0UL, 0UL );
  FD_TEST( env->ctx->state==FD_SNAPSHOT_STATE_IDLE );

  test_env_fini( env );
}

static void
test_truncated_frame_at_fini_transitions_to_malformed( void ) {
  test_env_t env[1];
  test_env_init( env, 65535UL );

  write_init_msg( env, 1 );
  send_ctrl( env, FD_SNAPSHOT_MSG_CTRL_INIT_FULL, 0UL, sizeof(fd_ssctrl_init_t) );

  ulong plain_sz = 50000UL;
  uchar * plaintext = malloc( plain_sz );
  FD_TEST( plaintext );
  fill_pattern( plaintext, plain_sz, 0x5UL );

  ulong bound = ZSTD_compressBound( plain_sz );
  uchar * comp = malloc( bound );
  FD_TEST( comp );
  ulong comp_sz = ZSTD_compress( comp, bound, plaintext, plain_sz, 3 );
  FD_TEST( !ZSTD_isError( comp_sz ) );

  /* Feed only half of the compressed frame: it is not complete, so the
     tile must remember it is still mid-frame (dirty) across the call. */
  ulong prefix_sz = comp_sz/2UL;
  memcpy( env->in_mem, comp, prefix_sz );
  int more = returnable_frag( env->ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_DATA, 0UL, prefix_sz, 0UL, 0UL, 0UL, env->stem );
  FD_TEST( !more );
  FD_TEST( env->ctx->dirty );
  FD_TEST( env->ctx->state==FD_SNAPSHOT_STATE_PROCESSING );

  /* snapct signals end-of-stream while a frame is still open: this must
     be treated as a malformed snapshot rather than finishing cleanly. */
  send_ctrl( env, FD_SNAPSHOT_MSG_CTRL_FINI, 0UL, 0UL );
  FD_TEST( env->ctx->state==FD_SNAPSHOT_STATE_ERROR );
  FD_TEST( last_pub_sig( env )==FD_SNAPSHOT_MSG_CTRL_ERROR );

  send_ctrl( env, FD_SNAPSHOT_MSG_CTRL_FAIL, 0UL, 0UL );
  FD_TEST( env->ctx->state==FD_SNAPSHOT_STATE_IDLE );

  free( comp ); free( plaintext );
  test_env_fini( env );
}

static void
test_control_shutdown( void ) {
  test_env_t env[1];
  test_env_init( env, 4096UL );

  FD_TEST( !should_shutdown( env->ctx ) );
  send_ctrl( env, FD_SNAPSHOT_MSG_CTRL_SHUTDOWN, 0UL, 0UL );
  FD_TEST( env->ctx->state==FD_SNAPSHOT_STATE_SHUTDOWN );
  FD_TEST( should_shutdown( env->ctx ) );

  test_env_fini( env );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  (void)populate_allowed_fds;
  (void)populate_allowed_seccomp;
  (void)unprivileged_init;

  test_scratch_sizes();
  test_uncompressed_passthrough_single_frag();
  test_uncompressed_passthrough_multi_chunk_output();
  test_zstd_roundtrip_small_out_mtu();
  test_zstd_roundtrip_chunked_input();
  test_zstd_malformed_input_transitions_to_error();
  test_truncated_frame_at_fini_transitions_to_malformed();
  test_control_shutdown();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
