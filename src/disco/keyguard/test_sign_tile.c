#define _GNU_SOURCE
#include "../fd_disco.h"
#include "fd_keyguard.h"
#include "fd_keyload.h"

#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdio.h>

#if FD_HAS_HOSTED && FD_HAS_ALLOCA

#define STEM_CALLBACK_SHOULD_SHUTDOWN(ctx) (0)
#define FD_TILE_TEST
#include "fd_sign_tile.c"

#define TEST_FORK_OK(child) do {                              \
    pid_t pid = fork();                                        \
    if( pid ) {                                                \
      int wstatus;                                             \
      FD_TEST( -1!=waitpid( pid, &wstatus, WUNTRACED ) );     \
      FD_TEST( WIFEXITED( wstatus ) );                         \
      FD_TEST( !WEXITSTATUS( wstatus ) );                      \
    } else {                                                   \
      do { child } while( 0 );                                 \
      exit( EXIT_SUCCESS );                                    \
    }                                                          \
} while( 0 )

#define TEST_FORK_CRASH(child) do {                            \
    pid_t pid = fork();                                        \
    if( pid ) {                                                \
      int wstatus;                                             \
      FD_TEST( -1!=waitpid( pid, &wstatus, WUNTRACED ) );     \
      FD_TEST( WIFSIGNALED( wstatus ) );                       \
    } else {                                                   \
      fd_log_level_stderr_set( 7 );                            \
      fd_log_level_logfile_set( 7 );                           \
      do { child } while( 0 );                                 \
      exit( EXIT_FAILURE );                                    \
    }                                                          \
} while( 0 )

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  (void)privileged_init;
  (void)unprivileged_init;
  (void)populate_allowed_seccomp;
  (void)populate_allowed_fds;
  (void)metrics_write;
  (void)during_housekeeping;

  /* Create workspace */

  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( "normal" ), 512UL, 0UL, "wksp", 0UL );
  FD_TEST( wksp );

  ulong depth = 128UL;

  ulong req_data_sz  = fd_dcache_req_data_sz( 2048UL, depth, 1UL, 1 );
  ulong resp_data_sz = fd_dcache_req_data_sz( 64UL,   depth, 1UL, 1 );

  fd_frag_meta_t * req_mcache  = fd_mcache_join( fd_mcache_new( fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( depth, 0UL ), 1UL ), depth, 0UL, 0UL ) );
  uchar *          req_dcache  = fd_dcache_join( fd_dcache_new( fd_wksp_alloc_laddr( wksp, fd_dcache_align(), fd_dcache_footprint( req_data_sz, 0UL ), 1UL ), req_data_sz, 0UL ) );

  fd_frag_meta_t * resp_mcache = fd_mcache_join( fd_mcache_new( fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( depth, 0UL ), 1UL ), depth, 0UL, 0UL ) );
  uchar *          resp_dcache = fd_dcache_join( fd_dcache_new( fd_wksp_alloc_laddr( wksp, fd_dcache_align(), fd_dcache_footprint( resp_data_sz, 0UL ), 1UL ), resp_data_sz, 0UL ) );

  FD_TEST( req_mcache && req_dcache && resp_mcache && resp_dcache );

  fd_keyswitch_t * keyswitch = fd_keyswitch_join( fd_keyswitch_new( fd_wksp_alloc_laddr( wksp, fd_keyswitch_align(), fd_keyswitch_footprint(), 1UL ), FD_KEYSWITCH_STATE_LOCKED ) );
  FD_TEST( keyswitch );

  ulong * metrics = fd_wksp_alloc_laddr( wksp, FD_METRICS_ALIGN, FD_METRICS_FOOTPRINT( 1UL ), 1UL );
  FD_TEST( metrics );
  fd_metrics_new( metrics, 1UL );
  fd_metrics_register( metrics );

  /* Generate random keypair */

  uchar private_key[32];
  uchar public_key [32];

  fd_rng_t rng[1];
  FD_TEST( fd_rng_join( fd_rng_new( rng, 42U, 0UL ) ) );
  for( ulong i=0UL; i<32UL; i++ ) private_key[i] = fd_rng_uchar( rng );

  fd_sha512_t _sha512[1];
  FD_TEST( fd_sha512_join( fd_sha512_new( _sha512 ) ) );
  fd_ed25519_public_from_private( public_key, private_key, _sha512 );

  char key_path[] = "/tmp/test_sign_tile_XXXXXX";
  int key_fd = mkstemp( key_path );
  FD_TEST( key_fd>=0 );

  uchar keypair[64];
  memcpy( keypair,      private_key, 32UL );
  memcpy( keypair+32UL, public_key,  32UL );

  char json_buf[512];
  int off = 0;
  json_buf[off++] = '[';
  for( ulong i=0UL; i<64UL; i++ ) {
    if( i ) json_buf[off++] = ',';
    off += sprintf( json_buf+off, "%u", (uint)keypair[i] );
  }
  json_buf[off++] = ']';

  FD_TEST( write( key_fd, json_buf, (ulong)off )==off );
  FD_TEST( !close( key_fd ) );

  /* Initialize sign tile context */

  fd_sign_ctx_t ctx[1];
  memset( ctx, 0, sizeof(fd_sign_ctx_t) );

  uchar * identity_key = fd_keyload_load( key_path, 0 );
  ctx->private_key = identity_key;
  ctx->public_key  = identity_key + 32UL;

  FD_TEST( fd_sha512_join( fd_sha512_new( ctx->sha512 ) ) );
  fd_histf_join( fd_histf_new( ctx->sign_duration,
                               FD_MHIST_SECONDS_MIN( SIGN, SIGN_DURATION_SECONDS ),
                               FD_MHIST_SECONDS_MAX( SIGN, SIGN_DURATION_SECONDS ) ) );

  ctx->keyswitch         = keyswitch;
  ctx->av_keyswitch      = NULL;
  ctx->authorized_voters_cnt = 0UL;

  derive_fields( ctx );

  ulong req_chunk0 = fd_dcache_compact_chunk0( wksp, req_dcache );
  ulong req_wmark  = fd_dcache_compact_wmark ( wksp, req_dcache, 2048UL );

  ctx->in[0].mem    = wksp;
  ctx->in[0].chunk0 = req_chunk0;
  ctx->in[0].wmark  = req_wmark;
  for( ulong i=1UL; i<MAX_IN; i++ ) ctx->in[i].role = -1;

  ulong resp_chunk0 = fd_dcache_compact_chunk0( wksp, resp_dcache );
  ulong resp_wmark  = fd_dcache_compact_wmark ( wksp, resp_dcache, 64UL );

  ctx->out[0].out_mem    = wksp;
  ctx->out[0].out_chunk0 = resp_chunk0;
  ctx->out[0].out_wmark  = resp_wmark;
  ctx->out[0].out_chunk  = resp_chunk0;

  /* Set up minimal stem context for after_frag */

  fd_frag_meta_t * out_mcache_arr[1] = { resp_mcache };
  ulong            out_seq_arr[1]    = { 0UL };
  ulong            out_depth_arr[1]  = { depth };
  ulong            cr_avail_arr[1]   = { depth };
  ulong            min_cr_avail      = depth;
  int              out_reliable[1]   = { 0 };

  fd_stem_context_t stem[1] = {{
    .mcaches             = out_mcache_arr,
    .seqs                = out_seq_arr,
    .depths              = out_depth_arr,
    .cr_avail            = cr_avail_arr,
    .min_cr_avail        = &min_cr_avail,
    .cr_decrement_amount = 1UL,
    .out_reliable        = out_reliable,
  }};

  /* Verification sha512 (separate from ctx->sha512) */

  fd_sha512_t verify_sha[1];
  FD_TEST( fd_sha512_join( fd_sha512_new( verify_sha ) ) );

  /* ---- Success: LEADER / shred (ED25519) ---- */

  FD_LOG_NOTICE(( "test_sign_leader_ok" ));
  {
    ctx->in[0].role = FD_KEYGUARD_ROLE_LEADER;
    ctx->in[0].mtu  = 32UL;
    ctx->out[0].out_chunk = resp_chunk0;
    out_seq_arr[0] = 0UL;

    uchar payload[32];
    memset( payload, 0xAB, 32UL );

    uchar * src = fd_chunk_to_laddr( wksp, req_chunk0 );
    memcpy( src, payload, 32UL );

    ulong sig = (ulong)(uint)FD_KEYGUARD_SIGN_TYPE_ED25519;
    during_frag( ctx, 0UL, 0UL, sig, req_chunk0, 32UL, 0UL );
    after_frag( ctx, 0UL, 0UL, sig, 32UL, 0UL, 0UL, stem );

    uchar * sig_out = fd_chunk_to_laddr( wksp, resp_chunk0 );
    FD_TEST( fd_ed25519_verify( payload, 32UL, sig_out, public_key, verify_sha )==FD_ED25519_SUCCESS );
  }

  /* ---- Success: BUNDLE (PUBKEY_CONCAT_ED25519) ---- */

  FD_LOG_NOTICE(( "test_sign_bundle_ok" ));
  {
    ctx->in[0].role = FD_KEYGUARD_ROLE_BUNDLE;
    ctx->in[0].mtu  = 9UL;
    ctx->out[0].out_chunk = resp_chunk0;
    out_seq_arr[0] = 0UL;

    uchar payload[9];
    memset( payload, 0xCD, 9UL );

    uchar * src = fd_chunk_to_laddr( wksp, req_chunk0 );
    memcpy( src, payload, 9UL );

    ulong sig = (ulong)(uint)FD_KEYGUARD_SIGN_TYPE_PUBKEY_CONCAT_ED25519;
    during_frag( ctx, 0UL, 0UL, sig, req_chunk0, 9UL, 0UL );
    after_frag( ctx, 0UL, 0UL, sig, 9UL, 0UL, 0UL, stem );

    uchar concat_msg[ FD_BASE58_ENCODED_32_SZ+1UL+9UL ];
    ulong concat_sz = ctx->public_key_base58_sz + 1UL + 9UL;
    memcpy( concat_msg, ctx->concat, ctx->public_key_base58_sz+1UL );
    memcpy( concat_msg+ctx->public_key_base58_sz+1UL, payload, 9UL );

    uchar * sig_out = fd_chunk_to_laddr( wksp, resp_chunk0 );
    FD_TEST( fd_ed25519_verify( concat_msg, concat_sz, sig_out, public_key, verify_sha )==FD_ED25519_SUCCESS );
  }

  /* ---- Success: EVENT (FD_EVENTS_AUTH_CONCAT_ED25519) ---- */

  FD_LOG_NOTICE(( "test_sign_event_ok" ));
  {
    ctx->in[0].role = FD_KEYGUARD_ROLE_EVENT;
    ctx->in[0].mtu  = 32UL;
    ctx->out[0].out_chunk = resp_chunk0;
    out_seq_arr[0] = 0UL;

    uchar payload[32];
    memset( payload, 0xEF, 32UL );

    uchar * src = fd_chunk_to_laddr( wksp, req_chunk0 );
    memcpy( src, payload, 32UL );

    ulong sig = (ulong)(uint)FD_KEYGUARD_SIGN_TYPE_FD_EVENTS_AUTH_CONCAT_ED25519;
    during_frag( ctx, 0UL, 0UL, sig, req_chunk0, 32UL, 0UL );
    after_frag( ctx, 0UL, 0UL, sig, 32UL, 0UL, 0UL, stem );

    uchar event_msg[15UL+32UL];
    memcpy( event_msg, "FD_EVENTS_AUTH-", 15UL );
    memcpy( event_msg+15UL, payload, 32UL );

    uchar * sig_out = fd_chunk_to_laddr( wksp, resp_chunk0 );
    FD_TEST( fd_ed25519_verify( event_msg, 47UL, sig_out, public_key, verify_sha )==FD_ED25519_SUCCESS );
  }

  /* ---- Success: GOSSIP pong (SHA256_ED25519) ---- */

  FD_LOG_NOTICE(( "test_sign_pong_ok" ));
  {
    ctx->in[0].role = FD_KEYGUARD_ROLE_GOSSIP;
    ctx->in[0].mtu  = 2048UL;
    ctx->out[0].out_chunk = resp_chunk0;
    out_seq_arr[0] = 0UL;

    uchar payload[48];
    memcpy( payload, "SOLANA_PING_PONG", 16UL );
    memset( payload+16UL, 0x77, 32UL );

    uchar * src = fd_chunk_to_laddr( wksp, req_chunk0 );
    memcpy( src, payload, 48UL );

    ulong sig = (ulong)(uint)FD_KEYGUARD_SIGN_TYPE_SHA256_ED25519;
    during_frag( ctx, 0UL, 0UL, sig, req_chunk0, 48UL, 0UL );
    after_frag( ctx, 0UL, 0UL, sig, 48UL, 0UL, 0UL, stem );

    uchar hash[32];
    fd_sha256_hash( payload, 48UL, hash );

    uchar * sig_out = fd_chunk_to_laddr( wksp, resp_chunk0 );
    FD_TEST( fd_ed25519_verify( hash, 32UL, sig_out, public_key, verify_sha )==FD_ED25519_SUCCESS );
  }

  /* ---- Crash: during_frag sz > mtu ---- */

  FD_LOG_NOTICE(( "test_during_frag_oversize" ));
  {
    ctx->in[0].role = FD_KEYGUARD_ROLE_LEADER;
    ctx->in[0].mtu  = 32UL;

    TEST_FORK_CRASH(
      during_frag( ctx, 0UL, 0UL, 0UL, req_chunk0, 33UL, 0UL );
    );
  }

  /* ---- Crash: during_frag chunk < chunk0 ---- */

  FD_LOG_NOTICE(( "test_during_frag_chunk_lo" ));
  {
    ctx->in[0].role = FD_KEYGUARD_ROLE_LEADER;
    ctx->in[0].mtu  = 32UL;

    TEST_FORK_CRASH(
      during_frag( ctx, 0UL, 0UL, 0UL, req_chunk0-1UL, 32UL, 0UL );
    );
  }

  /* ---- Crash: during_frag chunk > wmark ---- */

  FD_LOG_NOTICE(( "test_during_frag_chunk_hi" ));
  {
    ctx->in[0].role = FD_KEYGUARD_ROLE_LEADER;
    ctx->in[0].mtu  = 32UL;

    TEST_FORK_CRASH(
      during_frag( ctx, 0UL, 0UL, 0UL, req_wmark+1UL, 32UL, 0UL );
    );
  }

  /* ---- Crash: after_frag wrong sign type for LEADER ---- */

  FD_LOG_NOTICE(( "test_after_frag_bad_sign_type" ));
  {
    ctx->in[0].role = FD_KEYGUARD_ROLE_LEADER;
    ctx->in[0].mtu  = 32UL;

    memset( ctx->_data, 0xAB, 32UL );

    TEST_FORK_CRASH(
      after_frag( ctx, 0UL, 0UL, (ulong)(uint)FD_KEYGUARD_SIGN_TYPE_SHA256_ED25519, 32UL, 0UL, 0UL, stem );
    );
  }

  /* ---- Crash: after_frag payload size mismatch ---- */

  FD_LOG_NOTICE(( "test_after_frag_bad_payload_sz" ));
  {
    ctx->in[0].role = FD_KEYGUARD_ROLE_LEADER;
    ctx->in[0].mtu  = 32UL;

    memset( ctx->_data, 0xAB, 31UL );

    TEST_FORK_CRASH(
      after_frag( ctx, 0UL, 0UL, (ulong)(uint)FD_KEYGUARD_SIGN_TYPE_ED25519, 31UL, 0UL, 0UL, stem );
    );
  }

  /* Cleanup */

  unlink( key_path );
  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

#else

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_LOG_WARNING(( "skip: not hosted or no alloca" ));
  fd_halt();
  return 0;
}

#endif
