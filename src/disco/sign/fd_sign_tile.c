#define _GNU_SOURCE
#include "../tiles.h"

#include "generated/fd_sign_tile_seccomp.h"

#include "../keyguard/fd_keyguard.h"
#include "../keyguard/fd_keyload.h"
#include "../keyguard/fd_keyswitch.h"
#include "../../ballet/base58/fd_base58.h"
#include "../metrics/fd_metrics.h"

#include "../../util/hist/fd_histf.h"

#include <errno.h>
#include <sys/mman.h>

#define MAX_IN (32UL)

struct fd_auth_key {
  fd_pubkey_t public_key;
  uchar *     private_key;
  uint        hash;
};
typedef struct fd_auth_key fd_auth_key_t;

#define MAP_NAME               fd_auth_key_set
#define MAP_T                  fd_auth_key_t
#define MAP_LG_SLOT_CNT        5
#define MAP_KEY                public_key
#define MAP_KEY_T              fd_pubkey_t
#define MAP_KEY_NULL           (fd_pubkey_t){0}
#define MAP_KEY_EQUAL(k0,k1)   (!(memcmp((k0).key,(k1).key,sizeof(fd_pubkey_t))))
#define MAP_KEY_INVAL(k)       (MAP_KEY_EQUAL((k),MAP_KEY_NULL))
#define MAP_KEY_EQUAL_IS_SLOW  1
#define MAP_KEY_HASH(k)        ((uint)fd_ulong_hash( fd_ulong_load_8( (k).uc ) ))
#include "../../util/tmpl/fd_map.c"

/* fd_sign_in_ctx_t is a context object for each in (producer) mcache
   connected to the sign tile. */

struct fd_sign_out_ctx {
  fd_wksp_t * out_mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;
};
typedef struct fd_sign_out_ctx fd_sign_out_ctx_t;

struct fd_sign_in_ctx {
  int              role;
  fd_wksp_t *      mem;
  ulong            chunk0;
  ulong            wmark;
  ulong            mtu;
};
typedef struct fd_sign_in_ctx fd_sign_in_ctx_t;

typedef struct {
  uchar             _data[ FD_KEYGUARD_SIGN_REQ_MTU ];

  /* Pre-staged with the public key base58 encoded, followed by "-" in the first bytes */
  ulong public_key_base58_sz;
  uchar concat[ FD_BASE58_ENCODED_32_SZ+1UL+9UL ];

  uchar event_concat[ 18UL+32UL ];

  fd_sign_in_ctx_t  in[ MAX_IN ];
  fd_sign_out_ctx_t out[ MAX_IN ];

  fd_sha512_t       sha512 [ 1 ];

  fd_keyswitch_t *  keyswitch;

  uchar *           public_key;
  uchar *           private_key;

  fd_auth_key_t *   auth_key_set;

  fd_histf_t        sign_duration[1];
} fd_sign_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return alignof( fd_sign_ctx_t );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_sign_ctx_t ), sizeof( fd_sign_ctx_t ) );
  l = FD_LAYOUT_APPEND( l, fd_auth_key_set_align(), fd_auth_key_set_footprint() );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void FD_FN_SENSITIVE
derive_fields( fd_sign_ctx_t * ctx ) {
  uchar check_public_key[ 32 ];
  fd_ed25519_public_from_private( check_public_key, ctx->private_key, ctx->sha512 );
  if( FD_UNLIKELY( memcmp( check_public_key, ctx->public_key, 32UL ) ) )
    FD_LOG_EMERG(( "The public key in the identity key file does not match the public key derived from the private key. "
                   "Firedancer will not use the key pair to sign as it might leak the private key." ));

  fd_base58_encode_32( ctx->public_key, &ctx->public_key_base58_sz, (char *)ctx->concat );
  ctx->concat[ ctx->public_key_base58_sz ] = '-';

  memcpy( ctx->event_concat, "FD_METRICS_REPORT-", 18UL );
}

static void FD_FN_SENSITIVE
during_housekeeping_sensitive( fd_sign_ctx_t * ctx ) {
  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->keyswitch )==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
    memcpy( ctx->private_key, ctx->keyswitch->bytes, 32UL );
    explicit_bzero( ctx->keyswitch->bytes, 32UL );
    FD_COMPILER_MFENCE();
    memcpy( ctx->public_key, ctx->keyswitch->bytes+32UL, 32UL );

    derive_fields( ctx );
    fd_keyswitch_state( ctx->keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
  }
}

static inline void
during_housekeeping( fd_sign_ctx_t * ctx ) {
  during_housekeeping_sensitive( ctx );
}

static inline void
metrics_write( fd_sign_ctx_t * ctx ) {
  FD_MHIST_COPY( SIGN, SIGN_DURATION_SECONDS, ctx->sign_duration );
}

/* during_frag is called between pairs for sequence number checks, as
   we are reading incoming frags.  We don't actually need to copy the
   fragment here, see fd_dedup.c for why we do this.*/

static void FD_FN_SENSITIVE
during_frag_sensitive( void * _ctx,
                       ulong  in_idx,
                       ulong  seq,
                       ulong  sig,
                       ulong  chunk,
                       ulong  sz ) {
  (void)seq;
  (void)sig;

  fd_sign_ctx_t * ctx = (fd_sign_ctx_t *)_ctx;
  FD_TEST( in_idx<MAX_IN );

  int   role = ctx->in[ in_idx ].role;
  ulong mtu  = ctx->in[ in_idx ].mtu;

  if( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>mtu ) {
    FD_LOG_EMERG(( "oversz or out of bounds signing request (role=%d chunk=%lu sz=%lu mtu=%lu, chunk0=%lu, wmark=%lu)", role, chunk, sz, mtu, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));
  }

  void * src = fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk );
  fd_memcpy( ctx->_data, src, sz );
}


static void
during_frag( void * _ctx,
             ulong  in_idx,
             ulong  seq,
             ulong  sig,
             ulong  chunk,
             ulong  sz,
             ulong  ctl FD_PARAM_UNUSED ) {
  during_frag_sensitive( _ctx, in_idx, seq, sig, chunk, sz );
}

static void FD_FN_SENSITIVE
vote_txn_sign( fd_sign_ctx_t * ctx,
               uchar *         dst,
               ulong           sz ) {

  /* A vote transaction may be signed by either the identity key or a
     combination between the identity and the authorized voter.  The
     first signer is always the identity key. */

  uchar * message    = ctx->_data + 33UL;
  ulong   message_sz = sz - 33UL;

  fd_ed25519_sign( dst, message, message_sz, ctx->public_key, ctx->private_key, ctx->sha512 );

  if( ctx->_data[ 0 ]==1 ) {
    fd_auth_key_t * auth_key = fd_auth_key_set_query( ctx->auth_key_set, *(fd_pubkey_t const *)(ctx->_data + 1), NULL );
    FD_CRIT( auth_key==NULL, "authorized voter not found" );
    fd_ed25519_sign( dst + 64, message, message_sz, auth_key->public_key.uc, auth_key->private_key, ctx->sha512 );
  }
}

static void FD_FN_SENSITIVE
after_frag_sensitive( void *              _ctx,
                      ulong               in_idx,
                      ulong               seq,
                      ulong               sig,
                      ulong               sz,
                      ulong               tsorig,
                      ulong               tspub,
                      fd_stem_context_t * stem ) {
  (void)seq;
  (void)tspub;

  fd_sign_ctx_t * ctx = (fd_sign_ctx_t *)_ctx;

  /* If the frag is coming from the repair tile, then the upper 32 bits
     contain the repair tile nonce to identify the request.  The send
     tile will use the upper 32 bits to identify if it's a vote
     transaction or not: if the 32 bits are all 1s, then it's a vote
     transaction, otherwise it's not.
     The lower 32 bits specify the sign_type. */
  int sign_type   = (int)(uint)(sig);
  int is_vote_txn = ctx->in[ in_idx ].role==FD_KEYGUARD_ROLE_SEND && UINT_MAX==(sig>>32);

  FD_TEST( in_idx<MAX_IN );

  int role = ctx->in[ in_idx ].role;

  fd_keyguard_authority_t authority = {0};
  memcpy( authority.identity_pubkey, ctx->public_key, 32 );


  uchar * payload = is_vote_txn ? ctx->_data + 33UL : ctx->_data;
  if( FD_UNLIKELY( !fd_keyguard_payload_authorize( &authority, payload, sz, role, sign_type ) ) ) {
    FD_LOG_EMERG(( "fd_keyguard_payload_authorize failed (role=%d sign_type=%d)", role, sign_type ));
  }

  long sign_duration = -fd_tickcount();

  uchar * dst = fd_chunk_to_laddr( ctx->out[ in_idx ].out_mem, ctx->out[ in_idx ].out_chunk );

  switch( sign_type ) {
  case FD_KEYGUARD_SIGN_TYPE_ED25519: {
    if( is_vote_txn ) {
      vote_txn_sign( ctx, dst, sz );
    } else {
      fd_ed25519_sign( dst, ctx->_data, sz, ctx->public_key, ctx->private_key, ctx->sha512 );
    }
    break;
  }
  case FD_KEYGUARD_SIGN_TYPE_SHA256_ED25519: {
    uchar hash[ 32 ];
    fd_sha256_hash( ctx->_data, sz, hash );
    fd_ed25519_sign( dst, hash, 32UL, ctx->public_key, ctx->private_key, ctx->sha512 );
    break;
  }
  case FD_KEYGUARD_SIGN_TYPE_PUBKEY_CONCAT_ED25519: {
    memcpy( ctx->concat+ctx->public_key_base58_sz+1UL, ctx->_data, 9UL );
    fd_ed25519_sign( dst, ctx->concat, ctx->public_key_base58_sz+1UL+9UL, ctx->public_key, ctx->private_key, ctx->sha512 );
    break;
  }
  case FD_KEYGUARD_SIGN_TYPE_FD_METRICS_REPORT_CONCAT_ED25519: {
    memcpy( ctx->event_concat+18UL, ctx->_data, 32UL );
    fd_ed25519_sign( dst, ctx->event_concat, 18UL+32UL, ctx->public_key, ctx->private_key, ctx->sha512 );
    break;
  }
  default:
    FD_LOG_EMERG(( "invalid sign type: %d", sign_type ));
  }

  sign_duration += fd_tickcount();
  fd_histf_sample( ctx->sign_duration, (ulong)sign_duration );

  fd_stem_publish( stem, in_idx, sig, ctx->out[ in_idx ].out_chunk, 64UL, 0UL, tsorig, 0UL );
  ctx->out[ in_idx ].out_chunk = fd_dcache_compact_next( ctx->out[ in_idx ].out_chunk, 64UL, ctx->out[ in_idx ].out_chunk0, ctx->out[ in_idx ].out_wmark );
}

static void
after_frag( void *              _ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               sz,
            ulong               tsorig,
            ulong               tspub,
            fd_stem_context_t * stem ) {
  after_frag_sensitive( _ctx, in_idx, seq, sig, sz, tsorig, tspub, stem );
}

static void FD_FN_SENSITIVE
privileged_init_sensitive( fd_topo_t *      topo,
                           fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_sign_ctx_t * ctx    = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_sign_ctx_t ), sizeof( fd_sign_ctx_t ) );

  uchar * identity_key = fd_keyload_load( tile->sign.identity_key_path, /* pubkey only: */ 0 );
  ctx->private_key = identity_key;
  ctx->public_key  = identity_key + 32UL;

  fd_auth_key_t * av_map = FD_SCRATCH_ALLOC_APPEND( l, fd_auth_key_set_align(), fd_auth_key_set_footprint() );
  ctx->auth_key_set = fd_auth_key_set_join( fd_auth_key_set_new( av_map ) );
  for( ulong i=0UL; i<tile->sign.authorized_voter_paths_cnt; i++ ) {
    uchar * authorized_voter_key = fd_keyload_load( tile->sign.authorized_voter_paths[ i ], /* pubkey only: */ 0 );
    fd_auth_key_t * auth_key = fd_auth_key_set_insert( ctx->auth_key_set, *(fd_pubkey_t const *)(authorized_voter_key+32UL) );
    auth_key->private_key = authorized_voter_key;
  }

  /* The stack can be taken over and reorganized by under AddressSanitizer,
     which causes this code to fail.  */
#if FD_HAS_ASAN
  FD_LOG_WARNING(( "!!! SECURITY WARNING !!! YOU ARE RUNNING THE SIGNING TILE "
                   "WITH ADDRESS SANITIZER ENABLED. THIS CAN LEAK SENSITIVE "
                   "DATA INCLUDING YOUR PRIVATE KEYS INTO CORE DUMPS IF THIS "
                   "PROCESS ABORTS. IT IS HIGHLY ADVISED TO NOT TO RUN IN THIS "
                   "MODE IN PRODUCTION!" ));
#else
  /* Prevent the stack from showing up in core dumps just in case the
     private key somehow ends up in there. */
  FD_TEST( fd_tile_stack0() );
  FD_TEST( fd_tile_stack_sz() );
  if( FD_UNLIKELY( madvise( (void*)fd_tile_stack0(), fd_tile_stack_sz(), MADV_DONTDUMP ) ) )
    FD_LOG_ERR(( "madvise failed (%i-%s)", errno, fd_io_strerror( errno ) ));
#endif
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  privileged_init_sensitive( topo, tile );
}

static void FD_FN_SENSITIVE
unprivileged_init_sensitive( fd_topo_t *      topo,
                             fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_sign_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_sign_ctx_t ), sizeof( fd_sign_ctx_t ) );
  FD_TEST( fd_sha512_join( fd_sha512_new( ctx->sha512 ) ) );

  FD_TEST( tile->in_cnt<=MAX_IN );
  FD_TEST( tile->in_cnt==tile->out_cnt );

  fd_histf_join( fd_histf_new( ctx->sign_duration, FD_MHIST_SECONDS_MIN( SIGN, SIGN_DURATION_SECONDS ),
                                                       FD_MHIST_SECONDS_MAX( SIGN, SIGN_DURATION_SECONDS ) ) );

  ctx->keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, tile->keyswitch_obj_id ) );
  derive_fields( ctx );

  for( ulong i=0UL; i<MAX_IN; i++ ) ctx->in[ i ].role = -1;

  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * in_link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_link_t * out_link = &topo->links[ tile->out_link_id[ i ] ];

    if( in_link->mtu > FD_KEYGUARD_SIGN_REQ_MTU ) FD_LOG_CRIT(( "oversz link[%lu].mtu=%lu", i, in_link->mtu ));
    ctx->in[ i ].mem    = fd_wksp_containing( in_link->dcache );
    ctx->in[ i ].mtu    = in_link->mtu;
    ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, in_link->dcache );
    ctx->in[ i ].wmark  = fd_dcache_compact_wmark( ctx->in[ i ].mem, in_link->dcache, in_link->mtu );

    ctx->out[ i ].out_mem    = fd_wksp_containing( out_link->dcache );
    ctx->out[ i ].out_chunk0 = fd_dcache_compact_chunk0( ctx->out[ i ].out_mem, out_link->dcache );
    ctx->out[ i ].out_wmark  = fd_dcache_compact_wmark( ctx->out[ i ].out_mem, out_link->dcache, 64UL );
    ctx->out[ i ].out_chunk  = ctx->out[ i ].out_chunk0;

    if( !strcmp( in_link->name, "shred_sign" ) ) {
      ctx->in[ i ].role = FD_KEYGUARD_ROLE_LEADER;
      FD_TEST( !strcmp( out_link->name, "sign_shred" ) );
      FD_TEST( in_link->mtu==32UL );
      FD_TEST( out_link->mtu==64UL );
    } else if ( !strcmp( in_link->name, "gossip_sign" ) ) {
      ctx->in[ i ].role = FD_KEYGUARD_ROLE_GOSSIP;
      FD_TEST( !strcmp( out_link->name, "sign_gossip" ) );
      FD_TEST( in_link->mtu==2048UL );
      FD_TEST( out_link->mtu==64UL );
    } else if ( !strcmp( in_link->name, "repair_sign" )
             || !strcmp( in_link->name, "ping_sign" ) ) {
      ctx->in[ i ].role = FD_KEYGUARD_ROLE_REPAIR;
      if( !strcmp( in_link->name, "ping_sign" ) ) {
        FD_TEST( !strcmp( out_link->name, "sign_ping" ) );
      } else {
        FD_TEST( !strcmp( out_link->name, "sign_repair" ) );
      }
      FD_TEST( in_link->mtu==96 ); // FD_REPAIR_MAX_PREIMAGE_SZ
      FD_TEST( out_link->mtu==64UL );
    } else if ( !strcmp(in_link->name, "send_sign"  ) ) {
      ctx->in[ i ].role = FD_KEYGUARD_ROLE_SEND;
      FD_TEST( !strcmp( out_link->name, "sign_send"  ) );
      FD_TEST( in_link->mtu==FD_SEND_SIGN_MTU  );
      FD_TEST( out_link->mtu==FD_SIGN_SEND_MTU );
    } else if( !strcmp(in_link->name, "bundle_sign" ) ) {
      ctx->in[ i ].role = FD_KEYGUARD_ROLE_BUNDLE;
      FD_TEST( !strcmp( out_link->name, "sign_bundle" ) );
      FD_TEST( in_link->mtu==9UL );
      FD_TEST( out_link->mtu==64UL );
    } else if( !strcmp(in_link->name, "event_sign" ) ) {
      ctx->in[ i ].role = FD_KEYGUARD_ROLE_EVENT;
      FD_TEST( !strcmp( out_link->name, "sign_event" ) );
      FD_TEST( in_link->mtu==32UL );
      FD_TEST( out_link->mtu==64UL );
    } else if( !strcmp(in_link->name, "pack_sign" ) ) {
      ctx->in[ i ].role = FD_KEYGUARD_ROLE_BUNDLE_CRANK;
      FD_TEST( !strcmp( out_link->name, "sign_pack" ) );
      FD_TEST( in_link->mtu==1232UL );
      FD_TEST( out_link->mtu==64UL );
    } else {
      FD_LOG_CRIT(( "unexpected link %s", in_link->name ));
    }
  }

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  unprivileged_init_sensitive( topo, tile );
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo;
  (void)tile;

  populate_sock_filter_policy_fd_sign_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_sign_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  (void)topo;
  (void)tile;

  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

#define STEM_BURST (1UL)

/* See explanation in fd_pack */
#define STEM_LAZY  (128L*3000L)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_sign_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_sign_ctx_t)

#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_sign = {
  .name                     = "sign",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
