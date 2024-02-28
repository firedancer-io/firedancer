#include "fd_sign_tile.h"

#include "generated/fd_sign_tile_seccomp.h"

#include "../../keyguard/fd_keyload.h"
#include "../../keyguard/fd_keyguard.h"

FD_FN_CONST ulong
fd_sign_tile_align( void ) {
  return FD_SIGN_TILE_ALIGN;
}

FD_FN_PURE ulong
fd_sign_tile_footprint( fd_sign_tile_args_t const * args ) {
  (void)args;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_sign_tile_t ), sizeof( fd_sign_tile_t ) );
  return FD_LAYOUT_FINI( l, fd_sign_tile_align() );
}

ulong
fd_sign_tile_seccomp_policy( void *               shsign,
                             struct sock_filter * out,
                             ulong                out_cnt ) {
  (void)shsign;
  populate_sock_filter_policy_fd_sign_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_sign_tile_instr_cnt;
}

ulong
fd_sign_tile_allowed_fds( void * shsign,
                          int *  out,
                          ulong  out_cnt ) {
  (void)shsign;

  if( FD_UNLIKELY( out_cnt<2UL ) ) FD_LOG_ERR(( "out_cnt %lu", out_cnt ));

  ulong out_idx = 0;
  out[ out_idx++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) ) out[ out_idx++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_idx;
}

/* during_frag is called between pairs for sequence number checks, as
   we are reading incoming frags.  We don't actually need to copy the
   fragment here, see fd_dedup.c for why we do this.*/

static inline void
during_frag( void * _ctx,
             ulong  in_idx,
             ulong  seq,
             ulong  sig,
             ulong  chunk,
             ulong  sz,
             int *  opt_filter ) {
  (void)seq;
  (void)sig;
  (void)chunk;
  (void)sz;
  (void)opt_filter;

  fd_sign_tile_t * ctx = (fd_sign_tile_t *)_ctx;
  FD_TEST( in_idx<FD_SIGN_TILE_MAX_IN );

  switch( ctx->in_kind[ in_idx ] ) {
    case FD_KEYGUARD_ROLE_LEADER:
      fd_memcpy( ctx->_data, ctx->in_data[ in_idx ], 32UL );
      break;
    case FD_KEYGUARD_ROLE_TLS:
      fd_memcpy( ctx->_data, ctx->in_data[ in_idx ], 130UL );
      break;
    default:
      FD_LOG_CRIT(( "unexpected link kind %lu", ctx->in_kind[ in_idx ] ));
  }
}

static inline void
after_frag( void *             _ctx,
            ulong              in_idx,
            ulong              seq,
            ulong *            opt_sig,
            ulong *            opt_chunk,
            ulong *            opt_sz,
            ulong *            opt_tsorig,
            int *              opt_filter,
            fd_mux_context_t * mux ) {
  (void)seq;
  (void)opt_sig;
  (void)opt_chunk;
  (void)opt_sz;
  (void)opt_tsorig;
  (void)opt_filter;
  (void)mux;

  fd_sign_tile_t * ctx = (fd_sign_tile_t *)_ctx;

  FD_TEST( in_idx<FD_SIGN_TILE_MAX_IN );

  switch( ctx->in_kind[ in_idx ] ) {
    case FD_KEYGUARD_ROLE_LEADER: {
      if( FD_UNLIKELY( !fd_keyguard_payload_authorize( ctx->_data, 32UL, FD_KEYGUARD_ROLE_LEADER ) ) ) {
        FD_LOG_EMERG(( "fd_keyguard_payload_authorize failed" ));
      }
      fd_ed25519_sign( ctx->out[ in_idx ].data, ctx->_data, 32UL, ctx->public_key, ctx->private_key, ctx->sha512 );
      break;
    }
    case FD_KEYGUARD_ROLE_TLS: {
      if( FD_UNLIKELY( !fd_keyguard_payload_authorize( ctx->_data, 130UL, FD_KEYGUARD_ROLE_TLS ) ) ) {
        FD_LOG_EMERG(( "fd_keyguard_payload_authorize failed" ));
      }
      fd_ed25519_sign( ctx->out[ in_idx ].data, ctx->_data, 130UL, ctx->public_key, ctx->private_key, ctx->sha512 );
      break;
    }
    default:
      FD_LOG_CRIT(( "unexpected link kind %lu", ctx->in_kind[ in_idx ] ));
  }

  fd_mcache_publish( ctx->out[ in_idx ].mcache, 128UL, ctx->out[ in_idx ].seq, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL );
  ctx->out[ in_idx ].seq = fd_seq_inc( ctx->out[ in_idx ].seq, 1UL );
}

void
fd_sign_tile_join_privileged( void *                      shsign,
                              fd_sign_tile_args_t const * args ) {
  FD_SCRATCH_ALLOC_INIT( l, shsign );
  fd_sign_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_sign_tile_t ), sizeof( fd_sign_tile_t ) );

  uchar const * identity_key = fd_keyload_load( args->identity_key_path, /* pubkey only: */ 0 );
  ctx->private_key = identity_key;
  ctx->public_key  = identity_key + 32UL;
}

fd_sign_tile_t *
fd_sign_tile_join( void *                      shsign,
                   fd_sign_tile_args_t const * args,
                   fd_sign_tile_topo_t const * topo ) {
  FD_SCRATCH_ALLOC_INIT( l, shsign );
  fd_sign_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_sign_tile_t ), sizeof( fd_sign_tile_t ) );
  FD_TEST( fd_sha512_join( fd_sha512_new( ctx->sha512 ) ) );

  FD_TEST( topo->link_cnt<=FD_SIGN_TILE_MAX_IN );

  for( ulong i=0UL; i<FD_SIGN_TILE_MAX_IN; i++ ) ctx->in_kind[ i ] = ULONG_MAX;

  for( ulong i=0UL; i<topo->link_cnt; i++ ) {
    ctx->in_data[ i ] = topo->link_in_dcache[ i ];
    ctx->in_kind[ i ] = topo->link_in_kind[ i ];

    ctx->out[ i ].mcache = topo->link_out_mcache[ i ];
    ctx->out[ i ].data   = topo->link_out_dcache[ i ];
    ctx->out[ i ].seq    = 0UL;

    switch( ctx->in_kind[ i ] ) {
      case FD_KEYGUARD_ROLE_LEADER:
        FD_TEST( topo->link_in_mtu[ i ]==32UL );
        FD_TEST( topo->link_out_mtu[ i ]==64UL );
        break;
      case FD_KEYGUARD_ROLE_TLS:
        FD_TEST( topo->link_in_mtu[ i ]==130UL );
        FD_TEST( topo->link_out_mtu[ i ]==64UL );
        break;
      default:
        FD_LOG_CRIT(( "unexpected link kind %lu", ctx->in_kind[ i ] ));
    }
  }

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)shsign + fd_sign_tile_footprint( args ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)shsign - fd_sign_tile_footprint( args ), scratch_top, (ulong)shsign + fd_sign_tile_footprint( args ) ));

  return ctx;
}

void
fd_sign_tile_run( fd_sign_tile_t *        ctx,
                  fd_cnc_t *              cnc,
                  ulong                   in_cnt,
                  fd_frag_meta_t const ** in_mcache,
                  ulong **                in_fseq,
                  fd_frag_meta_t *        mcache,
                  ulong                   out_cnt,
                  ulong **                out_fseq ) {
  fd_mux_callbacks_t callbacks = {
    .during_frag         = during_frag,
    .after_frag          = after_frag,
  };

  fd_rng_t rng[1];
  fd_mux_tile( cnc,
               FD_MUX_FLAG_MANUAL_PUBLISH | FD_MUX_FLAG_COPY,
               in_cnt,
               in_mcache,
               in_fseq,
               mcache,
               out_cnt,
               out_fseq,
               1UL,
               0UL,
               0L,
               fd_rng_join( fd_rng_new( rng, 0, 0UL ) ),
               fd_alloca( FD_MUX_TILE_SCRATCH_ALIGN, FD_MUX_TILE_SCRATCH_FOOTPRINT( in_cnt, out_cnt ) ),
               ctx,
               &callbacks );
}
