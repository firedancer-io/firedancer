#include "../../disco/topo/fd_topo.h"
#include "../../disco/keyguard/fd_keyswitch.h"
#include "../../ballet/ed25519/fd_ed25519.h"

#include "fd_adminctl.h"
#include "generated/fd_admin_tile_seccomp.h"

struct fd_admin_tile_ctx {
  fd_adminctl_t *  adminctl;
  fd_keyswitch_t * tower_av_keyswitch;
  fd_keyswitch_t * sign_av_keyswitch[ FD_TOPO_MAX_TILES ];
  ulong            sign_av_keyswitch_cnt;
  fd_sha512_t      sha512[ 1 ];
};

typedef struct fd_admin_tile_ctx fd_admin_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return alignof(fd_admin_tile_ctx_t);
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return sizeof(fd_admin_tile_ctx_t);
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void *                scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  fd_admin_tile_ctx_t * ctx     = (fd_admin_tile_ctx_t *)scratch;
  fd_memset( ctx, 0, sizeof(fd_admin_tile_ctx_t) );

  fd_topo_obj_t const * adminctl_obj = fd_topo_find_tile_obj( topo, tile, "adminctl" );
  FD_TEST( adminctl_obj );

  ctx->adminctl = fd_adminctl_join( fd_topo_obj_laddr( topo, adminctl_obj->id ) );
  FD_TEST( ctx->adminctl );

  ulong tower_idx = fd_topo_find_tile( topo, "tower", 0UL );
  FD_TEST( tower_idx!=ULONG_MAX );
  FD_TEST( topo->tiles[ tower_idx ].av_keyswitch_obj_id!=ULONG_MAX );
  ctx->tower_av_keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, topo->tiles[ tower_idx ].av_keyswitch_obj_id ) );
  FD_TEST( ctx->tower_av_keyswitch );

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t const * sign_tile = &topo->tiles[ i ];
    if( FD_LIKELY( strcmp( sign_tile->name, "sign" ) ) ) continue;
    FD_TEST( sign_tile->av_keyswitch_obj_id!=ULONG_MAX );
    ctx->sign_av_keyswitch[ ctx->sign_av_keyswitch_cnt ] = fd_keyswitch_join( fd_topo_obj_laddr( topo, sign_tile->av_keyswitch_obj_id ) );
    FD_TEST( ctx->sign_av_keyswitch[ ctx->sign_av_keyswitch_cnt ] );
    ctx->sign_av_keyswitch_cnt++;
  }
  FD_TEST( ctx->sign_av_keyswitch_cnt );

  FD_TEST( fd_sha512_join( fd_sha512_new( ctx->sha512 ) ) );
}

/* The process of adding an authorized voter to the validator must be
   done carefully in order to prevent vote transactions being generated
   with an authorized voter that the sign tile is not yet aware of.
   The authorized voter must be added to the sign tile before it is
   added to the tower tile.  All transitions must be linear and in
   forward order. */

/* State 0: UNLOCKED
   The validator is not currently in the process of switching keys. */
#define FD_ADD_AUTH_VOTER_STATE_UNLOCKED             (0UL)

/* State 1: LOCKED
   Some client to the validator has requested to add an authorized
   voter.  To do so, it acquired an exclusive lock on the validator to
   prevent the switch potentially being interleaved with another
   client. */
#define FD_ADD_AUTH_VOTER_STATE_LOCKED               (1UL)

/* State 2: SIGN_TILE_REQUESTED
   The first step to add an authorized voter is to notify the sign
   tile that an authorized voter is being added. */
#define FD_ADD_AUTH_VOTER_STATE_SIGN_TILE_REQUESTED  (2UL)

/* State 3: SIGN_TILE_UPDATED
   The Sign tile has confirmed that it has updated its internal
   mapping for the set of supported authorized voters.  At this point
   the sign tile is aware of the new authorized voter but the Tower
   tile will not prepare vote transactions with the new authorized
   voter yet. */
#define FD_ADD_AUTH_VOTER_STATE_SIGN_TILE_UPDATED    (3UL)

/* State 4: TOWER_TILE_REQUESTED
   Once the Sign tile is updated, now the Tower tile must be notified
   that an authorized voter is being added so it can start preparing
   vote transactions with the new authorized voter. */
#define FD_ADD_AUTH_VOTER_STATE_TOWER_TILE_REQUESTED (4UL)

/* State 5: TOWER_TILE_UPDATED
   The Tower tile has confirmed that it has updated its internal
   mapping for the set of supported authorized voters. */
#define FD_ADD_AUTH_VOTER_STATE_TOWER_TILE_UPDATED   (5UL)

/* State 6: UNLOCK_REQUESTED
   The client now requests that the Tower tile unpause the pipeline
   so the validator can start producing votes with the new authorized
   voter. */
#define FD_ADD_AUTH_VOTER_STATE_UNLOCK_REQUESTED     (6UL)

static void FD_FN_SENSITIVE
poll_add_authorized_voter( fd_admin_tile_ctx_t * ctx,
                           ulong *               state,
                           uchar *               keypair,
                           ulong *               result ) {
  fd_keyswitch_t * tower = ctx->tower_av_keyswitch;

  switch( *state ) {
    case FD_ADD_AUTH_VOTER_STATE_UNLOCKED: {
      if( FD_LIKELY( FD_KEYSWITCH_STATE_UNLOCKED==FD_ATOMIC_CAS( &tower->state, FD_KEYSWITCH_STATE_UNLOCKED, FD_KEYSWITCH_STATE_LOCKED ) ) ) {
        *state = FD_ADD_AUTH_VOTER_STATE_LOCKED;
        FD_LOG_INFO(( "Locking authorized voter set for authorized voter update..." ));
      } else {
        /* keyswitch changes should be guarded and ordered by adminctl.
           If the keyswitch is in a locked state means there is
           unexpected process state and the validator should crash. */
        FD_LOG_CRIT(( "keyswitch is in a locked state but should be unlocked" ));
      }
      break;
    }
    case FD_ADD_AUTH_VOTER_STATE_LOCKED: {
      for( ulong i=0UL; i<ctx->sign_av_keyswitch_cnt; i++ ) {
        fd_keyswitch_t * sign = ctx->sign_av_keyswitch[ i ];
        memcpy( sign->bytes, keypair, 64UL );
        FD_COMPILER_MFENCE();
        sign->state = FD_KEYSWITCH_STATE_SWITCH_PENDING;
        FD_COMPILER_MFENCE();
      }
      fd_memzero_explicit( keypair, 32UL );
      *state = FD_ADD_AUTH_VOTER_STATE_SIGN_TILE_REQUESTED;
      FD_LOG_INFO(( "Requesting all sign tiles to update authorized voter key set..." ));
      break;
    }
    case FD_ADD_AUTH_VOTER_STATE_SIGN_TILE_REQUESTED: {
      int all_updated = 1;
      for( ulong i=0UL; i<ctx->sign_av_keyswitch_cnt; i++ ) {
        fd_keyswitch_t * sign = ctx->sign_av_keyswitch[ i ];
        if( FD_UNLIKELY( sign->state==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
          all_updated = 0;
        } else if( FD_UNLIKELY( sign->state==FD_KEYSWITCH_STATE_FAILED ) ) {
          /* Recoverable error: the sign tile failed to update the set
             of authorized voters is a result of bad caller input.  All
             the sign tiles should be in sync, which means that if one
             sign tile failed, we expect all of them to. */
          fd_memzero_explicit( sign->bytes, 64UL );
          if( FD_LIKELY( !*result ) ) *result = sign->result;
        } else { /* sign->state==FD_KEYSWITCH_STATE_COMPLETED */
          fd_memzero_explicit( sign->bytes, 64UL );
        }
      }

      if( FD_LIKELY( all_updated ) ) {
        if( FD_UNLIKELY( *result ) ) *state = FD_ADD_AUTH_VOTER_STATE_TOWER_TILE_UPDATED;
        else                         *state = FD_ADD_AUTH_VOTER_STATE_SIGN_TILE_UPDATED;
      } else {
        FD_SPIN_PAUSE();
      }
      break;
    }
    case FD_ADD_AUTH_VOTER_STATE_SIGN_TILE_UPDATED: {
      memcpy( tower->bytes, keypair+32UL, 32UL );
      FD_COMPILER_MFENCE();
      tower->state = FD_KEYSWITCH_STATE_SWITCH_PENDING;
      FD_COMPILER_MFENCE();
      *state = FD_ADD_AUTH_VOTER_STATE_TOWER_TILE_REQUESTED;
      FD_LOG_INFO(( "Requesting tower tile to update authorized voter key set..." ));
      break;
    }
    case FD_ADD_AUTH_VOTER_STATE_TOWER_TILE_REQUESTED: {
      /* There is a guarantee that the tower tile will be in sync with
         the set of authorized voters in the sign tile.  At this point
         that means that the command should succeed because invariants
         such as not having duplicate authorized voter keys and too many
         authorized voters are upheld.  If this doesn't hold true, the
         Tower tile will detect any corruption and gracefully crash the
         validator. */
      if( FD_LIKELY( tower->state==FD_KEYSWITCH_STATE_COMPLETED ) ) {
        *state = FD_ADD_AUTH_VOTER_STATE_TOWER_TILE_UPDATED;
        FD_LOG_INFO(( "Tower tile key set successfully updated..." ));
      } else {
        FD_SPIN_PAUSE();
      }
      break;
    }
    case FD_ADD_AUTH_VOTER_STATE_TOWER_TILE_UPDATED: {
      tower->state = FD_KEYSWITCH_STATE_UNHALT_PENDING;
      *state       = FD_ADD_AUTH_VOTER_STATE_UNLOCK_REQUESTED;
      FD_LOG_INFO(( "Requesting an unlock of the authorized voter key set..." ));
      break;
    }
    case FD_ADD_AUTH_VOTER_STATE_UNLOCK_REQUESTED: {
      if( FD_LIKELY( tower->state==FD_KEYSWITCH_STATE_UNLOCKED ) ) {
        *state = FD_ADD_AUTH_VOTER_STATE_UNLOCKED;
        FD_LOG_INFO(( "Authorized voter key set unlocked..." ));
      } else {
        FD_SPIN_PAUSE();
      }
      break;
    }
    default: {
      FD_LOG_CRIT(( "Unexpected add-authorized-voter state %lu", *state ));
    }
  }
}

static void FD_FN_SENSITIVE
add_authorized_voter( fd_admin_tile_ctx_t *     ctx,
                      ulong                     slot_idx,
                      void *                    data,
                      ulong                     data_sz ) {

  fd_adminctl_t * adminctl = ctx->adminctl;

  if( FD_UNLIKELY( data_sz<sizeof(ulong) ) ) {
    FD_LOG_WARNING(( "adminctl add-authorized-voter payload too small: %lu", data_sz ));
    fd_adminctl_complete( adminctl, slot_idx, FD_ADD_AUTHORIZED_VOTER_RESULT_PAYLOAD_TOO_SMALL );
    return;
  }

  ulong version = FD_LOAD( ulong, data );
  if( FD_UNLIKELY( version!=FD_ADMINCTL_ADD_AUTH_VOTER_PAYLOAD_VERSION ) ) {
    FD_LOG_WARNING(( "unsupported adminctl add-authorized-voter payload version %lu", version ));
    fd_adminctl_complete( adminctl, slot_idx, FD_ADD_AUTHORIZED_VOTER_RESULT_UNSUPPORTED_PAYLOAD_VERSION );
    return;
  }

  if( FD_UNLIKELY( data_sz!=sizeof(fd_adminctl_add_auth_voter_t) ) ) {
    FD_LOG_WARNING(( "unexpected adminctl add-authorized-voter payload_sz %lu", data_sz ));
    fd_adminctl_complete( adminctl, slot_idx, FD_ADD_AUTHORIZED_VOTER_RESULT_UNEXPECTED_PAYLOAD_SIZE );
    return;
  }

  fd_adminctl_add_auth_voter_t * req = fd_type_pun( data );

  uchar public_key[ 32UL ];
  fd_ed25519_public_from_private( public_key, req->keypair, ctx->sha512 );
  if( FD_UNLIKELY( memcmp( public_key, req->keypair+32UL, 32UL ) ) ) {
    FD_LOG_WARNING(( "add-authorized-voter failed: public key in key file does not match private key" ));
    fd_adminctl_complete( adminctl, slot_idx, FD_ADD_AUTHORIZED_VOTER_RESULT_KEYPAIR_MISMATCH );
    return;
  }

  ulong result = FD_ADMINCTL_RESULT_SUCCESS;
  ulong state  = FD_ADD_AUTH_VOTER_STATE_UNLOCKED;
  for(;;) {
    poll_add_authorized_voter( ctx, &state, req->keypair, &result );
    if( FD_UNLIKELY( state==FD_ADD_AUTH_VOTER_STATE_UNLOCKED ) ) break;
  }

  fd_adminctl_complete( adminctl, slot_idx, result );
}

static inline void FD_FN_SENSITIVE
after_credit( fd_admin_tile_ctx_t * ctx,
              fd_stem_context_t *   stem FD_PARAM_UNUSED,
              int *                 opt_poll_in FD_PARAM_UNUSED,
              int *                 charge_busy ) {

  fd_adminctl_t * adminctl   = ctx->adminctl;
  ulong           slot_idx   = ULONG_MAX;
  void *          payload    = NULL;
  ulong           payload_sz = 0UL;

  ulong cmd_id = fd_adminctl_poll( adminctl, &slot_idx, &payload, &payload_sz );
  switch( cmd_id ) {
    case FD_ADMINCTL_CMD_IDLE:
      break;
    case FD_ADMINCTL_CMD_ADD_AUTH_VOTER:
      add_authorized_voter( ctx, slot_idx, payload, payload_sz );
      *charge_busy = 1;
      break;
    default:
      FD_LOG_WARNING(( "unexpected adminctl cmd %lu", cmd_id ));
      fd_adminctl_complete( adminctl, slot_idx, FD_ADMINCTL_RESULT_UNKNOWN_COMMAND );
  }
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo FD_PARAM_UNUSED,
                          fd_topo_tile_t const * tile FD_PARAM_UNUSED,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {

  populate_sock_filter_policy_fd_admin_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_admin_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo FD_PARAM_UNUSED,
                      fd_topo_tile_t const * tile FD_PARAM_UNUSED,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {

  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

#define STEM_BURST (1UL)
#define STEM_LAZY  ((long)1e6) /* 1ms */

#define STEM_CALLBACK_CONTEXT_TYPE  fd_admin_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_admin_tile_ctx_t)

#define STEM_CALLBACK_AFTER_CREDIT after_credit

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_admin = {
  .name                     = "admin",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
