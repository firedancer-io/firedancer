#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../util/fd_version.h"

#include "fd_failover_bus.h"
#include "fd_failover_channel.h"
#include "fd_failover_role.h"
#include "fd_failover_stream.h"
#include "fd_failover_tls.h"
#include "../tower/fd_tower_tile.h"
#include "../replay/fd_replay_tile.h"
#include "../../choreo/tower/fd_tower_serdes.h"
#include "../../ballet/txn/fd_txn.h"

#include <sys/socket.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "generated/fd_failover_tile_seccomp.h"

/* The failover tile owns every socket of the pool link and is the only
   tile that keeps host networking for it.  It holds the junk keypair for
   TLS and nothing else, the staked key never enters this tile.  The
   admin tile keeps the identity switch and stays off the network. */

/* Limits on what an authenticated but misconfigured peer can push.  A
   round trip sample above a minute is dropped, and an advertised STATUS
   cadence above a minute is clamped before it sizes the silence window. */
#define FD_FAILOVER_TILE_RTT_MAX_NANOS   (60000000000UL)
#define FD_FAILOVER_TILE_PEER_MILLIS_MAX (60000UL)

/* A controller wait also ends on the monotonic clock, so a stalled
   replay cannot leave a transition in flight forever with every command
   answering busy.  The bound is derived from the slot deadline at one
   second per slot and clamped, so failover.deadline_slots stays the one
   knob that says how long an attempt may take, and a slow but live
   cluster is not aborted early. */
#define FD_FAILOVER_TILE_DEADLINE_SLOT_NANOS (1000000000UL)   /*   1s per slot */
#define FD_FAILOVER_TILE_DEADLINE_NANOS_MIN  (30000000000UL)  /*  30s floor    */
#define FD_FAILOVER_TILE_DEADLINE_NANOS_MAX  (300000000000UL) /* 300s ceiling  */

#define FD_FAILOVER_TILE_PEER_MAX (FD_TOPO_FAILOVER_MEMBER_MAX-1UL)

/* What we are currently doing within a state.  The state itself is saved
   in the role file and survives a restart, the action does not. */
#define FD_FAILOVER_ACTION_IDLE                (0UL)
#define FD_FAILOVER_ACTION_DEMOTE_SWITCH       (1UL) /* waiting for the junk key to be installed */
#define FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK     (2UL) /* confirmation sent, waiting for the peer */
#define FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY (3UL) /* waiting for replay to reach the final vote */
#define FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT  (4UL) /* waiting for the tower tile to adopt */
#define FD_FAILOVER_ACTION_PROMOTE_SWITCH      (5UL) /* waiting for the staked key to be installed */
#define FD_FAILOVER_ACTION_REJECT              (6UL) /* standing down, telling the peer why */
#define FD_FAILOVER_ACTION_FIRST_USE_WAIT      (7UL) /* waiting for the peer's stand-down */
#define FD_FAILOVER_ACTION_CONFIRM_WAIT_QUERY  (8UL) /* proving the installed junk key */
#define FD_FAILOVER_ACTION_CLEAR_WAIT_QUERY    (9UL) /* proving the installed key matches the record before clearing stuck */
#define FD_FAILOVER_ACTION_CNT                 (10UL)

/* apply_control answers with this when the command's answer waits on the
   admin tile.  It never leaves the tile, the parked bus request is
   answered from the controller when the wait ends. */
#define FD_FAILOVER_TILE_RESULT_DEFERRED (ULONG_MAX)

/* One pool peer, its session and what it last told us. */
struct fd_failover_peer {
  fd_failover_channel_t * channel;
  ulong                   member_idx;    /* position in the member list */
  int                     dial;          /* listed after us, so we dial it */
  fd_failover_status_t    status;        /* last STATUS from this peer */
  int                     status_valid;
  long                    status_time;
  ulong                   channel_state;      /* last seen session state, for edge detection */
  int                     session_setup;      /* silence window sized for this session */
  long                    effective_interval; /* slower of the two cadences, nanos */
  long                    last_status;
  int                     status_sent;   /* sent in this session */
  long                    rtt_nanos;
  ulong                   peer_sent_at;  /* sent_at of the newest peer STATUS, 0 if none */
  long                    peer_recv_at;  /* our clock when it arrived */

  fd_failover_consensus_cache_t consensus;       /* this peer's streamed tower, dropped on a session edge */
  fd_failover_consensus_cache_t consensus_floor; /* the highest tower ever streamed, kept across reconnects for the final tower check */
  ulong                         lag_slots;
  int                           cs_sent;   /* our latest tower reached this peer */
};

typedef struct fd_failover_peer fd_failover_peer_t;

struct fd_failover_tile_ctx {
  uchar               identity_pubkey[ 32UL ];
  ulong               role;
  fd_failover_hello_t hello;

  /* Controller state.  state is what is in the role file, action is what we
     are doing right now.  We always write the file before acting on a new
     state. */
  ulong                        state;
  ulong                        action;
  ulong                        action_term;
  int                          paused;
  int                          stuck;         /* a transition failed, shown to the operator */
  ulong                        switch_overdue_cnt; /* overdue switches, counted for the metric */
  ulong                        tower_rollback_cnt; /* confirmations whose final tower rolled back the streamed one */
  ulong                        identity_mismatch_cnt; /* clear found the installed key disagreeing with the record */
  ulong                        deadline_slot; /* replay slot at which this attempt aborts */
  long                         deadline_nanos; /* monotonic time at which it aborts, LONG_MAX when unarmed */
  int                          accept_peer_requests;
  ulong                        min_slots_to_leader;
  ulong                        deadline_slots;
  ulong                        catchup_gap_limit;

  /* The demotion confirmation, either the one we still have to send to the
     peer or the one we received from it.  We only send ours once the key
     switch is done. */
  fd_failover_demoted_record_t demoted_record;
  int                          demoted_valid;
  int                          demoted_historical;
  int                          demoted_sent;
  int                          send_demoted;
  ulong                        demoted_accept_term; /* a confirmation at this term may be replayed */

  /* The last promotion outcome we sent, kept so a peer that missed the ack
     or the refusal gets the same answer again when it resends the
     confirmation instead of the resend being dropped. */
  ulong                        reply_dem_term;  /* confirmation term it answers, ULONG_MAX for none */
  ushort                       reply_type;      /* PROMOTE_ACK or PROMOTE_REJECTED */
  ulong                        reply_out_term;  /* term to echo back in the reply */
  uchar                        reply_reason;    /* refusal reason, for a rejected reply */
  int                          reply_owed;      /* the reply could not be queued yet, the slot was busy */

  /* The one control message waiting to go out, if any. */
  ushort                       pending_type;
  ushort                       pending_sz;
  int                          pending_valid;
  ulong                        pending_session; /* handoff requests and answers belong to one session */
  uchar                        pending[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];

  /* The tower we will adopt when we get promoted. */
  uchar                        adopt_state[ FD_FAILOVER_TOWER_STATE_MAX ];
  ulong                        adopt_state_len;
  ulong                        adopt_expected_id;
  uchar                        reject_reason;
  fd_failover_handoff_req_t    handoff_req;    /* the request awaiting an answer */
  int                          handoff_pending;
  ulong                        handoff_session;
  ulong                        handoff_deadline_slot;
  long                         handoff_deadline;
  uchar                        handoff_code;   /* the peer's answer to it */
  uchar                        handoff_reason;
  ulong                        handoff_term;
  fd_stem_context_t *          step_stem; /* valid for the duration of after_credit */

  /* First use is authorized once at boot on member zero.  The grant is
     tied to a nonce and peer boot, and is never recovered from disk. */
  int                          first_use_authorized;
  int                          first_use_tried;
  int                          first_use_pending;
  int                          first_use_sent;
  int                          first_use_promoting;
  ulong                        first_use_nonce;
  ulong                        first_use_peer_boot;
  fd_failover_reclaim_t         first_use_req;
  long                         claim_deadline;
  fd_failover_reclaim_t         confirm_req;
  ulong                        confirm_peer_boot;
  int                          confirm_given;
  fd_failover_confirm_t         confirm_last;
  ulong                        confirm_last_boot;
  fd_failover_confirm_t         confirm_reply;
  int                          confirm_owed;

  /* The role file and its descriptors.  A role change is written here
     before it takes effect. */
  int                     role_dir_fd;
  int                     role_file_fd;   /* reserved for each temporary file */
  int                     role_sandboxed; /* the reserved number is fixed by seccomp */
  fd_failover_role_file_t role_file;

  ulong              member_cnt;
  ulong              self_idx;
  ulong              peer_cnt;
  fd_failover_peer_t peers[ FD_FAILOVER_TILE_PEER_MAX ];

  long  status_interval;
  ulong status_interval_millis;
  ulong peer_silence_intervals;
  ulong replication_lag_limit;

  uchar rx[ FD_FAILOVER_PAYLOAD_MAX ];

  /* The admin tile forwards operator commands over the bus and waits for
     one response frame per request. */
  ulong                 admin_in_idx;
  fd_wksp_t *           admin_in_mem;
  ulong                 admin_in_chunk0;
  ulong                 admin_in_wmark;
  ulong                 admin_out_idx;
  fd_wksp_t *           admin_out_mem;
  ulong                 admin_out_chunk0;
  ulong                 admin_out_wmark;
  ulong                 admin_out_chunk;
  fd_failover_bus_msg_t bus_req;
  ulong                 bus_req_sig;
  int                   bus_req_fresh;
  int                   clear_parked; /* a clear is waiting on the admin tile, its answer goes out from the controller */
  ulong                 clear_nonce;

  /* State of the identity switch we asked the admin tile for.  It selects
     a key preloaded by the signing tile, and success means the old key is
     gone from every tile's active identity. */
  ulong                     switch_request_id;
  ulong                     switch_pending_key; /* FD_FAILOVER_SWITCH_KEY_*, or CNT when idle */
  fd_failover_switch_resp_t switch_result;
  fd_failover_switch_resp_t switch_response; /* uncommitted input frame */
  ulong                     switch_answer_nonce; /* nonce of the frame being consumed */
  ulong                     switch_result_id;
  int                       switch_result_fresh;
  int                       switch_overdue;      /* the switch in flight passed its deadline, we still wait for it */
  ulong                     switch_query_id;
  int                       switch_query_pending;
  fd_failover_switch_resp_t  switch_state;
  ulong                     switch_state_nonce;
  int                       switch_state_fresh;

  /* Adoption request to the tower tile and its answer. */
  ulong                   adopt_out_idx;
  fd_wksp_t *             adopt_out_mem;
  ulong                   adopt_out_chunk0;
  ulong                   adopt_out_wmark;
  ulong                   adopt_out_chunk;
  ulong                   adopt_request_id;
  ulong                   adopt_in_idx;
  fd_wksp_t *             adopt_in_mem;
  ulong                   adopt_in_chunk0;
  ulong                   adopt_in_wmark;
  fd_tower_adopt_result_t adopt_result;
  ulong                   adopt_result_id;
  int                     adopt_result_fresh;

  ulong       tower_in_idx;
  fd_wksp_t * tower_in_mem;
  ulong       tower_in_chunk0;
  ulong       tower_in_wmark;

  /* Replay's reset message holds the cluster tip, its catch-up latch
     and the next leader slot, and its became-leader message marks the
     start of our own leader window.  Together they feed the readiness
     checks that the tower stream alone cannot. */
  ulong          replay_in_idx;
  fd_wksp_t *    replay_in_mem;
  ulong          replay_in_chunk0;
  ulong          replay_in_wmark;
  fd_poh_reset_t reset;
  ulong          turbine_slot;     /* highest cluster tip seen, SLOT_NULL before any */
  int            replay_caught_up; /* replay's one way boot latch */
  ulong          next_leader_slot; /* from the last reset, SLOT_NULL when unknown */
  int            is_leader;        /* set on became-leader, cleared by the first reset with a real next leader slot */

  fd_tower_slot_done_t slot_done;
  ulong                slot_done_seq;
  int                  slot_done_fresh;
  ulong                tower_seen_seq; /* seq of the last tower_out frag taken in, ULONG_MAX before any */
  int                  tower_gap;      /* a tower_out frag was skipped since the cached tower was built */

  ulong replay_slot;
  ulong root_slot;
  ulong last_vote_slot;

  /* Latest locally produced tower and its delivery state. */
  uchar cs_buf[ sizeof(fd_failover_consensus_state_t)+FD_FAILOVER_TOWER_STATE_MAX ];
  ulong cs_sz;
  int   cs_valid;
};

typedef struct fd_failover_tile_ctx fd_failover_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return fd_ulong_max( alignof(fd_failover_tile_ctx_t), fd_failover_channel_align() );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong peer_cnt = fd_ulong_sat_sub( tile->failov.member_cnt, 1UL );
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_failover_tile_ctx_t), sizeof(fd_failover_tile_ctx_t) );
  for( ulong i=0UL; i<peer_cnt; i++ ) {
    l = FD_LAYOUT_APPEND( l, fd_failover_channel_align(), fd_failover_channel_footprint() );
  }
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static long
duration_nanos( ulong count,
                ulong nanos_per_unit ) {
  return (long)fd_ulong_min( fd_ulong_sat_mul( count, nanos_per_unit ),
                             (ulong)LONG_MAX );
}

/* pool_layout finds this machine in the member list by its junk key and
   lays out one peer per other member.  A member dials everyone listed
   after it and accepts from everyone listed before it.  Returns -1 when
   the junk key is missing from the list or listed twice. */
static int
pool_layout( fd_failover_tile_ctx_t * ctx,
             fd_topo_tile_t const *   tile,
             uchar const *            junk_pubkey ) {
  ctx->member_cnt = tile->failov.member_cnt;
  ctx->self_idx   = ULONG_MAX;
  for( ulong i=0UL; i<ctx->member_cnt; i++ ) {
    if( !fd_memeq( tile->failov.member_junk_pubkey[ i ], junk_pubkey, 32UL ) ) continue;
    if( FD_UNLIKELY( ctx->self_idx!=ULONG_MAX ) ) return -1;
    ctx->self_idx = i;
  }
  if( FD_UNLIKELY( ctx->self_idx==ULONG_MAX ) ) return -1;
  ctx->peer_cnt = 0UL;
  for( ulong i=0UL; i<ctx->member_cnt; i++ ) {
    if( i==ctx->self_idx ) continue;
    fd_failover_peer_t * peer = &ctx->peers[ ctx->peer_cnt++ ];
    peer->member_idx              = i;
    peer->dial                    = ( i>ctx->self_idx );
    peer->lag_slots               = FD_FAILOVER_SLOT_NULL;
    peer->status.replay_slot      = FD_FAILOVER_SLOT_NULL;
    peer->status.turbine_slot     = FD_FAILOVER_SLOT_NULL;
    peer->status.last_vote_slot   = FD_FAILOVER_SLOT_NULL;
    peer->status.root_slot        = FD_FAILOVER_SLOT_NULL;
    peer->status.next_leader_slot = FD_FAILOVER_SLOT_NULL;
  }
  return 0;
}

/* pool_listen_fd returns the listener socket, or -1 when this member only
   dials or has not bound yet. */
static int
pool_listen_fd( fd_failover_tile_ctx_t const * ctx ) {
  for( ulong i=0UL; i<ctx->peer_cnt; i++ ) {
    fd_failover_peer_t const * peer = &ctx->peers[ i ];
    if( peer->dial || !peer->channel ) continue;
    int fd = fd_failover_channel_listen_fd( peer->channel );
    if( fd!=-1 ) return fd;
  }
  return -1;
}

/* role_dir_open creates and opens `<base>/failover`, owned by the
   validator user with no access for anyone else, and removes a temporary
   file left by a crash. */
static int
role_dir_open( char const * base_path,
               uint         owner_uid,
               uint         owner_gid ) {
  int base_fd = open( base_path, O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW );
  if( FD_UNLIKELY( base_fd<0 ) )
    FD_LOG_ERR(( "open(%s) failed (%i-%s)", base_path, errno, fd_io_strerror( errno ) ));

  if( FD_UNLIKELY( mkdirat( base_fd, "failover", 0700 ) && errno!=EEXIST ) )
    FD_LOG_ERR(( "mkdirat(failover) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  int dir_fd = openat( base_fd, "failover", O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW );
  if( FD_UNLIKELY( dir_fd<0 ) )
    FD_LOG_ERR(( "openat(failover) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  struct stat st;
  if( FD_UNLIKELY( fstat( dir_fd, &st ) ) )
    FD_LOG_ERR(( "fstat(failover) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( (st.st_uid!=(uid_t)owner_uid || st.st_gid!=(gid_t)owner_gid) &&
                   fchown( dir_fd, (uid_t)owner_uid, (gid_t)owner_gid ) ) )
    FD_LOG_ERR(( "fchown(failover) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( (st.st_mode & 07777U)!=0700U && fchmod( dir_fd, 0700 ) ) )
    FD_LOG_ERR(( "fchmod(failover) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( unlinkat( dir_fd, FD_FAILOVER_ROLE_TMP_PATH, 0 ) && errno!=ENOENT ) )
    FD_LOG_ERR(( "unlinkat(%s) failed (%i-%s)", FD_FAILOVER_ROLE_TMP_PATH, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( fsync( dir_fd ) ) )
    FD_LOG_ERR(( "fsync(failover) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( fsync( base_fd ) ) )
    FD_LOG_ERR(( "fsync(%s) failed (%i-%s)", base_path, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( base_fd ) ) )
    FD_LOG_ERR(( "close(%s) failed (%i-%s)", base_path, errno, fd_io_strerror( errno ) ));
  return dir_fd;
}

/* role_file_read loads the role file into ctx, or leaves the default
   standby record at term zero when the file is missing, unreadable or
   for another staked identity.  Returns zero or an errno value. */
static int
role_file_read( fd_failover_tile_ctx_t * ctx ) {
  fd_memset( &ctx->role_file, 0, sizeof(ctx->role_file) );
  ctx->role_file.version = FD_FAILOVER_ROLE_VERSION;
  ctx->role_file.role    = (uchar)FD_FAILOVER_STATE_STANDBY;
  fd_memcpy( ctx->role_file.staked_pubkey, ctx->hello.staked_pubkey, 32UL );

  fd_failover_role_file_t rf;
  int err = fd_failover_role_load( ctx->role_dir_fd, &rf );
  if( FD_LIKELY( !err ) ) {
    if( FD_UNLIKELY( !fd_memeq( rf.staked_pubkey, ctx->role_file.staked_pubkey, 32UL ) ) ) {
      FD_LOG_WARNING(( "%s is for a different staked identity, booting as a spare", FD_FAILOVER_ROLE_PATH ));
      return EPROTO;
    }
    ctx->role_file  = rf;
    ctx->hello.term = rf.term;
    return 0;
  }
  if( FD_UNLIKELY( err!=ENOENT ) ) {
    FD_LOG_WARNING(( "%s is unreadable (%i-%s), booting as a spare", FD_FAILOVER_ROLE_PATH, err, fd_io_strerror( err ) ));
  }
  return err ? err : 0;
}

/* An old or invalid role file is evidence against first use even though
   ordinary passive boot tolerates it.  A spent term cannot be rearmed. */
static int
first_use_check( fd_failover_tile_ctx_t const * ctx,
                 char const *                  pubkey,
                 int                           role_err,
                 int                           demoted_err ) {
  uchar named[ 32 ];
  return fd_base58_decode_32( pubkey, named ) &&
         fd_memeq( named, ctx->hello.staked_pubkey, 32UL ) &&
         ctx->member_cnt==2UL && ctx->self_idx==0UL &&
         ( !role_err || role_err==ENOENT ) &&
         ctx->role_file.role==FD_FAILOVER_STATE_STANDBY &&
         !ctx->role_file.term && demoted_err==ENOENT;
}

/* role_file_write stores the record before the new state takes effect.
   A write failure stops the tile.  Only the write at boot passes an
   owner, it runs before the uid switch, see fd_failover_role_store. */
static void
role_file_write( fd_failover_tile_ctx_t * ctx,
                 uint                     owner_uid,
                 uint                     owner_gid ) {
  int err = fd_failover_role_store( ctx->role_dir_fd, ctx->role_file_fd, ctx->role_sandboxed, owner_uid, owner_gid, &ctx->role_file );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "could not write %s (%i-%s)", FD_FAILOVER_ROLE_PATH, err, fd_io_strerror( err ) ));
  }
}

/* Write or delete the confirmation on disk to match what we have in
   memory. */
static void
demoted_write( fd_failover_tile_ctx_t * ctx ) {
  int err = fd_failover_demoted_store( ctx->role_dir_fd, ctx->role_file_fd, ctx->role_sandboxed, UINT_MAX, UINT_MAX, &ctx->demoted_record );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "could not write %s (%i-%s)", FD_FAILOVER_DEMOTED_PATH, err, fd_io_strerror( err ) ));
  }
}

static void
demoted_remove( fd_failover_tile_ctx_t * ctx ) {
  if( FD_UNLIKELY( unlinkat( ctx->role_dir_fd, FD_FAILOVER_DEMOTED_PATH, 0 ) && errno!=ENOENT ) ) {
    FD_LOG_ERR(( "unlinkat(%s) failed (%i-%s)", FD_FAILOVER_DEMOTED_PATH, errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( fsync( ctx->role_dir_fd ) ) ) {
    FD_LOG_ERR(( "fsync(failover directory) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  ctx->demoted_valid      = 0;
  ctx->demoted_historical = 0;
}

/* Update the role and term every channel puts in its HELLO.  The peer
   checks each frame against the HELLO it paired on, so if we leave a
   stale one in place the peer rejects our status and drops the session. */
static void
advertise( fd_failover_tile_ctx_t * ctx ) {
  for( ulong i=0UL; i<ctx->peer_cnt; i++ ) {
    if( FD_LIKELY( ctx->peers[ i ].channel ) ) {
      fd_failover_channel_set_role( ctx->peers[ i ].channel, ctx->role, ctx->hello.term );
    }
  }
}

/* Save the new state and term to the role file before acting on them.
   The term also goes into our HELLO so a peer pairing later sees it. */
static void
persist( fd_failover_tile_ctx_t * ctx,
         ulong                    state,
         ulong                    term ) {
  ctx->role_file.role   = (uchar)state;
  ctx->role_file.term   = term;
  ctx->role_file.paused = (uchar)!!ctx->paused;
  fd_memcpy( ctx->role_file.staked_pubkey, ctx->hello.staked_pubkey, 32UL );
  role_file_write( ctx, UINT_MAX, UINT_MAX );
  ctx->state      = state;
  ctx->hello.term = term;
  advertise( ctx );
}

/* Change the role we advertise.  This drops the sessions, since the peer
   paired on a HELLO with the old role. */
static void
set_role( fd_failover_tile_ctx_t * ctx,
          ulong                    role,
          long                     now ) {
  int changed = ctx->role!=role;
  ctx->role       = role;
  ctx->hello.role = (uchar)role;
  advertise( ctx );
  if( FD_UNLIKELY( !changed ) ) return;
  for( ulong i=0UL; i<ctx->peer_cnt; i++ ) fd_failover_channel_hangup( ctx->peers[ i ].channel, now );
}

/* Give up on the attempt once replay passes this slot, so a transition
   cannot hang forever.  A clock bound runs beside it, derived from the
   same slot count, so a stalled replay cannot hold a transition open
   forever either.  Either bound ending the wait is enough, since a wait
   only ever ends toward not voting. */
static long
deadline_limit_nanos( fd_failover_tile_ctx_t const * ctx ) {
  ulong nanos = fd_ulong_sat_mul( ctx->deadline_slots, FD_FAILOVER_TILE_DEADLINE_SLOT_NANOS );
  nanos = fd_ulong_max( nanos, FD_FAILOVER_TILE_DEADLINE_NANOS_MIN );
  nanos = fd_ulong_min( nanos, FD_FAILOVER_TILE_DEADLINE_NANOS_MAX );
  return (long)nanos;
}

static void
deadline_start( fd_failover_tile_ctx_t * ctx,
                ulong                    slots,
                long                     now ) {
  ctx->deadline_slot = ( ctx->replay_slot==FD_FAILOVER_SLOT_NULL )
                     ? FD_FAILOVER_SLOT_NULL
                     : fd_ulong_sat_add( ctx->replay_slot, slots );
  ctx->deadline_nanos = fd_long_sat_add( now, deadline_limit_nanos( ctx ) );
}

/* If we have not seen a replay slot yet, for example right after
   restarting in the middle of a handoff, arm the slot bound when the
   first one arrives.  The clock bound needs no slot, so it is armed at
   once if it is not already. */
static void
deadline_arm( fd_failover_tile_ctx_t * ctx,
              ulong                    slots,
              long                     now ) {
  if( FD_UNLIKELY( ctx->deadline_nanos==LONG_MAX ) ) {
    ctx->deadline_nanos = fd_long_sat_add( now, deadline_limit_nanos( ctx ) );
  }
  if( FD_LIKELY( ctx->deadline_slot!=FD_FAILOVER_SLOT_NULL ) ) return;
  if( FD_UNLIKELY( ctx->replay_slot==FD_FAILOVER_SLOT_NULL ) ) return;
  ctx->deadline_slot = fd_ulong_sat_add( ctx->replay_slot, slots );
}

static int
deadline_expired( fd_failover_tile_ctx_t const * ctx,
                  long                           now ) {
  int slot_expired = ctx->deadline_slot!=FD_FAILOVER_SLOT_NULL &&
                     ctx->replay_slot  !=FD_FAILOVER_SLOT_NULL &&
                     ctx->replay_slot>ctx->deadline_slot;
  int wall_expired = ctx->deadline_nanos!=LONG_MAX && now>=ctx->deadline_nanos;
  return slot_expired || wall_expired;
}

/* A switch in flight is never abandoned, its outcome is unknown until the
   admin tile answers.  We warn once and flag stuck. */
static void
switch_overdue( fd_failover_tile_ctx_t * ctx ) {
  ctx->stuck = 1;
  if( FD_LIKELY( ctx->switch_overdue ) ) return;
  ctx->switch_overdue = 1;
  ctx->switch_overdue_cnt++;
  FD_LOG_WARNING(( "the identity switch at term %lu has not answered inside its deadline, waiting for it", ctx->action_term ));
}

/* Only one control message can be outstanding at a time.  Status and
   tower frames are not affected. */
static int
queue_control( fd_failover_tile_ctx_t * ctx,
               ushort                   type,
               void const *             payload,
               ulong                    payload_sz ) {
  if( FD_UNLIKELY( ctx->pending_valid || payload_sz>sizeof(ctx->pending) ) ) return -1;
  ctx->pending_type  = type;
  ctx->pending_sz    = (ushort)payload_sz;
  ctx->pending_valid = 1;
  fd_memcpy( ctx->pending, payload, payload_sz );
  if( FD_UNLIKELY( type==(ushort)FD_FAILOVER_MSG_HANDOFF_REQ || type==(ushort)FD_FAILOVER_MSG_HANDOFF_RESP ) )
    ctx->pending_session = fd_failover_channel_metrics( ctx->peers[ 0 ].channel )->paired_cnt;
  return 0;
}

/* queue_reply queues the last promotion outcome from the cache.  If the
   control slot is busy the outcome stays owed and step_controller tries
   again once the slot drains, the peer waits on it and sends its
   confirmation only once per session, so nothing else would ask for it. */
static void
queue_reply( fd_failover_tile_ctx_t * ctx ) {
  int err;
  if( ctx->reply_type==(ushort)FD_FAILOVER_MSG_PROMOTE_ACK ) {
    fd_failover_promote_ack_t ack = { .term=ctx->reply_out_term };
    err = queue_control( ctx, (ushort)FD_FAILOVER_MSG_PROMOTE_ACK, &ack, sizeof(ack) );
  } else {
    fd_failover_promote_rejected_t rej = { .term=ctx->reply_out_term, .reason=ctx->reply_reason };
    err = queue_control( ctx, (ushort)FD_FAILOVER_MSG_PROMOTE_REJECTED, &rej, sizeof(rej) );
  }
  ctx->reply_owed = !!err;
}

static void
pending_flush( fd_failover_tile_ctx_t * ctx,
               fd_failover_peer_t *     peer,
               long                     now ) {
  if( FD_LIKELY( !ctx->pending_valid ) ) return;
  /* These messages describe one request on this session.  Replaying an
     old answer after reconnect could match a new request at the same term. */
  if( FD_UNLIKELY( ( ctx->pending_type==(ushort)FD_FAILOVER_MSG_HANDOFF_REQ ||
                     ctx->pending_type==(ushort)FD_FAILOVER_MSG_HANDOFF_RESP ) &&
                   ( fd_failover_channel_state( peer->channel )!=FD_FAILOVER_SESSION_PAIRED ||
                     fd_failover_channel_metrics( peer->channel )->paired_cnt!=ctx->pending_session ) ) ) {
    ctx->pending_valid = 0;
    return;
  }
  if( FD_UNLIKELY( fd_failover_channel_state( peer->channel )!=FD_FAILOVER_SESSION_PAIRED ||
                   fd_failover_channel_tx_pending( peer->channel ) ) ) return;
  if( FD_LIKELY( !fd_failover_channel_send( peer->channel, now, ctx->pending_type, ctx->pending, ctx->pending_sz ) ) ) {
    if( FD_UNLIKELY( ctx->pending_type==(ushort)FD_FAILOVER_MSG_DEMOTED ) ) ctx->demoted_sent = 1;
    if( FD_UNLIKELY( ctx->pending_type==(ushort)FD_FAILOVER_MSG_RECLAIM ) ) ctx->first_use_sent = 1;
    ctx->pending_valid = 0;
  }
}

static void
restore_records( fd_failover_tile_ctx_t * ctx,
                 int                      role_err,
                 int                      demoted_err,
                 uint                     owner_uid,
                 uint                     owner_gid ) {
  ulong saved = (ulong)ctx->role_file.role;
  ctx->state               = fd_failover_state_boot( saved );
  ctx->action              = FD_FAILOVER_ACTION_IDLE;
  ctx->paused              = !!ctx->role_file.paused;
  ctx->action_term         = ctx->role_file.term;
  ctx->deadline_slot       = FD_FAILOVER_SLOT_NULL;
  ctx->deadline_nanos      = LONG_MAX;
  ctx->demoted_accept_term = ULONG_MAX;
  ctx->reply_dem_term      = ULONG_MAX;
  ctx->reply_owed          = 0;
  ctx->handoff_code        = (uchar)FD_FAILOVER_HANDOFF_CODE_CNT;

  if( FD_UNLIKELY( saved==FD_FAILOVER_STATE_PROMOTING ||
                   saved==FD_FAILOVER_STATE_ACTIVE || saved==FD_FAILOVER_STATE_RECLAIMING ) )
    ctx->demoted_accept_term = ctx->role_file.term;

  if( FD_UNLIKELY( !role_err && !demoted_err &&
                   ctx->demoted_record.source==FD_FAILOVER_DEMOTED_SOURCE_UNKNOWN &&
                   ctx->demoted_record.demoted.term==ctx->role_file.term &&
                   (saved==FD_FAILOVER_STATE_PROMOTING || saved==FD_FAILOVER_STATE_DEMOTING) ) ) {
    ctx->demoted_record.source = saved==FD_FAILOVER_STATE_PROMOTING
                                 ? FD_FAILOVER_DEMOTED_SOURCE_PEER : FD_FAILOVER_DEMOTED_SOURCE_LOCAL;
    int err = fd_failover_demoted_store( ctx->role_dir_fd, ctx->role_file_fd, ctx->role_sandboxed,
                                        owner_uid, owner_gid, &ctx->demoted_record );
    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "could not preserve demotion record source (%i-%s)", err, fd_io_strerror( err ) ));
  }

  ctx->role       = FD_FAILOVER_ROLE_STANDBY;
  ctx->hello.role = (uchar)ctx->role;
  ctx->hello.term = ctx->role_file.term;
  if( FD_UNLIKELY( role_err || ctx->state!=saved ) ) {
    ctx->role_file.role = (uchar)ctx->state;
    role_file_write( ctx, owner_uid, owner_gid );
  }

  if( FD_LIKELY( !demoted_err ) ) {
    ctx->demoted_valid = 1;
    if( FD_UNLIKELY( ctx->demoted_record.source==FD_FAILOVER_DEMOTED_SOURCE_UNKNOWN ) ) {
      ctx->demoted_historical = 1;
      ctx->stuck = 1;
      FD_LOG_WARNING(( "%s has no unambiguous source, preserving it without resending or permitting promotion", FD_FAILOVER_DEMOTED_PATH ));
    } else if( FD_LIKELY( !role_err && ctx->demoted_record.demoted.term==ctx->role_file.term &&
                         ctx->state==FD_FAILOVER_STATE_STANDBY ) ) {
      if( ctx->demoted_record.source==FD_FAILOVER_DEMOTED_SOURCE_LOCAL ) {
        ctx->last_vote_slot = ctx->demoted_record.demoted.last_vote_slot;
        ctx->send_demoted   = 1;
        ctx->action        = FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK;
        ctx->action_term   = ctx->demoted_record.demoted.term;
        ulong state_len = (ulong)ctx->demoted_record.demoted.state_len;
        uchar payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];
        fd_memcpy( payload, &ctx->demoted_record.demoted, sizeof(fd_failover_demoted_t) );
        fd_memcpy( payload+sizeof(fd_failover_demoted_t), ctx->demoted_record.state, state_len );
        FD_TEST( !queue_control( ctx, (ushort)FD_FAILOVER_MSG_DEMOTED, payload, sizeof(fd_failover_demoted_t)+state_len ) );
      } else {
        ctx->demoted_accept_term = ctx->role_file.term;
      }
    } else {
      /* This includes a received record persisted just before the role
         update.  Keep the evidence, but require a fresh peer exchange
         before it may authorize another transition. */
      ctx->demoted_historical = 1;
    }
  } else if( FD_UNLIKELY( demoted_err==EPROTO ) ) {
    ctx->stuck = 1;
    FD_LOG_WARNING(( "%s is invalid, preserving it and remaining passive", FD_FAILOVER_DEMOTED_PATH ));
  } else if( FD_UNLIKELY( demoted_err!=ENOENT ) ) {
    FD_LOG_ERR(( "reading %s failed (%i-%s)", FD_FAILOVER_DEMOTED_PATH, demoted_err, fd_io_strerror( demoted_err ) ));
  }
}

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_failover_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_failover_tile_ctx_t), sizeof(fd_failover_tile_ctx_t) );
  fd_memset( ctx, 0, sizeof(fd_failover_tile_ctx_t) );
  ctx->role_dir_fd        = -1;
  ctx->role_file_fd       = -1;
  ctx->switch_pending_key = FD_FAILOVER_SWITCH_KEY_CNT;
  ctx->replay_slot        = FD_FAILOVER_SLOT_NULL;
  ctx->root_slot          = FD_FAILOVER_SLOT_NULL;
  ctx->last_vote_slot     = FD_FAILOVER_SLOT_NULL;
  ctx->turbine_slot       = FD_FAILOVER_SLOT_NULL;
  ctx->next_leader_slot   = FD_FAILOVER_SLOT_NULL;
  ctx->tower_seen_seq     = ULONG_MAX;

  if( FD_UNLIKELY( !strcmp( tile->failov.identity_key_path, "" ) ) )
    FD_LOG_ERR(( "identity_key_path not set" ));

  /* Only public keys are read here, the junk private key below is the
     one secret this tile keeps. */
  uchar const * identity_pubkey = fd_keyload_load( tile->failov.identity_key_path, 1 );
  fd_memcpy( ctx->identity_pubkey, identity_pubkey, 32UL );
  fd_keyload_unload( identity_pubkey, 1 );

  ctx->hello.version = (ushort)FD_FAILOVER_VERSION;
  uchar const * junk_pubkey = fd_keyload_load( tile->failov.junk_identity_path, 1 );
  fd_memcpy( ctx->hello.junk_pubkey, junk_pubkey, 32UL );
  fd_keyload_unload( junk_pubkey, 1 );
  uchar const * staked_pubkey = fd_keyload_load( tile->failov.staked_identity_path, 1 );
  fd_memcpy( ctx->hello.staked_pubkey, staked_pubkey, 32UL );
  fd_keyload_unload( staked_pubkey, 1 );

  if( FD_UNLIKELY( tile->failov.member_cnt<2UL ) ) {
    FD_LOG_ERR(( "[failover.members] lists %lu machines, a pool needs this one and at least one spare", tile->failov.member_cnt ));
  }
  if( FD_UNLIKELY( pool_layout( ctx, tile, ctx->hello.junk_pubkey ) ) ) {
    FD_BASE58_ENCODE_32_BYTES( ctx->hello.junk_pubkey, junk_b58 );
    FD_LOG_ERR(( "this machine's junk identity %s must appear exactly once in [failover.member_junk_pubkeys]", junk_b58 ));
  }

  /* Every failover machine restarts as a spare under its junk identity,
     whatever it was before, so the identity the validator loaded has to
     be this machine's junk key. */
  if( FD_UNLIKELY( !fd_memeq( ctx->identity_pubkey, ctx->hello.junk_pubkey, 32UL ) ) ) {
    FD_LOG_ERR(( "a failover machine must boot under [failover.junk_identity_path]" ));
  }
  uchar const * vote_account = fd_keyload_load( tile->failov.vote_account_path, 1 );
  fd_memcpy( ctx->hello.vote_account, vote_account, 32UL );
  fd_keyload_unload( vote_account, 1 );
  fd_memcpy( ctx->hello.commit, fd_commit_ref_cstr,
             fd_ulong_min( sizeof(ctx->hello.commit), strlen( fd_commit_ref_cstr ) ) );
  ctx->hello.cfg_hash = tile->failov.cfg_hash;
  ctx->hello.status_interval_millis = (uint)fd_ulong_min( tile->failov.status_interval_millis, UINT_MAX );

  /* The role file sits beside the tower file under the base path and is
     opened before the sandbox, which allows no further opens. */
  ctx->role_dir_fd = role_dir_open( tile->failov.base_path, tile->failov.target_uid, tile->failov.target_gid );

  /* The store path reopens this descriptor number, so reserve it now.
     Under seccomp openat must return the same number, which holds only
     if no lower number is free, and the launcher closes stdin before
     starting tiles.  Fail at boot rather than at the first transition. */
  ctx->role_file_fd   = fcntl( ctx->role_dir_fd, F_DUPFD_CLOEXEC, 0 );
  if( FD_UNLIKELY( -1==ctx->role_file_fd ) )
    FD_LOG_ERR(( "fcntl(F_DUPFD_CLOEXEC) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  ctx->role_sandboxed = tile->failov.role_file_sandboxed;
  if( FD_UNLIKELY( ctx->role_sandboxed && ctx->role_file_fd!=0 ) ) {
    FD_LOG_ERR(( "reserved role file descriptor is %i, expected 0: another descriptor was open when the failover tile started", ctx->role_file_fd ));
  }

  int role_err   = role_file_read( ctx );
  int demoted_err = fd_failover_demoted_load( ctx->role_dir_fd, &ctx->demoted_record );
  if( FD_UNLIKELY( tile->failov.failover_first_use[ 0 ] ) ) {
    if( FD_UNLIKELY( !first_use_check( ctx, tile->failov.failover_first_use, role_err, demoted_err ) ) )
      FD_LOG_ERR(( "--failover-first-use requires the pool's staked identity, member zero, a standby role at term zero or no role file, and no demotion record" ));
    ctx->first_use_authorized = 1;
    FD_LOG_NOTICE(( "first use armed, waiting for the paired standby peer to confirm standing down" ));
  }
  restore_records( ctx, role_err, demoted_err, tile->failov.target_uid, tile->failov.target_gid );
  FD_TEST( fd_rng_secure( &ctx->hello.boot_id, 8UL ) );
  ctx->first_use_nonce = ctx->hello.boot_id;

  /* One session object per peer, each pinned to that member's junk key.
     The junk keypair is loaded once and copied into every TLS context. */
  uchar const * junk_keypair = fd_keyload_load( tile->failov.junk_identity_path, 0 );
  ulong listen_cnt = 0UL;
  for( ulong i=0UL; i<ctx->peer_cnt; i++ ) {
    fd_failover_peer_t * peer = &ctx->peers[ i ];
    void * ch_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_failover_channel_align(), fd_failover_channel_footprint() );
    peer->channel = fd_failover_channel_join( fd_failover_channel_new( ch_mem ) );
    FD_TEST( peer->channel );
    int tls_err = fd_failover_channel_set_identity( peer->channel, junk_keypair, tile->failov.member_junk_pubkey[ peer->member_idx ], &ctx->hello );
    if( FD_UNLIKELY( tls_err ) ) {
      FD_LOG_ERR(( "failover TLS initialization failed for member %lu, check the junk keypair and the member keys", peer->member_idx ));
    }
    listen_cnt += (ulong)!peer->dial;
  }
  fd_keyload_unload( junk_keypair, 0 );

  /* Every accepting peer would bind the same port today. */
  if( FD_UNLIKELY( listen_cnt>1UL ) ) {
    FD_LOG_ERR(( "a member accepts from at most one peer today, [failover.members] lists %lu before this machine", listen_cnt ));
  }
  for( ulong i=0UL; i<ctx->peer_cnt; i++ ) {
    fd_failover_peer_t * peer = &ctx->peers[ i ];
    if( peer->dial ) continue;
    /* Listeners bind here, the sandbox forbids bind once it is entered. */
    fd_failover_channel_init_listener( peer->channel, tile->failov.bind_addr, tile->failov.member[ ctx->self_idx ].port );
    fd_failover_channel_expect_peer( peer->channel, tile->failov.member[ peer->member_idx ].ip );
  }

  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, scratch_align() )==(ulong)scratch+scratch_footprint( tile ) );
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void *                   scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  fd_failover_tile_ctx_t * ctx     = (fd_failover_tile_ctx_t *)scratch;

  ctx->tower_in_idx  = ULONG_MAX;
  ctx->admin_in_idx  = ULONG_MAX;
  ctx->adopt_in_idx  = ULONG_MAX;
  ctx->replay_in_idx = ULONG_MAX;
  ctx->adopt_out_idx = fd_topo_find_tile_out_link( topo, tile, "failov_tower", 0UL );
  if( FD_LIKELY( ctx->adopt_out_idx!=ULONG_MAX ) ) {
    fd_topo_link_t const * link = &topo->links[ tile->out_link_id[ ctx->adopt_out_idx ] ];
    ctx->adopt_out_mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
    ctx->adopt_out_chunk0 = fd_dcache_compact_chunk0( ctx->adopt_out_mem, link->dcache );
    ctx->adopt_out_wmark  = fd_dcache_compact_wmark ( ctx->adopt_out_mem, link->dcache, link->mtu );
    ctx->adopt_out_chunk  = ctx->adopt_out_chunk0;
  }
  ctx->admin_out_idx = fd_topo_find_tile_out_link( topo, tile, "failov_admin", 0UL );
  if( FD_LIKELY( ctx->admin_out_idx!=ULONG_MAX ) ) {
    fd_topo_link_t const * link = &topo->links[ tile->out_link_id[ ctx->admin_out_idx ] ];
    ctx->admin_out_mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
    ctx->admin_out_chunk0 = fd_dcache_compact_chunk0( ctx->admin_out_mem, link->dcache );
    ctx->admin_out_wmark  = fd_dcache_compact_wmark ( ctx->admin_out_mem, link->dcache, link->mtu );
    ctx->admin_out_chunk  = ctx->admin_out_chunk0;
  }
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    if( FD_LIKELY( !strcmp( link->name, "tower_failov" ) ) ) {
      ctx->adopt_in_idx    = i;
      ctx->adopt_in_mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      ctx->adopt_in_chunk0 = fd_dcache_compact_chunk0( ctx->adopt_in_mem, link->dcache );
      ctx->adopt_in_wmark  = fd_dcache_compact_wmark ( ctx->adopt_in_mem, link->dcache, link->mtu );
      continue;
    }
    if( FD_LIKELY( !strcmp( link->name, "admin_failov" ) ) ) {
      ctx->admin_in_idx    = i;
      ctx->admin_in_mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      ctx->admin_in_chunk0 = fd_dcache_compact_chunk0( ctx->admin_in_mem, link->dcache );
      ctx->admin_in_wmark  = fd_dcache_compact_wmark ( ctx->admin_in_mem, link->dcache, link->mtu );
      continue;
    }
    if( FD_LIKELY( !strcmp( link->name, "tower_out" ) ) ) {
      ctx->tower_in_idx    = i;
      ctx->tower_in_mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      ctx->tower_in_chunk0 = fd_dcache_compact_chunk0( ctx->tower_in_mem, link->dcache );
      ctx->tower_in_wmark  = fd_dcache_compact_wmark( ctx->tower_in_mem, link->dcache, link->mtu );
      continue;
    }
    if( FD_LIKELY( !strcmp( link->name, "replay_out" ) ) ) {
      ctx->replay_in_idx    = i;
      ctx->replay_in_mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      ctx->replay_in_chunk0 = fd_dcache_compact_chunk0( ctx->replay_in_mem, link->dcache );
      ctx->replay_in_wmark  = fd_dcache_compact_wmark( ctx->replay_in_mem, link->dcache, link->mtu );
      continue;
    }
    FD_LOG_ERR(( "unexpected input link name %s", link->name ));
  }

  ctx->status_interval        = duration_nanos( tile->failov.status_interval_millis, 1000000UL );
  ctx->status_interval_millis = tile->failov.status_interval_millis;
  ctx->peer_silence_intervals = tile->failov.peer_silence_intervals;
  ctx->replication_lag_limit  = tile->failov.replication_lag_slots;
  ctx->accept_peer_requests   = tile->failov.accept_peer_requests;
  ctx->min_slots_to_leader    = tile->failov.min_slots_to_leader;
  ctx->deadline_slots         = tile->failov.deadline_slots;
  ctx->catchup_gap_limit      = tile->failov.catchup_gap_slots;

  for( ulong i=0UL; i<ctx->peer_cnt; i++ ) {
    fd_failover_peer_t * peer = &ctx->peers[ i ];
    fd_failover_channel_set_timing( peer->channel,
                                    FD_FAILOVER_CHANNEL_HELLO_TIMEOUT_NANOS,
                                    duration_nanos( fd_ulong_sat_mul( tile->failov.status_interval_millis,
                                                                      tile->failov.peer_silence_intervals ), 1000000UL ),
                                    duration_nanos( tile->failov.retry_backoff_min_millis, 1000000UL ),
                                    duration_nanos( tile->failov.retry_backoff_max_millis, 1000000UL ) );
    if( FD_LIKELY( peer->dial ) ) {
      fd_topo_ip_port_t const * member = &tile->failov.member[ peer->member_idx ];
      fd_failover_channel_init_dialer( peer->channel, member->ip, member->port );
    }
    peer->channel_state = fd_failover_channel_state( peer->channel );
  }
}

/* The peer echoes our STATUS timestamp together with how long it held
   it, so its cadence drops out of the round trip sample. */
static void
peer_rtt_sample( fd_failover_peer_t *         peer,
                 long                         now,
                 fd_failover_status_t const * status ) {
  if( FD_UNLIKELY( !status->echo_sent_at || status->echo_sent_at>(ulong)now ) ) return;
  ulong elapsed = (ulong)now-status->echo_sent_at;
  if( FD_UNLIKELY( status->echo_delay>elapsed || elapsed>FD_FAILOVER_TILE_RTT_MAX_NANOS ) ) return;
  long sample = (long)( elapsed-status->echo_delay );
  peer->rtt_nanos = peer->rtt_nanos
    ? peer->rtt_nanos+(sample-peer->rtt_nanos)/8L
    : sample;
}

static void
peer_update_lag( fd_failover_peer_t * peer ) {
  peer->lag_slots = fd_failover_replication_lag( peer->status_valid,
                                                 &peer->status,
                                                 fd_failover_channel_peer_hello( peer->channel )->boot_id,
                                                 &peer->consensus );
}

/* A status older than two intervals says nothing about the peer now.
   The valid flag alone only says one arrived on this session. */
static int
peer_status_fresh( fd_failover_tile_ctx_t const * ctx,
                   fd_failover_peer_t const *     peer,
                   long                           now ) {
  if( FD_UNLIKELY( !peer->status_valid || now<peer->status_time ) ) return 0;
  long interval = peer->effective_interval ? peer->effective_interval : ctx->status_interval;
  return fd_long_sat_sub( now, peer->status_time )<=fd_long_sat_add( interval, interval );
}

/* A session edge invalidates everything the old session told us. */
static void
peer_sync_channel_state( fd_failover_peer_t * peer ) {
  ulong state = fd_failover_channel_state( peer->channel );
  if( FD_LIKELY( state==peer->channel_state ) ) return;

  peer->channel_state      = state;
  peer->status_valid       = 0;
  peer->status_time        = 0L;
  peer->peer_sent_at       = 0UL;
  peer->session_setup      = 0;
  peer->rtt_nanos          = 0L;
  /* The streamed tower came over the session that just ended, so forget it
     along with the rest.  Otherwise we would measure replication lag
     against a stale copy. */
  fd_memset( &peer->consensus, 0, sizeof(peer->consensus) );
  if( FD_UNLIKELY( state==FD_FAILOVER_SESSION_PAIRED ) ) {
    peer->status_sent = 0;
    peer->cs_sent     = 0;
  }
  peer_update_lag( peer );
}

/* Turn the tower's vote transaction into the CONSENSUS_STATE frame every
   spare receives.  A malformed transaction is logged and skipped, the
   spares keep the previous tower. */
static void
prepare_consensus( fd_failover_tile_ctx_t *     ctx,
                   fd_tower_slot_done_t const * done ) {
  if( FD_UNLIKELY( !done->vote_txn_sz || done->vote_txn_sz>sizeof(done->vote_txn) ) ) {
    FD_LOG_WARNING(( "tower produced an invalid vote transaction size" ));
    return;
  }

  uchar txn_mem[ FD_TXN_MAX_SZ ] __attribute__((aligned(alignof(fd_txn_t))));
  fd_compact_tower_sync_serde_t serde;
  if( FD_UNLIKELY( !fd_txn_parse( done->vote_txn, done->vote_txn_sz, txn_mem, NULL ) ||
                   !fd_txn_parse_simple_vote( (fd_txn_t const *)txn_mem, done->vote_txn, &serde ) ) ) {
    FD_LOG_WARNING(( "tower produced an invalid vote transaction" ));
    return;
  }

  fd_tower_vote_t votes[ FD_TOWER_VOTE_MAX ];
  ulong vote_cnt;
  ulong root;
  if( FD_UNLIKELY( fd_compact_tower_sync_to_votes( &serde, votes, &vote_cnt, &root ) ||
                   !vote_cnt || votes[ vote_cnt-1UL ].slot!=done->vote_slot ) ) {
    FD_LOG_WARNING(( "tower vote transaction does not match its slot metadata" ));
    return;
  }

  ulong state_sz = 0UL;
  if( FD_UNLIKELY( fd_compact_tower_sync_ser( &serde,
                                              ctx->cs_buf+sizeof(fd_failover_consensus_state_t),
                                              FD_FAILOVER_TOWER_STATE_MAX,
                                              &state_sz ) ) ) {
    FD_LOG_WARNING(( "tower vote transaction exceeds the failover state limit" ));
    return;
  }

  fd_failover_consensus_state_t msg = {
    .term      = ctx->hello.term,
    .link_seq  = ctx->slot_done_seq,
    .vote_slot = done->vote_slot,
    .mode      = (uchar)FD_FAILOVER_MODE_TOWER,
    .state_len = (ushort)state_sz,
  };
  fd_memcpy( ctx->cs_buf, &msg, sizeof(msg) );
  ctx->cs_sz     = sizeof(msg)+state_sz;
  ctx->cs_valid  = 1;
  ctx->tower_gap = 0; /* anything skipped before this vote is superseded by it */
  for( ulong i=0UL; i<ctx->peer_cnt; i++ ) ctx->peers[ i ].cs_sent = 0;
}

/* Fold one tower slot_done into the local slot view.  The tower can
   report slots out of order across forks, so the replay slot is a
   running maximum. */
static void
consume_slot_done( fd_failover_tile_ctx_t *     ctx,
                   fd_tower_slot_done_t const * done ) {
  if( FD_LIKELY( ctx->replay_slot==FD_FAILOVER_SLOT_NULL || done->replay_slot>ctx->replay_slot ) )
    ctx->replay_slot = done->replay_slot;
  if( FD_LIKELY( done->root_slot!=FD_FAILOVER_SLOT_NULL ) ) ctx->root_slot = done->root_slot;
  if( FD_LIKELY( done->has_vote_txn && done->vote_slot!=FD_FAILOVER_SLOT_NULL ) ) {
    ctx->last_vote_slot = done->vote_slot;
    /* Admin can unhalt the new signer before its switch answer reaches
       this tile.  Those first votes already belong to the new tenure. */
    if( FD_LIKELY( ctx->role==FD_FAILOVER_ROLE_ACTIVE ||
                   (ctx->state==FD_FAILOVER_STATE_PROMOTING && ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH) ) )
      prepare_consensus( ctx, done );
  }
}

/* consume_reset folds replay's reset message into the readiness view.
   The tip is a running maximum since a reset is republished on a reorg,
   and a reset that names a real next leader slot ends our leader window:
   replay reports the sentinel from becoming leader until its next reset,
   which is exactly the interval the leader-near check cannot see. */
static void
consume_reset( fd_failover_tile_ctx_t * ctx,
               fd_poh_reset_t const *   reset ) {
  if( FD_LIKELY( reset->turbine_slot!=FD_FAILOVER_SLOT_NULL &&
                 ( ctx->turbine_slot==FD_FAILOVER_SLOT_NULL || reset->turbine_slot>ctx->turbine_slot ) ) ) {
    ctx->turbine_slot = reset->turbine_slot;
  }
  ctx->replay_caught_up |= !!reset->caught_up;
  ctx->next_leader_slot  = reset->next_leader_slot;
  if( FD_LIKELY( reset->next_leader_slot!=FD_FAILOVER_SLOT_NULL ) ) ctx->is_leader = 0;
}

/* caught_up_locally is the live signal: replay's boot latch, which never
   comes down on its own, together with the tip being within the
   configured gap of the replayed slot.  Neither alone works, the latch
   cannot see falling behind and the gap can be fooled right after boot
   before the tip has moved.  Unknown is not caught up. */
static int
caught_up_locally( fd_failover_tile_ctx_t const * ctx ) {
  if( FD_UNLIKELY( !ctx->replay_caught_up ||
                   ctx->replay_slot==FD_FAILOVER_SLOT_NULL ||
                   ctx->turbine_slot==FD_FAILOVER_SLOT_NULL ) ) return 0;
  /* A leader replays past its own tip, its own blocks are not in it. */
  return ctx->turbine_slot<=ctx->replay_slot ||
         ctx->turbine_slot-ctx->replay_slot<=ctx->catchup_gap_limit;
}

/* Our side of STATUS for one peer. */
static fd_failover_status_t
local_status( fd_failover_tile_ctx_t const * ctx,
              fd_failover_peer_t const *     peer ) {
  fd_failover_status_t status;
  fd_memset( &status, 0, sizeof(status) );
  status.term             = ctx->hello.term;
  status.role             = (uchar)ctx->role;
  status.replay_slot      = ctx->replay_slot;
  status.turbine_slot     = ctx->turbine_slot;
  status.last_vote_slot   = ctx->last_vote_slot;
  status.root_slot        = ctx->root_slot;
  status.next_leader_slot = ctx->next_leader_slot;
  if( FD_UNLIKELY( peer->lag_slots!=FD_FAILOVER_SLOT_NULL && peer->lag_slots>ctx->replication_lag_limit ) ) {
    status.status |= FD_FAILOVER_STATUS_REPLAG;
  }
  /* The peer drops the session if our slot view cannot be right, so fix it
     up before sending.  Both cases happen in normal operation, right after
     a restart the restored last vote is ahead of replay, and a machine
     that stopped voting keeps rooting past its last vote. */
  if( FD_UNLIKELY( status.replay_slot!=FD_FAILOVER_SLOT_NULL &&
                   status.last_vote_slot!=FD_FAILOVER_SLOT_NULL &&
                   status.last_vote_slot>status.replay_slot ) ) {
    status.status        |= FD_FAILOVER_STATUS_CATCHUP;
    status.last_vote_slot = FD_FAILOVER_SLOT_NULL;
  }
  if( FD_UNLIKELY( status.root_slot!=FD_FAILOVER_SLOT_NULL &&
                   ( ( status.replay_slot!=FD_FAILOVER_SLOT_NULL &&
                       status.root_slot>status.replay_slot ) ||
                     ( status.last_vote_slot!=FD_FAILOVER_SLOT_NULL &&
                       status.root_slot>status.last_vote_slot ) ) ) ) {
    status.root_slot = FD_FAILOVER_SLOT_NULL;
  }
  /* The readiness flags, then the same reductions the peer's decoder
     demands: a leader slot at or below the final root is impossible, a
     leader window needs a replayed slot, and caught up needs a known tip,
     a known replayed slot and a view that was not reduced above.  The
     rooted-vote flag stays clear, replay keeps that fact to itself. */
  if( FD_UNLIKELY( ctx->is_leader ) )          status.flags |= FD_FAILOVER_FLAG_IS_LEADER;
  if( FD_LIKELY( caught_up_locally( ctx ) ) )  status.flags |= FD_FAILOVER_FLAG_CAUGHT_UP;
  if( FD_UNLIKELY( status.next_leader_slot!=FD_FAILOVER_SLOT_NULL &&
                   status.root_slot!=FD_FAILOVER_SLOT_NULL &&
                   status.next_leader_slot<=status.root_slot ) ) {
    status.next_leader_slot = FD_FAILOVER_SLOT_NULL;
  }
  if( FD_UNLIKELY( status.replay_slot==FD_FAILOVER_SLOT_NULL ) ) status.flags &= (uchar)~FD_FAILOVER_FLAG_IS_LEADER;
  if( FD_UNLIKELY( status.turbine_slot==FD_FAILOVER_SLOT_NULL || status.replay_slot==FD_FAILOVER_SLOT_NULL ||
                   ( status.status & FD_FAILOVER_STATUS_CATCHUP ) ) ) {
    status.flags &= (uchar)~FD_FAILOVER_FLAG_CAUGHT_UP;
  }
  /* The peer and the operator both get to see busy, paused and stuck. */
  if( FD_UNLIKELY( ctx->action!=FD_FAILOVER_ACTION_IDLE ) ) status.status |= FD_FAILOVER_STATUS_BUSY;
  if( FD_UNLIKELY( ctx->paused )                          ) status.status |= FD_FAILOVER_STATUS_PAUSED;
  if( FD_UNLIKELY( ctx->stuck )                           ) status.status |= FD_FAILOVER_STATUS_STUCK;
  status.ack_seq = fd_failover_channel_ack_seq( peer->channel );
  return status;
}

/* Decode a DEMOTED frame into a record.  The frame is the message
   followed by the final tower, so we compute the tower digest here and
   end up with the same record we would store on disk. */
static int
demoted_payload_decode( uchar const *                  payload,
                        ulong                          payload_sz,
                        fd_failover_demoted_record_t * out ) {
  if( FD_UNLIKELY( payload_sz<sizeof(fd_failover_demoted_t) ||
                   payload_sz>FD_FAILOVER_DEMOTED_PAYLOAD_MAX ) ) return -1;

  fd_failover_demoted_record_t record;
  fd_memset( &record, 0, sizeof(record) );
  fd_memcpy( &record.demoted, payload, sizeof(fd_failover_demoted_t) );

  ulong state_len = payload_sz-sizeof(fd_failover_demoted_t);
  if( FD_UNLIKELY( (ulong)record.demoted.state_len!=state_len ||
                   !state_len || state_len>FD_FAILOVER_TOWER_STATE_MAX ||
                   record.demoted.mode!=(uchar)FD_FAILOVER_MODE_TOWER ||
                   record.demoted.last_vote_slot==FD_FAILOVER_SLOT_NULL ||
                   record.demoted.term>=ULONG_MAX-1UL ) ) return -1;

  /* The tower has to end at the slot the record claims, or the metadata
     and the tower it describes could drift apart unnoticed. */
  fd_compact_tower_sync_serde_t serde;
  fd_tower_vote_t votes[ FD_TOWER_VOTE_MAX ];
  ulong vote_cnt;
  ulong root;
  if( FD_UNLIKELY( fd_compact_tower_sync_de_exact( &serde, payload+sizeof(fd_failover_demoted_t), state_len ) ||
                   fd_compact_tower_sync_to_votes( &serde, votes, &vote_cnt, &root ) ||
                   !vote_cnt || votes[ vote_cnt-1UL ].slot!=record.demoted.last_vote_slot ) ) return -1;

  fd_memcpy( record.state, payload+sizeof(fd_failover_demoted_t), state_len );
  fd_sha256_hash( record.state, state_len, record.digest );
  *out = record;
  return 0;
}

/* Forward declarations, step_controller below drives these. */
static ulong request_switch( fd_failover_tile_ctx_t * ctx, fd_stem_context_t * stem, ulong key );
static void  start_demotion( fd_failover_tile_ctx_t * ctx, fd_stem_context_t * stem, ulong term, ulong deadline_slots, int send_demoted, long now );
static void  demotion_switched( fd_failover_tile_ctx_t * ctx, long now );
static void  reject_promotion( fd_failover_tile_ctx_t * ctx, uchar reason, long now );
static void  start_promotion( fd_failover_tile_ctx_t * ctx, fd_failover_demoted_record_t const * record, ulong term, long now );
static ulong switch_query( fd_failover_tile_ctx_t * ctx, fd_stem_context_t * stem );
static void  publish_control_response( fd_failover_tile_ctx_t * ctx, fd_stem_context_t * stem, ulong nonce, ulong result );

/* These new waits have a monotonic bound even before replay starts. */
static void
claim_deadline_start( fd_failover_tile_ctx_t * ctx,
                      long                     now ) {
  ulong seconds = fd_ulong_max( 30UL, fd_ulong_min( ctx->deadline_slots, 300UL ) );
  ctx->claim_deadline = fd_long_sat_add( now, (long)(seconds*1000000000UL) );
  deadline_start( ctx, ctx->deadline_slots, now );
}

static int
claim_expired( fd_failover_tile_ctx_t const * ctx,
               long                          now ) {
  return now>=ctx->claim_deadline || deadline_expired( ctx, now );
}

/* A lost readiness answer must not leave an idle standby permanently
   unavailable for first use.  Ending this wait grants no authority and
   does not cancel a demotion the peer may already have started. */
static void
step_handoff_request( fd_failover_tile_ctx_t * ctx,
                      long                     now ) {
  if( FD_LIKELY( !ctx->handoff_pending ) ) return;
  fd_failover_peer_t * peer = &ctx->peers[ 0 ];
  int same_session = fd_failover_channel_state( peer->channel )==FD_FAILOVER_SESSION_PAIRED &&
                     fd_failover_channel_metrics( peer->channel )->paired_cnt==ctx->handoff_session;
  if( FD_UNLIKELY( ctx->handoff_deadline_slot==FD_FAILOVER_SLOT_NULL && ctx->replay_slot!=FD_FAILOVER_SLOT_NULL ) )
    ctx->handoff_deadline_slot = fd_ulong_sat_add( ctx->replay_slot, ctx->deadline_slots );
  int expired = now>=ctx->handoff_deadline ||
                ( ctx->handoff_deadline_slot!=FD_FAILOVER_SLOT_NULL && ctx->replay_slot!=FD_FAILOVER_SLOT_NULL &&
                  ctx->replay_slot>ctx->handoff_deadline_slot );
  if( FD_LIKELY( same_session && !expired && !ctx->paused ) ) return;
  ctx->handoff_pending = 0;
  ctx->handoff_code    = (uchar)FD_FAILOVER_HANDOFF_CODE_CNT; /* no peer verdict */
  ctx->handoff_reason  = ctx->paused ? FD_FAILOVER_REJECT_PAUSED :
                         expired ? FD_FAILOVER_REJECT_DEADLINE : FD_FAILOVER_REJECT_STATUS_STALE;
  ctx->handoff_term    = ctx->handoff_req.proposed_term;
  if( ctx->pending_valid && ctx->pending_type==(ushort)FD_FAILOVER_MSG_HANDOFF_REQ ) ctx->pending_valid = 0;
  /* Requests have no nonce.  A fresh session ensures an old answer cannot
     complete the next request with the same fields. */
  if( FD_UNLIKELY( same_session ) ) fd_failover_channel_hangup( peer->channel, now );
  FD_LOG_WARNING(( "handoff request at term %lu ended without a peer verdict (reason %u), inspect both members before retrying",
                   ctx->handoff_term, (uint)ctx->handoff_reason ));
}

static void
queue_confirm( fd_failover_tile_ctx_t * ctx,
                fd_failover_reclaim_t const * req,
                uchar code,
                uchar reason ) {
  ctx->confirm_reply = (fd_failover_confirm_t){ .term=req->term, .nonce=req->nonce, .code=code, .reason=reason };
  ctx->confirm_owed = !!queue_control( ctx, (ushort)FD_FAILOVER_MSG_CONFIRM, &ctx->confirm_reply, sizeof(ctx->confirm_reply) );
}

static void
first_use_failed( fd_failover_tile_ctx_t * ctx,
                   uchar                    reason ) {
  ctx->first_use_pending    = 0;
  ctx->first_use_authorized = 0;
  if( ctx->pending_valid && ctx->pending_type==(ushort)FD_FAILOVER_MSG_RECLAIM ) ctx->pending_valid = 0;
  ctx->action = FD_FAILOVER_ACTION_IDLE;
  ctx->stuck  = 1;
  FD_LOG_WARNING(( "first use refused at term %lu (reason %u), remaining passive", ctx->action_term, (uint)reason ));
}

static void
maybe_first_use( fd_failover_tile_ctx_t * ctx,
                  long                     now ) {
  if( FD_LIKELY( !ctx->first_use_authorized || ctx->first_use_tried ) ) return;
  if( FD_UNLIKELY( ctx->state!=FD_FAILOVER_STATE_STANDBY || ctx->action!=FD_FAILOVER_ACTION_IDLE ||
                   ctx->paused || ctx->stuck || ctx->pending_valid || ctx->handoff_pending ||
                   ctx->send_demoted || ctx->demoted_valid || ctx->switch_query_pending ||
                   ctx->switch_pending_key!=FD_FAILOVER_SWITCH_KEY_CNT ||
                   ctx->member_cnt!=2UL || ctx->self_idx || ctx->peer_cnt!=1UL ) ) return;
  fd_failover_peer_t * peer = &ctx->peers[ 0 ];
  if( FD_UNLIKELY( fd_failover_channel_state( peer->channel )!=FD_FAILOVER_SESSION_PAIRED ||
                   !peer_status_fresh( ctx, peer, now ) || peer->status.role!=FD_FAILOVER_ROLE_STANDBY ||
                   (peer->status.status & (FD_FAILOVER_STATUS_BUSY|FD_FAILOVER_STATUS_PAUSED|FD_FAILOVER_STATUS_STUCK)) ) ) return;
  ulong term = fd_failover_reclaim_term( ctx->hello.term, peer->status.term );
  if( FD_UNLIKELY( term==ULONG_MAX ) ) return;
  if( FD_UNLIKELY( !++ctx->first_use_nonce ) ) ctx->first_use_nonce++;
  ctx->first_use_req       = (fd_failover_reclaim_t){ .term=term, .nonce=ctx->first_use_nonce };
  ctx->first_use_peer_boot = fd_failover_channel_peer_hello( peer->channel )->boot_id;
  ctx->first_use_pending   = 1;
  ctx->first_use_tried     = 1;
  ctx->first_use_sent      = 0;
  ctx->action_term         = term;
  ctx->action              = FD_FAILOVER_ACTION_FIRST_USE_WAIT;
  claim_deadline_start( ctx, now );
  (void)queue_control( ctx, (ushort)FD_FAILOVER_MSG_RECLAIM, &ctx->first_use_req, sizeof(ctx->first_use_req) );
  FD_LOG_NOTICE(( "first use requesting the peer's stand-down at term %lu", term ));
}

/* Send the tower we are adopting to the tower tile.  This is the final
   tower from the peer's demotion record, not the streamed one, because
   only the record is final.  The reply comes back with the request id so
   we can tell a late reply apart.  Returns the id, or ULONG_MAX if there
   is nothing to adopt. */
static ulong
publish_adopt_state( fd_failover_tile_ctx_t * ctx,
                     fd_stem_context_t *      stem ) {
  if( FD_UNLIKELY( ctx->adopt_out_idx==ULONG_MAX || !ctx->adopt_state_len ) ) return ULONG_MAX;

  if( FD_UNLIKELY( !++ctx->adopt_request_id ) ) ctx->adopt_request_id++;
  fd_memcpy( fd_chunk_to_laddr( ctx->adopt_out_mem, ctx->adopt_out_chunk ), ctx->adopt_state, ctx->adopt_state_len );
  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, ctx->adopt_out_idx, ctx->adopt_request_id, ctx->adopt_out_chunk, ctx->adopt_state_len, 0UL, tspub, tspub );
  ctx->adopt_out_chunk    = fd_dcache_compact_next( ctx->adopt_out_chunk, ctx->adopt_state_len, ctx->adopt_out_chunk0, ctx->adopt_out_wmark );
  ctx->adopt_result_fresh = 0;
  return ctx->adopt_request_id;
}

/* Move the current transition along.  Each step waits on one thing, the
   admin tile, the tower tile, replay reaching a slot, or the peer.  If a
   step misses its deadline we stand down. */
static void
step_controller( fd_failover_tile_ctx_t * ctx,
                 fd_stem_context_t *      stem,
                 long                     now ) {
  step_handoff_request( ctx, now );
  /* An outcome that could not be queued while another control message
     held the slot is still owed to the peer, send it once the slot is
     free. */
  if( FD_UNLIKELY( ctx->reply_owed && !ctx->pending_valid ) ) queue_reply( ctx );
  if( FD_UNLIKELY( ctx->confirm_owed && !ctx->pending_valid ) )
    ctx->confirm_owed = !!queue_control( ctx, (ushort)FD_FAILOVER_MSG_CONFIRM, &ctx->confirm_reply, sizeof(ctx->confirm_reply) );
  if( FD_LIKELY( ctx->action==FD_FAILOVER_ACTION_IDLE ) ) return;

  switch( ctx->action ) {

  case FD_FAILOVER_ACTION_DEMOTE_SWITCH: {
    deadline_arm( ctx, ctx->deadline_slots, now );
    if( FD_LIKELY( !ctx->switch_result_fresh ) ) {
      /* No answer yet.  We do not know whether the junk key got installed,
         so we claim nothing and keep waiting, the late answer still counts.
         Past the deadline we raise stuck for the operator. */
      if( FD_UNLIKELY( deadline_expired( ctx, now ) ) ) switch_overdue( ctx );
      return;
    }
    if( FD_UNLIKELY( ctx->switch_result.result!=FD_FAILOVER_SWITCH_OK ) ) {
      /* The switch failed, we still have the identity, so we send no
         confirmation. */
      ctx->switch_result_fresh = 0;
      ctx->switch_overdue      = 0;
      FD_LOG_WARNING(( "the identity switch for a demotion failed with %lu", ctx->switch_result.result ));
      persist( ctx, FD_FAILOVER_STATE_ACTIVE, ctx->action_term );
      ctx->action = FD_FAILOVER_ACTION_IDLE;
      ctx->stuck  = 1;
      return;
    }
    /* The watermark is the tower tile's output sequence when it stopped
       signing.  Every frag it published before that is consumed before the
       final tower is taken from the cache, or the last vote it signed could
       be missing from the confirmation.  Same link, same counter, so the
       wait is exact. */
    if( FD_UNLIKELY( !fd_seq_ge( fd_seq_inc( ctx->tower_seen_seq, 1UL ), ctx->switch_result.tower_watermark ) ) ) {
      if( FD_UNLIKELY( deadline_expired( ctx, now ) ) ) {
        /* The identity is gone from here, so standing down without a
           confirmation is the safe direction, nobody can promote on it. */
        FD_LOG_WARNING(( "the tower stream never reached the watermark %lu, demotion at term %lu confirms nothing", ctx->switch_result.tower_watermark, ctx->action_term ));
        ctx->switch_result_fresh = 0;
        ctx->switch_overdue      = 0;
        set_role( ctx, FD_FAILOVER_ROLE_STANDBY, now );
        persist( ctx, FD_FAILOVER_STATE_STANDBY, ctx->action_term );
        ctx->action = FD_FAILOVER_ACTION_IDLE;
        ctx->stuck  = 1;
      }
      return;
    }
    ctx->switch_result_fresh = 0;
    ctx->switch_overdue      = 0;
    demotion_switched( ctx, now );
    return;
  }

  case FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK: {
    /* If the peer goes quiet we do not undo the demotion, we only raise the
       alarm.  The identity is already gone from this machine, so waiting is
       safe. */
    deadline_arm( ctx, ctx->deadline_slots, now );
    /* We keep sending the confirmation until the peer answers.  It may not be
       in flight because the control slot was busy when the demotion
       finished, or because the session died before the peer acted on it. */
    if( FD_UNLIKELY( ctx->send_demoted && !ctx->demoted_sent && !ctx->pending_valid &&
                     ctx->demoted_valid ) ) {
      ulong state_len = (ulong)ctx->demoted_record.demoted.state_len;
      uchar payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];
      fd_memcpy( payload, &ctx->demoted_record.demoted, sizeof(fd_failover_demoted_t) );
      fd_memcpy( payload+sizeof(fd_failover_demoted_t), ctx->demoted_record.state, state_len );
      (void)queue_control( ctx, (ushort)FD_FAILOVER_MSG_DEMOTED, payload,
                           sizeof(fd_failover_demoted_t)+state_len );
    }
    if( FD_UNLIKELY( deadline_expired( ctx, now ) ) ) {
      /* The identity is already gone, so we keep retrying the confirmation
         after the deadline rather than give up, since a reconnect must
         still deliver it.  We only raise the alarm once. */
      if( FD_UNLIKELY( !ctx->stuck ) )
        FD_LOG_WARNING(( "the peer has not acknowledged the demotion at term %lu, still retrying", ctx->action_term ));
      ctx->stuck = 1;
    }
    return;
  }

  case FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY: {
    deadline_arm( ctx, ctx->deadline_slots, now );
    /* A pause accepted while the promotion is still waiting, before the key
       switch is requested, stands it down so the pause is honored. */
    if( FD_UNLIKELY( ctx->paused ) ) {
      reject_promotion( ctx, FD_FAILOVER_REJECT_PAUSED, now );
      return;
    }
    if( FD_UNLIKELY( deadline_expired( ctx, now ) ) ) {
      reject_promotion( ctx, FD_FAILOVER_REJECT_REPLAY_BEHIND, now );
      return;
    }
    /* Wait for replay to reach the final vote before adopting, otherwise the
       tower refers to blocks we have not seen yet. */
    if( FD_UNLIKELY( ctx->replay_slot==FD_FAILOVER_SLOT_NULL ||
                     ctx->replay_slot<ctx->demoted_record.demoted.last_vote_slot ) ) return;
    ulong id = publish_adopt_state( ctx, stem );
    if( FD_UNLIKELY( id==ULONG_MAX ) ) {
      reject_promotion( ctx, FD_FAILOVER_REJECT_ADOPTION_FAILED, now );
      return;
    }
    ctx->adopt_expected_id = id;
    ctx->action            = FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT;
    return;
  }

  case FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT: {
    deadline_arm( ctx, ctx->deadline_slots, now );
    if( FD_UNLIKELY( ctx->paused ) ) {
      reject_promotion( ctx, FD_FAILOVER_REJECT_PAUSED, now );
      return;
    }
    if( FD_UNLIKELY( deadline_expired( ctx, now ) ) ) {
      reject_promotion( ctx, FD_FAILOVER_REJECT_ADOPTION_FAILED, now );
      return;
    }
    if( FD_LIKELY( !ctx->adopt_result_fresh ) ) return;
    ctx->adopt_result_fresh = 0;
    if( FD_UNLIKELY( ctx->adopt_result_id!=ctx->adopt_expected_id ) ) return;
    if( FD_UNLIKELY( ctx->adopt_result.result!=FD_TOWER_ADOPT_SUCCESS ) ) {
      FD_LOG_WARNING(( "the tower tile refused the received tower with %lu", ctx->adopt_result.result ));
      reject_promotion( ctx, ( ctx->adopt_result.result==FD_TOWER_ADOPT_ERR_BLOCK_MISMATCH ||
                               ctx->adopt_result.result==FD_TOWER_ADOPT_ERR_STALE )
                             ? FD_FAILOVER_REJECT_ADOPTION_MISMATCH
                             : FD_FAILOVER_REJECT_ADOPTION_FAILED, now );
      return;
    }
    if( FD_UNLIKELY( ctx->adopt_result.vote_slot!=ctx->demoted_record.demoted.last_vote_slot ) ) {
      /* The tower tile keeps the prefix replay has produced, so a tower that
         ends short of the confirmed last vote would leave lockouts behind.
         That is a mismatch, not a promotion. */
      FD_LOG_WARNING(( "the adopted tower ends at slot %lu, the confirmation says %lu", ctx->adopt_result.vote_slot, ctx->demoted_record.demoted.last_vote_slot ));
      reject_promotion( ctx, FD_FAILOVER_REJECT_ADOPTION_MISMATCH, now );
      return;
    }
    if( FD_UNLIKELY( request_switch( ctx, stem, FD_FAILOVER_SWITCH_KEY_STAKED )==ULONG_MAX ) ) {
      reject_promotion( ctx, FD_FAILOVER_REJECT_ADOPTION_FAILED, now );
      return;
    }
    ctx->action = FD_FAILOVER_ACTION_PROMOTE_SWITCH;
    return;
  }

  case FD_FAILOVER_ACTION_PROMOTE_SWITCH: {
    deadline_arm( ctx, ctx->deadline_slots, now );
    if( FD_LIKELY( !ctx->switch_result_fresh ) ) {
      /* No answer yet.  Standing down here would tell the peer nobody
         promoted while the staked key may well be installed, the one way a
         STANDBY record and a staked identity could come to coexist.  So we
         keep waiting and raise stuck past the deadline, the late answer
         still counts. */
      if( FD_UNLIKELY( deadline_expired( ctx, now ) ) ) switch_overdue( ctx );
      return;
    }
    ctx->switch_result_fresh = 0;
    ctx->switch_overdue      = 0;
    if( FD_UNLIKELY( ctx->switch_result.result!=FD_FAILOVER_SWITCH_OK ) ) {
      reject_promotion( ctx, FD_FAILOVER_REJECT_STATE_MISMATCH, now );
      return;
    }
    persist( ctx, FD_FAILOVER_STATE_ACTIVE, ctx->action_term );
    set_role( ctx, FD_FAILOVER_ROLE_ACTIVE, now );
    if( FD_UNLIKELY( ctx->first_use_promoting ) ) {
      ctx->first_use_promoting = 0;
      ctx->action = FD_FAILOVER_ACTION_IDLE;
      ctx->stuck  = 0;
      FD_LOG_NOTICE(( "first use installed the staked identity at term %lu, verify the first landed vote", ctx->action_term ));
      return;
    }
    /* The ack tells the old active it can drop its confirmation.  Keep it
       as the outcome for this term, so a confirmation resent at this term
       gets the ack again rather than being dropped as a mid transition
       message, and so it stays owed if the control slot is busy. */
    ctx->reply_dem_term = ctx->action_term;
    ctx->reply_type     = (ushort)FD_FAILOVER_MSG_PROMOTE_ACK;
    ctx->reply_out_term = ctx->action_term;
    queue_reply( ctx );
    ctx->action = FD_FAILOVER_ACTION_IDLE;
    ctx->stuck  = 0;
    return;
  }

  case FD_FAILOVER_ACTION_REJECT: {
    /* The refusal is queued, wait for it to go out or for the operator to
       step in. */
    if( FD_LIKELY( !ctx->pending_valid || deadline_expired( ctx, now ) ) ) ctx->action = FD_FAILOVER_ACTION_IDLE;
    return;
  }

  case FD_FAILOVER_ACTION_FIRST_USE_WAIT: {
    deadline_arm( ctx, ctx->deadline_slots, now );
    if( FD_UNLIKELY( ctx->paused || claim_expired( ctx, now ) ) ) {
      first_use_failed( ctx, ctx->paused ? FD_FAILOVER_REJECT_PAUSED : FD_FAILOVER_REJECT_DEADLINE );
      return;
    }
    fd_failover_peer_t * peer = &ctx->peers[ 0 ];
    if( FD_UNLIKELY( fd_failover_channel_state( peer->channel )==FD_FAILOVER_SESSION_PAIRED &&
                     fd_failover_channel_peer_hello( peer->channel )->boot_id!=ctx->first_use_peer_boot ) ) {
      first_use_failed( ctx, FD_FAILOVER_REJECT_STATE_MISMATCH );
      return;
    }
    if( FD_UNLIKELY( !ctx->first_use_sent && !ctx->pending_valid ) )
      (void)queue_control( ctx, (ushort)FD_FAILOVER_MSG_RECLAIM, &ctx->first_use_req, sizeof(ctx->first_use_req) );
    return;
  }

  case FD_FAILOVER_ACTION_CONFIRM_WAIT_QUERY: {
    deadline_arm( ctx, ctx->deadline_slots, now );
    fd_failover_peer_t * peer = &ctx->peers[ 0 ];
    int paired = fd_failover_channel_state( peer->channel )==FD_FAILOVER_SESSION_PAIRED;
    int same_boot = paired && fd_failover_channel_peer_hello( peer->channel )->boot_id==ctx->confirm_peer_boot;
    uchar reason = FD_FAILOVER_REJECT_NONE;
    uchar code   = FD_FAILOVER_RECLAIM_REFUSED;
    if( FD_UNLIKELY( ctx->paused || claim_expired( ctx, now ) || !same_boot ) ) {
      reason = ctx->paused ? FD_FAILOVER_REJECT_PAUSED : FD_FAILOVER_REJECT_DEADLINE;
    } else {
      if( FD_LIKELY( !ctx->switch_state_fresh ) ) return;
      fd_failover_status_t local = local_status( ctx, peer );
      int junk = ctx->switch_state.result==FD_FAILOVER_SWITCH_STATE_JUNK &&
                 ctx->switch_state.tower_watermark==ULONG_MAX &&
                 fd_memeq( ctx->switch_state.identity, ctx->hello.junk_pubkey, 32UL );
      code = fd_failover_reclaim_check( &ctx->confirm_req, &local, &peer->status,
                                        peer_status_fresh( ctx, peer, now ), ctx->state, junk,
                                        ctx->switch_pending_key!=FD_FAILOVER_SWITCH_KEY_CNT,
                                        ctx->send_demoted, &reason );
      if( code==FD_FAILOVER_RECLAIM_REFUSED && reason==FD_FAILOVER_REJECT_HOLDS_IDENTITY ) ctx->stuck = 1;
    }
    ctx->switch_query_pending = 0;
    ctx->switch_state_fresh   = 0;
    if( FD_LIKELY( code==FD_FAILOVER_RECLAIM_CONFIRMED ) ) {
      persist( ctx, FD_FAILOVER_STATE_STANDBY, ctx->confirm_req.term );
      ctx->confirm_given     = 1;
      ctx->confirm_last      = (fd_failover_confirm_t){ .term=ctx->confirm_req.term, .nonce=ctx->confirm_req.nonce, .code=code };
      ctx->confirm_last_boot = ctx->confirm_peer_boot;
      FD_LOG_NOTICE(( "confirmed the peer's first use after proving the junk key and recording standby at term %lu", ctx->confirm_req.term ));
    }
    ctx->action = FD_FAILOVER_ACTION_IDLE;
    if( same_boot ) queue_confirm( ctx, &ctx->confirm_req, code, reason );
    return;
  }

  case FD_FAILOVER_ACTION_CLEAR_WAIT_QUERY: {
    /* stuck says the record may not match reality.  It is lowered only
       once the admin tile has said which key is installed and that
       agrees with the recorded role, anything else is the alarm the flag
       was raised for. */
    deadline_arm( ctx, ctx->deadline_slots, now );
    if( FD_LIKELY( !ctx->switch_state_fresh ) ) {
      if( FD_UNLIKELY( deadline_expired( ctx, now ) ) ) {
        /* A query has no side effects, so unlike a switch it can be
           given up on.  A late answer finds no query pending and is
           dropped. */
        FD_LOG_WARNING(( "the admin tile did not answer which identity is installed, stuck stays set" ));
        ctx->switch_query_pending = 0;
        ctx->clear_parked         = 0;
        ctx->action               = FD_FAILOVER_ACTION_IDLE;
      }
      return;
    }
    ctx->switch_state_fresh = 0;
    ulong want = ctx->state==FD_FAILOVER_STATE_ACTIVE  ? FD_FAILOVER_SWITCH_STATE_STAKED
               : ctx->state==FD_FAILOVER_STATE_STANDBY ? FD_FAILOVER_SWITCH_STATE_JUNK
               : FD_FAILOVER_SWITCH_STATE_CNT;
    ulong result;
    if( FD_LIKELY( ctx->switch_state.result==want ) ) {
      ctx->stuck          = 0;
      ctx->switch_overdue = 0;
      result = FD_ADMINCTL_RESULT_SUCCESS;
    } else {
      FD_BASE58_ENCODE_32_BYTES( ctx->switch_state.identity, installed );
      FD_LOG_WARNING(( "the record says state %lu but the installed identity is %s (%lu), stuck stays set, do not promote anything",
                       ctx->state, installed, ctx->switch_state.result ));
      ctx->identity_mismatch_cnt++;
      result = FD_FAILOVER_CONTROL_RESULT_IDENTITY_MISMATCH;
    }
    ctx->action = FD_FAILOVER_ACTION_IDLE;
    if( FD_LIKELY( ctx->clear_parked ) ) {
      ctx->clear_parked = 0;
      publish_control_response( ctx, stem, ctx->clear_nonce, result );
    }
    return;
  }

  default: FD_LOG_ERR(( "unexpected failover action %lu", ctx->action ));
  }
}

/* Handle a controller message.  Anything malformed drops the session,
   these messages move the staked identity so we do not guess at them. */
static void
handle_control( fd_failover_tile_ctx_t * ctx,
                fd_failover_peer_t *     peer,
                ushort                   type,
                ulong                    payload_sz,
                long                     now ) {
  fd_failover_hello_t const * peer_hello = fd_failover_channel_peer_hello( peer->channel );

  switch( type ) {

  case (ushort)FD_FAILOVER_MSG_RECLAIM: {
    if( FD_UNLIKELY( payload_sz!=sizeof(fd_failover_reclaim_t) ) ) break;
    fd_failover_reclaim_t req;
    fd_memcpy( &req, ctx->rx, sizeof(req) );
    if( FD_UNLIKELY( !req.nonce ) ) break;
    if( FD_UNLIKELY( ctx->pending_valid || ctx->confirm_owed ) ) return;
    if( FD_UNLIKELY( ctx->member_cnt!=2UL || ctx->self_idx!=1UL || peer->member_idx!=0UL ) ) {
      queue_confirm( ctx, &req, FD_FAILOVER_RECLAIM_REFUSED, FD_FAILOVER_REJECT_BAD_REQUEST );
      return;
    }
    if( FD_UNLIKELY( ctx->state==FD_FAILOVER_STATE_ACTIVE || ctx->role==FD_FAILOVER_ROLE_ACTIVE ) ) {
      queue_confirm( ctx, &req, FD_FAILOVER_RECLAIM_HELD, FD_FAILOVER_REJECT_NONE );
      return;
    }
    if( FD_UNLIKELY( ctx->action!=FD_FAILOVER_ACTION_IDLE || ctx->handoff_pending || ctx->switch_query_pending ) ) {
      queue_confirm( ctx, &req, FD_FAILOVER_RECLAIM_REFUSED, FD_FAILOVER_REJECT_BUSY );
      return;
    }
    if( FD_UNLIKELY( ctx->state!=FD_FAILOVER_STATE_STANDBY || ctx->send_demoted || ctx->demoted_valid || ctx->stuck ) ) {
      queue_confirm( ctx, &req, FD_FAILOVER_RECLAIM_REFUSED, FD_FAILOVER_REJECT_STATE_MISMATCH );
      return;
    }
    if( FD_UNLIKELY( ctx->paused ) ) {
      queue_confirm( ctx, &req, FD_FAILOVER_RECLAIM_REFUSED, FD_FAILOVER_REJECT_PAUSED );
      return;
    }
    if( FD_UNLIKELY( !peer_status_fresh( ctx, peer, now ) || peer->status.role!=FD_FAILOVER_ROLE_STANDBY ||
                     peer_hello->role!=FD_FAILOVER_ROLE_STANDBY ) ) {
      queue_confirm( ctx, &req, FD_FAILOVER_RECLAIM_REFUSED, FD_FAILOVER_REJECT_STATUS_STALE );
      return;
    }
    if( FD_UNLIKELY( ctx->switch_pending_key!=FD_FAILOVER_SWITCH_KEY_CNT ) ) {
      queue_confirm( ctx, &req, FD_FAILOVER_RECLAIM_REFUSED, FD_FAILOVER_REJECT_SWITCH_PENDING );
      return;
    }
    if( FD_LIKELY( ctx->confirm_given && ctx->confirm_last_boot==peer_hello->boot_id &&
                   ctx->hello.term==req.term && req.term==ctx->confirm_last.term && req.nonce==ctx->confirm_last.nonce ) ) {
      queue_confirm( ctx, &req, FD_FAILOVER_RECLAIM_CONFIRMED, FD_FAILOVER_REJECT_NONE );
      return;
    }
    if( FD_UNLIKELY( req.term<=ctx->hello.term || req.term!=fd_failover_reclaim_term( ctx->hello.term, peer->status.term ) ) ) {
      queue_confirm( ctx, &req, FD_FAILOVER_RECLAIM_STALE_TERM, FD_FAILOVER_REJECT_NONE );
      return;
    }
    if( FD_UNLIKELY( !ctx->step_stem || switch_query( ctx, ctx->step_stem )==ULONG_MAX ) ) {
      queue_confirm( ctx, &req, FD_FAILOVER_RECLAIM_REFUSED, FD_FAILOVER_REJECT_SWITCH_PENDING );
      return;
    }
    ctx->confirm_req       = req;
    ctx->confirm_peer_boot = peer_hello->boot_id;
    ctx->action            = FD_FAILOVER_ACTION_CONFIRM_WAIT_QUERY;
    claim_deadline_start( ctx, now );
    return;
  }

  case (ushort)FD_FAILOVER_MSG_CONFIRM: {
    if( FD_UNLIKELY( payload_sz!=sizeof(fd_failover_confirm_t) ) ) break;
    fd_failover_confirm_t confirm;
    fd_memcpy( &confirm, ctx->rx, sizeof(confirm) );
    if( FD_UNLIKELY( !ctx->first_use_pending || ctx->action!=FD_FAILOVER_ACTION_FIRST_USE_WAIT ||
                     !fd_failover_confirm_check( &confirm, &ctx->first_use_req ) ) ) return;
    if( FD_UNLIKELY( ctx->paused || claim_expired( ctx, now ) ) ) {
      first_use_failed( ctx, ctx->paused ? FD_FAILOVER_REJECT_PAUSED : FD_FAILOVER_REJECT_DEADLINE );
      return;
    }
    if( FD_UNLIKELY( !ctx->first_use_authorized || ctx->self_idx || peer->member_idx!=1UL ||
                     ctx->state!=FD_FAILOVER_STATE_STANDBY || ctx->hello.term>=confirm.term ||
                     peer_hello->boot_id!=ctx->first_use_peer_boot ||
                     peer_hello->role!=FD_FAILOVER_ROLE_STANDBY ||
                     !peer_status_fresh( ctx, peer, now ) || peer->status.role!=FD_FAILOVER_ROLE_STANDBY ||
                     peer->status.term>confirm.term || !ctx->step_stem ) ) {
      first_use_failed( ctx, FD_FAILOVER_REJECT_STATE_MISMATCH );
      return;
    }
    if( FD_UNLIKELY( confirm.code!=FD_FAILOVER_RECLAIM_CONFIRMED ) ) {
      first_use_failed( ctx, confirm.code==FD_FAILOVER_RECLAIM_HELD ? FD_FAILOVER_REJECT_HOLDS_IDENTITY
                                                                 : confirm.reason ? confirm.reason : FD_FAILOVER_REJECT_STATE_MISMATCH );
      return;
    }
    ctx->first_use_pending    = 0;
    ctx->first_use_authorized = 0;
    if( ctx->pending_valid && ctx->pending_type==(ushort)FD_FAILOVER_MSG_RECLAIM ) ctx->pending_valid = 0;
    persist( ctx, FD_FAILOVER_STATE_PROMOTING, confirm.term );
    ctx->first_use_promoting = 1;
    ctx->action_term = confirm.term;
    ctx->stuck       = 0;
    deadline_start( ctx, ctx->deadline_slots, now );
    if( FD_UNLIKELY( request_switch( ctx, ctx->step_stem, FD_FAILOVER_SWITCH_KEY_STAKED )==ULONG_MAX ) ) {
      reject_promotion( ctx, FD_FAILOVER_REJECT_SWITCH_PENDING, now );
      return;
    }
    ctx->action = FD_FAILOVER_ACTION_PROMOTE_SWITCH;
    return;
  }

  case (ushort)FD_FAILOVER_MSG_HANDOFF_REQ: {
    /* A handoff request from the peer.  Only a standby may send one. */
    if( FD_UNLIKELY( payload_sz!=sizeof(fd_failover_handoff_req_t) ||
                     peer_hello->role!=FD_FAILOVER_ROLE_STANDBY ) ) break;
    /* The control slot is busy so we cannot answer right now.  The request
       itself is fine, so just ignore it, the peer will retry or time out. */
    if( FD_UNLIKELY( ctx->pending_valid ) ) return;

    fd_failover_handoff_req_t req;
    fd_memcpy( &req, ctx->rx, sizeof(req) );
    fd_failover_status_t local = local_status( ctx, peer );
    uchar reason = FD_FAILOVER_REJECT_NONE;
    uchar code   = fd_failover_handoff_req_check( &req, &local, 0, ctx->min_slots_to_leader,
                                                  ctx->deadline_slots, &reason );
    if( FD_LIKELY( code==FD_FAILOVER_HANDOFF_PROCEED ) ) {
      if( FD_UNLIKELY( ctx->state!=FD_FAILOVER_STATE_ACTIVE || ctx->action!=FD_FAILOVER_ACTION_IDLE ) ) {
        code   = ( ctx->state==FD_FAILOVER_STATE_STANDBY && ctx->action==FD_FAILOVER_ACTION_IDLE )
               ? FD_FAILOVER_HANDOFF_ALREADY_STANDBY
               : FD_FAILOVER_HANDOFF_REJECTED;
        reason = code==FD_FAILOVER_HANDOFF_REJECTED ? FD_FAILOVER_REJECT_BUSY : FD_FAILOVER_REJECT_NONE;
      } else {
        code = fd_failover_handoff_check( &req, &local, &peer->status,
                                          peer_status_fresh( ctx, peer, now ),
                                          peer->cs_sent,
                                          ctx->accept_peer_requests,
                                          0, ctx->min_slots_to_leader,
                                          ctx->deadline_slots, &reason );
      }
    }

    fd_failover_handoff_resp_t resp = {
      .proposed_term  = req.proposed_term,
      .baton_slot     = req.baton_slot,
      .attempt        = req.attempt,
      .deadline_slots = req.deadline_slots,
      .code           = code,
      .reason         = reason,
      .drill          = req.drill,
    };
    FD_TEST( !queue_control( ctx, (ushort)FD_FAILOVER_MSG_HANDOFF_RESP, &resp, sizeof(resp) ) );
    /* A drill runs all the checks but does not switch. */
    if( FD_UNLIKELY( code==FD_FAILOVER_HANDOFF_PROCEED && !req.drill ) ) {
      start_demotion( ctx, ctx->step_stem, req.proposed_term, req.deadline_slots, 1, now );
    }
    return;
  }

  case (ushort)FD_FAILOVER_MSG_HANDOFF_RESP: {
    /* The answer to our request.  On PROCEED the confirmation follows, so we
       just note it, any other code ends the attempt with a reason for the
       operator.  The answer has to match the request we are waiting on field
       for field, so a reply to an attempt we gave up on is not mistaken for
       this one.  A mismatch is not a protocol error, dropping the session
       here would kill the exchange. */
    if( FD_UNLIKELY( payload_sz!=sizeof(fd_failover_handoff_resp_t) ) ) break;
    step_handoff_request( ctx, now );
    fd_failover_handoff_resp_t resp;
    fd_memcpy( &resp, ctx->rx, sizeof(resp) );
    if( FD_UNLIKELY( !ctx->handoff_pending ||
                     !fd_failover_handoff_resp_check( &resp, &ctx->handoff_req ) ) ) {
      return;
    }
    ctx->handoff_pending = 0;
    ctx->handoff_code    = resp.code;
    ctx->handoff_reason  = resp.reason;
    ctx->handoff_term    = resp.proposed_term;
    if( FD_UNLIKELY( resp.code!=FD_FAILOVER_HANDOFF_PROCEED ) ) {
      FD_LOG_WARNING(( "the peer answered the handoff request at term %lu with code %u and reason %u",
                       resp.proposed_term, (uint)resp.code, (uint)resp.reason ));
    }
    return;
  }

  case (ushort)FD_FAILOVER_MSG_DEMOTED: {
    /* The peer says it can no longer sign and hands us its tower. */
    if( FD_UNLIKELY( payload_sz<sizeof(fd_failover_demoted_t) ) ) break;

    fd_failover_demoted_record_t record;
    if( FD_UNLIKELY( demoted_payload_decode( ctx->rx, payload_sz, &record ) ) ) break;
    /* If we already answered a confirmation at this term the peer just did
       not get our reply, so send the same answer again.  This only repeats a
       past outcome, it does not adopt or refuse anew, so it runs ahead of the
       term and tower checks that a resend at the old term would fail. */
    if( FD_UNLIKELY( ctx->reply_dem_term!=ULONG_MAX && record.demoted.term==ctx->reply_dem_term ) ) {
      queue_reply( ctx );
      return;
    }
    if( FD_UNLIKELY( !fd_failover_demoted_term_check( record.demoted.term, ctx->hello.term,
                                                      peer_hello->term, peer_hello->role,
                                                      record.demoted.term==ctx->demoted_accept_term ) ) ) break;
    /* The final tower may not be older than the last one this peer streamed
       to us, a replayed or regressed confirmation would drop lockouts.  The
       watermark is the halt sequence, in the same space as the stream's
       link sequence. */
    if( FD_UNLIKELY( !fd_failover_consensus_final_check( &peer->consensus_floor, peer_hello->boot_id,
                                                         record.demoted.term, record.demoted.watermark,
                                                         record.demoted.last_vote_slot,
                                                         record.state, (ulong)record.demoted.state_len ) ) ) {
      FD_LOG_WARNING(( "the peer's final tower at term %lu is older than the one it streamed, refusing", record.demoted.term ));
      ctx->tower_rollback_cnt++;
      fd_failover_channel_protocol_error( peer->channel, now );
      peer_sync_channel_state( peer );
      return;
    }
    if( FD_UNLIKELY( ctx->state!=FD_FAILOVER_STATE_STANDBY || ctx->action!=FD_FAILOVER_ACTION_IDLE ) ) {
      /* A confirmation in the middle of a transition is left for the operator. */
      return;
    }
    if( FD_UNLIKELY( ctx->paused ) ) {
      /* reject_promotion builds the refusal from action_term, so set that to
         the record's term first.  That is the term the peer matches against. */
      ctx->action_term = record.demoted.term;
      reject_promotion( ctx, FD_FAILOVER_REJECT_PAUSED, now );
      return;
    }
    start_promotion( ctx, &record, record.demoted.term, now );
    return;
  }

  case (ushort)FD_FAILOVER_MSG_PROMOTE_ACK: {
    /* The peer took the identity, so our confirmation did its job.  An ack
       that arrives after we stopped waiting still counts.  An ack we were not
       expecting is ignored, it is not a reason to drop the session. */
    if( FD_UNLIKELY( payload_sz!=sizeof(fd_failover_promote_ack_t) ) ) break;
    fd_failover_promote_ack_t ack;
    fd_memcpy( &ack, ctx->rx, sizeof(ack) );
    if( FD_UNLIKELY( !ctx->send_demoted || ack.term!=ctx->action_term ) ) return;
    if( FD_LIKELY( ctx->demoted_valid ) ) demoted_remove( ctx );
    if( FD_LIKELY( ctx->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK ) ) {
      ctx->action = FD_FAILOVER_ACTION_IDLE;
    }
    ctx->send_demoted = 0;
    ctx->stuck        = 0;
    return;
  }

  case (ushort)FD_FAILOVER_MSG_PROMOTE_REJECTED: {
    /* This proves nobody promoted, so we can take the identity back the
       normal way. */
    if( FD_UNLIKELY( payload_sz!=sizeof(fd_failover_promote_rejected_t) ) ) break;
    fd_failover_promote_rejected_t rej;
    fd_memcpy( &rej, ctx->rx, sizeof(rej) );
    if( FD_UNLIKELY( rej.reason>=FD_FAILOVER_REJECT_CNT ) ) break;
    if( FD_UNLIKELY( !ctx->send_demoted || rej.term!=ctx->action_term+1UL ) ) return;
    FD_LOG_WARNING(( "the peer declined promotion at term %lu for reason %u", rej.term, (uint)rej.reason ));
    /* The refusal used up a term and both sides have to agree on that, or
       every later confirmation is off by one.  Drop the record too, it has
       the old term and a restart would resend it to a peer that already
       refused.  The operator decides what happens next. */
    if( FD_LIKELY( ctx->demoted_valid ) ) demoted_remove( ctx );
    persist( ctx, ctx->state, rej.term );
    ctx->action_term  = rej.term;
    ctx->send_demoted = 0;
    ctx->action       = FD_FAILOVER_ACTION_IDLE;
    ctx->stuck        = 1;
    return;
  }

  case (ushort)FD_FAILOVER_MSG_PAUSE:
  case (ushort)FD_FAILOVER_MSG_RESUME: {
    if( FD_UNLIKELY( payload_sz!=sizeof(fd_failover_control_t) ) ) break;
    fd_failover_control_t msg;
    fd_memcpy( &msg, ctx->rx, sizeof(msg) );
    if( FD_UNLIKELY( msg.term<ctx->hello.term ) ) break;
    ctx->paused = type==(ushort)FD_FAILOVER_MSG_PAUSE;
    persist( ctx, ctx->state, ctx->hello.term );
    return;
  }

  default: break;
  }

  fd_failover_channel_protocol_error( peer->channel, now );
  peer_sync_channel_state( peer );
}

/* Drive one peer's session from the run loop.  Channel time is the
   monotonic clock, wall clock steps must not drop a healthy session. */
static void
peer_poll( fd_failover_tile_ctx_t * ctx,
           fd_failover_peer_t *     peer,
           long                     now,
           int *                    charge_busy ) {
  ulong was = peer->channel_state;
  peer_sync_channel_state( peer );

  ushort type;
  ulong  payload_sz;
  if( FD_UNLIKELY( fd_failover_channel_poll( peer->channel, now, charge_busy, &type, ctx->rx, &payload_sz ) ) ) {
    if( FD_LIKELY( type==(ushort)FD_FAILOVER_MSG_STATUS ) ) {
      fd_failover_status_t status;
      if( FD_UNLIKELY( !fd_failover_status_decode( &status,
                                                   fd_failover_channel_peer_hello( peer->channel ),
                                                   fd_failover_channel_tx_seq( peer->channel ),
                                                   ctx->rx,
                                                   payload_sz ) ) ) {
        fd_failover_channel_protocol_error( peer->channel, now );
        peer_sync_channel_state( peer );
        return;
      }
      peer->status       = status;
      peer->status_valid = 1;
      peer->status_time  = now;
      peer_update_lag( peer );
      peer_rtt_sample( peer, now, &status );
      peer->peer_sent_at = status.sent_at;
      peer->peer_recv_at = now;
    } else if( FD_LIKELY( type==(ushort)FD_FAILOVER_MSG_CONSENSUS_STATE ) ) {
      if( FD_UNLIKELY( !fd_failover_consensus_decode( &peer->consensus,
                                                      ctx->role,
                                                      fd_failover_channel_peer_hello( peer->channel ),
                                                      ctx->rx,
                                                      payload_sz ) ) ) {
        fd_failover_channel_protocol_error( peer->channel, now );
        peer_sync_channel_state( peer );
        return;
      }
      peer_update_lag( peer );
      /* Raise the durable floor, which unlike peer->consensus is not wiped
         on a session edge, so the final tower check still has the history
         after a reconnect. */
      if( FD_LIKELY( fd_failover_consensus_final_check( &peer->consensus_floor, peer->consensus.peer_boot_id,
                                                        peer->consensus.msg.term, peer->consensus.msg.link_seq,
                                                        peer->consensus.msg.vote_slot, peer->consensus.state,
                                                        (ulong)peer->consensus.msg.state_len ) ) )
        peer->consensus_floor = peer->consensus;
    } else {
      handle_control( ctx, peer, type, payload_sz, now );
    }
  }

  peer_sync_channel_state( peer );

  /* The pairing can complete inside the poll above, so check the session
     transition here, after it, not before.  If we sent a confirmation on a
     session that then died, send it again on the new one. */
  if( FD_UNLIKELY( was!=peer->channel_state &&
                   peer->channel_state==FD_FAILOVER_SESSION_PAIRED ) ) {
    ctx->demoted_sent = 0;
    ctx->first_use_sent = 0;
  }

  if( FD_UNLIKELY( fd_failover_channel_state( peer->channel )!=FD_FAILOVER_SESSION_PAIRED ) ) return;

  if( FD_UNLIKELY( !peer->session_setup ) ) {
    /* Size the silence window from the slower of the two cadences, so
       members with different status_interval_millis settings hold. */
    ulong peer_millis = fd_ulong_min( fd_failover_channel_peer_hello( peer->channel )->status_interval_millis, FD_FAILOVER_TILE_PEER_MILLIS_MAX );
    ulong millis      = fd_ulong_max( ctx->status_interval_millis, peer_millis );
    peer->effective_interval = duration_nanos( millis, 1000000UL );
    fd_failover_channel_set_silence( peer->channel,
                                     duration_nanos( fd_ulong_sat_mul( millis, ctx->peer_silence_intervals ), 1000000UL ) );
    peer->session_setup = 1;
  }

  int status_due = !peer->status_sent ||
                   now<peer->last_status ||
                   fd_long_sat_sub( now, peer->last_status )>=ctx->status_interval;
  if( FD_UNLIKELY( status_due && !fd_failover_channel_tx_pending( peer->channel ) ) ) {
    fd_failover_status_t status = local_status( ctx, peer );
    status.sent_at      = (ulong)now;
    status.echo_sent_at = peer->peer_sent_at;
    status.echo_delay   = peer->peer_sent_at ? (ulong)fd_long_sat_sub( now, peer->peer_recv_at ) : 0UL;

    if( FD_LIKELY( !fd_failover_channel_send( peer->channel, now, (ushort)FD_FAILOVER_MSG_STATUS,
                                              (uchar const *)&status, sizeof(status) ) ) ) {
      peer->last_status = now;
      peer->status_sent = 1;
      *charge_busy = 1;
    }
  }

  if( FD_UNLIKELY( ctx->role==FD_FAILOVER_ROLE_ACTIVE &&
                   ctx->cs_valid &&
                   !peer->cs_sent &&
                   !fd_failover_channel_tx_pending( peer->channel ) &&
                   fd_failover_channel_state( peer->channel )==FD_FAILOVER_SESSION_PAIRED &&
                   !fd_failover_channel_send( peer->channel, now, (ushort)FD_FAILOVER_MSG_CONSENSUS_STATE,
                                              ctx->cs_buf, ctx->cs_sz ) ) ) {
    peer->cs_sent = 1;
    *charge_busy = 1;
  }

  peer_sync_channel_state( peer );
}

/* One peer's view of the pool for the status payload and the metrics.
   This reports pool health only, not handoff readiness. */
static void
status_snapshot( fd_failover_tile_ctx_t const *       ctx,
                 ulong                                peer_idx,
                 long                                 now,
                 fd_adminctl_failover_status_resp_t * resp ) {
  fd_adminctl_failover_status_resp_init( resp );
  resp->enabled               = 1U;
  resp->member_cnt            = (uchar)ctx->member_cnt;
  resp->self_idx              = (uchar)ctx->self_idx;
  resp->peer_idx              = (uchar)peer_idx;

  ulong paired = 0UL;
  for( ulong i=0UL; i<ctx->peer_cnt; i++ ) {
    paired += (ulong)( fd_failover_channel_state( ctx->peers[ i ].channel )==FD_FAILOVER_SESSION_PAIRED );
  }
  resp->peers_paired = (uchar)paired;

  fd_failover_peer_t const *            peer  = &ctx->peers[ peer_idx ];
  fd_failover_channel_metrics_t const * m     = fd_failover_channel_metrics( peer->channel );
  fd_failover_status_t                  local = local_status( ctx, peer );

  resp->role                  = local.role;
  resp->term                  = local.term;
  resp->link_state            = (uchar)fd_failover_channel_state( peer->channel );
  resp->status                = local.status;
  /* The operator sees a pending request as busy.  The wire status only
     describes transition work, so asking for a handoff does not make the
     requester fail its own peer readiness check. */
  if( FD_UNLIKELY( ctx->handoff_pending ) ) resp->status |= FD_FAILOVER_STATUS_BUSY;
  resp->flags                 = local.flags;
  resp->replication_lag_slots = peer->lag_slots;
  resp->rtt_nanos             = (ulong)fd_long_max( peer->rtt_nanos, 0L );
  resp->replay_slot           = local.replay_slot;
  resp->root_slot             = local.root_slot;
  resp->turbine_slot          = local.turbine_slot;
  resp->next_leader_slot      = local.next_leader_slot;
  resp->last_vote_slot        = local.last_vote_slot;
  resp->frames_sent           = m->frames_sent;
  resp->frames_received       = m->frames_received;
  resp->tls_failures          = m->tls_fail_cnt;
  resp->wire_failures         = m->wire_fatal_cnt;
  resp->hello_rejections      = m->hello_reject_cnt;
  resp->connection_attempts   = m->connection_attempt_cnt;
  resp->sessions_paired       = m->paired_cnt;
  resp->pending_handshakes    = fd_failover_channel_pending( peer->channel );
  resp->admission_drops       = m->admission_drop_cnt;
  resp->handshake_timeouts    = m->handshake_timeout_cnt;

  if( FD_LIKELY( peer->status_valid ) ) {
    resp->peer_role             = peer->status.role;
    resp->peer_term             = peer->status.term;
    resp->peer_status           = peer->status.status;
    resp->peer_flags            = peer->status.flags;
    resp->peer_status_valid     = 1U;
    resp->peer_replay_slot      = peer->status.replay_slot;
    resp->peer_root_slot        = peer->status.root_slot;
    resp->peer_turbine_slot     = peer->status.turbine_slot;
    resp->peer_next_leader_slot = peer->status.next_leader_slot;
    resp->peer_last_vote_slot   = peer->status.last_vote_slot;
    if( FD_LIKELY( now>=peer->status_time ) ) {
      resp->peer_status_age_nanos = (ulong)fd_long_sat_sub( now, peer->status_time );
    }
  }

  int peer_fresh = peer_status_fresh( ctx, peer, now );

  if( FD_UNLIKELY( resp->link_state!=FD_FAILOVER_SESSION_PAIRED ) ) {
    resp->readiness_reason = FD_FAILOVER_READINESS_LINK_DOWN;
  } else if( FD_UNLIKELY( !peer_fresh ) ) {
    resp->readiness_reason = FD_FAILOVER_READINESS_STATUS_STALE;
  } else if( FD_UNLIKELY( resp->term!=resp->peer_term ||
                          !((resp->role==FD_FAILOVER_ROLE_ACTIVE  && resp->peer_role==FD_FAILOVER_ROLE_STANDBY) ||
                            (resp->role==FD_FAILOVER_ROLE_STANDBY && resp->peer_role==FD_FAILOVER_ROLE_ACTIVE )) ) ) {
    resp->readiness_reason = FD_FAILOVER_READINESS_ROLE_CONFLICT;
  } else {
    uint active_status  = resp->role==FD_FAILOVER_ROLE_ACTIVE ? resp->status      : resp->peer_status;
    uint standby_status = resp->role==FD_FAILOVER_ROLE_ACTIVE ? resp->peer_status : resp->status;
    if( FD_UNLIKELY( active_status ) ) {
      resp->readiness_reason = FD_FAILOVER_READINESS_ACTIVE_UNHEALTHY;
    } else if( FD_UNLIKELY( standby_status & ~FD_FAILOVER_STATUS_REPLAG ) ) {
      resp->readiness_reason = FD_FAILOVER_READINESS_STANDBY_UNHEALTHY;
    } else if( FD_UNLIKELY( standby_status&FD_FAILOVER_STATUS_REPLAG ) ) {
      resp->readiness_reason = FD_FAILOVER_READINESS_STANDBY_BEHIND;
    } else {
      /* Link, cadence, roles and status bits are all in order.  The
         caught-up check and the handoff verdict are not part of this. */
      resp->pool_healthy     = 1U;
      resp->readiness_reason = FD_FAILOVER_READINESS_POOL_HEALTHY;
    }
  }
}

/* Asks the admin tile to switch to the given key.  Only one request can
   be in flight, and the reply comes back with the same id so a late reply
   can be told apart. */
FD_FN_UNUSED static ulong
request_switch( fd_failover_tile_ctx_t * ctx,
                fd_stem_context_t *      stem,
                ulong                    key ) {
  if( FD_UNLIKELY( ctx->admin_out_idx==ULONG_MAX ||
                   ctx->switch_pending_key!=FD_FAILOVER_SWITCH_KEY_CNT || ctx->switch_query_pending ) ) return ULONG_MAX;

  if( FD_UNLIKELY( !++ctx->switch_request_id ) ) ctx->switch_request_id++;
  fd_failover_bus_msg_t * out = fd_chunk_to_laddr( ctx->admin_out_mem, ctx->admin_out_chunk );
  fd_memset( out, 0, sizeof(*out) );
  out->nonce = ctx->switch_request_id;
  fd_failover_switch_req_t req = { .key=key };
  fd_memcpy( out->payload, &req, sizeof(req) );
  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, ctx->admin_out_idx, FD_FAILOVER_BUS_SWITCH_REQ, ctx->admin_out_chunk, sizeof(*out), 0UL, tspub, tspub );
  ctx->admin_out_chunk      = fd_dcache_compact_next( ctx->admin_out_chunk, sizeof(*out), ctx->admin_out_chunk0, ctx->admin_out_wmark );
  ctx->switch_pending_key   = key;
  ctx->switch_result_fresh  = 0;
  ctx->switch_overdue       = 0;
  return ctx->switch_request_id;
}

/* Records the result of the switch we asked for.  A reply for some other
   request is dropped, otherwise an old reply could be mistaken for a
   finished demotion. */
static int
switch_answer( fd_failover_tile_ctx_t * ctx,
               ulong                    nonce ) {
  if( FD_UNLIKELY( ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_CNT ||
                   nonce!=ctx->switch_request_id ) ) {
    FD_LOG_WARNING(( "dropping a stale identity switch answer" ));
    return 0;
  }
  ctx->switch_pending_key  = FD_FAILOVER_SWITCH_KEY_CNT;
  ctx->switch_result_id    = nonce;
  ctx->switch_result_fresh = 1;
  return 1;
}

static ulong
switch_query( fd_failover_tile_ctx_t * ctx,
               fd_stem_context_t *      stem ) {
  if( FD_UNLIKELY( ctx->admin_out_idx==ULONG_MAX || ctx->switch_query_pending ||
                   ctx->switch_pending_key!=FD_FAILOVER_SWITCH_KEY_CNT ) ) return ULONG_MAX;
  if( FD_UNLIKELY( !++ctx->switch_query_id ) ) ctx->switch_query_id++;
  fd_failover_bus_msg_t * out = fd_chunk_to_laddr( ctx->admin_out_mem, ctx->admin_out_chunk );
  fd_memset( out, 0, sizeof(*out) );
  out->nonce = ctx->switch_query_id;
  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, ctx->admin_out_idx, FD_FAILOVER_BUS_SWITCH_QUERY, ctx->admin_out_chunk, sizeof(*out), 0UL, tspub, tspub );
  ctx->admin_out_chunk = fd_dcache_compact_next( ctx->admin_out_chunk, sizeof(*out), ctx->admin_out_chunk0, ctx->admin_out_wmark );
  ctx->switch_query_pending = 1;
  ctx->switch_state_fresh   = 0;
  return ctx->switch_query_id;
}

static int
switch_state_answer( fd_failover_tile_ctx_t * ctx,
                      ulong                    nonce ) {
  if( FD_UNLIKELY( !ctx->switch_query_pending || nonce!=ctx->switch_query_id ) ) return 0;
  ctx->switch_query_pending = 0;
  ctx->switch_state_fresh   = 1;
  return 1;
}

/* Give up the staked identity at a new term.  We write the record and
   send the confirmation only after the switch, so a peer that receives a
   confirmation knows we cannot sign anymore. */
static void
start_demotion( fd_failover_tile_ctx_t * ctx,
                fd_stem_context_t *      stem,
                ulong                    term,
                ulong                    deadline_slots,
                int                      send_demoted,
                long                     now ) {
  if( FD_UNLIKELY( ctx->demoted_valid ) ) demoted_remove( ctx );
  persist( ctx, FD_FAILOVER_STATE_DEMOTING, term );
  ctx->action_term   = term;
  ctx->send_demoted  = !!send_demoted;
  ctx->demoted_sent  = 0;
  ctx->stuck         = 0;
  deadline_start( ctx, deadline_slots, now );
  ctx->action = FD_FAILOVER_ACTION_DEMOTE_SWITCH;
  if( FD_UNLIKELY( request_switch( ctx, stem, FD_FAILOVER_SWITCH_KEY_JUNK )==ULONG_MAX ) ) {
    /* The request never went out and we still have the identity, so the
       record has to say ACTIVE. */
    FD_LOG_WARNING(( "an identity switch could not be requested, standing down at term %lu", term ));
    persist( ctx, FD_FAILOVER_STATE_ACTIVE, term );
    ctx->action = FD_FAILOVER_ACTION_IDLE;
    ctx->stuck  = 1;
  }
}

/* Called once the junk key is installed everywhere.  The final tower is
   our latest one, and the watermark is where the tower tile stopped, so
   the peer can tell a final record from a stream update. */
static void
demotion_switched( fd_failover_tile_ctx_t * ctx,
                   long                     now ) {
  set_role( ctx, FD_FAILOVER_ROLE_STANDBY, now );

  if( FD_UNLIKELY( !ctx->send_demoted ) ) {
    persist( ctx, FD_FAILOVER_STATE_STANDBY, ctx->action_term );
    ctx->action = FD_FAILOVER_ACTION_IDLE;
    return;
  }

  fd_failover_consensus_state_t cs;
  fd_memcpy( &cs, ctx->cs_buf, sizeof(cs) );
  if( FD_UNLIKELY( !ctx->cs_valid || !ctx->cs_sz ||
                   ctx->last_vote_slot==FD_FAILOVER_SLOT_NULL ||
                   cs.vote_slot!=ctx->last_vote_slot || ctx->tower_gap ) ) {
    /* We have no final tower to hand over, or the one we have is not the
       tower of our last vote, or a tower frag was skipped since it was
       built.  The peer gets nothing and cannot promote, which is the safe
       outcome. */
    FD_LOG_WARNING(( "demotion at term %lu has no final tower to confirm for its last vote %lu", ctx->action_term, ctx->last_vote_slot ));
    persist( ctx, FD_FAILOVER_STATE_STANDBY, ctx->action_term );
    ctx->action = FD_FAILOVER_ACTION_IDLE;
    ctx->stuck  = 1;
    return;
  }

  ulong state_len = ctx->cs_sz-sizeof(fd_failover_consensus_state_t);
  fd_memset( &ctx->demoted_record, 0, sizeof(ctx->demoted_record) );
  ctx->demoted_record.demoted.term           = ctx->action_term;
  ctx->demoted_record.demoted.last_vote_slot = ctx->last_vote_slot;
  ctx->demoted_record.demoted.watermark      = ctx->switch_result.tower_watermark;
  ctx->demoted_record.demoted.mode           = (uchar)FD_FAILOVER_MODE_TOWER;
  ctx->demoted_record.demoted.state_len      = (ushort)state_len;
  ctx->demoted_record.source                 = FD_FAILOVER_DEMOTED_SOURCE_LOCAL;
  fd_memcpy( ctx->demoted_record.state, ctx->cs_buf+sizeof(fd_failover_consensus_state_t), state_len );
  fd_sha256_hash( ctx->demoted_record.state, state_len, ctx->demoted_record.digest );

  demoted_write( ctx );
  ctx->demoted_valid = 1;
  persist( ctx, FD_FAILOVER_STATE_STANDBY, ctx->action_term );

  uchar payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];
  fd_memcpy( payload, &ctx->demoted_record.demoted, sizeof(fd_failover_demoted_t) );
  fd_memcpy( payload+sizeof(fd_failover_demoted_t), ctx->demoted_record.state, state_len );
  /* The control slot may still be holding an unsent answer, so if this
     fails we retry from the wait rather than die. */
  (void)queue_control( ctx, (ushort)FD_FAILOVER_MSG_DEMOTED, payload, sizeof(fd_failover_demoted_t)+state_len );
  ctx->action = FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK;
  deadline_start( ctx, ctx->deadline_slots, now );
}

/* Stand back down.  The refusal gives the peer something to act on, so it
   uses up a term and we send it rather than let the peer time out. */
static void
reject_promotion( fd_failover_tile_ctx_t * ctx,
                  uchar                    reason,
                  long                     now ) {
  if( FD_UNLIKELY( ctx->demoted_valid ) ) demoted_remove( ctx );
  ulong dem_term = ctx->action_term;
  ulong term     = dem_term;
  if( FD_LIKELY( term<ULONG_MAX-1UL ) ) term++;
  persist( ctx, FD_FAILOVER_STATE_STANDBY, term );
  set_role( ctx, FD_FAILOVER_ROLE_STANDBY, now );
  ctx->action_term   = term;
  ctx->reject_reason = reason;
  ctx->stuck         = 1;
  ctx->action        = FD_FAILOVER_ACTION_REJECT;
  if( FD_UNLIKELY( ctx->first_use_promoting ) ) {
    ctx->first_use_promoting = 0;
    ctx->action = FD_FAILOVER_ACTION_IDLE;
    FD_LOG_WARNING(( "first-use identity switch failed, remaining passive at term %lu", term ));
    return;
  }

  /* Keep the outcome so a confirmation resent at the old term is answered
     with the same refusal instead of failing the term check and dropping
     the session. */
  ctx->reply_dem_term = dem_term;
  ctx->reply_type     = (ushort)FD_FAILOVER_MSG_PROMOTE_REJECTED;
  ctx->reply_out_term = term;
  ctx->reply_reason   = reason;

  queue_reply( ctx );
  if( FD_UNLIKELY( ctx->reply_owed ) ) {
    /* A control message already holds the slot.  The refusal is owed and
       goes out once the slot drains, there is nothing more to wait on here. */
    ctx->action = FD_FAILOVER_ACTION_IDLE;
  }
}

/* Take the staked identity at the peer's term, once we have its
   confirmation on disk. */
static void
start_promotion( fd_failover_tile_ctx_t *             ctx,
                 fd_failover_demoted_record_t const * record,
                 ulong                                term,
                 long                                 now ) {
  ctx->demoted_record     = *record;
  ctx->demoted_record.source = FD_FAILOVER_DEMOTED_SOURCE_PEER;
  ctx->demoted_valid      = 1;
  ctx->demoted_historical = 0;
  demoted_write( ctx );

  ctx->adopt_state_len = record->demoted.state_len;
  fd_memcpy( ctx->adopt_state, record->state, record->demoted.state_len );

  /* A refusal already used up a term here, so taking the identity at the
     record's term would go backwards. */
  term = fd_ulong_max( term, ctx->hello.term );
  persist( ctx, FD_FAILOVER_STATE_PROMOTING, term );
  ctx->action_term   = term;
  /* Until this tenure produces a vote, its final tower is exactly the
     one adopted from the peer.  A previous local tenure's cached stream
     must never be sent or handed back in its place. */
  fd_failover_consensus_state_t cs = { .term=term, .link_seq=ctx->tower_seen_seq,
                                      .vote_slot=record->demoted.last_vote_slot,
                                      .mode=(uchar)FD_FAILOVER_MODE_TOWER,
                                      .state_len=record->demoted.state_len };
  fd_memcpy( ctx->cs_buf, &cs, sizeof(cs) );
  fd_memcpy( ctx->cs_buf+sizeof(cs), ctx->adopt_state, ctx->adopt_state_len );
  ctx->cs_sz          = sizeof(cs)+ctx->adopt_state_len;
  ctx->cs_valid       = 1;
  ctx->tower_gap      = 0;
  ctx->last_vote_slot = cs.vote_slot;
  /* The peer resends the confirmation until we ack it, so a second copy at
     this term is normal. */
  ctx->demoted_accept_term = term;
  ctx->reject_reason       = FD_FAILOVER_REJECT_NONE;
  ctx->stuck               = 0;
  deadline_start( ctx, ctx->deadline_slots, now );
  ctx->action = FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY;
}

/* Run an operator command.  If we refuse it we say why.  Anything that
   moves the identity needs the peer's confirmation first. */
static ulong
apply_control( fd_failover_tile_ctx_t *               ctx,
               fd_stem_context_t *                    stem,
               fd_adminctl_failover_control_t const * req,
               long                                   now ) {
  fd_failover_peer_t * peer = ctx->peer_cnt ? &ctx->peers[ 0 ] : NULL;
  if( FD_UNLIKELY( !peer ) ) return FD_FAILOVER_CONTROL_RESULT_DISABLED;

  int paired = fd_failover_channel_state( peer->channel )==FD_FAILOVER_SESSION_PAIRED;

  switch( req->cmd ) {

  case FD_ADMINCTL_FAILOVER_CMD_PAUSE:
  case FD_ADMINCTL_FAILOVER_CMD_RESUME: {
    /* pause has to survive a restart, so write it to the role file first.
       Tell the peer too so it shows up on both sides. */
    ctx->paused = req->cmd==FD_ADMINCTL_FAILOVER_CMD_PAUSE;
    persist( ctx, ctx->state, ctx->hello.term );
    fd_failover_control_t msg = { .term=ctx->hello.term };
    ushort type = (ushort)( ctx->paused ? FD_FAILOVER_MSG_PAUSE : FD_FAILOVER_MSG_RESUME );
    /* Coalesce with a pause or resume already waiting on a down link, so the
       peer gets the latest intent rather than a stale one stuck in the slot. */
    if( FD_UNLIKELY( ctx->pending_valid &&
                     ( ctx->pending_type==(ushort)FD_FAILOVER_MSG_PAUSE ||
                       ctx->pending_type==(ushort)FD_FAILOVER_MSG_RESUME ) ) ) {
      ctx->pending_type = type;
      ctx->pending_sz   = (ushort)sizeof(msg);
      fd_memcpy( ctx->pending, &msg, sizeof(msg) );
    } else {
      (void)queue_control( ctx, type, &msg, sizeof(msg) );
    }
    return FD_ADMINCTL_RESULT_SUCCESS;
  }

  case FD_ADMINCTL_FAILOVER_CMD_DEMOTE: {
    /* Drop the identity without promoting anyone.  Used to take the active
       out of service. */
    if( FD_UNLIKELY( ctx->action!=FD_FAILOVER_ACTION_IDLE ) ) return FD_FAILOVER_CONTROL_RESULT_BUSY;
    if( FD_UNLIKELY( ctx->state!=FD_FAILOVER_STATE_ACTIVE ) ) return FD_FAILOVER_CONTROL_RESULT_BAD_ROLE;
    if( FD_UNLIKELY( ctx->paused ) ) return FD_FAILOVER_CONTROL_RESULT_PAUSED;
    if( FD_UNLIKELY( ctx->hello.term>=ULONG_MAX-1UL ) ) return FD_FAILOVER_CONTROL_RESULT_UNSUPPORTED;
    /* No confirmation, nobody is supposed to promote. */
    start_demotion( ctx, stem, ctx->hello.term+1UL, ctx->deadline_slots, 0, now );
    return FD_ADMINCTL_RESULT_SUCCESS;
  }

  case FD_ADMINCTL_FAILOVER_CMD_HANDOFF:
  case FD_ADMINCTL_FAILOVER_CMD_DRILL: {
    /* Ask the active to hand over.  A drill goes through all the checks but
       stops short of switching. */
    if( FD_UNLIKELY( ctx->action!=FD_FAILOVER_ACTION_IDLE || ctx->pending_valid || ctx->handoff_pending ) ) return FD_FAILOVER_CONTROL_RESULT_BUSY;
    if( FD_UNLIKELY( !paired || !peer->status_valid ) ) return FD_FAILOVER_CONTROL_RESULT_NOT_PAIRED;
    if( FD_UNLIKELY( ctx->paused ) ) return FD_FAILOVER_CONTROL_RESULT_PAUSED;
    if( FD_UNLIKELY( ctx->hello.term>=ULONG_MAX-1UL ) ) return FD_FAILOVER_CONTROL_RESULT_UNSUPPORTED;

    int drill = req->cmd==FD_ADMINCTL_FAILOVER_CMD_DRILL;
    if( FD_UNLIKELY( ctx->state==FD_FAILOVER_STATE_ACTIVE ) ) {
      /* If we are the active, handoff means demote ourselves and let the spare
         promote.  It runs the same pre-checks a spare's request gets, our
         own readiness and leader window included, so the identity is not
         given up to a spare that cannot take it or from a machine that is
         about to lead, and a drill runs them all and moves nothing. */
      fd_failover_handoff_req_t msg = {
        .proposed_term  = ctx->hello.term+1UL,
        .baton_slot     = 0UL,
        .attempt        = 0U,
        .reason         = (uchar)( drill ? FD_FAILOVER_HANDOFF_REASON_DRILL
                                         : FD_FAILOVER_HANDOFF_REASON_OPERATOR ),
        .deadline_slots = (uint)ctx->deadline_slots,
        .drill          = (uchar)!!drill,
      };
      fd_failover_status_t local = local_status( ctx, peer );
      uchar reason;
      uchar code = fd_failover_handoff_check( &msg, &local, &peer->status, peer_status_fresh( ctx, peer, now ),
                                              peer->cs_sent, ctx->accept_peer_requests, 1,
                                              ctx->min_slots_to_leader, ctx->deadline_slots, &reason );
      ctx->handoff_code   = code;
      ctx->handoff_reason = reason;
      ctx->handoff_term   = msg.proposed_term;
      if( FD_UNLIKELY( code!=FD_FAILOVER_HANDOFF_PROCEED ) ) {
        /* The spare's own status refusing keeps its result, the reasons
           this machine adds answer precondition, and the status names the
           reason either way. */
        FD_LOG_WARNING(( "handoff refused by a pre-check (reason %u)", (uint)reason ));
        switch( reason ) {
        case FD_FAILOVER_REJECT_PAUSED:         return FD_FAILOVER_CONTROL_RESULT_PAUSED;
        case FD_FAILOVER_REJECT_BUSY:           return FD_FAILOVER_CONTROL_RESULT_BUSY;
        case FD_FAILOVER_REJECT_STATUS_STALE:
        case FD_FAILOVER_REJECT_PEER_UNHEALTHY:
        case FD_FAILOVER_REJECT_PEER_BEHIND:    return FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY;
        default:                                return FD_FAILOVER_CONTROL_RESULT_PRECONDITION;
        }
      }
      if( FD_UNLIKELY( drill ) ) return FD_ADMINCTL_RESULT_SUCCESS;
      start_demotion( ctx, stem, msg.proposed_term, ctx->deadline_slots, 1, now );
      return FD_ADMINCTL_RESULT_SUCCESS;
    }

    ulong term = fd_ulong_max( ctx->hello.term, peer->status.term )+1UL;
    fd_failover_handoff_req_t msg = {
      .proposed_term  = term,
      .baton_slot     = 0UL,
      .attempt        = 0U,
      .reason         = (uchar)( drill ? FD_FAILOVER_HANDOFF_REASON_DRILL
                                       : FD_FAILOVER_HANDOFF_REASON_STANDBY ),
      .deadline_slots = (uint)ctx->deadline_slots,
      .drill          = (uchar)!!drill,
    };
    if( FD_UNLIKELY( queue_control( ctx, (ushort)FD_FAILOVER_MSG_HANDOFF_REQ, &msg, sizeof(msg) ) ) ) {
      return FD_FAILOVER_CONTROL_RESULT_BUSY;
    }
    /* Keep the request around, the answer gets matched against it. */
    ctx->handoff_req     = msg;
    ctx->handoff_pending = 1;
    ctx->handoff_session = fd_failover_channel_metrics( peer->channel )->paired_cnt;
    ctx->handoff_deadline_slot = ctx->replay_slot==FD_FAILOVER_SLOT_NULL
                              ? FD_FAILOVER_SLOT_NULL : fd_ulong_sat_add( ctx->replay_slot, ctx->deadline_slots );
    ulong seconds = fd_ulong_max( 30UL, fd_ulong_min( ctx->deadline_slots, 300UL ) );
    ctx->handoff_deadline = fd_long_sat_add( now, (long)(seconds*1000000000UL) );
    ctx->handoff_code    = (uchar)FD_FAILOVER_HANDOFF_CODE_CNT;
    ctx->handoff_reason  = FD_FAILOVER_REJECT_NONE;
    return FD_ADMINCTL_RESULT_SUCCESS;
  }

  case FD_ADMINCTL_FAILOVER_CMD_PROMOTE: {
    /* Take the identity.  This needs the peer's demotion confirmation on
       disk.  --force does not skip that, it only requires the operator to
       spell out the pubkey. */
    if( FD_UNLIKELY( ctx->action!=FD_FAILOVER_ACTION_IDLE ) ) return FD_FAILOVER_CONTROL_RESULT_BUSY;
    if( FD_UNLIKELY( ctx->state!=FD_FAILOVER_STATE_STANDBY ) ) return FD_FAILOVER_CONTROL_RESULT_BAD_ROLE;
    if( FD_UNLIKELY( ctx->paused ) ) return FD_FAILOVER_CONTROL_RESULT_PAUSED;
    /* Our own outgoing confirmation does not count.  It says we stopped, it
       says nothing about whether the peer promoted, and using it could put
       the identity on both machines. */
    if( FD_UNLIKELY( !ctx->demoted_valid || ctx->demoted_historical || ctx->send_demoted ||
                     ctx->demoted_record.source!=FD_FAILOVER_DEMOTED_SOURCE_PEER ||
                     ctx->demoted_record.demoted.term!=ctx->hello.term ) ) return FD_FAILOVER_CONTROL_RESULT_NO_EVIDENCE;
    if( FD_UNLIKELY( req->force && !fd_memeq( req->staked_pubkey, ctx->hello.staked_pubkey, 32UL ) ) )
      return FD_FAILOVER_CONTROL_RESULT_BAD_IDENTITY;
    /* The confirmation on disk may not be older than the tower this peer
       streamed while it was active, the same check the wire path runs.
       The floor outlives the session that carried the stream, so a
       reconnect in between does not lose the history it is checked
       against. */
    if( FD_UNLIKELY( !fd_failover_consensus_final_check( &peer->consensus_floor,
                                                         fd_failover_channel_peer_hello( peer->channel )->boot_id,
                                                         ctx->demoted_record.demoted.term,
                                                         ctx->demoted_record.demoted.watermark,
                                                         ctx->demoted_record.demoted.last_vote_slot,
                                                         ctx->demoted_record.state,
                                                         (ulong)ctx->demoted_record.demoted.state_len ) ) ) {
      ctx->tower_rollback_cnt++;
      return FD_FAILOVER_CONTROL_RESULT_TOWER_ROLLBACK;
    }
    start_promotion( ctx, &ctx->demoted_record, ctx->demoted_record.demoted.term, now );
    return FD_ADMINCTL_RESULT_SUCCESS;
  }

  case FD_ADMINCTL_FAILOVER_CMD_CLEAR: {
    /* stuck means the record may not match reality, so it is lowered only
       once reality has been asked.  Nothing may be moving: a switch or a
       transition in flight is exactly the condition the flag reports,
       and a confirmation still owed keeps its own stuck live. */
    if( FD_UNLIKELY( ctx->action!=FD_FAILOVER_ACTION_IDLE ) ) return FD_FAILOVER_CONTROL_RESULT_BUSY;
    if( FD_UNLIKELY( ctx->switch_pending_key!=FD_FAILOVER_SWITCH_KEY_CNT ) ) return FD_FAILOVER_CONTROL_RESULT_BUSY;
    if( FD_UNLIKELY( ctx->send_demoted ) ) return FD_FAILOVER_CONTROL_RESULT_NO_EVIDENCE;
    if( FD_LIKELY( !ctx->stuck ) ) return FD_ADMINCTL_RESULT_SUCCESS;
    if( FD_UNLIKELY( switch_query( ctx, stem )==ULONG_MAX ) ) return FD_FAILOVER_CONTROL_RESULT_BUSY;
    deadline_start( ctx, ctx->deadline_slots, now );
    ctx->action = FD_FAILOVER_ACTION_CLEAR_WAIT_QUERY;
    return FD_FAILOVER_TILE_RESULT_DEFERRED;
  }

  default: break;
  }
  return FD_FAILOVER_CONTROL_RESULT_UNSUPPORTED;
}

/* publish_control_response answers a control request on the bus with
   the controller's state after the command. */
static void
publish_control_response( fd_failover_tile_ctx_t * ctx,
                          fd_stem_context_t *      stem,
                          ulong                    nonce,
                          ulong                    result ) {
  fd_adminctl_failover_control_resp_t answer = {
    .version = FD_ADMINCTL_FAILOVER_CONTROL_PAYLOAD_VERSION,
    .term    = ctx->hello.term,
    .state   = (uchar)ctx->state,
    .role    = (uchar)ctx->role,
    .paused  = (uchar)!!ctx->paused,
  };
  fd_failover_bus_msg_t * out = fd_chunk_to_laddr( ctx->admin_out_mem, ctx->admin_out_chunk );
  fd_memset( out, 0, sizeof(*out) );
  out->nonce  = nonce;
  out->result = result;
  fd_memcpy( out->payload, &answer, sizeof(answer) );
  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, ctx->admin_out_idx, FD_FAILOVER_BUS_CONTROL_RESP, ctx->admin_out_chunk, sizeof(*out), 0UL, tspub, tspub );
  ctx->admin_out_chunk = fd_dcache_compact_next( ctx->admin_out_chunk, sizeof(*out), ctx->admin_out_chunk0, ctx->admin_out_wmark );
}

/* Answer one bus request.  The admin tile validated the ABI already, so
   only the peer selection can fail here. */
static void
serve_bus_request( fd_failover_tile_ctx_t * ctx,
                   fd_stem_context_t *      stem,
                   long                     now ) {
  fd_failover_bus_msg_t const * req = &ctx->bus_req;

  /* Run the command before grabbing the response chunk.  The command itself
     may publish a switch request on this link, which would advance the
     chunk under us. */
  if( FD_UNLIKELY( ctx->bus_req_sig==FD_FAILOVER_BUS_CONTROL_REQ ) ) {
    fd_adminctl_failover_control_t control;
    fd_memcpy( &control, req->payload, sizeof(control) );
    ulong result = apply_control( ctx, stem, &control, now );
    if( FD_UNLIKELY( result==FD_FAILOVER_TILE_RESULT_DEFERRED ) ) {
      /* The command's answer waits on the admin tile.  The nonce is kept
         apart from the request, which a later frame may overwrite. */
      ctx->clear_parked = 1;
      ctx->clear_nonce  = req->nonce;
      return;
    }
    publish_control_response( ctx, stem, req->nonce, result );
    return;
  }

  fd_failover_bus_msg_t * out = fd_chunk_to_laddr( ctx->admin_out_mem, ctx->admin_out_chunk );
  fd_memset( out, 0, sizeof(*out) );
  out->nonce  = req->nonce;
  out->result = FD_ADMINCTL_RESULT_SUCCESS;
  fd_adminctl_failover_status_req_t const * status_req = (fd_adminctl_failover_status_req_t const *)req->payload;
  if( FD_UNLIKELY( status_req->peer_idx>=ctx->peer_cnt ) ) {
    out->result = FD_FAILOVER_STATUS_RESULT_NO_SUCH_PEER;
  } else {
    status_snapshot( ctx, status_req->peer_idx, now, (fd_adminctl_failover_status_resp_t *)out->payload );
  }

  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, ctx->admin_out_idx, FD_FAILOVER_BUS_STATUS_RESP, ctx->admin_out_chunk, sizeof(*out), 0UL, tspub, tspub );
  ctx->admin_out_chunk = fd_dcache_compact_next( ctx->admin_out_chunk, sizeof(*out), ctx->admin_out_chunk0, ctx->admin_out_wmark );
}

static inline void
metrics_write( fd_failover_tile_ctx_t * ctx ) {
  fd_adminctl_failover_status_resp_t status;
  status_snapshot( ctx, 0UL, fd_failover_clock(), &status );

  int peer_valid = !!status.peer_status_valid;
  int lag_valid  = ( status.replication_lag_slots!=FD_FAILOVER_SLOT_NULL );
  FD_MGAUGE_SET( FAILOV, MEMBER_CNT,             status.member_cnt );
  FD_MGAUGE_SET( FAILOV, PEERS_PAIRED,           status.peers_paired );
  FD_MGAUGE_SET( FAILOV, LINK,                   status.link_state );
  FD_MGAUGE_SET( FAILOV, ROLE,                   status.role );
  FD_MGAUGE_SET( FAILOV, TERM,                   status.term );
  FD_MGAUGE_SET( FAILOV, STATUS,                 status.status );
  FD_MGAUGE_SET( FAILOV, PEER_ROLE,              peer_valid ? status.peer_role : 0UL );
  FD_MGAUGE_SET( FAILOV, PEER_TERM,              peer_valid ? status.peer_term : 0UL );
  FD_MGAUGE_SET( FAILOV, PEER_STATUS,            peer_valid ? status.peer_status : 0UL );
  FD_MGAUGE_SET( FAILOV, REPLICATION_LAG_SLOTS,  lag_valid ? status.replication_lag_slots : 0UL );
  FD_MGAUGE_SET( FAILOV, RTT_NANOS,              status.rtt_nanos );
  FD_MGAUGE_SET( FAILOV, PEER_STATUS_VALID,      (ulong)peer_valid );
  FD_MGAUGE_SET( FAILOV, PEER_STATUS_AGE_NANOS,  status.peer_status_age_nanos==ULONG_MAX ? 0UL : status.peer_status_age_nanos );
  FD_MGAUGE_SET( FAILOV, REPLICATION_LAG_VALID,  (ulong)lag_valid );
  FD_MGAUGE_SET( FAILOV, POOL_HEALTHY,           status.pool_healthy );
  FD_MGAUGE_SET( FAILOV, POOL_HEALTH_REASON,     status.readiness_reason );
  FD_MCNT_SET  ( FAILOV, FRAMES_SENT,            status.frames_sent );
  FD_MCNT_SET  ( FAILOV, FRAMES_RECEIVED,        status.frames_received );
  FD_MCNT_SET  ( FAILOV, TLS_FAILURES,           status.tls_failures );
  FD_MCNT_SET  ( FAILOV, WIRE_FAILURES,          status.wire_failures );
  FD_MCNT_SET  ( FAILOV, HELLO_REJECTIONS,       status.hello_rejections );
  FD_MCNT_SET  ( FAILOV, CONNECTION_ATTEMPTS,    status.connection_attempts );
  FD_MCNT_SET  ( FAILOV, SESSIONS_PAIRED,        status.sessions_paired );
  FD_MGAUGE_SET( FAILOV, PENDING_HANDSHAKES,     status.pending_handshakes );
  FD_MCNT_SET  ( FAILOV, ADMISSION_DROPS,        status.admission_drops );
  FD_MCNT_SET  ( FAILOV, HANDSHAKE_TIMEOUTS,     status.handshake_timeouts );
  FD_MCNT_SET  ( FAILOV, SWITCH_OVERDUE,         ctx->switch_overdue_cnt );
  FD_MCNT_SET  ( FAILOV, TOWER_ROLLBACK,         ctx->tower_rollback_cnt );
  FD_MCNT_SET  ( FAILOV, IDENTITY_MISMATCH,      ctx->identity_mismatch_cnt );
}

static inline void
after_credit( fd_failover_tile_ctx_t * ctx,
              fd_stem_context_t *      stem,
              int *                    opt_poll_in FD_PARAM_UNUSED,
              int *                    charge_busy ) {
  if( FD_UNLIKELY( ctx->slot_done_fresh ) ) {
    ctx->slot_done_fresh = 0;
    consume_slot_done( ctx, &ctx->slot_done );
  }
  long now = fd_failover_clock();
  ctx->step_stem = stem;
  step_controller( ctx, stem, now );
  for( ulong i=0UL; i<ctx->peer_cnt; i++ ) peer_poll( ctx, &ctx->peers[ i ], now, charge_busy );
  maybe_first_use( ctx, now );
  for( ulong i=0UL; i<ctx->peer_cnt; i++ ) pending_flush( ctx, &ctx->peers[ i ], now );
  ctx->step_stem = NULL;
  if( FD_UNLIKELY( ctx->bus_req_fresh ) ) {
    ctx->bus_req_fresh = 0;
    serve_bus_request( ctx, stem, now );
    *charge_busy = 1;
  }
}

static inline int
before_frag( fd_failover_tile_ctx_t * ctx,
             ulong                    in_idx,
             ulong                    seq,
             ulong                    sig ) {
  if( FD_LIKELY( in_idx==ctx->tower_in_idx ) ) {
    /* A skipped frag may have been a vote.  A slot done counts toward the
       watermark in after_frag, once the stem has checked the copy.  One
       abandoned to an overrun must not count, or the final tower would be
       taken from the cache with that vote missing.  Other frags hold no
       vote and count here. */
    if( FD_UNLIKELY( ctx->tower_seen_seq!=ULONG_MAX && seq!=fd_seq_inc( ctx->tower_seen_seq, 1UL ) ) ) ctx->tower_gap = 1;
    if( FD_UNLIKELY( sig!=FD_TOWER_SIG_SLOT_DONE ) ) {
      ctx->tower_seen_seq = seq;
      return 1;
    }
    return 0;
  }
  if( FD_LIKELY( in_idx==ctx->replay_in_idx ) ) {
    /* Every executed transaction passes here too, so this is the
       cheapest possible refusal of everything but the two we read. */
    return sig!=REPLAY_SIG_RESET && sig!=REPLAY_SIG_BECAME_LEADER;
  }
  if( FD_UNLIKELY( in_idx==ctx->admin_in_idx ) ) {
    /* Status and control requests, and switch replies.  Dropping a switch
       reply here would leave the switch hanging forever. */
    return sig!=FD_FAILOVER_BUS_STATUS_REQ &&
           sig!=FD_FAILOVER_BUS_CONTROL_REQ &&
           sig!=FD_FAILOVER_BUS_SWITCH_RESP &&
           sig!=FD_FAILOVER_BUS_SWITCH_STATE;
  }
  return 0;
}

static void
during_frag( fd_failover_tile_ctx_t * ctx,
             ulong                    in_idx,
             ulong                    seq FD_PARAM_UNUSED,
             ulong                    sig FD_PARAM_UNUSED,
             ulong                    chunk,
             ulong                    sz,
             ulong                    ctl FD_PARAM_UNUSED ) {
  if( FD_UNLIKELY( in_idx==ctx->adopt_in_idx ) ) {
    if( FD_UNLIKELY( chunk<ctx->adopt_in_chunk0 || chunk>ctx->adopt_in_wmark || sz!=sizeof(fd_tower_adopt_result_t) ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->adopt_in_chunk0, ctx->adopt_in_wmark ));
    }
    fd_memcpy( &ctx->adopt_result, fd_chunk_to_laddr_const( ctx->adopt_in_mem, chunk ), sizeof(fd_tower_adopt_result_t) );
    return;
  }
  if( FD_UNLIKELY( in_idx==ctx->admin_in_idx ) ) {
    if( FD_UNLIKELY( chunk<ctx->admin_in_chunk0 || chunk>ctx->admin_in_wmark || sz!=sizeof(fd_failover_bus_msg_t) ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->admin_in_chunk0, ctx->admin_in_wmark ));
    }
    fd_failover_bus_msg_t const * msg = fd_chunk_to_laddr_const( ctx->admin_in_mem, chunk );
    if( FD_UNLIKELY( sig==FD_FAILOVER_BUS_SWITCH_STATE ) ) {
      fd_memcpy( &ctx->switch_response, msg->payload, sizeof(ctx->switch_response) );
      ctx->switch_state_nonce = msg->nonce;
      return;
    }
    if( FD_UNLIKELY( sig==FD_FAILOVER_BUS_SWITCH_RESP ) ) {
      fd_memcpy( &ctx->switch_response, msg->payload, sizeof(ctx->switch_response) );
      ctx->switch_answer_nonce = msg->nonce;
      return;
    }
    fd_memcpy( &ctx->bus_req, msg, sizeof(fd_failover_bus_msg_t) );
    ctx->bus_req_sig = sig;
    return;
  }
  if( FD_UNLIKELY( in_idx==ctx->replay_in_idx ) ) {
    if( FD_LIKELY( sig!=REPLAY_SIG_RESET ) ) return; /* becoming leader is an edge, nothing to copy */
    if( FD_UNLIKELY( chunk<ctx->replay_in_chunk0 || chunk>ctx->replay_in_wmark || sz!=sizeof(fd_poh_reset_t) ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->replay_in_chunk0, ctx->replay_in_wmark ));
    }
    fd_memcpy( &ctx->reset, fd_chunk_to_laddr_const( ctx->replay_in_mem, chunk ), sizeof(fd_poh_reset_t) );
    return;
  }
  if( FD_UNLIKELY( in_idx!=ctx->tower_in_idx ) ) return;
  if( FD_UNLIKELY( chunk<ctx->tower_in_chunk0 || chunk>ctx->tower_in_wmark || sz!=sizeof(fd_tower_msg_t) ) ) {
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->tower_in_chunk0, ctx->tower_in_wmark ));
  }
  fd_memcpy( &ctx->slot_done, fd_chunk_to_laddr_const( ctx->tower_in_mem, chunk ), sizeof(fd_tower_slot_done_t) );
}

static void
after_frag( fd_failover_tile_ctx_t * ctx,
            ulong                    in_idx,
            ulong                    seq,
            ulong                    sig,
            ulong                    sz FD_PARAM_UNUSED,
            ulong                    tsorig FD_PARAM_UNUSED,
            ulong                    tspub FD_PARAM_UNUSED,
            fd_stem_context_t *      stem FD_PARAM_UNUSED ) {
  if( FD_UNLIKELY( in_idx==ctx->adopt_in_idx ) ) {
    ctx->adopt_result_id    = sig;
    ctx->adopt_result_fresh = 1;
    return;
  }
  if( FD_UNLIKELY( in_idx==ctx->admin_in_idx ) ) {
    if( FD_UNLIKELY( sig==FD_FAILOVER_BUS_SWITCH_STATE ) ) {
      if( FD_LIKELY( switch_state_answer( ctx, ctx->switch_state_nonce ) ) ) ctx->switch_state = ctx->switch_response;
      return;
    }
    if( FD_UNLIKELY( sig==FD_FAILOVER_BUS_SWITCH_RESP ) ) {
      /* The accepted result can remain live while the tower drains.
         Commit the payload only after the stem and nonce checks pass. */
      if( FD_LIKELY( switch_answer( ctx, ctx->switch_answer_nonce ) ) ) ctx->switch_result = ctx->switch_response;
      return;
    }
    /* Answered from after_credit, where a publish credit is available. */
    ctx->bus_req_fresh = 1;
    return;
  }
  if( FD_UNLIKELY( in_idx==ctx->replay_in_idx ) ) {
    if( FD_UNLIKELY( sig==REPLAY_SIG_BECAME_LEADER ) ) ctx->is_leader = 1;
    else consume_reset( ctx, &ctx->reset );
    return;
  }
  if( FD_LIKELY( in_idx!=ctx->tower_in_idx ) ) return;
  ctx->slot_done_seq   = seq;
  ctx->slot_done_fresh = 1;
  /* after_credit folds the slot done in before it steps the controller,
     so the barrier never counts a frag whose tower is not in the cache. */
  ctx->tower_seen_seq  = seq;
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  fd_failover_tile_ctx_t const * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  /* One policy covers both directions.  A member that only dials has no
     listener, so accept4 is pinned to a descriptor that is never a socket
     and would fail with EBADF.  The channel never calls accept4 on a
     dialing peer anyway. */
  populate_sock_filter_policy_fd_failover_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)pool_listen_fd( ctx ),
                                               (uint)ctx->role_dir_fd, (uint)ctx->role_file_fd );
  return sock_filter_policy_fd_failover_tile_instr_cnt;
}

/* Candidates, one listener and the tile's own descriptors.  This tracks
   the member count so the limit survives a larger pool. */
static ulong
rlimit_file_cnt( fd_topo_t const *      topo FD_PARAM_UNUSED,
                 fd_topo_tile_t const * tile ) {
  ulong peer_cnt = fd_ulong_sat_sub( tile->failov.member_cnt, 1UL );
  return FD_FAILOVER_CHANNEL_CANDIDATE_MAX*peer_cnt + peer_cnt + 8UL;
}

/* Landlock confines writes to the role file directory. */
static int
populate_allowed_write_path_fd( fd_topo_t const *      topo,
                                fd_topo_tile_t const * tile ) {
  fd_failover_tile_ctx_t const * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  return ctx->role_dir_fd;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  fd_failover_tile_ctx_t const * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  int logfile_fd = fd_log_private_logfile_fd();
  int listen_fd  = pool_listen_fd( ctx );

  ulong required_fds = 3UL + (ulong)(-1!=logfile_fd) + (ulong)(-1!=listen_fd);
  if( FD_UNLIKELY( out_fds_cnt<required_fds ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY(   -1!=logfile_fd ) ) out_fds[ out_cnt++ ] = logfile_fd; /* logfile */
  if( FD_UNLIKELY( -1!=listen_fd  ) ) out_fds[ out_cnt++ ] = listen_fd;  /* pool listener */
  out_fds[ out_cnt++ ] = ctx->role_dir_fd;  /* role file directory */
  out_fds[ out_cnt++ ] = ctx->role_file_fd; /* reserved role file descriptor */
  return out_cnt;
}

/* Worst case per iteration is an adopt request, a switch request and a
   bus response, so the burst is 3. */
#define STEM_BURST (3UL)
#define STEM_LAZY  ((long)1e6) /* 1ms */

#define STEM_CALLBACK_CONTEXT_TYPE  fd_failover_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_failover_tile_ctx_t)

#define STEM_CALLBACK_METRICS_WRITE metrics_write
#define STEM_CALLBACK_AFTER_CREDIT  after_credit
#define STEM_CALLBACK_BEFORE_FRAG   before_frag
#define STEM_CALLBACK_DURING_FRAG   during_frag
#define STEM_CALLBACK_AFTER_FRAG    after_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_failov = {
  .name                     = "failov",
  .keep_host_networking     = 1,
  .allow_connect            = 1,
  .rlimit_file_cnt_fn       = rlimit_file_cnt,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .populate_allowed_write_path_fd = populate_allowed_write_path_fd,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
