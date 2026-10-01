#include "../../disco/topo/fd_topo.h"
#include "../../disco/topo/fd_dns_resolve.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/keyguard/fd_keyguard.h"
#include "../../disco/keyguard/fd_keyguard_client.h"
#include "../../flamenco/gossip/fd_gossip_message.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/hex/fd_hex.h"
#include "../../ballet/txn/fd_txn.h"
#include "../../choreo/tower/fd_tower_serdes.h"
#include "../../util/fd_version.h"
#include "../../util/net/fd_ip4.h"
#include "../tower/fd_tower_tile.h"
#include "../votor/fd_votor_tile.h"

#include "fd_failover_bus.h"
#include "fd_failover_channel.h"

#include <string.h>
#include <sys/socket.h>

#include "generated/fd_failover_tile_seccomp.h"

/* The votor answers adoptions in the tower tile's layout, with its
   vote_bound where the tower tile has acct_vote_slot, which is what
   floor_covered and alpenglow_adopted read under Alpenglow.  Its codes
   match the tower tile's, and STALE has no tower tile code, see
   votor_adopt_code. */
FD_STATIC_ASSERT( FD_VOTOR_ADOPT_SUCCESS            ==FD_TOWER_ADOPT_SUCCESS,             adopt_codes );
FD_STATIC_ASSERT( FD_VOTOR_ADOPT_ERR_DECODE         ==FD_TOWER_ADOPT_ERR_DECODE,          adopt_codes );
FD_STATIC_ASSERT( FD_VOTOR_ADOPT_ERR_INVALID        ==FD_TOWER_ADOPT_ERR_INVALID,         adopt_codes );
FD_STATIC_ASSERT( FD_VOTOR_ADOPT_ERR_UNREPLAYED_ROOT==FD_TOWER_ADOPT_ERR_UNREPLAYED_ROOT, adopt_codes );
FD_STATIC_ASSERT( FD_VOTOR_ADOPT_ERR_BLOCK_MISMATCH ==FD_TOWER_ADOPT_ERR_BLOCK_MISMATCH,  adopt_codes );
FD_STATIC_ASSERT( FD_VOTOR_ADOPT_ERR_UNREPLAYED     ==FD_TOWER_ADOPT_ERR_UNREPLAYED,      adopt_codes );
FD_STATIC_ASSERT( FD_VOTOR_ADOPT_ERR_STALE          > FD_TOWER_ADOPT_ERR_UNREPLAYED,      adopt_codes );
FD_STATIC_ASSERT( sizeof(fd_votor_adopt_result_t)==sizeof(fd_tower_adopt_result_t), adopt_layout );
FD_STATIC_ASSERT( offsetof(fd_votor_adopt_result_t,result)    ==offsetof(fd_tower_adopt_result_t,result),         adopt_layout );
FD_STATIC_ASSERT( offsetof(fd_votor_adopt_result_t,root)      ==offsetof(fd_tower_adopt_result_t,root),           adopt_layout );
FD_STATIC_ASSERT( offsetof(fd_votor_adopt_result_t,vote_slot) ==offsetof(fd_tower_adopt_result_t,vote_slot),      adopt_layout );
FD_STATIC_ASSERT( offsetof(fd_votor_adopt_result_t,vote_bound)==offsetof(fd_tower_adopt_result_t,acct_vote_slot), adopt_layout );

/* The failov tile owns the socket to the other failover machine and is
   the only tile that keeps host networking for it.  It holds no private
   key.  The sign tile signs our member certificate with the staked key
   and our TLS handshakes with the junk key.  The admin tile keeps the
   identity switch and stays off the network. */

/* Idle socket poll spacing */
#define FD_FAILOVER_TILE_POLL_NANOS (50000L) /* 50us */

/* A transition gives up once replay passes this many slots past its
   start. */
#define FD_FAILOVER_DEADLINE_SLOTS (64UL)

/* A vote account tower short of the coverage floor is taken once replay
   passes the floor by this much, upstream's rule for switching
   identities. */
#define FD_FAILOVER_FLOOR_SLACK_SLOTS (512UL)

/* The promotion's replay and adopt waits also end on our clock, one
   second per deadline slot, so a standby whose replay froze stops. */
#define FD_FAILOVER_DEADLINE_SLOT_NANOS (1000000000L)

/* A staked contact info from another host newer than this means an
   active is publishing, two gossip refreshes of 7.5s. */
#define FD_FAILOVER_GOSSIP_FRESH_NANOS (15000000000L)

/* The controller actions, promotion sources and handoff results are
   in fd_adminctl.h, `failover status` reports them. */

/* Which key a switch installs, CNT while none is in flight */
#define FD_FAILOVER_SWITCH_KEY_JUNK   (0UL) /* The junk identity. */
#define FD_FAILOVER_SWITCH_KEY_STAKED (1UL) /* The staked identity. */
#define FD_FAILOVER_SWITCH_KEY_CNT    (2UL) /* No identity switch is pending. */

/* Our DEMOTED to the handoff target */
#define FD_FAILOVER_DELIVERY_NONE (0UL) /* Nothing is owed. */
#define FD_FAILOVER_DELIVERY_OWED (1UL) /* Owed, not sent on this session. */
#define FD_FAILOVER_DELIVERY_SENT (2UL) /* Sent on this session, a new session sends it again. */

/* Our last response to a DEMOTED */
#define FD_FAILOVER_REPLY_NONE (0UL) /* No response yet. */
#define FD_FAILOVER_REPLY_KEPT (1UL) /* Kept, the same DEMOTED again gets it again. */
#define FD_FAILOVER_REPLY_OWED (2UL) /* Kept, not queued yet because the control slot was busy. */

/* A compact tower and the slot of its last vote.  In alpenglow mode it
   is a vote history and its tip. */
struct fd_failover_tower {
  int   valid;
  ulong tip;
  ulong sz;
  uchar state[ FD_FAILOVER_STATE_MAX ];
};

typedef struct fd_failover_tower fd_failover_tower_t;

/* The member and boot a message or request is bound to. */
struct fd_failover_peer {
  ulong boot_id;
  uchar junk[ 32 ];
};

typedef struct fd_failover_peer fd_failover_peer_t;

static inline int
peer_eq( fd_failover_peer_t const * bound,
         ulong                      boot_id,
         uchar const *              junk ) {
  return bound->boot_id==boot_id && fd_memeq( bound->junk, junk, 32UL );
}

/* The session we last saw on the channel. */
struct fd_failover_session {
  ulong state;            /* last seen session state, for edge detection */
  ulong generation;       /* catches a replacement paired during one poll */
  ulong peer_boot_id;
  ulong peer_role;        /* latest HELLO or accepted handoff seen on this session */
  int   close_after_send;
  ulong close_handoff_id;
};

typedef struct fd_failover_session fd_failover_session_t;

/* Our handoff request, sent by the standby. */
struct fd_failover_request {
  ulong              id;             /* zero when none is open */
  fd_failover_peer_t peer;           /* the active boot we authenticated for it */
  uint               addr;           /* kept until the exchange finishes */
  long               until;          /* retry deadline, zero while the operator must retry */
  int                sent;           /* sent on this session */
  int                peer_restarted; /* paused because the boot we authenticated restarted */
  ulong              last_id;
  ulong              result;
  ulong              send_cnt;
  long               log_at;
};

typedef struct fd_failover_request fd_failover_request_t;

/* Our demotion. */
struct fd_failover_handoff {
  ulong              id;            /* id of our latest demotion */
  fd_failover_peer_t target;        /* peer boot it is for */
  ulong              result;        /* FD_FAILOVER_HANDOFF_* of the latest DEMOTED */
  ulong              delivery;      /* FD_FAILOVER_DELIVERY_* */
  long               until;         /* also bound the drain when replay stops */
  long               log_at;
  long               result_log_at;
  ulong              payload_sz;
  uchar              payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];
};

typedef struct fd_failover_handoff fd_failover_handoff_t;

/* The promotion in progress. */
struct fd_failover_promotion {
  char                label[ 48 ];  /* handoff ID or operator promotion, fixed for every step */
  ulong               source;
  int                 empty;        /* forced recovery after the vote account could not be adopted */
  int                 from_peer;    /* the peer's DEMOTED requested it, we send the response */
  fd_failover_peer_t  peer;         /* that DEMOTED's member boot, it gets our response */
  ulong               handoff_id;   /* and its handoff id */
  ulong               floor;        /* coverage floor when it started */
  int                 force;        /* `failover promote --force`, the checks on the peer are skipped */
  long                staked_at;    /* staked_seen_at when it started */
  int                 active_seen;  /* an ACTIVE peer authenticated after promotion started */
  long                until;        /* our clock when the replay and adopt waits give up, 0 until armed */
  fd_failover_tower_t adopt;        /* what goes to the tower tile, empty for the vote account */
  ulong               adopt_id;
  int                 retry;        /* ask the tower tile again once replay passes retry_slot */
  ulong               retry_slot;
  ulong               floor_acct;   /* the account's last vote in the latest response short of the floor */
  int                 floor_logged; /* we said once that we wait for the floor */
  int                 retry_logged; /* and that we ask the tower tile again as replay moves */
};

typedef struct fd_failover_promotion fd_failover_promotion_t;

/* Our last response to a DEMOTED.  The same DEMOTED again gets the same
   response, so a peer that missed it is not left waiting. */
struct fd_failover_reply {
  ulong              state;      /* FD_FAILOVER_REPLY_* */
  fd_failover_peer_t peer;
  ulong              handoff_id;
  ushort             type;       /* PROMOTE_ACK or PROMOTE_REJECTED */
  uchar              reason;     /* for a rejected reply */
  long               log_at;
};

typedef struct fd_failover_reply fd_failover_reply_t;

/* The one control message waiting to go out, if any. */
struct fd_failover_tx {
  ushort             type;
  ushort             sz;
  int                valid;
  fd_failover_peer_t to;
  uchar              payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];
};

typedef struct fd_failover_tx fd_failover_tx_t;

/* State of the identity switch we asked the admin tile for.  It
   selects a key preloaded by the signing tile by its public key, and
   success means the old key is gone from every tile's active identity. */
struct fd_failover_id_switch {
  ulong                     request_id;
  ulong                     pending_key;    /* FD_FAILOVER_SWITCH_KEY_*, or CNT when idle */
  fd_failover_switch_resp_t result;
  fd_failover_switch_resp_t response;       /* uncommitted input frame */
  ulong                     response_nonce; /* nonce of the frame being consumed */
  int                       fresh;
  int                       overdue;        /* the switch in flight passed its deadline, we still wait for it */
  int                       discard;        /* set-identity ran while it was in flight, its answer is dropped */
  ulong                     epoch;          /* operator epoch we last saw, sent with every request */
};

typedef struct fd_failover_id_switch fd_failover_id_switch_t;

struct fd_failover_tile_ctx {
  fd_keyguard_client_t keyguard_client[ 1 ];
  int                  member_cert_set;

  fd_failover_hello_t     hello;
  ulong                   role;
  uint                    cmd_addr;    /* from `failover promote --address`, 0 when gossip finds the active */
  ushort                  cmd_port;    /* from `failover promote --port`, 0 for our own port */
  ushort                  port;
  fd_failover_channel_t * channel;
  fd_failover_session_t   session;
  long                    poll_at;     /* next idle socket poll */

  fd_failover_request_t request;
  int                   last_requested; /* status describes our request rather than our demotion */
  long                  handoff_refuse_log_at;

  ulong peer_floor; /* highest last vote the peer reported, kept across sessions */
  ulong own_floor;  /* highest vote we signed while ACTIVE this boot */

  /* gossip_ciseen, polled unreliably for contact infos */
  ulong       gossip_in_idx;
  fd_wksp_t * gossip_in_mem;
  ulong       gossip_in_chunk0;
  ulong       gossip_in_wmark;
  ulong       gossip_in_mtu;

  fd_ip4_port_t own_gossip;          /* our own gossip socket */
  uchar         gossip_origin[ 32 ]; /* copied in during_frag */
  fd_ip4_port_t gossip_socket;       /* copied in during_frag, zero for a remove or IPv6 */
  uint          staked_addr;         /* from a staked contact info that is not ours, 0 none */
  long          staked_seen_at;      /* our clock when that one arrived, 0 never */

  /* Controller */
  ulong action;
  int   stuck;         /* a transition failed or is overdue, shown to the operator */
  int   stuck_logged;  /* the stuck value we last told the operator about */
  ulong deadline_slot; /* replay slot at which this attempt aborts */

  /* Handoff ids count up from a random base per boot, so ids from two
     boots of ours do not collide. */
  ulong                 handoff_base;
  ulong                 handoff_cnt;
  fd_failover_handoff_t handoff;
  int                   taken; /* the peer took the identity, only a new tenure clears this */

  fd_failover_tower_t peer_tower; /* stored peer tower, from a DEMOTED */

  fd_failover_promotion_t promotion;
  fd_failover_reply_t     reply;
  fd_failover_tx_t        tx;

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
  fd_failover_bus_msg_t  bus_req;
  int                    bus_req_fresh;
  fd_failover_operator_t bus_operator; /* copied in during_frag */

  fd_failover_id_switch_t id_switch;

  /* Adoption request to the tower tile and its response. */
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

  /* tower_out, polled unreliably */
  ulong       tower_in_idx;
  fd_wksp_t * tower_in_mem;
  ulong       tower_in_chunk0;
  ulong       tower_in_wmark;

  fd_tower_slot_done_t slot_done;
  int                  slot_done_fresh;
  ulong                tower_seen_seq; /* seq of the last tower_out frag taken in, ULONG_MAX before any */
  int                  tower_gap;      /* a tower_out frag was skipped since the cached tower was built */

  /* Under Alpenglow the vote tile is votor, its frames come on
     votor_hist in place of tower_out and the adopt links are
     failov_votor and votor_failov.  The frame is the full history. */
  ulong               mode;             /* FD_FAILOVER_MODE_* */
  fd_votor_hist_msg_t hist;
  ulong               adopt_anchor;     /* finality anchor of the history being adopted, SLOT_NULL when none */
  ulong               empty_vote_after; /* an empty history votes only past this slot, SLOT_NULL until known */
  int                 hist_warned;      /* we warned of a bad frame and no good one came since */

  ulong replay_slot;
  ulong root_slot;
  ulong last_vote_slot;

  fd_failover_tower_t current_tower; /* tower of our latest vote */

  uchar rx[ FD_FAILOVER_PAYLOAD_MAX ];
};

typedef struct fd_failover_tile_ctx fd_failover_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return fd_ulong_max( alignof(fd_failover_tile_ctx_t), fd_failover_channel_align() );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_failover_tile_ctx_t), sizeof(fd_failover_tile_ctx_t)  );
  l = FD_LAYOUT_APPEND( l, fd_failover_channel_align(),     fd_failover_channel_footprint() );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

/* TLS CertificateVerify, signed by the sign tile with the junk key. */
static void
sign_ed25519( void *      signer_ctx,
              uchar       sig[ static FD_ED25519_SIG_SZ ],
              uchar const msg[ static FD_TLS_CV_SIGN_SZ ] ) {
  fd_failover_tile_ctx_t * ctx = signer_ctx;
  fd_keyguard_client_sign( ctx->keyguard_client, sig, msg, FD_TLS_CV_SIGN_SZ, FD_KEYGUARD_SIGN_TYPE_ED25519 );
}

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_failover_tile_ctx_t * ctx         = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_failover_tile_ctx_t), sizeof(fd_failover_tile_ctx_t)  );
  void *                   channel_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_failover_channel_align(),     fd_failover_channel_footprint() );
  /* Start idle with no handoff or promotion in progress. */
  fd_memset( ctx, 0, sizeof(fd_failover_tile_ctx_t) );
  /* No admin switch is pending at boot. */
  ctx->id_switch.pending_key = FD_FAILOVER_SWITCH_KEY_CNT;
  ctx->deadline_slot         = FD_FAILOVER_SLOT_NULL;
  ctx->peer_floor            = FD_FAILOVER_SLOT_NULL;
  ctx->own_floor             = FD_FAILOVER_SLOT_NULL;
  ctx->replay_slot           = FD_FAILOVER_SLOT_NULL;
  ctx->root_slot             = FD_FAILOVER_SLOT_NULL;
  ctx->last_vote_slot        = FD_FAILOVER_SLOT_NULL;
  ctx->tower_seen_seq        = ULONG_MAX;
  FD_TEST( fd_rng_secure( &ctx->handoff_base, sizeof(ulong) ) );

  /* The junk identity is this machine's own key, it goes into HELLO and
     TLS.  We keep only the public keys of it and of the staked
     [paths.identity_key].  Like every tile's identity load, the loader
     reads the whole file and zeroes the private half before it returns. */
  uchar const * junk_pubkey   = fd_keyload_load( tile->failov.identity_key_path, 1 );
  uchar const * staked_pubkey = fd_keyload_load( tile->failov.staked_key_path,   1 ); /* public key only, like the other tiles' identity loads */
  fd_memcpy( ctx->hello.junk_pubkey,   junk_pubkey,   32UL );
  fd_memcpy( ctx->hello.staked_pubkey, staked_pubkey, 32UL );
  fd_keyload_unload( junk_pubkey,   1 );
  fd_keyload_unload( staked_pubkey, 1 );

  if( FD_UNLIKELY( fd_memeq( ctx->hello.junk_pubkey, ctx->hello.staked_pubkey, 32UL ) ) ) {
    FD_LOG_ERR(( "the failover junk identity `%s` is the staked [paths.identity_key], each failover machine boots under its own key", tile->failov.identity_key_path ));
  }

  /* The vote key is a base58 pubkey or a keypair file, same as in the
     tower tile. */
  if( FD_UNLIKELY( !fd_base58_decode_32( tile->failov.vote_account_path, ctx->hello.vote_account ) ) ) {
    if( FD_UNLIKELY( !strcmp( tile->failov.vote_account_path, "" ) ) ) FD_LOG_ERR(( "missing [paths.vote_account]" ));
    uchar const * vote_account = fd_keyload_load( tile->failov.vote_account_path, 1 );
    fd_memcpy( ctx->hello.vote_account, vote_account, 32UL );
    fd_keyload_unload( vote_account, 1 );
  }

  /* The votor_hist link puts us in alpenglow mode.  The mode goes in
     HELLO, and a peer in the other mode does not pair. */
  ctx->mode             = fd_topo_find_tile_in_link( topo, tile, "votor_hist", 0UL )!=ULONG_MAX ? FD_FAILOVER_MODE_ALPENGLOW : FD_FAILOVER_MODE_TOWER;
  ctx->adopt_anchor     = FD_FAILOVER_SLOT_NULL;
  ctx->empty_vote_after = FD_FAILOVER_SLOT_NULL;

  /* Every boot runs the junk key, so we start as a standby. */
  ctx->role          = FD_FAILOVER_ROLE_STANDBY;
  ctx->hello.version = (ushort)FD_FAILOVER_VERSION;
  ctx->hello.role    = (uchar)ctx->role;
  ctx->hello.mode    = (uchar)ctx->mode;
  while( FD_UNLIKELY( !ctx->hello.boot_id ) ) FD_TEST( fd_rng_secure( &ctx->hello.boot_id, sizeof(ulong) ) );
  /* The commit field has the hash bytes, a build without one leaves it
     zero. */
  if( FD_LIKELY( strlen( fd_commit_ref_cstr )==2UL*sizeof(ctx->hello.commit) &&
                 fd_hex_decode( ctx->hello.commit, fd_commit_ref_cstr, sizeof(ctx->hello.commit) )!=sizeof(ctx->hello.commit) ) ) {
    fd_memset( ctx->hello.commit, 0, sizeof(ctx->hello.commit) );
  }
  ctx->port = tile->failov.port;

  /* Same resolution as the gossip tile, so our own staked contact info
     is never taken for the peer's. */
  ctx->own_gossip = tile->failov.gossip_addr;
  if( FD_UNLIKELY( tile->failov.gossip_host[ 0 ]!='\0' ) ) {
    if( FD_UNLIKELY( !fd_dns_resolve_address( tile->failov.gossip_host, &ctx->own_gossip.addr ) ) ) {
      FD_LOG_ERR(( "could not resolve [gossip.host] `%s`", tile->failov.gossip_host ));
    }
  }

  ctx->channel = fd_failover_channel_join( fd_failover_channel_new( channel_mem ) );
  FD_TEST( ctx->channel );
  fd_tls_sign_t signer = { .ctx=ctx, .sign_fn=sign_ed25519 };
  if( FD_UNLIKELY( fd_failover_channel_set_identity( ctx->channel, ctx->hello.junk_pubkey, signer, &ctx->hello ) ) ) {
    FD_LOG_ERR(( "failover TLS setup failed for the junk identity `%s`", tile->failov.identity_key_path ));
  }

  /* Every member listens, and the sandbox forbids bind.  We dial only
     for a handoff, the address given with `failover promote --address`
     or the active's address from gossip. */
  fd_failover_channel_init_listener( ctx->channel, tile->failov.listen_addr, tile->failov.port );
  ctx->session.state = fd_failover_channel_state( ctx->channel );

  char junk_b58  [ FD_BASE58_ENCODED_32_SZ ];
  char staked_b58[ FD_BASE58_ENCODED_32_SZ ];
  fd_base58_encode_32( ctx->hello.junk_pubkey,   NULL, junk_b58   );
  fd_base58_encode_32( ctx->hello.staked_pubkey, NULL, staked_b58 );
  FD_LOG_NOTICE(( "failover is on, booting as a standby under junk identity `%s` for staked identity `%s`, listening on `" FD_IP4_ADDR_FMT ":%u`, "
                  "this machine does not vote until `failover promote` hands it the identity from the active, or `failover promote --force` takes it when no machine holds it, "
                  "the junk identity is this machine's own, never copy it to the other machine", junk_b58, staked_b58, FD_IP4_ADDR_FMT_ARGS( tile->failov.listen_addr ), (uint)tile->failov.port ));

  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, scratch_align() )==(ulong)scratch+scratch_footprint( tile ) );
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  fd_failover_tile_ctx_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  ctx->gossip_in_idx = ULONG_MAX;
  ctx->tower_in_idx  = ULONG_MAX;
  ctx->admin_in_idx  = ULONG_MAX;
  ctx->adopt_in_idx  = ULONG_MAX;
  ctx->adopt_out_idx = fd_topo_find_tile_out_link( topo, tile, "adopt_tower", 0UL );
  if( FD_UNLIKELY( ctx->adopt_out_idx==ULONG_MAX ) ) ctx->adopt_out_idx = fd_topo_find_tile_out_link( topo, tile, "failov_votor", 0UL );
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
    if( FD_LIKELY( !strcmp( link->name, "gossip_ciseen" ) ) ) {
      ctx->gossip_in_idx    = i;
      ctx->gossip_in_mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      ctx->gossip_in_chunk0 = fd_dcache_compact_chunk0( ctx->gossip_in_mem, link->dcache );
      ctx->gossip_in_wmark  = fd_dcache_compact_wmark ( ctx->gossip_in_mem, link->dcache, link->mtu );
      ctx->gossip_in_mtu    = link->mtu;
      continue;
    }
    if( FD_LIKELY( !strcmp( link->name, "tower_adopt" ) || !strcmp( link->name, "votor_failov" ) ) ) {
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
    if( FD_LIKELY( !strcmp( link->name, "tower_out" ) || !strcmp( link->name, "votor_hist" ) ) ) {
      ctx->tower_in_idx    = i;
      ctx->tower_in_mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      ctx->tower_in_chunk0 = fd_dcache_compact_chunk0( ctx->tower_in_mem, link->dcache );
      ctx->tower_in_wmark  = fd_dcache_compact_wmark ( ctx->tower_in_mem, link->dcache, link->mtu );
      continue;
    }
    /* The keyguard client reads sign_failov itself. */
    if( FD_LIKELY( !strcmp( link->name, "sign_failov" ) ) ) continue;
    FD_LOG_ERR(( "unexpected input link name %s", link->name ));
  }

  ulong sign_in_idx  = fd_topo_find_tile_in_link ( topo, tile, "sign_failov", tile->kind_id );
  ulong sign_out_idx = fd_topo_find_tile_out_link( topo, tile, "failov_sign", tile->kind_id );
  FD_TEST( sign_in_idx!=ULONG_MAX && sign_out_idx!=ULONG_MAX );
  fd_topo_link_t const * sign_in  = &topo->links[ tile->in_link_id [ sign_in_idx  ] ];
  fd_topo_link_t const * sign_out = &topo->links[ tile->out_link_id[ sign_out_idx ] ];

  fd_sleep_t * sleep = NULL;
  if( FD_UNLIKELY( topo->sleep_obj_id!=ULONG_MAX ) ) {
    sleep = fd_sleep_join( fd_topo_obj_laddr( topo, topo->sleep_obj_id ) );
    FD_TEST( sleep );
  }

  if( FD_UNLIKELY( !fd_keyguard_client_join( fd_keyguard_client_new( ctx->keyguard_client,
                                                                     sign_out->mcache,
                                                                     sign_out->dcache,
                                                                     sign_in->mcache,
                                                                     sign_in->dcache,
                                                                     sign_out->mtu,
                                                                     sign_in->mtu,
                                                                     sleep,
                                                                     sign_out->id,
                                                                     fd_topo_find_link_consumer( topo, sign_out ) ) ) ) ) {
    FD_LOG_ERR(( "failed to construct keyguard" ));
  }
}

/* A set-identity that moves the failover identity reaches the sign tile
   before its OPERATOR reaches us.  A certificate signed with the new key
   then waits for that OPERATOR, which restarts us and asks again. */
static void
member_cert_signed( fd_failover_tile_ctx_t * ctx,
                    uchar const              cert[ 64 ] ) {
  ctx->member_cert_set = 1;
  if( FD_UNLIKELY( fd_failover_channel_set_member_cert( ctx->channel, cert ) ) ) {
    FD_LOG_WARNING(( "the sign tile signed our member certificate with another key, set-identity moved the failover identity, we ask again once failover restarts for it" ));
    return;
  }
  FD_LOG_NOTICE(( "the sign tile signed our member certificate with the failover identity, this machine can pair with the other failover machine now" ));
}

/* Before we pair, the sign tile signs our member certificate with the
   failover identity.  It checks the message is the cert prefix and its
   own junk pubkey. */
static void
request_member_cert( fd_failover_tile_ctx_t * ctx ) {
  uchar msg [ FD_KEYGUARD_MEMBER_CERT_MSG_SZ ];
  uchar cert[ 64 ];
  fd_failover_member_cert_msg( msg, ctx->hello.junk_pubkey );
  fd_keyguard_client_sign( ctx->keyguard_client, cert, msg, sizeof(msg), FD_KEYGUARD_SIGN_TYPE_ED25519 );
  member_cert_signed( ctx, cert );
}

/* A new connection repeats the request for the same handoff. */
static void
sync_session( fd_failover_tile_ctx_t * ctx ) {
  ulong state      = fd_failover_channel_state( ctx->channel );
  ulong generation = fd_failover_channel_generation( ctx->channel );
  if( FD_LIKELY( state==ctx->session.state && generation==ctx->session.generation ) ) return;
  ctx->session.state      = state;
  ctx->session.generation = generation;
  /* A changed session may resend the same request, it does not cancel local work. */
  ctx->request.sent             = 0;
  ctx->session.close_after_send = 0;
  /* A result answers a request on the session it came in on.  The
     requester sends the request again on a new session and gets a new
     result, so a queued one would only hold the send slot. */
  if( ctx->tx.valid && ctx->tx.type==(ushort)FD_FAILOVER_MSG_HANDOFF_RESULT ) ctx->tx.valid = 0;
  if( FD_UNLIKELY( state==FD_FAILOVER_SESSION_PAIRED ) ) {
    fd_failover_hello_t const * peer = fd_failover_channel_peer_hello( ctx->channel );
    ctx->session.peer_boot_id = peer->boot_id;
    ctx->session.peer_role    = peer->role;
    if( ctx->handoff.delivery==FD_FAILOVER_DELIVERY_SENT ) ctx->handoff.delivery = FD_FAILOVER_DELIVERY_OWED;
    if( FD_UNLIKELY( ( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY ||
                       ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT ) &&
                     peer->role==(uchar)FD_FAILOVER_ROLE_ACTIVE ) ) ctx->promotion.active_seen = 1;
    /* An active peer votes past any tower we kept, a promotion in flight
       already copied the one it adopts. */
    if( FD_UNLIKELY( peer->role==(uchar)FD_FAILOVER_ROLE_ACTIVE && ( ctx->peer_tower.valid ) ) )
      FD_LOG_NOTICE(( "peer boot %016lx authenticated ACTIVE, discarding saved final state from before its voting tenure, keeping coverage floors", peer->boot_id ));
    if( FD_UNLIKELY( peer->role==(uchar)FD_FAILOVER_ROLE_ACTIVE ) ) {
      ctx->peer_tower.valid = 0;
    }
  }
}

/* The port a handoff dials, `failover promote --port` or our own. */
static inline ushort
dial_port( fd_failover_tile_ctx_t const * ctx ) {
  return ctx->cmd_port ? ctx->cmd_port : ctx->port;
}

static void
set_role( fd_failover_tile_ctx_t * ctx,
          ulong                    role ) {
  /* Publish the role reached by the completed identity switch. */
  ctx->role       = role;
  ctx->hello.role = (uchar)role;
  fd_failover_channel_set_role( ctx->channel, role );
}

/* Give up on the attempt once replay passes this slot, so a transition
   cannot hang forever. */
static void
deadline_start( fd_failover_tile_ctx_t * ctx,
                ulong                    slots ) {
  ctx->deadline_slot = ( ctx->replay_slot==FD_FAILOVER_SLOT_NULL )
                     ? FD_FAILOVER_SLOT_NULL
                     : fd_ulong_sat_add( ctx->replay_slot, slots );
}

/* If we have not seen a replay slot yet, arm the deadline when the
   first one arrives. */
static void
deadline_arm( fd_failover_tile_ctx_t * ctx,
              ulong                    slots ) {
  if( FD_LIKELY( ctx->deadline_slot!=FD_FAILOVER_SLOT_NULL ) ) return;
  if( FD_UNLIKELY( ctx->replay_slot==FD_FAILOVER_SLOT_NULL ) ) return;
  ctx->deadline_slot = fd_ulong_sat_add( ctx->replay_slot, slots );
}

static int
deadline_expired( fd_failover_tile_ctx_t const * ctx ) {
  return ctx->deadline_slot!=FD_FAILOVER_SLOT_NULL &&
         ctx->replay_slot  !=FD_FAILOVER_SLOT_NULL &&
         ctx->replay_slot>ctx->deadline_slot;
}

/* The vote account source may wait until replay passes the floor by the
   slack, so its deadline sits past that.  The clock bound is armed by
   the first wait and gives a second for every slot the deadline gives. */
static void
promote_deadline_arm( fd_failover_tile_ctx_t * ctx,
                      long                     now ) {
  deadline_arm( ctx, FD_FAILOVER_DEADLINE_SLOTS );
  if( FD_UNLIKELY( ctx->promotion.source==FD_FAILOVER_SOURCE_VOTE_ACCOUNT &&
                   ctx->promotion.floor!=FD_FAILOVER_SLOT_NULL &&
                   ctx->deadline_slot!=FD_FAILOVER_SLOT_NULL ) ) {
    ctx->deadline_slot = fd_ulong_max( ctx->deadline_slot,
                                       fd_ulong_sat_add( ctx->promotion.floor, FD_FAILOVER_FLOOR_SLACK_SLOTS+FD_FAILOVER_DEADLINE_SLOTS ) );
  }
  if( FD_UNLIKELY( !ctx->promotion.until ) ) {
    ulong slots = FD_FAILOVER_DEADLINE_SLOTS;
    if( FD_UNLIKELY( ctx->promotion.source==FD_FAILOVER_SOURCE_VOTE_ACCOUNT &&
                     ctx->promotion.floor!=FD_FAILOVER_SLOT_NULL ) ) slots += FD_FAILOVER_FLOOR_SLACK_SLOTS;
    ctx->promotion.until = fd_long_sat_add( now, (long)slots*FD_FAILOVER_DEADLINE_SLOT_NANOS );
  }
}

/* A promotion wait ends at the slot deadline or on our clock, a replay
   that froze never reaches the slot deadline. */
static int
promote_expired( fd_failover_tile_ctx_t const * ctx,
                 long                           now ) {
  if( FD_LIKELY( now<ctx->promotion.until ) ) return deadline_expired( ctx );
  if( FD_UNLIKELY( ctx->replay_slot==FD_FAILOVER_SLOT_NULL ) ) {
    FD_LOG_WARNING(( "%s: the promotion ran out of time before replay started, wait until this machine has caught up", ctx->promotion.label ));
  } else {
    FD_LOG_WARNING(( "%s: the promotion ran out of time with replay at slot %lu, replay may be stuck, check that this machine is catching up", ctx->promotion.label, ctx->replay_slot ));
  }
  return 1;
}

/* A switch in flight is never abandoned, its outcome is unknown until the
   admin tile responds.  We warn once and flag stuck. */
static void
switch_overdue( fd_failover_tile_ctx_t * ctx ) {
  ctx->stuck = 1;
  if( FD_LIKELY( ctx->id_switch.overdue ) ) return;
  ctx->id_switch.overdue = 1;
  char demotion[ 48 ];
  fd_cstr_printf( demotion, sizeof(demotion), NULL, "handoff %lu", ctx->handoff.id );
  FD_LOG_WARNING(( "%s: identity switch %lu to %s is overdue, its outcome is unknown, we keep waiting and refuse another switch, check the admin and sign tile logs",
                   ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_STAKED ? ctx->promotion.label : demotion,
                   ctx->id_switch.request_id, ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_STAKED ? "staked" : "junk" ));
}

/* Only one control message can be outstanding at a time.  Its recipient
   is fixed even if the connection changes before it is sent. */
static int
queue_control( fd_failover_tile_ctx_t *   ctx,
               ushort                     type,
               fd_failover_peer_t const * to,
               void const *               payload,
               ulong                      payload_sz ) {
  if( FD_UNLIKELY( ctx->tx.valid || !payload_sz || payload_sz>sizeof(ctx->tx.payload) ) ) return -1;
  ctx->tx.type  = type;
  ctx->tx.sz    = (ushort)payload_sz;
  ctx->tx.valid = 1;
  ctx->tx.to    = *to;
  fd_memcpy( ctx->tx.payload, payload, payload_sz );
  return 0;
}

/* Our DEMOTED goes to the handoff target. */
static int
queue_demoted( fd_failover_tile_ctx_t * ctx ) {
  return queue_control( ctx, (ushort)FD_FAILOVER_MSG_DEMOTED, &ctx->handoff.target, ctx->handoff.payload, ctx->handoff.payload_sz );
}

/* Tells the requester, the member and boot to, that we recorded its
   handoff response, or that its handoff cannot go ahead. */
static void
handoff_result_to( fd_failover_tile_ctx_t *   ctx,
                   fd_failover_peer_t const * to,
                   ulong                      id,
                   ulong                      result ) {
  fd_failover_handoff_result_t response = { .handoff_id=id, .result=result };
  if( FD_LIKELY( !queue_control( ctx, FD_FAILOVER_MSG_HANDOFF_RESULT, to, &response, sizeof(response) ) ) ) {
    /* Keep the connection until the result has drained. */
    ctx->session.close_after_send = 1;
    ctx->session.close_handoff_id = id;
  }
}

/* queue_reply queues our last response to a DEMOTED.  If the control slot
   is busy the response stays owed and step_controller tries again once
   the slot drains, the peer waits on it and sends its DEMOTED only once
   per session, so nothing else would ask for it. */
static void
queue_reply( fd_failover_tile_ctx_t * ctx ) {
  uchar payload[ sizeof(fd_failover_promote_rejected_t) ];
  ulong payload_sz = ctx->reply.type==(ushort)FD_FAILOVER_MSG_PROMOTE_ACK
                   ? fd_failover_promote_ack_encode( payload, ctx->reply.handoff_id )
                   : fd_failover_promote_rejected_encode( payload, ctx->reply.handoff_id, ctx->reply.reason );
  ctx->reply.state = queue_control( ctx, ctx->reply.type, &ctx->reply.peer, payload, payload_sz ) ? FD_FAILOVER_REPLY_OWED : FD_FAILOVER_REPLY_KEPT;
}

/* Remembers our response to the DEMOTED with handoff_id from peer,
   then queues it. */
static void
finish_reply( fd_failover_tile_ctx_t *   ctx,
              fd_failover_peer_t const * peer,
              ulong                      handoff_id,
              ushort                     type,
              uchar                      reason ) {
  if( ctx->reply.state==FD_FAILOVER_REPLY_NONE || ctx->reply.peer.boot_id!=peer->boot_id || ctx->reply.handoff_id!=handoff_id || ctx->reply.type!=type )
    ctx->reply.log_at = 0L;
  ctx->reply.peer       = *peer;
  ctx->reply.handoff_id = handoff_id;
  ctx->reply.type       = type;
  ctx->reply.reason     = reason;
  queue_reply( ctx );
}

/* The name of a result the old active sent us for our handoff request, or
   the one we sent, and what the operator can do about it. */
static char const *
relayed_refusal( ulong         result,
                 ulong         mode,
                 char const ** hint ) {
  switch( result ) {
  case FD_ADMINCTL_RESULT_SUCCESS:
    *hint = "the old active recorded that we took the identity but this machine is a standby, check `failover status` on both machines";
    return "SUCCESS";
  case FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY:
    *hint = "the active could not finish this handoff and may have given up the identity, check `failover status` there";
    return "PEER_UNREADY";
  case FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS:
    *hint = "the active is busy with another transition, run `failover promote` here again once `failover status` there shows it idle";
    return "IN_PROGRESS";
  case FD_FAILOVER_CONTROL_RESULT_BAD_ROLE:
    *hint = "the machine we dialed is not the active any more, check `failover status` on both machines";
    return "BAD_ROLE";
  case FD_FAILOVER_CONTROL_RESULT_NO_FINAL_TOWER:
    *hint = "the active has no eligible final vote state to hand over and keeps the identity, its log says why";
    return mode==FD_FAILOVER_MODE_ALPENGLOW ? "NO_FINAL_HISTORY" : "NO_FINAL_TOWER";
  case FD_FAILOVER_CONTROL_RESULT_REPLAY_BEHIND:
    *hint = "this machine's replay is too far behind the active's last vote and the active keeps the identity, run `failover promote` here again once this machine has caught up";
    return "REPLAY_BEHIND";
  default:
    *hint = "the active answered with a result this machine does not know, run the same Firedancer version on both machines";
    return "UNKNOWN";
  }
}

/* What a control message we just sent changes on our side. */
static void
control_sent( fd_failover_tile_ctx_t * ctx,
              long                     now ) {
  switch( ctx->tx.type ) {
  case (ushort)FD_FAILOVER_MSG_DEMOTED:
    if( ctx->handoff.delivery==FD_FAILOVER_DELIVERY_OWED ) ctx->handoff.delivery = FD_FAILOVER_DELIVERY_SENT;
    if( now>=ctx->handoff.log_at ) {
      ctx->handoff.log_at = fd_long_sat_add( now, 60000000000L );
      FD_LOG_NOTICE(( "handoff %lu: sent final state (DEMOTED) to peer boot %016lx, last vote slot %lu, we remain standby waiting for its answer",
                      ctx->handoff.id, ctx->handoff.target.boot_id, ctx->last_vote_slot ));
    }
    break;
  case (ushort)FD_FAILOVER_MSG_PROMOTE_ACK:
  case (ushort)FD_FAILOVER_MSG_PROMOTE_REJECTED:
    if( now>=ctx->reply.log_at ) {
      ctx->reply.log_at = fd_long_sat_add( now, 60000000000L );
      FD_LOG_NOTICE(( "handoff %lu: sent %s to peer boot %016lx, %s, waiting for its final confirmation",
                      ctx->reply.handoff_id, ctx->tx.type==FD_FAILOVER_MSG_PROMOTE_ACK ? "ACK" : "refusal",
                      ctx->reply.peer.boot_id, ctx->role==FD_FAILOVER_ROLE_ACTIVE ? "we hold the staked identity" : "we remain standby" ));
    }
    break;
  case (ushort)FD_FAILOVER_MSG_HANDOFF_RESULT: {
    fd_failover_handoff_result_t result;
    fd_memcpy( &result, ctx->tx.payload, sizeof(result) );
    if( now>=ctx->handoff.result_log_at ) {
      ctx->handoff.result_log_at = fd_long_sat_add( now, 60000000000L );
      char const * hint;
      FD_LOG_NOTICE(( "handoff %lu: sent %s confirmation%s%s%s to peer boot %016lx, closing connection after queued bytes drain",
                      result.handoff_id, result.result==FD_ADMINCTL_RESULT_SUCCESS ? "success" : "refusal",
                      result.result==FD_ADMINCTL_RESULT_SUCCESS ? "" : " (",
                      result.result==FD_ADMINCTL_RESULT_SUCCESS ? "" : relayed_refusal( result.result, ctx->mode, &hint ),
                      result.result==FD_ADMINCTL_RESULT_SUCCESS ? "" : ")", ctx->tx.to.boot_id ));
    }
    break;
  }
  default: break;
  }
}

static void
pending_flush( fd_failover_tile_ctx_t * ctx,
               long                     now ) {
  if( FD_LIKELY( !ctx->tx.valid ) ) return;
  if( FD_UNLIKELY( fd_failover_channel_state( ctx->channel )!=FD_FAILOVER_SESSION_PAIRED ||
                   fd_failover_channel_tx_pending( ctx->channel ) ) ) return;
  /* A resumed handoff still belongs to the same member and boot. */
  if( FD_UNLIKELY( !peer_eq( &ctx->tx.to, ctx->session.peer_boot_id, fd_failover_channel_peer_hello( ctx->channel )->junk_pubkey ) ) ) return;
  if( FD_UNLIKELY( fd_failover_channel_send( ctx->channel, now, ctx->tx.type, ctx->tx.payload, ctx->tx.sz ) ) ) return;
  control_sent( ctx, now );
  ctx->tx.valid = 0;
}

/* Keep the tower of our latest vote from the tower's vote transaction.
   It is the final tower we hand over at a demotion.  A malformed
   transaction is logged and skipped, the previous tower stays. */
static void
prepare_consensus( fd_failover_tile_ctx_t *     ctx,
                   fd_tower_slot_done_t const * done ) {
  if( FD_UNLIKELY( !done->vote_txn_sz || done->vote_txn_sz>sizeof(done->vote_txn) ) ) {
    FD_LOG_WARNING(( "tower produced an invalid vote transaction size" ));
    return;
  }

  uchar                         txn_mem[ FD_TXN_MAX_SZ ] __attribute__((aligned(alignof(fd_txn_t))));
  fd_compact_tower_sync_serde_t serde;
  if( FD_UNLIKELY( !fd_txn_parse( done->vote_txn, done->vote_txn_sz, txn_mem, NULL ) ||
                   !fd_txn_parse_simple_vote( (fd_txn_t const *)txn_mem, done->vote_txn, &serde ) ) ) {
    FD_LOG_WARNING(( "tower produced an invalid vote transaction" ));
    return;
  }

  fd_tower_vote_t votes[ FD_TOWER_VOTE_MAX ];
  ulong           vote_cnt;
  ulong           root;
  if( FD_UNLIKELY( fd_compact_tower_sync_to_votes( &serde, votes, &vote_cnt, &root ) ||
                   !vote_cnt || votes[ vote_cnt-1UL ].slot!=done->vote_slot ) ) {
    FD_LOG_WARNING(( "tower vote transaction does not match its slot metadata" ));
    return;
  }

  /* Encode aside so a failed encode leaves the previous tower whole. */
  uchar state[ FD_FAILOVER_TOWER_STATE_MAX ];
  ulong state_sz = 0UL;
  if( FD_UNLIKELY( fd_compact_tower_sync_ser( &serde, state, sizeof(state), &state_sz ) ) ) {
    FD_LOG_WARNING(( "tower vote transaction exceeds the failover state limit" ));
    return;
  }

  fd_memcpy( ctx->current_tower.state, state, state_sz );
  ctx->current_tower.valid = 1;
  ctx->current_tower.tip   = done->vote_slot;
  ctx->current_tower.sz    = state_sz;
  ctx->tower_gap           = 0; /* anything skipped before this vote is superseded by it */
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
    /* Only the voting identity publishes votes, so every vote here is one
       we signed, also before our role catches up with a switch. */
    if( FD_LIKELY( ctx->own_floor==FD_FAILOVER_SLOT_NULL || done->vote_slot>ctx->own_floor ) ) ctx->own_floor = done->vote_slot;
    prepare_consensus( ctx, done );
  }
}

/* The alpenglow twin of prepare_consensus.  The frame already holds the
   whole history, so its serialized bytes are the final history we hand
   over.  The bytes go into a scratch buffer first, a failed encode
   leaves the cached history as it was. */
static void
prepare_consensus_alpenglow( fd_failover_tile_ctx_t *    ctx,
                             fd_votor_hist_msg_t const * hist ) {
  uchar state[ FD_FAILOVER_ALPENGLOW_STATE_MAX ];
  ulong state_sz = 0UL;
  if( FD_UNLIKELY( ag_hist_ser( &hist->hist, state, FD_FAILOVER_ALPENGLOW_STATE_MAX, &state_sz ) ||
                   ag_hist_tip( &hist->hist )!=hist->vote_slot ) ) {
    /* Once until a good frame, a bad votor could send one every slot. */
    if( FD_UNLIKELY( !ctx->hist_warned ) ) FD_LOG_WARNING(( "votor produced a vote history that does not match its slot metadata, until a good one arrives a handoff hands over nothing" ));
    ctx->hist_warned = 1;
    return;
  }
  ctx->hist_warned = 0;
  fd_memcpy( ctx->current_tower.state, state, state_sz );
  ctx->current_tower.valid = 1;
  ctx->current_tower.tip   = hist->vote_slot;
  ctx->current_tower.sz    = state_sz;
  ctx->tower_gap           = 0; /* a complete snapshot supersedes whatever was skipped */
}

/* The alpenglow twin of consume_slot_done. */
static void
consume_hist( fd_failover_tile_ctx_t *    ctx,
              fd_votor_hist_msg_t const * hist ) {
  if( FD_LIKELY( hist->replay_slot!=FD_FAILOVER_SLOT_NULL &&
                 ( ctx->replay_slot==FD_FAILOVER_SLOT_NULL || hist->replay_slot>ctx->replay_slot ) ) )
    ctx->replay_slot = hist->replay_slot;
  if( FD_LIKELY( hist->root_slot!=FD_FAILOVER_SLOT_NULL ) ) ctx->root_slot = hist->root_slot;
  int producing = ctx->role==FD_FAILOVER_ROLE_ACTIVE || ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH;
  if( FD_LIKELY( hist->has_vote && hist->vote_slot!=FD_FAILOVER_SLOT_NULL ) ) {
    /* Only the voting identity sends votes, so every vote here is one we
       signed, also before our role catches up with a switch.  Any later
       promotion has to cover it. */
    ctx->last_vote_slot = hist->vote_slot;
    if( FD_LIKELY( ctx->own_floor==FD_FAILOVER_SLOT_NULL || hist->vote_slot>ctx->own_floor ) ) ctx->own_floor = hist->vote_slot;
    prepare_consensus_alpenglow( ctx, hist );
  } else if( FD_UNLIKELY( producing && ctx->current_tower.valid && hist->vote_slot!=FD_FAILOVER_SLOT_NULL && hist->vote_slot>=ctx->last_vote_slot ) ) {
    /* A frame with no new vote can still change the bytes, a leader slot
       that moved or a built-but-unsent vote marked bad at the halt.  Its
       tip can be past our last vote, from slots marked voted while we
       stood by or votes never sent, and the history we hand over then
       ends there. */
    ctx->last_vote_slot = hist->vote_slot;
    prepare_consensus_alpenglow( ctx, hist );
  }
}

/* Sends the tower we adopt to the tower tile, empty for the vote
   account.  The response comes back with the request id so we can tell a
   late one apart.  Returns the id, or ULONG_MAX if nothing went out. */
static ulong
publish_adopt_state( fd_failover_tile_ctx_t * ctx,
                     fd_stem_context_t *      stem ) {
  if( FD_UNLIKELY( ctx->adopt_out_idx==ULONG_MAX ||
                   ( !ctx->promotion.adopt.sz && ctx->promotion.source!=FD_FAILOVER_SOURCE_VOTE_ACCOUNT ) ) ) return ULONG_MAX;

  if( FD_UNLIKELY( !++ctx->adopt_request_id ) ) ctx->adopt_request_id++;
  fd_memcpy( fd_chunk_to_laddr( ctx->adopt_out_mem, ctx->adopt_out_chunk ), ctx->promotion.adopt.state, ctx->promotion.adopt.sz );
  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  ulong ctl   = ctx->mode==FD_FAILOVER_MODE_TOWER && ctx->promotion.empty && ctx->promotion.force && !ctx->promotion.from_peer ? FD_TOWER_ADOPT_CTL_EMPTY : 0UL;
  fd_stem_publish( stem, ctx->adopt_out_idx, ctx->adopt_request_id, ctx->adopt_out_chunk, ctx->promotion.adopt.sz, ctl, tspub, tspub );
  ctx->adopt_out_chunk    = fd_dcache_compact_next( ctx->adopt_out_chunk, ctx->promotion.adopt.sz, ctx->adopt_out_chunk0, ctx->adopt_out_wmark );
  ctx->adopt_result_fresh = 0;
  return ctx->adopt_request_id;
}

/* Asks the admin tile to switch to the given key.  Only the public key
   goes out, the signing tile preloaded both keypairs.  Only one request
   can be in flight, and the reply comes back with the same id so a late
   reply can be told apart. */
static ulong
request_switch( fd_failover_tile_ctx_t * ctx,
                fd_stem_context_t *      stem,
                ulong                    key ) {
  if( FD_UNLIKELY( ctx->admin_out_idx==ULONG_MAX || ctx->id_switch.pending_key!=FD_FAILOVER_SWITCH_KEY_CNT ) ) return ULONG_MAX;

  if( FD_UNLIKELY( !++ctx->id_switch.request_id ) ) ctx->id_switch.request_id++;
  fd_failover_bus_msg_t * out = fd_chunk_to_laddr( ctx->admin_out_mem, ctx->admin_out_chunk );
  fd_memset( out, 0, sizeof(*out) );
  out->nonce = ctx->id_switch.request_id;
  fd_failover_switch_req_t req;
  fd_memcpy( req.identity, key==FD_FAILOVER_SWITCH_KEY_STAKED ? ctx->hello.staked_pubkey : ctx->hello.junk_pubkey, 32UL );
  req.epoch = ctx->id_switch.epoch;
  fd_memcpy( out->payload, &req, sizeof(req) );
  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, ctx->admin_out_idx, FD_FAILOVER_BUS_SWITCH_REQ, ctx->admin_out_chunk, sizeof(*out), 0UL, tspub, tspub );
  ctx->admin_out_chunk     = fd_dcache_compact_next( ctx->admin_out_chunk, sizeof(*out), ctx->admin_out_chunk0, ctx->admin_out_wmark );
  /* Keep the switch pending until admin responds to this request ID. */
  ctx->id_switch.pending_key = key;
  ctx->id_switch.fresh       = 0;
  return ctx->id_switch.request_id;
}

/* Records the result of the switch we asked for.  A reply for some other
   request is dropped, otherwise an old reply could be mistaken for a
   finished demotion. */
static int
switch_answer( fd_failover_tile_ctx_t * ctx,
               ulong                    nonce ) {
  if( FD_UNLIKELY( ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_CNT ||
                   nonce!=ctx->id_switch.request_id ) ) {
    FD_LOG_WARNING(( "dropping a stale identity switch answer" ));
    return 0;
  }
  /* A matching response ends the pending switch. */
  ctx->id_switch.pending_key = FD_FAILOVER_SWITCH_KEY_CNT;
  if( FD_UNLIKELY( ctx->id_switch.discard ) ) {
    ctx->id_switch.discard = 0;
    return 0;
  }
  ctx->id_switch.fresh = 1;
  return 1;
}

/* set-identity installed a key while failover is on.  We start over as
   if this machine had rebooted with that key: a new boot, so the other
   machine treats anything bound to the old one as from a restarted peer,
   nothing in flight, the failover identity set-identity left, and the
   role the installed key gives.  A peer with another failover identity
   fails HELLO.  Floors stay, they cover votes already signed.  A switch
   still in flight keeps one outstanding, its answer is dropped. */
static void
operator_switched( fd_failover_tile_ctx_t *       ctx,
                   fd_failover_operator_t const * operator ) {
  if( FD_UNLIKELY( operator->epoch<=ctx->id_switch.epoch ) ) return;
  ctx->id_switch.epoch   = operator->epoch;
  ctx->id_switch.discard = ctx->id_switch.pending_key!=FD_FAILOVER_SWITCH_KEY_CNT;
  ctx->id_switch.fresh   = 0;
  ctx->id_switch.overdue = 0;

  long now = fd_failover_clock();
  fd_failover_channel_init_dialer( ctx->channel, 0U, 0 );
  fd_failover_channel_hangup( ctx->channel, now );

  fd_memset( &ctx->request,   0, sizeof(ctx->request)   );
  fd_memset( &ctx->handoff,   0, sizeof(ctx->handoff)   );
  fd_memset( &ctx->promotion, 0, sizeof(ctx->promotion) );
  fd_memset( &ctx->reply,     0, sizeof(ctx->reply)     );
  fd_memset( &ctx->tx,        0, sizeof(ctx->tx)        );
  ctx->peer_tower.valid         = 0;
  ctx->current_tower.valid      = 0;
  ctx->last_vote_slot           = FD_FAILOVER_SLOT_NULL;
  ctx->tower_gap                = 0;
  ctx->taken                    = 0;
  ctx->last_requested           = 0;
  ctx->cmd_addr                 = 0U;
  ctx->cmd_port                 = (ushort)0;
  ctx->session.close_after_send = 0;
  ctx->adopt_result_fresh       = 0;
  ctx->action                   = FD_FAILOVER_ACTION_IDLE;
  ctx->stuck                    = 0;
  ctx->deadline_slot            = FD_FAILOVER_SLOT_NULL;
  /* What gossip told us is about the old failover identity. */
  if( FD_UNLIKELY( !fd_memeq( operator->failover_identity, ctx->hello.staked_pubkey, 32UL ) ) ) {
    ctx->staked_addr    = 0U;
    ctx->staked_seen_at = 0L;
  }

  ulong boot_id = ctx->hello.boot_id;
  do FD_TEST( fd_rng_secure( &ctx->hello.boot_id, sizeof(ulong) ) ); while( FD_UNLIKELY( !ctx->hello.boot_id || ctx->hello.boot_id==boot_id ) );
  fd_memcpy( ctx->hello.staked_pubkey, operator->failover_identity, 32UL );
  int staked = !fd_memeq( operator->identity, ctx->hello.junk_pubkey, 32UL );
  ctx->role       = staked ? FD_FAILOVER_ROLE_ACTIVE : FD_FAILOVER_ROLE_STANDBY;
  ctx->hello.role = (uchar)ctx->role;
  fd_tls_sign_t signer = { .ctx=ctx, .sign_fn=sign_ed25519 };
  if( FD_UNLIKELY( fd_failover_channel_set_identity( ctx->channel, ctx->hello.junk_pubkey, signer, &ctx->hello ) ) ) {
    FD_LOG_ERR(( "failover TLS setup failed after set-identity" ));
  }
  ctx->member_cert_set = 0;
  sync_session( ctx );

  FD_BASE58_ENCODE_32_BYTES( operator->identity,          identity );
  FD_BASE58_ENCODE_32_BYTES( operator->failover_identity, failover_identity );
  FD_LOG_WARNING(( "set-identity installed `%s`, failover restarted on this machine as a %s for identity `%s` with a new boot %016lx, "
                   "anything in progress was dropped and the other machine sees a restart",
                   identity, staked ? "active" : "standby", failover_identity, ctx->hello.boot_id ));
}

/* Our DEMOTED got its response or cannot get one any more. */
static void
handoff_resolved( fd_failover_tile_ctx_t * ctx,
                  ulong                    result ) {
  if( FD_UNLIKELY( ctx->tx.valid && ctx->tx.type==(ushort)FD_FAILOVER_MSG_DEMOTED ) ) ctx->tx.valid = 0;
  /* The handoff outcome ends the ACK wait, this machine stays standby. */
  if( FD_LIKELY( ctx->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK ) ) ctx->action = FD_FAILOVER_ACTION_IDLE;
  ctx->handoff.delivery = FD_FAILOVER_DELIVERY_NONE;
  ctx->handoff.result   = result;
}

/* A demotion that ends without sending anything.  Nobody can promote
   on it, and a requester bound to it is told at once rather than at its
   deadline. */
static void
demotion_abort( fd_failover_tile_ctx_t * ctx ) {
  if( FD_UNLIKELY( ctx->handoff.delivery!=FD_FAILOVER_DELIVERY_NONE ) ) {
    handoff_result_to( ctx, &ctx->handoff.target, ctx->handoff.id, FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY );
  }
  /* End the failed demotion without changing the installed identity. */
  ctx->action           = FD_FAILOVER_ACTION_IDLE;
  ctx->stuck            = 1;
  ctx->handoff.delivery = FD_FAILOVER_DELIVERY_NONE;
}

/* The switch, the drain and the wait for the peer's answer each get the
   whole deadline, in slots and on our clock. */
static void
demotion_deadline_start( fd_failover_tile_ctx_t * ctx ) {
  deadline_start( ctx, FD_FAILOVER_DEADLINE_SLOTS );
  ctx->handoff.until = fd_long_sat_add( fd_failover_clock(), FD_FAILOVER_CHANNEL_IDLE_NANOS );
}

/* Give up the staked identity for the peer that asked, on the session
   it asked on.  The switch itself is asked for from step_controller,
   DEMOTED goes to the peer boot we see now. */
static void
start_demotion( fd_failover_tile_ctx_t * ctx,
                ulong                    handoff_id ) {
  fd_memset( &ctx->handoff, 0, sizeof(ctx->handoff) );
  ctx->handoff.id             = handoff_id;
  ctx->handoff.result         = FD_FAILOVER_HANDOFF_NONE; /* until its DEMOTED goes out */
  ctx->handoff.delivery       = FD_FAILOVER_DELIVERY_OWED;
  ctx->handoff.target.boot_id = ctx->session.peer_boot_id;
  fd_memcpy( ctx->handoff.target.junk, fd_failover_channel_peer_hello( ctx->channel )->junk_pubkey, 32UL );
  ctx->last_requested = 0;
  ctx->stuck          = 0;
  demotion_deadline_start( ctx );
  /* Start the junk key switch before sending any final state. */
  ctx->action = FD_FAILOVER_ACTION_DEMOTE_SWITCH;
}

/* The slot a standby's replay has to reach before it adopts what we hand
   over, the tip of our tower, or the finality anchor of our vote history
   under Alpenglow. */
static ulong
ready_slot( fd_failover_tile_ctx_t const * ctx ) {
  if( FD_LIKELY( ctx->mode==FD_FAILOVER_MODE_TOWER ) ) return ctx->last_vote_slot;
  ag_hist_t hist[1];
  if( FD_UNLIKELY( ag_hist_de( ctx->current_tower.state, ctx->current_tower.sz, hist ) ) ) return ctx->last_vote_slot;
  return hist->anchor;
}

/* The final tower has to be the tower of our last vote, with no tower
   frag skipped since it was built. */
static int
final_tower_ok( fd_failover_tile_ctx_t const * ctx ) {
  return ctx->current_tower.valid && ctx->current_tower.sz &&
         ctx->last_vote_slot!=FD_FAILOVER_SLOT_NULL &&
         ctx->current_tower.tip==ctx->last_vote_slot && !ctx->tower_gap;
}

/* Called once the junk key is installed everywhere. Our latest tower is
   the final one, we hand it to the peer. */
static void
demotion_switched( fd_failover_tile_ctx_t * ctx ) {
  /* The junk key is installed and the Tower has drained. */
  set_role( ctx, FD_FAILOVER_ROLE_STANDBY );
  if( FD_LIKELY( ctx->mode==FD_FAILOVER_MODE_TOWER ) ) FD_LOG_NOTICE(( "handoff %lu: the tower drained, we are a standby now", ctx->handoff.id ));
  else                                                FD_LOG_NOTICE(( "handoff %lu: the vote history stream drained, we are a standby now", ctx->handoff.id ));

  int final_ok = final_tower_ok( ctx );

  ctx->handoff.payload_sz = !final_ok
                  ? 0UL
                  : ctx->mode==FD_FAILOVER_MODE_ALPENGLOW
                  ? fd_failover_demoted_encode_alpenglow( ctx->handoff.payload, ctx->handoff.id, ctx->handoff.target.boot_id, ctx->last_vote_slot,
                                                          ctx->current_tower.state, ctx->current_tower.sz )
                  : fd_failover_demoted_encode( ctx->handoff.payload, ctx->handoff.id, ctx->handoff.target.boot_id, ctx->last_vote_slot,
                                                ctx->current_tower.state, ctx->current_tower.sz );
  if( FD_UNLIKELY( !ctx->handoff.payload_sz ) ) {
    /* We have no final tower to hand over, or the one we have is not the
       tower of our last vote.  The peer gets nothing and cannot promote. */
    if( FD_LIKELY( ctx->mode==FD_FAILOVER_MODE_TOWER ) ) FD_LOG_WARNING(( "handoff %lu has no final tower for its last vote %lu, sending nothing, nobody votes until `failover promote --force` runs on one machine", ctx->handoff.id, ctx->last_vote_slot ));
    else                                                FD_LOG_WARNING(( "handoff %lu has no final vote history for its last vote %lu, sending nothing, nobody votes until `failover promote --force` runs on one machine", ctx->handoff.id, ctx->last_vote_slot ));
    /* End demotion without sending final state. */
    demotion_abort( ctx );
    return;
  }

  ctx->handoff.result = FD_FAILOVER_HANDOFF_PENDING;
  /* The control slot may still be holding an unsent response, so if this
     fails we retry from the wait. */
  (void)queue_demoted( ctx );
  /* Final state is ready, wait for the bound peer to accept or refuse it. */
  ctx->action = FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK;
  demotion_deadline_start( ctx );
}

/* Names for the log, never numbers. */
static char const *
reject_name( uint reason ) {
  static char const * const names[ FD_FAILOVER_REJECT_CNT ] = {
    "none", "busy", "holds identity", "replay behind",
    "adoption mismatch", "adoption failed", "switch failed"
  };
  return reason<FD_FAILOVER_REJECT_CNT ? names[ reason ] : "unknown";
}

static char const *
adopt_err_name( ulong result ) {
  switch( result ) {
  case FD_TOWER_ADOPT_ERR_DECODE:          return "decode error";
  case FD_TOWER_ADOPT_ERR_INVALID:         return "invalid";
  case FD_TOWER_ADOPT_ERR_UNREPLAYED_ROOT: return "root not replayed";
  case FD_TOWER_ADOPT_ERR_BLOCK_MISMATCH:  return "block mismatch";
  case FD_TOWER_ADOPT_ERR_UNREPLAYED:      return "votes not replayed";
  case FD_VOTOR_ADOPT_ERR_STALE:           return "older than the votes this machine sent as this identity";
  default:                                 return "unknown";
  }
}

static char const *
source_name( ulong mode,
             ulong source ) {
  int alpenglow = mode==FD_FAILOVER_MODE_ALPENGLOW;
  switch( source ) {
  case FD_FAILOVER_SOURCE_PEER:         return alpenglow ? "the vote history the peer gave us" : "the tower the peer gave us";
  case FD_FAILOVER_SOURCE_VOTE_ACCOUNT: return alpenglow ? "an empty history"                  : "the vote account";
  default:                              return "unknown";
  }
}

/* Slot sentinels are not useful to an operator reading a transition. */
static char const *
slot_text( ulong slot, char text[ 32 ] ) {
  if( FD_UNLIKELY( slot==FD_FAILOVER_SLOT_NULL ) ) return "none";
  fd_cstr_printf( text, 32UL, NULL, "%lu", slot );
  return text;
}

/* The name of a refusal and what the operator can do about it. */
static char const *
control_refusal( ulong         result,
                 ulong         mode,
                 char const ** hint ) {
  switch( result ) {
  case FD_FAILOVER_CONTROL_RESULT_BAD_ROLE:
    *hint = "`promote` runs on a standby, see `failover status`";
    return "BAD_ROLE";
  case FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS:
    *hint = "a transition or key switch is running, wait for it, `failover status` shows it";
    return "IN_PROGRESS";
  case FD_FAILOVER_CONTROL_RESULT_NO_ACTIVE_ADDRESS:
    *hint = "wait for gossip to show the staked identity, or give the active's address with `failover promote --address`, "
            "and if both machines show `role: standby` no machine holds the identity and `failover promote --force` on one of them takes it";
    return "NO_ACTIVE_ADDRESS";
  case FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY:
    *hint = "the peer could not finish this request, see `failover status` on the peer";
    return "PEER_UNREADY";
  case FD_FAILOVER_CONTROL_RESULT_PEER_UNVERIFIED:
    *hint = "the peer cannot be verified, --force is required, including first use and restart. Vote history is unknown: it has not been checked. Use `failover promote` here to request a handoff from an active failover peer, or `failover promote --force` only after ensuring every other machine with this identity cannot sign";
    return "PEER_UNVERIFIED";
  case FD_FAILOVER_CONTROL_RESULT_PEER_ACTIVE:
    *hint = "the peer holds the identity or said so recently, run `failover promote` here, or `failover promote --force` if it cannot sign";
    return "PEER_ACTIVE";
  case FD_FAILOVER_CONTROL_RESULT_HANDOFF_PENDING:
    *hint = "the peer has not answered our handoff, if it shows `role: active` run `failover promote` there to finish it, "
            "if it shows `role: standby` nothing votes and `failover promote --force` on one machine takes the identity";
    return "HANDOFF_PENDING";
  case FD_FAILOVER_CONTROL_RESULT_TAKEN:
    *hint = "the peer took our last handoff and may be voting, run `failover promote` here, or `failover promote --force` if it cannot sign";
    return "TAKEN";
  case FD_FAILOVER_CONTROL_RESULT_STAKED_SEEN:
    *hint = "gossip showed the staked identity at another host within 15 seconds, stop it or wait, or `failover promote --force` if it cannot sign";
    return "STAKED_SEEN";
  case FD_FAILOVER_CONTROL_RESULT_NO_FINAL_TOWER:
    *hint = "the active has no eligible final vote state to hand over and keeps the identity, its log explains whether no vote is known or history is missing, check its voting progress before retrying";
    return mode==FD_FAILOVER_MODE_ALPENGLOW ? "NO_FINAL_HISTORY" : "NO_FINAL_TOWER";
  default:
    *hint = "the failover tile does not know this command";
    return "UNSUPPORTED";
  }
}

/* Wait for the old active to confirm our response to its DEMOTED.  A
   request that paused during the promotion dials again, and if the boot
   we answered restarted, peer_poll ends the request when it pairs with
   the new one. */
static void
request_wait_result( fd_failover_tile_ctx_t * ctx ) {
  if( FD_UNLIKELY( !ctx->request.until ) ) fd_failover_channel_init_dialer( ctx->channel, ctx->request.addr, dial_port( ctx ) );
  ctx->action        = FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT;
  ctx->request.until = fd_long_sat_add( fd_failover_clock(), FD_FAILOVER_CHANNEL_IDLE_NANOS );
}

/* Stand back down. If the peer's DEMOTED asked for the promotion we
   tell it why and retire the recovery caches: either member may recover
   independently after a refusal, without reporting its later votes.
   Retries within a running adoption still use its separate copy. */
static void
reject_promotion( fd_failover_tile_ctx_t * ctx,
                  uchar                    reason,
                  int                      bad_tower ) {
  if( FD_UNLIKELY( bad_tower && ctx->promotion.source==FD_FAILOVER_SOURCE_PEER ) ) ctx->peer_tower.valid = 0;
  ctx->stuck  = 1;
  /* Failed local promotion returns to idle on the standby. */
  ctx->action = FD_FAILOVER_ACTION_IDLE;
  if( FD_UNLIKELY( !ctx->promotion.from_peer ) ) {
    FD_LOG_WARNING(( "%s: promotion failed (%s), we stay a standby, check that one machine votes and see `failover status`, "
                     "run `failover promote --force` again once this machine has caught up and the other cannot sign", ctx->promotion.label, reject_name( reason ) ));
    if( !ctx->promotion.force && reason!=FD_FAILOVER_REJECT_HOLDS_IDENTITY && reason!=FD_FAILOVER_REJECT_SWITCH_FAILED )
      FD_LOG_WARNING(( "no eligible vote history could be adopted, `failover promote --force` permits incomplete or empty history after the peer is fenced" ));
    return;
  }
  ctx->peer_tower.valid    = 0;
  ctx->promotion.from_peer = 0;
  /* A failed handoff waits for the old active to confirm our refusal. */
  request_wait_result( ctx );
  if( FD_UNLIKELY( reason==FD_FAILOVER_REJECT_HOLDS_IDENTITY ) ) {
    FD_LOG_WARNING(( "refusing the peer's handoff %lu (%s), we stay a standby, another machine may hold the staked identity, "
                     "check `failover status` on both machines", ctx->promotion.handoff_id, reject_name( reason ) ));
  } else {
    FD_LOG_WARNING(( "refusing the peer's handoff %lu (%s), we stay a standby and the peer already gave up the staked identity, "
                     "nothing votes until `failover promote --force` runs on one machine, check `failover status` on both machines first",
                     ctx->promotion.handoff_id, reject_name( reason ) ));
  }
  finish_reply( ctx, &ctx->promotion.peer, ctx->promotion.handoff_id, (ushort)FD_FAILOVER_MSG_PROMOTE_REJECTED, reason );
}

/* The floor joins the final votes handed to us and our own signed votes. */
static ulong
coverage_floor( fd_failover_tile_ctx_t const * ctx ) {
  if( FD_UNLIKELY( ctx->peer_floor==FD_FAILOVER_SLOT_NULL ) ) return ctx->own_floor;
  if( FD_UNLIKELY( ctx->own_floor ==FD_FAILOVER_SLOT_NULL ) ) return ctx->peer_floor;
  return fd_ulong_max( ctx->peer_floor, ctx->own_floor );
}

/* Saved history waits for its finality anchor.  Empty recovery is an
   explicit FORCE override: fence future votes at our replay position,
   or at the coverage floor when that is higher, without waiting for
   missing peer history.  The votor retains this machine's existing vote
   marks and any stronger local bound, and leads no window at or below
   the fence. */
static void
alpenglow_promote_start( fd_failover_tile_ctx_t * ctx ) {
  ctx->adopt_anchor     = FD_FAILOVER_SLOT_NULL;
  ctx->empty_vote_after = FD_FAILOVER_SLOT_NULL;
  if( FD_LIKELY( ctx->promotion.source!=FD_FAILOVER_SOURCE_VOTE_ACCOUNT ) ) {
    ag_hist_t hist[1];
    if( FD_LIKELY( !ag_hist_de( ctx->promotion.adopt.state, ctx->promotion.adopt.sz, hist ) ) ) ctx->adopt_anchor = hist->anchor;
  }
}

static int
alpenglow_replay_ready( fd_failover_tile_ctx_t * ctx ) {
  if( FD_LIKELY( ctx->promotion.source!=FD_FAILOVER_SOURCE_VOTE_ACCOUNT ) )
    return ctx->adopt_anchor==FD_FAILOVER_SLOT_NULL || ctx->replay_slot>=ctx->adopt_anchor;
  if( FD_UNLIKELY( !ctx->promotion.force ) ) {
    FD_LOG_WARNING(( "%s: no eligible saved vote history is available, Alpenglow has no vote-account history source, so empty-history promotion requires --force after the peer is fenced", ctx->promotion.label ));
    /* End the failed adoption attempt while remaining standby. */
    reject_promotion( ctx, FD_FAILOVER_REJECT_ADOPTION_FAILED, 0 );
    return 0;
  }
  ulong floor = ctx->promotion.floor;
  ctx->empty_vote_after = floor==FD_FAILOVER_SLOT_NULL ? ctx->replay_slot : fd_ulong_max( ctx->replay_slot, floor );
  if( FD_UNLIKELY( floor==FD_FAILOVER_SLOT_NULL ) ) {
    FD_LOG_WARNING(( "%s: --force accepts empty Alpenglow history, no vote or leader window at or below replay slot %lu, no earlier vote as the staked identity "
                     "is known, so a vote the peer cast above that slot is not covered, local vote marks and stronger local bounds remain",
                     ctx->promotion.label, ctx->empty_vote_after ));
  } else {
    FD_LOG_WARNING(( "%s: --force accepts empty Alpenglow history, no vote or leader window at or below slot %lu, which covers replay at slot %lu and the "
                     "last vote known as the staked identity at slot %lu, local vote marks and stronger local bounds remain",
                     ctx->promotion.label, ctx->empty_vote_after, ctx->replay_slot, floor ));
  }
  FD_STORE( ulong, ctx->promotion.adopt.state, ctx->empty_vote_after );
  ctx->promotion.adopt.sz = FD_VOTOR_ADOPT_EMPTY_SZ;
  return 1;
}

/* Says what the votor took, the history's tip and anchor or the empty
   history.  Its response has the vote bound where the tower tile's has
   acct_vote_slot. */
static void
alpenglow_adopted( fd_failover_tile_ctx_t const * ctx ) {
  ulong bound = ctx->adopt_result.acct_vote_slot;
  if( FD_UNLIKELY( ctx->promotion.source==FD_FAILOVER_SOURCE_VOTE_ACCOUNT ) ) {
    FD_LOG_NOTICE(( "%s: the votor started an empty vote history, no vote at or below slot %lu", ctx->promotion.label, bound ));
  } else if( FD_LIKELY( bound==FD_FAILOVER_SLOT_NULL ) ) {
    FD_LOG_NOTICE(( "%s: the votor adopted the vote history ending at slot %lu, finality anchor at slot %lu", ctx->promotion.label, ctx->adopt_result.vote_slot, ctx->adopt_anchor ));
  } else {
    FD_LOG_NOTICE(( "%s: the votor adopted the vote history ending at slot %lu, finality anchor at slot %lu, no vote at or below slot %lu", ctx->promotion.label,
                    ctx->adopt_result.vote_slot, ctx->adopt_anchor, bound ));
  }
}

/* Take the staked identity with the tower from source.  A peer is given
   when that member's DEMOTED with handoff_id asked for it, it gets our
   response.  An operator promotion passes NULL and 0.  force is promote
   --force. */
static void
start_promotion( fd_failover_tile_ctx_t *   ctx,
                 ulong                      source,
                 fd_failover_peer_t const * peer,
                 ulong                      handoff_id,
                 int                        force ) {
  int                from_peer = !!peer;
  fd_failover_peer_t bound     = {0};
  if( from_peer ) bound = *peer;
  fd_memset( &ctx->promotion, 0, sizeof(ctx->promotion) );
  if( source==FD_FAILOVER_SOURCE_PEER ) ctx->promotion.adopt = ctx->peer_tower;
  else                                  ctx->promotion.adopt.tip = FD_FAILOVER_SLOT_NULL;
  if( from_peer ) {
    ctx->promotion.peer       = bound;
    ctx->promotion.handoff_id = handoff_id;
    fd_cstr_printf( ctx->promotion.label, sizeof(ctx->promotion.label), NULL, "handoff %lu", handoff_id );
  } else {
    fd_cstr_printf( ctx->promotion.label, sizeof(ctx->promotion.label), NULL, "operator promotion" );
  }
  ctx->promotion.source     = source;
  ctx->promotion.from_peer  = from_peer;
  ctx->promotion.force      = force;
  ctx->promotion.floor      = coverage_floor( ctx );
  ctx->promotion.floor_acct = FD_FAILOVER_SLOT_NULL;
  /* What we knew of another holder at the start, promote_holder_seen
     looks for anything newer. */
  ctx->promotion.staked_at = ctx->staked_seen_at;
  /* Until this tenure votes, its final tower is exactly the adopted one,
     never a tower cached from an earlier tenure. */
  ctx->current_tower  = ctx->promotion.adopt;
  ctx->tower_gap      = 0;
  ctx->last_vote_slot = ctx->promotion.adopt.tip;
  ctx->stuck          = 0;
  if( FD_UNLIKELY( ctx->mode==FD_FAILOVER_MODE_ALPENGLOW ) ) alpenglow_promote_start( ctx );
  deadline_start( ctx, FD_FAILOVER_DEADLINE_SLOTS );
  /* Replay must reach the selected history before adoption. */
  ctx->action = FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY;
  if( FD_UNLIKELY( ctx->mode==FD_FAILOVER_MODE_ALPENGLOW ) ) {
    /* A vote history waits for replay to reach its finality anchor. */
    if( FD_UNLIKELY( from_peer && ctx->adopt_anchor!=FD_FAILOVER_SLOT_NULL &&
                     ( ctx->replay_slot==FD_FAILOVER_SLOT_NULL || ctx->replay_slot<ctx->adopt_anchor ) ) ) {
      FD_LOG_NOTICE(( "%s: the promotion waits for replay to reach the finality anchor at slot %lu before it adopts %s", ctx->promotion.label, ctx->adopt_anchor, source_name( ctx->mode, source ) ));
    }
  } else if( FD_UNLIKELY( from_peer && ctx->promotion.adopt.tip!=FD_FAILOVER_SLOT_NULL &&
                          ( ctx->replay_slot==FD_FAILOVER_SLOT_NULL || ctx->replay_slot<ctx->promotion.adopt.tip ) ) ) {
    FD_LOG_NOTICE(( "%s: the promotion waits for replay to reach slot %lu before it adopts %s", ctx->promotion.label, ctx->promotion.adopt.tip, source_name( ctx->mode, source ) ));
  }
}

/* An operator promotion tries saved state, then the vote account, then
   (only with FORCE) an empty tower.  Enter only before publication or
   after the matching adoption response: never overlap local work.  A
   handoff must still adopt its bound final state or report a refusal. */
static int
promote_fallback( fd_failover_tile_ctx_t * ctx,
                  char const *             reason ) {
  if( FD_UNLIKELY( ctx->promotion.from_peer || ctx->promotion.empty ) ) return 0;
  if( ctx->promotion.source!=FD_FAILOVER_SOURCE_VOTE_ACCOUNT ) {
    FD_LOG_NOTICE(( "%s: %s is not eligible (%s), trying %s", ctx->promotion.label,
                    source_name( ctx->mode, ctx->promotion.source ), reason, source_name( ctx->mode, FD_FAILOVER_SOURCE_VOTE_ACCOUNT ) ));
    if( ctx->promotion.source==FD_FAILOVER_SOURCE_PEER ) ctx->peer_tower.valid = 0;
    /* Ineligible saved state falls back to the vote account. */
    ctx->promotion.source = FD_FAILOVER_SOURCE_VOTE_ACCOUNT;
  } else {
    /* Under Alpenglow the empty history is the last source. */
    if( !ctx->promotion.force || ctx->mode==FD_FAILOVER_MODE_ALPENGLOW ) return 0;
    FD_LOG_WARNING(( "%s: the vote account cannot be adopted (%s), --force proceeds with an empty tower", ctx->promotion.label, reason ));
    /* Only a forced operator promotion may fall back to empty history. */
    ctx->promotion.empty = 1;
  }
  ctx->promotion.adopt.valid = 0;
  ctx->promotion.adopt.tip   = FD_FAILOVER_SLOT_NULL;
  ctx->promotion.adopt.sz    = 0UL;
  ctx->current_tower         = ctx->promotion.adopt;
  ctx->last_vote_slot        = FD_FAILOVER_SLOT_NULL;
  ctx->promotion.retry       = 0;
  ctx->adopt_result_fresh    = 0;
  if( ctx->mode==FD_FAILOVER_MODE_ALPENGLOW ) alpenglow_promote_start( ctx );
  /* Retry adoption from the fallback source after the prior attempt has ended. */
  ctx->action             = FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY;
  return 1;
}

/* Coverage floor.  The peer reported or we signed votes up to the
   floor, an adopted tower short of them could vote against their
   lockouts.  For the vote account its own last vote counts, votes our
   root already passed are on the chain we replayed.  The vote account
   may also go ahead once replay passed the floor by the slack.  With no
   floor known we go ahead, like an upstream restart. */
static int
floor_covered( fd_failover_tile_ctx_t const * ctx ) {
  /* An empty Alpenglow history preserves only its local vote bound.
     FORCE decides whether missing peer history can be overridden. */
  if( FD_UNLIKELY( ctx->mode==FD_FAILOVER_MODE_ALPENGLOW && ctx->promotion.source==FD_FAILOVER_SOURCE_VOTE_ACCOUNT ) )
    return ctx->promotion.floor==FD_FAILOVER_SLOT_NULL ||
           ( ctx->adopt_result.acct_vote_slot!=FD_FAILOVER_SLOT_NULL && ctx->adopt_result.acct_vote_slot>=ctx->promotion.floor );
  ulong floor = ctx->promotion.floor;
  ulong tip   = ctx->promotion.source==FD_FAILOVER_SOURCE_VOTE_ACCOUNT ? ctx->adopt_result.acct_vote_slot
                                                                     : ctx->adopt_result.vote_slot;
  if( FD_LIKELY( floor==FD_FAILOVER_SLOT_NULL ) ) return 1;
  if( FD_LIKELY( tip!=FD_FAILOVER_SLOT_NULL && tip>=floor ) ) return 1;
  return ctx->promotion.source==FD_FAILOVER_SOURCE_VOTE_ACCOUNT &&
         ctx->replay_slot!=FD_FAILOVER_SLOT_NULL &&
         ctx->replay_slot>fd_ulong_sat_add( floor, FD_FAILOVER_FLOOR_SLACK_SLOTS );
}

/* The bound DEMOTED supersedes that session's initial ACTIVE HELLO.
   A later ACTIVE authentication is another holder, and stays one if
   the connection drops.  An operator promote also watches gossip. */
static int
promote_holder_seen( fd_failover_tile_ctx_t const * ctx ) {
  if( FD_UNLIKELY( ctx->promotion.force ) ) return 0;
  if( FD_UNLIKELY( ctx->promotion.active_seen ) ) return 1;
  if( FD_UNLIKELY( ctx->promotion.from_peer ) ) return 0;
  return ctx->staked_seen_at!=ctx->promotion.staked_at;
}

static void
step_demote_drain( fd_failover_tile_ctx_t * ctx ) {
  deadline_arm( ctx, FD_FAILOVER_DEADLINE_SLOTS );
  int expired = deadline_expired( ctx ) || ( ctx->handoff.until && fd_failover_clock()>=ctx->handoff.until );
  /* The watermark is the tower tile's output sequence when it stopped
     signing.  Every frag it published before that is consumed before the
     final tower is taken from the cache, or the last vote it signed could
     be missing from DEMOTED.  Same link, same counter, so the wait is
     exact. */
  if( FD_UNLIKELY( !fd_seq_ge( fd_seq_inc( ctx->tower_seen_seq, 1UL ), ctx->id_switch.result.tower_watermark ) ) ) {
    if( FD_UNLIKELY( expired ) ) {
      /* The identity is gone from here, so we stand by and send
         nothing, nobody can promote on it. */
      if( FD_LIKELY( ctx->mode==FD_FAILOVER_MODE_TOWER ) ) FD_LOG_WARNING(( "handoff %lu: the tower did not report its last votes in time, up to seq %lu, sending nothing, nobody votes until `failover promote --force` runs on one machine", ctx->handoff.id, ctx->id_switch.result.tower_watermark ));
      else                                                FD_LOG_WARNING(( "handoff %lu: the vote history stream did not report its last votes in time, up to seq %lu, sending nothing, nobody votes until `failover promote --force` runs on one machine", ctx->handoff.id, ctx->id_switch.result.tower_watermark ));
      ctx->id_switch.fresh   = 0;
      ctx->id_switch.overdue = 0;
      /* The junk switch succeeded, a drain timeout still leaves us standby. */
      set_role( ctx, FD_FAILOVER_ROLE_STANDBY );
      /* End demotion without sending final state. */
      demotion_abort( ctx );
    }
    return;
  }
  ctx->id_switch.fresh   = 0;
  ctx->id_switch.overdue = 0;
  /* The switch and drain finished, complete demotion or send final state. */
  demotion_switched( ctx );
}

static void
step_demote_switch( fd_failover_tile_ctx_t * ctx,
                    fd_stem_context_t *      stem ) {
  deadline_arm( ctx, FD_FAILOVER_DEADLINE_SLOTS );
  int expired = deadline_expired( ctx ) || ( ctx->handoff.until && fd_failover_clock()>=ctx->handoff.until );
  if( FD_UNLIKELY( ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_CNT && !ctx->id_switch.fresh ) ) {
    if( FD_UNLIKELY( request_switch( ctx, stem, FD_FAILOVER_SWITCH_KEY_JUNK )==ULONG_MAX ) ) {
      /* The request never went out and we still have the identity, so
         nothing is owed to the peer. */
      FD_LOG_WARNING(( "an identity switch could not be requested, remaining the active" ));
      /* End demotion without sending final state. */
      demotion_abort( ctx );
      return;
    }
    FD_LOG_NOTICE(( "handoff %lu: asked the admin tile to install the junk identity", ctx->handoff.id ));
    return;
  }
  if( FD_LIKELY( !ctx->id_switch.fresh ) ) {
    /* No response yet.  We do not know whether the junk key got installed,
       so we claim nothing and keep waiting, the late response still counts.
       Past the deadline we raise stuck for the operator. */
    if( FD_UNLIKELY( expired ) ) switch_overdue( ctx );
    return;
  }
  if( FD_UNLIKELY( ctx->id_switch.result.result!=FD_FAILOVER_SWITCH_OK ) ) {
    /* The switch failed and we still have the identity, so we send
       nothing. */
    ctx->id_switch.fresh   = 0;
    ctx->id_switch.overdue = 0;
    FD_LOG_WARNING(( "the identity switch for handoff %lu failed (%s), we keep the staked identity and stay the active", ctx->handoff.id,
                     ctx->id_switch.result.result==FD_FAILOVER_SWITCH_ERR_DISABLED ? "failover disabled" : "unknown" ));
    /* End demotion without sending final state. */
    demotion_abort( ctx );
    return;
  }
  /* The junk key is installed everywhere, the answer holds the watermark
     the drain waits for. */
  if( FD_LIKELY( ctx->mode==FD_FAILOVER_MODE_TOWER ) ) FD_LOG_NOTICE(( "handoff %lu: the junk identity is installed, waiting for the tower to drain up to seq %lu", ctx->handoff.id, ctx->id_switch.result.tower_watermark ));
  else                                                FD_LOG_NOTICE(( "handoff %lu: the junk identity is installed, waiting for the vote history stream to drain up to seq %lu", ctx->handoff.id, ctx->id_switch.result.tower_watermark ));
  ctx->action = FD_FAILOVER_ACTION_DEMOTE_DRAIN;
  demotion_deadline_start( ctx );
  step_demote_drain( ctx );
}

static void
step_demote_wait_ack( fd_failover_tile_ctx_t * ctx ) {
  /* If the peer goes quiet we do not undo the demotion, we only raise
     the alarm.  The identity is already gone from this machine. */
  deadline_arm( ctx, FD_FAILOVER_DEADLINE_SLOTS );
  /* A new peer boot cannot respond to this DEMOTED. Its earlier boot may
     already have taken the identity and voted before losing its ACK. */
  if( FD_UNLIKELY( fd_failover_channel_state( ctx->channel )==FD_FAILOVER_SESSION_PAIRED &&
                   fd_memeq( fd_failover_channel_peer_hello( ctx->channel )->junk_pubkey, ctx->handoff.target.junk, 32UL ) &&
                   ctx->session.peer_boot_id!=ctx->handoff.target.boot_id ) ) {
    FD_LOG_WARNING(( "the peer restarted before it answered handoff %lu and may have voted before it restarted, neither machine holds the staked identity now, "
                     "nothing votes until `failover promote --force` runs on one of them", ctx->handoff.id ));
    ctx->peer_tower.valid = 0;
    /* A new peer boot ends this ACK wait without proving whether it voted. */
    handoff_resolved( ctx, FD_FAILOVER_HANDOFF_RESTARTED );
    return;
  }
  /* A reconnect from the same member can finish its handoff. */
  if( FD_UNLIKELY( ctx->handoff.delivery==FD_FAILOVER_DELIVERY_OWED && !ctx->tx.valid ) ) {
    (void)queue_demoted( ctx );
  }
  if( FD_UNLIKELY( deadline_expired( ctx ) || ( ctx->handoff.until && fd_failover_clock()>=ctx->handoff.until ) ) ) {
    if( FD_UNLIKELY( !ctx->stuck ) )
      FD_LOG_WARNING(( "the peer has not answered handoff %lu, we remain standby and resend final state when it reconnects, "
                       "if the peer shows `role: active` run `failover promote` there to finish this handoff, "
                       "if it shows `role: standby` nothing votes and `failover promote --force` on one machine takes the identity", ctx->handoff.id ));
    ctx->stuck = 1;
  }
  return;
}

static void
step_promote_wait_replay( fd_failover_tile_ctx_t * ctx,
                          fd_stem_context_t *      stem ) {
  long now = fd_failover_clock();
  promote_deadline_arm( ctx, now );
  if( FD_UNLIKELY( promote_expired( ctx, now ) ) ) {
    /* Replay timed out, fail the promotion while remaining standby. */
    reject_promotion( ctx, FD_FAILOVER_REJECT_REPLAY_BEHIND, 0 );
    return;
  }
  /* Wait for replay to reach the tower's tip before adopting, otherwise
     the tower refers to blocks we have not seen yet. */
  if( FD_UNLIKELY( ctx->replay_slot==FD_FAILOVER_SLOT_NULL ) ) return;
  if( FD_UNLIKELY( ctx->mode==FD_FAILOVER_MODE_TOWER && ctx->promotion.adopt.tip!=FD_FAILOVER_SLOT_NULL && ctx->replay_slot<ctx->promotion.adopt.tip ) ) {
    /* Operator promotion tries a fallback, a handoff keeps waiting for its tip. */
    (void)promote_fallback( ctx, "replay has not reached its tip" );
    return;
  }
  if( FD_UNLIKELY( ctx->mode==FD_FAILOVER_MODE_ALPENGLOW && !alpenglow_replay_ready( ctx ) ) ) {
    /* Operator promotion tries the empty history, a handoff keeps waiting for its anchor. */
    if( ctx->promotion.source!=FD_FAILOVER_SOURCE_VOTE_ACCOUNT ) (void)promote_fallback( ctx, "replay has not reached its finality anchor" );
    return;
  }
  ulong id = publish_adopt_state( ctx, stem );
  if( FD_UNLIKELY( id==ULONG_MAX ) ) {
    /* End the failed adoption attempt while remaining standby. */
    reject_promotion( ctx, FD_FAILOVER_REJECT_ADOPTION_FAILED, 0 );
    return;
  }
  if( FD_LIKELY( ctx->mode==FD_FAILOVER_MODE_TOWER ) ) FD_LOG_NOTICE(( "%s: asking the tower tile to adopt %s", ctx->promotion.label,
                  ctx->promotion.empty ? "an empty tower authorized by --force" : source_name( ctx->mode, ctx->promotion.source ) ));
  else                                                FD_LOG_NOTICE(( "%s: asking the votor to adopt %s", ctx->promotion.label, source_name( ctx->mode, ctx->promotion.source ) ));
  ctx->promotion.adopt_id = id;
  ctx->promotion.retry    = 0;
  /* The adoption request is published, wait for its response. */
  ctx->action            = FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT;
  return;
}

static void
step_promote_wait_adopt( fd_failover_tile_ctx_t * ctx,
                         fd_stem_context_t *      stem ) {
  long now = fd_failover_clock();
  promote_deadline_arm( ctx, now );
  if( FD_UNLIKELY( promote_expired( ctx, now ) ) ) {
    /* Adoption timed out, fail promotion while remaining standby. */
    reject_promotion( ctx, FD_FAILOVER_REJECT_ADOPTION_FAILED, 0 );
    return;
  }
  if( FD_UNLIKELY( ctx->promotion.retry ) ) {
    /* The tower tile has not replayed every block the tower votes on, or
       the adopted tip is short of the floor.  Ask again once replay
       passes retry_slot, the deadline above bounds the wait. */
    if( FD_LIKELY( ctx->replay_slot<=ctx->promotion.retry_slot ) ) return;
    ulong id = publish_adopt_state( ctx, stem );
    if( FD_UNLIKELY( id==ULONG_MAX ) ) {
      /* End the failed adoption attempt while remaining standby. */
      reject_promotion( ctx, FD_FAILOVER_REJECT_ADOPTION_FAILED, 0 );
      return;
    }
    /* Replay advanced, retry adoption without leaving the adoption wait. */
    ctx->promotion.adopt_id = id;
    ctx->promotion.retry    = 0;
    return;
  }
  if( FD_LIKELY( !ctx->adopt_result_fresh ) ) return; /* Wait for an adoption response. */
  ctx->adopt_result_fresh = 0;
  if( FD_UNLIKELY( ctx->adopt_result_id!=ctx->promotion.adopt_id ) ) return; /* Ignore responses to earlier attempts. */
  if( FD_UNLIKELY( ctx->adopt_result.result==FD_TOWER_ADOPT_ERR_UNREPLAYED ) ) {
    /* Operator promotion tries a fallback before waiting for more replay. */
    if( promote_fallback( ctx, ctx->mode==FD_FAILOVER_MODE_TOWER ? "its blocks have not been replayed" : "the votor is not up yet" ) ) return;
    if( FD_UNLIKELY( !ctx->promotion.from_peer ) ) {
      /* End the failed adoption attempt while remaining standby. */
      reject_promotion( ctx, FD_FAILOVER_REJECT_ADOPTION_FAILED, 0 );
      return;
    }
    if( FD_UNLIKELY( !ctx->promotion.retry_logged ) ) {
      if( FD_LIKELY( ctx->mode==FD_FAILOVER_MODE_TOWER ) ) FD_LOG_NOTICE(( "%s: the tower tile has not replayed every block the tower votes on, asking again as replay moves", ctx->promotion.label ));
      else                                                FD_LOG_NOTICE(( "%s: the votor is not ready to adopt the vote history, asking again as replay moves", ctx->promotion.label ));
      ctx->promotion.retry_logged = 1;
    }
    /* Keep the bound final state and wait for replay before retrying. */
    ctx->promotion.retry      = 1;
    ctx->promotion.retry_slot = ctx->replay_slot;
    return;
  }
  if( FD_UNLIKELY( ctx->adopt_result.result!=FD_TOWER_ADOPT_SUCCESS ) ) {
    /* Try the next permitted source before failing promotion. */
    if( promote_fallback( ctx, adopt_err_name( ctx->adopt_result.result ) ) ) return;
    if( FD_LIKELY( ctx->mode==FD_FAILOVER_MODE_TOWER ) ) FD_LOG_WARNING(( "%s: the tower tile refused %s (%s)", ctx->promotion.label, source_name( ctx->mode, ctx->promotion.source ), adopt_err_name( ctx->adopt_result.result ) ));
    else                                                FD_LOG_WARNING(( "%s: the votor refused %s (%s)", ctx->promotion.label, source_name( ctx->mode, ctx->promotion.source ), adopt_err_name( ctx->adopt_result.result ) ));
    ulong result = ctx->adopt_result.result;
    /* Tower rejected the history, stop promotion and report any handoff refusal. */
    reject_promotion( ctx, result==FD_TOWER_ADOPT_ERR_BLOCK_MISMATCH ? FD_FAILOVER_REJECT_ADOPTION_MISMATCH
                                                                     : FD_FAILOVER_REJECT_ADOPTION_FAILED,
                      result==FD_TOWER_ADOPT_ERR_BLOCK_MISMATCH || result==FD_TOWER_ADOPT_ERR_DECODE ||
                      result==FD_TOWER_ADOPT_ERR_INVALID        || result==FD_VOTOR_ADOPT_ERR_STALE );
    return;
  }
  if( FD_UNLIKELY( ctx->promotion.adopt.tip!=FD_FAILOVER_SLOT_NULL && ctx->adopt_result.vote_slot!=ctx->promotion.adopt.tip ) ) {
    /* The tower tile keeps the prefix replay has produced, so a tower
       that ends short of its last vote would leave lockouts behind.
       That is a mismatch, not a promotion. */
    /* Operator promotion may retry a different source after a tip mismatch. */
    if( promote_fallback( ctx, "adoption did not retain its final vote" ) ) return;
    if( FD_LIKELY( ctx->mode==FD_FAILOVER_MODE_TOWER ) ) FD_LOG_WARNING(( "%s: the adopted tower ends at slot %lu, the tower says %lu, replay does not have its last vote, so it is a mismatch", ctx->promotion.label, ctx->adopt_result.vote_slot, ctx->promotion.adopt.tip ));
    else                                                FD_LOG_WARNING(( "%s: the adopted vote history ends at slot %lu, the history says %lu, so it is a mismatch", ctx->promotion.label, ctx->adopt_result.vote_slot, ctx->promotion.adopt.tip ));
    /* The adopted tip differs, fail promotion without installing the staked key. */
    reject_promotion( ctx, FD_FAILOVER_REJECT_ADOPTION_MISMATCH, 1 );
    return;
  }
  if( FD_UNLIKELY( ctx->mode==FD_FAILOVER_MODE_ALPENGLOW ) ) alpenglow_adopted( ctx );
  int covered       = floor_covered( ctx );
  int empty_account = ctx->promotion.source==FD_FAILOVER_SOURCE_VOTE_ACCOUNT &&
                      ( ctx->mode==FD_FAILOVER_MODE_ALPENGLOW || ctx->adopt_result.acct_vote_slot==FD_FAILOVER_SLOT_NULL );
  if( FD_UNLIKELY( !ctx->promotion.from_peer && ( !covered || empty_account ) ) ) {
    /* Insufficient saved history falls back to the vote account. */
    if( ctx->promotion.source!=FD_FAILOVER_SOURCE_VOTE_ACCOUNT &&
        promote_fallback( ctx, "its votes do not cover the known signing history" ) ) return;
    if( !ctx->promotion.force ) {
      char tip[ 32 ], floor[ 32 ];
      if( ctx->mode==FD_FAILOVER_MODE_ALPENGLOW )
        FD_LOG_WARNING(( "%s: no eligible saved vote history is available, Alpenglow has no vote-account history source, so empty-history promotion requires --force after the peer is fenced", ctx->promotion.label ));
      else if( empty_account )
        FD_LOG_WARNING(( "%s: no vote history found in the vote account, promotion requires --force after the peer is fenced", ctx->promotion.label ));
      else
        FD_LOG_WARNING(( "%s: the vote account has incomplete history (last account vote %s, required coverage floor %s), promotion requires --force after the peer is fenced", ctx->promotion.label,
                         slot_text( ctx->adopt_result.acct_vote_slot, tip ), slot_text( ctx->promotion.floor, floor ) ));
      /* End the failed adoption attempt while remaining standby. */
      reject_promotion( ctx, FD_FAILOVER_REJECT_ADOPTION_FAILED, 0 );
      return;
    }
    if( ctx->mode==FD_FAILOVER_MODE_TOWER && !ctx->promotion.empty ) {
      char tip[ 32 ], floor[ 32 ];
      FD_LOG_WARNING(( "%s: --force accepts %s vote-account history (last account vote %s, required coverage floor %s), earlier votes and lockouts may be lost", ctx->promotion.label,
                       empty_account ? "empty" : "incomplete", slot_text( ctx->adopt_result.acct_vote_slot, tip ), slot_text( ctx->promotion.floor, floor ) ));
    }
  }
  if( FD_UNLIKELY( !covered && !ctx->promotion.force ) ) {
    /* We see the account's last vote only in a response.  While it moves
       votes are still landing, so we ask again once replay moves.  Once
       it stops, asking again only adopts the same tower, so we ask once
       replay passes the floor by the slack.  The tip of a peer or own
       tower never changes, so it is not asked for again and the
       deadline ends that wait. */
    int acct  = ctx->promotion.source==FD_FAILOVER_SOURCE_VOTE_ACCOUNT;
    int moved = acct && ctx->adopt_result.acct_vote_slot!=ctx->promotion.floor_acct;
    if( FD_UNLIKELY( !ctx->promotion.floor_logged ) ) {
      if( FD_LIKELY( acct ) ) {
        if( FD_UNLIKELY( ctx->adopt_result.acct_vote_slot==FD_FAILOVER_SLOT_NULL ) ) {
          FD_LOG_NOTICE(( "%s: the vote account has no vote yet, waiting for one at or past the coverage floor at slot %lu, or for replay to pass slot %lu", ctx->promotion.label,
                          ctx->promotion.floor, fd_ulong_sat_add( ctx->promotion.floor, FD_FAILOVER_FLOOR_SLACK_SLOTS ) ));
        } else {
          FD_LOG_NOTICE(( "%s: the vote account's last vote is slot %lu, waiting for it to reach the coverage floor at slot %lu, or for replay to pass slot %lu", ctx->promotion.label,
                          ctx->adopt_result.acct_vote_slot, ctx->promotion.floor, fd_ulong_sat_add( ctx->promotion.floor, FD_FAILOVER_FLOOR_SLACK_SLOTS ) ));
        }
      } else {
        FD_LOG_WARNING(( "%s: %s ends at slot %lu, short of the coverage floor at slot %lu, the promotion stops at its deadline", ctx->promotion.label,
                         source_name( ctx->mode, ctx->promotion.source ), ctx->adopt_result.vote_slot, ctx->promotion.floor ));
      }
      ctx->promotion.floor_logged = 1;
    }
    /* Stay in the adoption wait until coverage can advance or the deadline expires. */
    ctx->promotion.floor_acct = ctx->adopt_result.acct_vote_slot;
    ctx->promotion.retry      = 1;
    ctx->promotion.retry_slot = moved ? ctx->replay_slot :
                            acct  ? fd_ulong_max( ctx->replay_slot, fd_ulong_sat_add( ctx->promotion.floor, FD_FAILOVER_FLOOR_SLACK_SLOTS ) ) :
                                    FD_FAILOVER_SLOT_NULL;
    return;
  }
  if( FD_UNLIKELY( promote_holder_seen( ctx ) ) ) {
    /* The identity may be held elsewhere now, so we do not install it
       too. */
    FD_LOG_WARNING(( "%s: another machine may hold the identity now, %s, "
                     "not installing the staked key, check `failover status` on both machines", ctx->promotion.label,
                     ctx->promotion.active_seen ? "a peer authenticated as ACTIVE during this promotion"
                                              : "gossip showed the staked identity at another host" ));
    /* Another holder was seen, stop before installing the staked key. */
    reject_promotion( ctx, FD_FAILOVER_REJECT_HOLDS_IDENTITY, 0 );
    return;
  }
  if( FD_UNLIKELY( ctx->promotion.adopt.tip==FD_FAILOVER_SLOT_NULL ) ) ctx->last_vote_slot = ctx->adopt_result.vote_slot;
  if( FD_UNLIKELY( request_switch( ctx, stem, FD_FAILOVER_SWITCH_KEY_STAKED )==ULONG_MAX ) ) {
    /* The switch was not submitted, fail promotion while remaining standby. */
    reject_promotion( ctx, FD_FAILOVER_REJECT_ADOPTION_FAILED, 0 );
    return;
  }
  if( FD_LIKELY( ctx->mode==FD_FAILOVER_MODE_TOWER ) ) FD_LOG_NOTICE(( "%s: the tower tile adopted %s, asking the admin tile to install the staked identity", ctx->promotion.label,
                  ctx->promotion.empty ? "an empty tower authorized by --force" : source_name( ctx->mode, ctx->promotion.source ) ));
  else                                                FD_LOG_NOTICE(( "%s: asking the admin tile to install the staked identity", ctx->promotion.label ));
  /* Adoption passed, wait for admin to install the staked identity. */
  ctx->action = FD_FAILOVER_ACTION_PROMOTE_SWITCH;
  return;
}

static void
step_promote_switch( fd_failover_tile_ctx_t * ctx ) {
  deadline_arm( ctx, FD_FAILOVER_DEADLINE_SLOTS );
  if( FD_LIKELY( !ctx->id_switch.fresh ) ) {
    /* No response yet.  Standing down here would tell the peer nobody
       promoted while the staked key may well be installed.  So we keep
       waiting and raise stuck past the deadline, the late response still
       counts. */
    if( FD_UNLIKELY( deadline_expired( ctx ) || ( ctx->promotion.until && fd_failover_clock()>=ctx->promotion.until ) ) ) switch_overdue( ctx );
    return;
  }
  ctx->id_switch.fresh   = 0;
  ctx->id_switch.overdue = 0;
  if( FD_UNLIKELY( ctx->id_switch.result.result!=FD_FAILOVER_SWITCH_OK ) ) {
    /* Admin refused the switch, remain standby and fail the promotion. */
    reject_promotion( ctx, FD_FAILOVER_REJECT_SWITCH_FAILED, 0 );
    return;
  }
  /* Admin confirmed the staked identity is installed, become active. */
  set_role( ctx, FD_FAILOVER_ROLE_ACTIVE );
  /* A new tenure starts, the towers we kept are older than its votes. */
  ctx->peer_tower.valid = 0;
  ctx->taken            = 0;
  /* Local promotion is complete. */
  ctx->action           = FD_FAILOVER_ACTION_IDLE;
  ctx->stuck            = 0;
  if( FD_UNLIKELY( ctx->mode==FD_FAILOVER_MODE_ALPENGLOW ) ) {
    if( FD_LIKELY( ctx->promotion.source!=FD_FAILOVER_SOURCE_VOTE_ACCOUNT ) ) {
      FD_LOG_NOTICE(( "%s: we are the active now, the staked identity is installed and the adopted vote history ends at slot %lu", ctx->promotion.label, ctx->last_vote_slot ));
    } else {
      FD_LOG_NOTICE(( "%s: we are the active now, the staked identity is installed with an empty history, no vote at or below slot %lu", ctx->promotion.label, ctx->empty_vote_after ));
    }
  } else if( FD_UNLIKELY( ctx->last_vote_slot==FD_FAILOVER_SLOT_NULL ) ) {
    FD_LOG_NOTICE(( "%s: we are the active now, the staked identity is installed with %s", ctx->promotion.label,
                    ctx->promotion.empty ? "an empty tower authorized by --force" : "the vote account's tower" ));
  } else {
    FD_LOG_NOTICE(( "%s: we are the active now, the staked identity is installed and the adopted tower ends at slot %lu", ctx->promotion.label, ctx->last_vote_slot ));
  }
  if( FD_UNLIKELY( ctx->promotion.from_peer ) ) {
    /* The ACK tells the old active its handoff is done.  We keep it as
       our response, so the same DEMOTED again gets the ACK again. */
    ctx->promotion.from_peer  = 0;
    /* Remain active while the old active confirms our ACK. */
    request_wait_result( ctx );
    finish_reply( ctx, &ctx->promotion.peer, ctx->promotion.handoff_id, (ushort)FD_FAILOVER_MSG_PROMOTE_ACK, (uchar)FD_FAILOVER_REJECT_NONE );
  }
  return;
}

/* Move the current transition along.  Each step waits on one thing, the
   admin tile, the tower tile, replay reaching a slot, or the peer.  If a
   step misses its deadline we stand down, except that a key switch in
   flight is always waited for. */
static void
step_controller( fd_failover_tile_ctx_t * ctx,
                 fd_stem_context_t *      stem ) {
  /* A response that could not be queued while another control message
     held the slot is still owed to the peer, send it once the slot is
     free. */
  if( FD_UNLIKELY( ctx->reply.state==FD_FAILOVER_REPLY_OWED && !ctx->tx.valid ) ) queue_reply( ctx );
  if( FD_LIKELY( ctx->action==FD_FAILOVER_ACTION_IDLE ) ) return;

  switch( ctx->action ) {

  case FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER:
  case FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT:
    return; /* Peer polling handles these waits. */

  case FD_FAILOVER_ACTION_DEMOTE_SWITCH:
    step_demote_switch( ctx, stem );
    return;

  case FD_FAILOVER_ACTION_DEMOTE_DRAIN:
    step_demote_drain( ctx );
    return;

  case FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK:
    step_demote_wait_ack( ctx );
    return;

  case FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY:
    step_promote_wait_replay( ctx, stem );
    return;

  case FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT:
    step_promote_wait_adopt( ctx, stem );
    return;

  case FD_FAILOVER_ACTION_PROMOTE_SWITCH:
    step_promote_switch( ctx );
    return;

  default: FD_LOG_ERR(( "unexpected failover action %lu", ctx->action ));
  }
}

static void
request_end( fd_failover_tile_ctx_t * ctx, long now, ulong result );

/* A lost response is not a cancellation.  Keep the request and its member
   binding so another `failover promote` resumes the same operation. */
static char const *
request_wait( fd_failover_tile_ctx_t const * ctx ) {
  switch( ctx->action ) {
  case FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER:
    if( !ctx->request.peer.boot_id ) return "no peer authenticated, no handoff request sent, we remain standby";
    if( !ctx->request.send_cnt ) return "peer authenticated, no handoff request sent, we remain standby";
    return "waiting for final state, the peer may still hold the identity";
  case FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY: return "replay catch-up continues locally, we remain standby";
  case FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT:  return "adoption continues locally, we remain standby";
  case FD_FAILOVER_ACTION_PROMOTE_SWITCH:      return "the staked key switch continues locally, its outcome is still unknown";
  case FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT:
    return ctx->role==FD_FAILOVER_ROLE_ACTIVE ? "we hold the staked identity, waiting for the peer to confirm our ACK"
                                               : "we remain standby, waiting for the peer to confirm our refusal";
  default: return "the local transition is retained";
  }
}

/* What the operator can do about a paused request. */
static char const *
request_next( fd_failover_tile_ctx_t const * ctx ) {
  if( FD_UNLIKELY( ctx->request.peer_restarted ) ) return "the active boot we authenticated restarted, `failover promote` here starts a new handoff";
  switch( ctx->action ) {
  case FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER:
    if( !ctx->request.send_cnt ) return "nothing was sent and the active is unchanged, `failover promote` here resumes the request, "
                                        "and if the active is down and cannot sign `failover promote --force` takes over";
    return "the active may already have given up the identity, check `failover status` there, `failover promote` here resumes the request";
  case FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT:
    if( ctx->role==FD_FAILOVER_ROLE_ACTIVE ) return "this machine holds the staked identity and votes, `failover promote` here asks the old active again to confirm";
    if( ctx->reply.reason==FD_FAILOVER_REJECT_HOLDS_IDENTITY ) return "this machine refused the handoff because another machine may hold the staked identity, "
                                                                      "check `failover status` on both machines, `failover promote` here asks the old active again to confirm";
    return "neither machine holds the staked identity, `failover promote` here asks the old active again to confirm, "
           "and `failover promote --force` on one machine takes the identity";
  default:
    return "the local promotion goes on and dials again when it ends";
  }
}

static void
request_pause( fd_failover_tile_ctx_t * ctx,
               long                     now,
               char const *             why ) {
  FD_LOG_WARNING(( "handoff %lu paused (%s): %s, dialing stopped, %s", ctx->request.id, why, request_wait( ctx ), request_next( ctx ) ));
  /* Pause dialing without changing the action or the authenticated binding. */
  ctx->request.until = 0L;
  ctx->stuck         = 1;
  fd_failover_channel_init_dialer( ctx->channel, 0U, 0 );
  fd_failover_channel_hangup( ctx->channel, now );
  sync_session( ctx );
}

/* The same, to the member and boot of the current session. */
static void
handoff_result( fd_failover_tile_ctx_t * ctx,
                ulong                    id,
                ulong                    result ) {
  fd_failover_hello_t const * peer = fd_failover_channel_peer_hello( ctx->channel );
  fd_failover_peer_t          to   = { .boot_id=peer->boot_id };
  fd_memcpy( to.junk, peer->junk_pubkey, 32UL );
  handoff_result_to( ctx, &to, id, result );
}

/* An ACK or refusal counts only for the DEMOTED we still owe, from the
   member and boot it went to.  Nothing went out yet during the junk
   switch or the drain, so an answer then confirms nothing. */
static int
demoted_answer_bound( fd_failover_tile_ctx_t const * ctx,
                      ulong                          handoff_id ) {
  return ctx->handoff.delivery!=FD_FAILOVER_DELIVERY_NONE && handoff_id==ctx->handoff.id &&
         peer_eq( &ctx->handoff.target, ctx->session.peer_boot_id, fd_failover_channel_peer_hello( ctx->channel )->junk_pubkey ) &&
         ctx->action!=FD_FAILOVER_ACTION_DEMOTE_SWITCH && ctx->action!=FD_FAILOVER_ACTION_DEMOTE_DRAIN;
}

/* Handle a controller message.  Anything malformed drops the session,
   these messages move the staked identity so we do not guess at them. */
static void
handle_control( fd_failover_tile_ctx_t * ctx,
                ushort                   type,
                ulong                    payload_sz,
                long                     now ) {
  switch( type ) {

  case (ushort)FD_FAILOVER_MSG_HANDOFF_REQUEST: {
    fd_failover_handoff_request_t request;
    if( FD_UNLIKELY( !fd_failover_handoff_request_decode( &request, ctx->rx, payload_sz ) ) ) break;
    fd_failover_hello_t const * peer = fd_failover_channel_peer_hello( ctx->channel );
    if( FD_UNLIKELY( request.target_boot_id!=ctx->hello.boot_id ) ) {
      handoff_result( ctx, request.handoff_id, FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY );
      return;
    }
    if( FD_UNLIKELY( request.handoff_id==ctx->handoff.id && peer_eq( &ctx->handoff.target, peer->boot_id, peer->junk_pubkey ) ) ) {
      /* A duplicate request keeps the same demotion and reuses its eventual response. */
      if( ctx->action==FD_FAILOVER_ACTION_DEMOTE_SWITCH || ctx->action==FD_FAILOVER_ACTION_DEMOTE_DRAIN ) return;
      if( ctx->handoff.delivery!=FD_FAILOVER_DELIVERY_NONE && ctx->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK ) {
        if( !ctx->tx.valid ) (void)queue_demoted( ctx );
      } else {
        handoff_result( ctx, request.handoff_id, ctx->handoff.result==FD_FAILOVER_HANDOFF_TAKEN
                                               ? FD_ADMINCTL_RESULT_SUCCESS : FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY );
      }
      return;
    }
    ulong result = FD_ADMINCTL_RESULT_SUCCESS;
    if( ctx->action!=FD_FAILOVER_ACTION_IDLE || ctx->id_switch.pending_key!=FD_FAILOVER_SWITCH_KEY_CNT || ctx->tx.valid || ctx->session.close_after_send ) result = FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS;
    else if( ctx->role!=FD_FAILOVER_ROLE_ACTIVE || peer->role!=FD_FAILOVER_ROLE_STANDBY ) result = FD_FAILOVER_CONTROL_RESULT_BAD_ROLE;
    else if( !final_tower_ok( ctx ) ) result = FD_FAILOVER_CONTROL_RESULT_NO_FINAL_TOWER;
    /* A standby this far behind could not reach the slot its promotion
       waits for before the deadline. */
    else if( request.replay_slot==FD_FAILOVER_SLOT_NULL ||
             fd_ulong_sat_add( request.replay_slot, FD_FAILOVER_DEADLINE_SLOTS )<ready_slot( ctx ) ) result = FD_FAILOVER_CONTROL_RESULT_REPLAY_BEHIND;
    /* Refuse the request without changing the current role or action. */
    if( FD_UNLIKELY( result!=FD_ADMINCTL_RESULT_SUCCESS ) ) {
      if( result==FD_FAILOVER_CONTROL_RESULT_NO_FINAL_TOWER && now>=ctx->handoff_refuse_log_at ) {
        ctx->handoff_refuse_log_at = fd_long_sat_add( now, 60000000000L );
        char tip[ 32 ], last[ 32 ];
        char const * why = ctx->tower_gap ? "a vote-history update was skipped, the final state cannot be verified" :
                           ctx->last_vote_slot==FD_FAILOVER_SLOT_NULL ? "no vote is known to the failover controller, it cannot determine whether this machine has not voted or is unable to vote" :
                           !ctx->current_tower.valid || !ctx->current_tower.sz ? "a vote is known but its final state is unavailable" :
                           "the saved final state does not match the latest known vote";
        FD_LOG_WARNING(( "handoff %lu refused: %s (latest known vote %s, saved history tip %s), this machine keeps the staked identity, check local voting progress and vote-history logs before retrying",
                         request.handoff_id, why, slot_text( ctx->last_vote_slot, last ),
                         slot_text( ctx->current_tower.valid ? ctx->current_tower.tip : FD_FAILOVER_SLOT_NULL, tip ) ));
      } else if( result==FD_FAILOVER_CONTROL_RESULT_REPLAY_BEHIND && now>=ctx->handoff_refuse_log_at ) {
        ctx->handoff_refuse_log_at = fd_long_sat_add( now, 60000000000L );
        char replay[ 32 ];
        FD_LOG_WARNING(( "handoff %lu refused: the standby's replay is at slot %s, more than %lu slots behind %s at slot %lu, this machine keeps the staked identity, "
                         "run `failover promote` there again once it has caught up",
                         request.handoff_id, slot_text( request.replay_slot, replay ), FD_FAILOVER_DEADLINE_SLOTS,
                         ctx->mode==FD_FAILOVER_MODE_TOWER ? "our last vote" : "our finality anchor", ready_slot( ctx ) ));
      }
      handoff_result( ctx, request.handoff_id, result );
      return;
    }
    /* An accepted request starts demotion on the active. */
    start_demotion( ctx, request.handoff_id );
    char member[ FD_BASE58_ENCODED_32_SZ ];
    fd_base58_encode_32( peer->junk_pubkey, NULL, member );
    FD_LOG_NOTICE(( "handoff %lu: accepted request from member %s boot %016lx, preparing to give up the staked identity", ctx->handoff.id, member, ctx->handoff.target.boot_id ));
    return;
  }

  case (ushort)FD_FAILOVER_MSG_HANDOFF_RESULT: {
    fd_failover_handoff_result_t result;
    if( FD_UNLIKELY( !fd_failover_handoff_result_decode( &result, ctx->rx, payload_sz ) ) ) break;
    fd_failover_hello_t const * peer = fd_failover_channel_peer_hello( ctx->channel );
    if( FD_UNLIKELY( !ctx->request.id || result.handoff_id!=ctx->request.id ||
                     !peer_eq( &ctx->request.peer, peer->boot_id, peer->junk_pubkey ) ) ) return;
    if( FD_UNLIKELY( ctx->action!=FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER &&
                     ctx->action!=FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT ) ) return;
    int failed = result.result!=FD_ADMINCTL_RESULT_SUCCESS || ctx->role!=FD_FAILOVER_ROLE_ACTIVE;
    if( FD_UNLIKELY( failed && ctx->role==FD_FAILOVER_ROLE_ACTIVE ) ) {
      FD_LOG_WARNING(( "handoff %lu: the old active did not record that we took the identity and may hold it again, check `failover status` on both machines at once", result.handoff_id ));
    } else if( FD_UNLIKELY( failed && ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT && ctx->reply.reason==FD_FAILOVER_REJECT_HOLDS_IDENTITY ) ) {
      FD_LOG_WARNING(( "handoff %lu ended, this machine refused the final state (%s) because another machine may hold the staked identity, and the old active "
                       "recorded it, check `failover status` on both machines", result.handoff_id, reject_name( ctx->reply.reason ) ));
    } else if( FD_UNLIKELY( failed && ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT ) ) {
      FD_LOG_WARNING(( "handoff %lu ended, this machine refused the final state (%s) and the old active recorded it, neither machine holds the staked identity, "
                       "nothing votes until `failover promote --force` runs on one of them", result.handoff_id, reject_name( ctx->reply.reason ) ));
    } else if( FD_UNLIKELY( failed ) ) {
      char const * hint;
      char const * name = relayed_refusal( result.result, ctx->mode, &hint );
      FD_LOG_WARNING(( "handoff %lu ended (%s), %s", result.handoff_id, name, hint ));
    }
    /* A bound final result ends the request without changing our installed identity. */
    request_end( ctx, now, failed ? FD_FAILOVER_HANDOFF_DECLINED : FD_FAILOVER_HANDOFF_TAKEN );
    if( !failed )
      FD_LOG_NOTICE(( "handoff %lu complete: the old active confirmed our ACK, we hold the staked identity, on-demand connection closed", result.handoff_id ));
    else
      FD_LOG_NOTICE(( "handoff %lu: request ended, %s, on-demand connection closed", result.handoff_id,
                      ctx->role==FD_FAILOVER_ROLE_ACTIVE ? "we still hold the staked identity" : "we remain standby" ));
    return;
  }

  case (ushort)FD_FAILOVER_MSG_DEMOTED: {
    /* The peer says it can no longer sign and hands us its tower. */
    fd_failover_demoted_t demoted;
    if( FD_UNLIKELY( !fd_failover_demoted_decode( &demoted, ctx->rx, payload_sz ) ) ) break;
    /* HELLO pairs only members in one mode, a DEMOTED in the other is
       malformed. */
    if( FD_UNLIKELY( demoted.mode!=(uchar)ctx->mode ) ) break;
    ulong                       boot_id = ctx->session.peer_boot_id;
    fd_failover_hello_t const * peer    = fd_failover_channel_peer_hello( ctx->channel );
    /* Bind before deduplication.  An unsolicited DEMOTED cannot change
       this operation or replace its cached response. */
    if( FD_UNLIKELY( !ctx->request.id || ctx->request.id!=demoted.handoff_id ||
                     !peer_eq( &ctx->request.peer, boot_id, peer->junk_pubkey ) ) ) return;
    if( FD_UNLIKELY( demoted.target_boot_id!=ctx->hello.boot_id ) ) break;
    /* The same DEMOTED again.  While we still work on it we say nothing,
       once we are done we repeat our response. */
    if( FD_UNLIKELY( ctx->promotion.from_peer && ctx->promotion.peer.boot_id==boot_id && ctx->promotion.handoff_id==demoted.handoff_id ) ) return;
    if( FD_UNLIKELY( ctx->reply.state!=FD_FAILOVER_REPLY_NONE && ctx->reply.handoff_id==demoted.handoff_id && peer_eq( &ctx->reply.peer, boot_id, peer->junk_pubkey ) ) ) {
      queue_reply( ctx );
      return;
    }
    fd_failover_tower_t tower = { .valid=1, .tip=demoted.last_vote_slot, .sz=(ulong)demoted.state_len };
    fd_memcpy( tower.state, ctx->rx+sizeof(fd_failover_demoted_t), tower.sz );
    uchar        reason = FD_FAILOVER_REJECT_NONE;
    char const * why    = NULL;
    if( FD_UNLIKELY( ctx->role!=FD_FAILOVER_ROLE_STANDBY ) ) {
      reason = FD_FAILOVER_REJECT_HOLDS_IDENTITY;
      why    = "we hold the staked identity";
    } else if( FD_UNLIKELY( ctx->action!=FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER ||
                            ctx->id_switch.pending_key!=FD_FAILOVER_SWITCH_KEY_CNT ) ) {
      reason = FD_FAILOVER_REJECT_BUSY;
      why    = "a transition or key switch is running here";
    }
    if( FD_UNLIKELY( reason!=FD_FAILOVER_REJECT_NONE ) ) {
      FD_LOG_WARNING(( "refusing the peer's handoff %lu (%s), %s, check `failover status` on both machines", demoted.handoff_id, reject_name( reason ), why ));
      finish_reply( ctx, &ctx->request.peer, demoted.handoff_id, (ushort)FD_FAILOVER_MSG_PROMOTE_REJECTED, reason );
      return;
    }
    if( FD_LIKELY( ctx->mode==FD_FAILOVER_MODE_TOWER ) ) FD_LOG_NOTICE(( "handoff %lu: accepted the peer's final tower ending at slot %lu, waiting for local adoption before taking the identity", demoted.handoff_id, tower.tip ));
    else                                                FD_LOG_NOTICE(( "handoff %lu: accepted the peer's final vote history ending at slot %lu, waiting for local adoption before taking the identity", demoted.handoff_id, tower.tip ));
    if( ctx->peer_floor==FD_FAILOVER_SLOT_NULL || tower.tip>ctx->peer_floor ) ctx->peer_floor = tower.tip;
    ctx->peer_tower        = tower;
    ctx->session.peer_role = FD_FAILOVER_ROLE_STANDBY;
    /* The bound final state moves the standby from peer wait to replay wait. */
    start_promotion( ctx, FD_FAILOVER_SOURCE_PEER, &ctx->request.peer, demoted.handoff_id, 0 );
    return;
  }

  case (ushort)FD_FAILOVER_MSG_PROMOTE_ACK: {
    /* The peer took the identity, so our DEMOTED did its job.  An ACK that
       arrives after the deadline still counts.  An ACK we were not
       expecting is ignored, it is not a reason to drop the session. */
    fd_failover_promote_ack_t ack;
    if( FD_UNLIKELY( !fd_failover_promote_ack_decode( &ack, ctx->rx, payload_sz ) ) ) break;
    if( FD_UNLIKELY( !demoted_answer_bound( ctx, ack.handoff_id ) ) ) return;
    FD_LOG_NOTICE(( "handoff %lu: received ACK, the peer took the staked identity, we stay a standby", ack.handoff_id ));
    /* The peer ACK ends the demotion wait and records that it took the identity. */
    handoff_resolved( ctx, FD_FAILOVER_HANDOFF_TAKEN );
    ctx->taken             = 1;
    ctx->session.peer_role = FD_FAILOVER_ROLE_ACTIVE;
    ctx->stuck             = 0;
    /* The peer votes past the final tower we handed it from here on. */
    ctx->peer_tower.valid = 0;
    handoff_result( ctx, ack.handoff_id, FD_ADMINCTL_RESULT_SUCCESS );
    return;
  }

  case (ushort)FD_FAILOVER_MSG_PROMOTE_REJECTED: {
    /* This request did not promote the peer. Either member may now
       recover without telling the other, so its old state is no longer
       an independent recovery source. */
    fd_failover_promote_rejected_t rej;
    if( FD_UNLIKELY( !fd_failover_promote_rejected_decode( &rej, ctx->rx, payload_sz ) ) ) break;
    if( FD_UNLIKELY( !demoted_answer_bound( ctx, rej.handoff_id ) ) ) return;
    if( FD_UNLIKELY( rej.reason==FD_FAILOVER_REJECT_HOLDS_IDENTITY ) ) {
      FD_LOG_WARNING(( "the peer declined handoff %lu (%s), it saw another machine that may hold the staked identity, this machine gave it up and "
                       "stays a standby, check `failover status` on both machines and the peer's log", rej.handoff_id, reject_name( rej.reason ) ));
    } else {
      FD_LOG_WARNING(( "the peer declined handoff %lu (%s), neither machine holds the staked identity now, nothing votes until `failover promote --force` runs on one of them, "
                       "see the peer's log first", rej.handoff_id, reject_name( rej.reason ) ));
    }
    ctx->peer_tower.valid = 0;
    /* The peer refusal ends the demotion wait, this machine stays standby. */
    handoff_resolved( ctx, FD_FAILOVER_HANDOFF_DECLINED );
    ctx->stuck = 1;
    handoff_result( ctx, rej.handoff_id, FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY );
    return;
  }

  default: break;
  }

  /* Malformed control traffic drops the connection and retains local work. */
  fd_failover_channel_protocol_error( ctx->channel, now );
  sync_session( ctx );
}

/* Finish an operation that received a response or a recovery explicitly
   accepted by the operator.  result is the FD_FAILOVER_HANDOFF_* status
   shows for it. */
static void
request_end( fd_failover_tile_ctx_t * ctx,
             long                     now,
             ulong                    result ) {
  int failed = result!=FD_FAILOVER_HANDOFF_TAKEN;
  FD_TEST( ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_CNT &&
           ( ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER || ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT ) );
  ctx->request.result           = result;
  ctx->request.id               = 0UL;
  ctx->request.until            = 0L;
  ctx->tx.valid                 = 0;
  ctx->session.close_after_send = 0;
  if( ctx->reply.state==FD_FAILOVER_REPLY_OWED ) ctx->reply.state = FD_FAILOVER_REPLY_KEPT;
  /* Return to idle after a response or cancellation. */
  ctx->action           = FD_FAILOVER_ACTION_IDLE;
  ctx->stuck            = failed;
  fd_failover_channel_init_dialer( ctx->channel, 0U, 0 );
  fd_failover_channel_hangup( ctx->channel, now );
  sync_session( ctx );
}

/* The standby dials only while its operator's handoff is open. */
static void
peer_poll( fd_failover_tile_ctx_t * ctx,
           long                     now,
           int *                    charge_busy ) {
  sync_session( ctx );
  if( FD_UNLIKELY( ctx->request.id && ctx->request.until && now>=ctx->request.until &&
                   ( ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER ||
                     ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT ) ) ) {
    /* The network deadline pauses this request without cancelling it. */
    request_pause( ctx, now, !ctx->request.peer.boot_id ? "no peer authenticated before the 64-second deadline" :
                            !ctx->request.send_cnt ? "no handoff request sent before the 64-second deadline" :
                                                        "no final answer before the 64-second deadline" );
    return;
  }
  if( FD_UNLIKELY( ctx->session.close_after_send && !ctx->tx.valid && !fd_failover_channel_tx_pending( ctx->channel ) ) ) {
    /* The result drained, close the session without changing role or action. */
    ctx->session.close_after_send = 0;
    fd_failover_channel_hangup( ctx->channel, now );
    FD_LOG_NOTICE(( "handoff %lu: confirmation drained, on-demand connection closed, listener ready for the next request", ctx->session.close_handoff_id ));
    sync_session( ctx );
    return;
  }

  ushort type;
  ulong  payload_sz;
  if( FD_UNLIKELY( fd_failover_channel_poll( ctx->channel, now, charge_busy, &type, ctx->rx, &payload_sz ) ) ) {
    sync_session( ctx );
    handle_control( ctx, type, payload_sz, now );
  }
  sync_session( ctx );
  if( FD_LIKELY( !ctx->request.id || !ctx->request.until || ctx->request.sent ||
                 fd_failover_channel_state( ctx->channel )!=FD_FAILOVER_SESSION_PAIRED ) ) return;
  fd_failover_hello_t const * peer = fd_failover_channel_peer_hello( ctx->channel );
  if( FD_UNLIKELY( !ctx->request.peer.boot_id ) ) {
    if( FD_UNLIKELY( peer->role!=FD_FAILOVER_ROLE_ACTIVE ) ) {
      FD_LOG_WARNING(( "handoff %lu dialed a standby at `" FD_IP4_ADDR_FMT ":%hu`, give the active's address with `failover promote --address`, "
                       "and if both machines show `role: standby` no machine holds the identity and `failover promote --force` on one of them takes it",
                       ctx->request.id, FD_IP4_ADDR_FMT_ARGS( ctx->request.addr ), dial_port( ctx ) ));
      /* End the peer wait without changing the installed identity. */
      request_end( ctx, now, FD_FAILOVER_HANDOFF_NOT_ACTIVE );
      return;
    }
    /* Bind the request to the first authenticated active member and boot. */
    ctx->request.peer.boot_id = peer->boot_id;
    fd_memcpy( ctx->request.peer.junk, peer->junk_pubkey, 32UL );
  } else if( FD_UNLIKELY( !peer_eq( &ctx->request.peer, peer->boot_id, peer->junk_pubkey ) ) ) {
    /* The member we bound restarted before it confirmed our answer.  Its
       new boot knows nothing of this handoff and cannot confirm it, so
       the wait ends, as the ACK wait does on its side. */
    if( FD_UNLIKELY( ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT &&
                     ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_CNT &&
                     fd_memeq( peer->junk_pubkey, ctx->request.peer.junk, 32UL ) ) ) {
      int active      = ctx->role==FD_FAILOVER_ROLE_ACTIVE;
      int peer_active = peer->role==FD_FAILOVER_ROLE_ACTIVE;
      FD_LOG_WARNING(( "handoff %lu: the peer restarted before it confirmed our %s, ending the request, %s, %s", ctx->request.id,
                       active ? "ACK" : "refusal", active ? "we hold the staked identity" : "we remain standby",
                       active && peer_active  ? "and its new boot says it is active too, check `failover status` on both machines at once" :
                       active                 ? "its new boot is a standby" :
                       peer_active            ? "its new boot is the active" :
                                                "its new boot is a standby too, nothing votes until `failover promote --force` runs on one machine" ));
      request_end( ctx, now, active ? FD_FAILOVER_HANDOFF_TAKEN : FD_FAILOVER_HANDOFF_DECLINED );
      return;
    }
    /* A changed peer pauses the request without replacing its binding.
       The same member on a new boot can never demote for it. */
    ctx->request.peer_restarted = ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER && fd_memeq( peer->junk_pubkey, ctx->request.peer.junk, 32UL );
    request_pause( ctx, now, ctx->request.peer_restarted ? "the authenticated boot restarted" : "authenticated member or boot changed" );
    return;
  }
  fd_failover_handoff_request_t request = { .handoff_id=ctx->request.id, .target_boot_id=ctx->request.peer.boot_id, .replay_slot=ctx->replay_slot };
  if( FD_LIKELY( !fd_failover_channel_send( ctx->channel, now, FD_FAILOVER_MSG_HANDOFF_REQUEST,
                                            (uchar const *)&request, sizeof(request) ) ) ) {
    /* The request is sent, keep waiting for final state or confirmation. */
    ctx->request.sent     = 1;
    ctx->request.send_cnt = fd_ulong_sat_add( ctx->request.send_cnt, 1UL );
    if( now>=ctx->request.log_at ) {
      ctx->request.log_at = fd_long_sat_add( now, 60000000000L );
      char member[ FD_BASE58_ENCODED_32_SZ ];
      fd_base58_encode_32( ctx->request.peer.junk, NULL, member );
      FD_LOG_NOTICE(( "handoff %lu: sent REQUEST to authenticated member %s boot %016lx, %s (send %lu)",
                      ctx->request.id, member, ctx->request.peer.boot_id, request_wait( ctx ), ctx->request.send_cnt ));
    }
    *charge_busy = 1;
  }
}


/* Whether a takeover without the active may go ahead now.  Returns the
   refusal, or FD_ADMINCTL_RESULT_SUCCESS.  `failover status` asks the
   same without force.  force skips every check on the peer and our own
   handoff with no response, never a promotion or switch in flight. */
static ulong
promote_guard( fd_failover_tile_ctx_t const * ctx,
               long                           now,
               int                            force ) {
  int paired = fd_failover_channel_state( ctx->channel )==FD_FAILOVER_SESSION_PAIRED;

  if( FD_UNLIKELY( ctx->role!=FD_FAILOVER_ROLE_STANDBY ) )                           return FD_FAILOVER_CONTROL_RESULT_BAD_ROLE;
  if( FD_UNLIKELY( ctx->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK && !force ) )     return FD_FAILOVER_CONTROL_RESULT_HANDOFF_PENDING;
  int request_wait = ctx->request.id &&
                     ( ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER ||
                       ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT );
  if( FD_UNLIKELY( ( ctx->action!=FD_FAILOVER_ACTION_IDLE && ctx->action!=FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK &&
                     !( force && request_wait ) ) ||
                   ctx->id_switch.pending_key!=FD_FAILOVER_SWITCH_KEY_CNT ) )           return FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS;
  if( FD_UNLIKELY( force ) ) return FD_ADMINCTL_RESULT_SUCCESS;
  /* Losing a session does not prove that the peer stopped voting. */
  if( FD_UNLIKELY( ctx->taken ) ) return FD_FAILOVER_CONTROL_RESULT_TAKEN;
  if( FD_UNLIKELY( paired && fd_failover_channel_peer_hello( ctx->channel )->role==FD_FAILOVER_ROLE_ACTIVE ) )
    return FD_FAILOVER_CONTROL_RESULT_PEER_ACTIVE;
  /* Gossip has a fresh contact info for the staked identity from
     another host, an active is publishing right now. */
  if( FD_UNLIKELY( ctx->staked_seen_at && now>=ctx->staked_seen_at &&
                   now-ctx->staked_seen_at<FD_FAILOVER_GOSSIP_FRESH_NANOS ) ) return FD_FAILOVER_CONTROL_RESULT_STAKED_SEEN;
  /* With on-demand connections even a paired standby HELLO is only a past role snapshot,
     and a takeover without the active never dials or negotiates a transfer.
     Silence, bootstrap and restart therefore require the operator's
     explicit assertion that the peer cannot sign. */
  return FD_FAILOVER_CONTROL_RESULT_PEER_UNVERIFIED;
}

/* The tower a promote would adopt now.  A tower that ends below the
   floor can never cover it, and one that ends at or under our root
   would adopt no votes, so we skip either for the vote account. */
static ulong
promote_source( fd_failover_tile_ctx_t const * ctx ) {
  /* A final state with no response might already have enabled peer votes.
     Fencing the peer now cannot undo those votes. Recovery must consult
     the shared source. Keep the serialized DEMOTED for normal retries. */
  if( FD_UNLIKELY( ctx->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK ) ) return FD_FAILOVER_SOURCE_VOTE_ACCOUNT;
  ulong floor = coverage_floor( ctx );
  ulong root  = ctx->root_slot;
  int   peer_ok = ctx->peer_tower.valid && ( floor==FD_FAILOVER_SLOT_NULL || ctx->peer_tower.tip>=floor ) &&
                                           ( root ==FD_FAILOVER_SLOT_NULL || ctx->peer_tower.tip> root  );
  return peer_ok ? FD_FAILOVER_SOURCE_PEER : FD_FAILOVER_SOURCE_VOTE_ACCOUNT;
}

/* Whether our handoff request stopped at its deadline and waits for
   `failover promote` to resume it. */
static inline int
request_paused( fd_failover_tile_ctx_t const * ctx ) {
  return ctx->request.id && !ctx->request.until &&
         ( ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER || ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT );
}

/* Run an operator command.  If we refuse it we say why.  An accepted
   command starts over and clears stuck, a refused one leaves it. */
static ulong
apply_control( fd_failover_tile_ctx_t *           ctx,
               fd_adminctl_failover_req_t const * req,
               long                               now ) {
  switch( req->cmd ) {

  case FD_ADMINCTL_FAILOVER_CMD_HANDOFF: {
    int paused = request_paused( ctx ) && ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_CNT;
    if( FD_UNLIKELY( paused && ctx->request.peer_restarted ) ) {
      /* The active boot we authenticated restarted before it demoted,
         its new boot never demotes for this request, so we end it and
         start a new one. */
      FD_LOG_NOTICE(( "handoff %lu was bound to active boot %016lx, which restarted, ending it and starting a new handoff", ctx->request.id, ctx->request.peer.boot_id ));
      request_end( ctx, now, FD_FAILOVER_HANDOFF_RESTARTED );
      paused = 0;
    }
    if( FD_UNLIKELY( paused ) ) {
      /* Resume the paused wait with the same request and any existing
         peer binding.  A given address or port replaces where we dial,
         even for a bound request, whose binding still has to match.
         Otherwise a command address is kept, and until a peer is bound a
         gossip address follows gossip. */
      ctx->request.until = fd_long_sat_add( now, FD_FAILOVER_CHANNEL_IDLE_NANOS );
      ctx->request.sent  = 0;
      ctx->stuck         = 0;
      if( req->addr ) ctx->cmd_addr = req->addr;
      if( req->port ) ctx->cmd_port = req->port;
      if(      ctx->cmd_addr                                  ) ctx->request.addr = ctx->cmd_addr;
      else if( !ctx->request.peer.boot_id && ctx->staked_addr ) ctx->request.addr = ctx->staked_addr;
      fd_failover_channel_init_dialer( ctx->channel, ctx->request.addr, dial_port( ctx ) );
      FD_LOG_NOTICE(( "resuming handoff %lu at `" FD_IP4_ADDR_FMT ":%hu` from %s, %s, %s",
                      ctx->request.id, FD_IP4_ADDR_FMT_ARGS( ctx->request.addr ), dial_port( ctx ),
                      ctx->cmd_addr ? "`failover promote --address`" : "gossip",
                      ctx->request.peer.boot_id ? "same authenticated member and boot" : "active has not authenticated yet",
                      request_wait( ctx ) ));
      return FD_ADMINCTL_RESULT_SUCCESS;
    }
    if( FD_UNLIKELY( ctx->action!=FD_FAILOVER_ACTION_IDLE || ctx->id_switch.pending_key!=FD_FAILOVER_SWITCH_KEY_CNT ) )
      return FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS;
    if( FD_UNLIKELY( ctx->role!=FD_FAILOVER_ROLE_STANDBY ) ) return FD_FAILOVER_CONTROL_RESULT_BAD_ROLE;
    uint addr = req->addr ? req->addr : ctx->staked_addr;
    if( FD_UNLIKELY( !addr ) ) return FD_FAILOVER_CONTROL_RESULT_NO_ACTIVE_ADDRESS;
    ctx->cmd_addr = req->addr;
    ctx->cmd_port = req->port;
    fd_memset( &ctx->request, 0, sizeof(ctx->request) );
    ctx->request.id = ctx->handoff_base+(++ctx->handoff_cnt);
    if( FD_UNLIKELY( !ctx->request.id ) ) ctx->request.id = ++ctx->handoff_cnt;
    ctx->request.last_id = ctx->request.id;
    ctx->request.result  = FD_FAILOVER_HANDOFF_PENDING;
    ctx->request.addr    = addr;
    ctx->request.until   = fd_long_sat_add( now, FD_FAILOVER_CHANNEL_IDLE_NANOS );
    ctx->last_requested  = 1;
    ctx->stuck           = 0;
    /* An idle standby starts a new handoff and waits for the active. */
    ctx->action                   = FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER;
    ctx->session.close_after_send = 0;
    fd_failover_channel_init_dialer( ctx->channel, addr, dial_port( ctx ) );
    FD_LOG_NOTICE(( "requesting handoff %lu from the active at `" FD_IP4_ADDR_FMT ":%hu` using %s, authenticating the peer before requesting final state",
                    ctx->request.id, FD_IP4_ADDR_FMT_ARGS( addr ), dial_port( ctx ), ctx->cmd_addr ? "`failover promote --address`" : "gossip" ));
    return FD_ADMINCTL_RESULT_SUCCESS;
  }

  case FD_ADMINCTL_FAILOVER_CMD_PROMOTE: {
    /* A takeover never dials. --force explicitly asserts that the peer
       cannot sign, including bootstrap when no peer can be verified.
       It cannot abandon local adoption or an unknown identity switch.
       Source selection is automatic. FORCE also accepts incomplete or
       empty history. YES only controls CLI confirmation. */
    int   force  = !!( req->flags & FD_ADMINCTL_FAILOVER_FLAG_FORCE );
    ulong result = promote_guard( ctx, now, force );
    if( FD_UNLIKELY( result!=FD_ADMINCTL_RESULT_SUCCESS ) ) return result;
    ulong source = promote_source( ctx );
    /* The operator fenced the peer.  Only a request with no local
       adoption or key switch in flight can be cancelled for recovery. */
    if( force && ctx->role==FD_FAILOVER_ROLE_STANDBY && ctx->request.id &&
        ( ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER || ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT ) &&
        ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_CNT ) {
      FD_LOG_NOTICE(( "handoff %lu cancelled by `failover promote --force` on the operator's word that the peer cannot sign, proceeding with local recovery", ctx->request.id ));
      /* Forced recovery ends the peer wait without changing the installed identity. */
      request_end( ctx, now, FD_FAILOVER_HANDOFF_CANCELLED );
    }
    if( FD_UNLIKELY( ctx->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK ) ) {
      FD_LOG_WARNING(( "`failover promote --force` stops waiting for the peer's answer to handoff %lu, discarding saved final state because the peer may have voted, coverage floors retained", ctx->handoff.id ));
      ctx->peer_tower.valid = 0;
      /* Forced recovery ends the ACK wait before starting local promotion. */
      handoff_resolved( ctx, FD_FAILOVER_HANDOFF_CANCELLED );
    }
    if( force ) FD_LOG_WARNING(( "operator promotion: --force asserts the peer cannot sign, peer checks are bypassed and incomplete or empty vote history is permitted if needed" ));
    int alpenglow = ctx->mode==FD_FAILOVER_MODE_ALPENGLOW;
    if( source==FD_FAILOVER_SOURCE_VOTE_ACCOUNT ) {
      fd_failover_tower_t const * saved  = &ctx->peer_tower;
      char const *                stored = alpenglow ? "the stored peer vote history" : "the stored peer tower";
      if( saved->valid ) {
        ulong floor = coverage_floor( ctx );
        if( floor!=FD_FAILOVER_SLOT_NULL && saved->tip<floor )
          FD_LOG_NOTICE(( "operator promotion: %s ends at slot %lu below the known signing floor %lu, skipping it", stored, saved->tip, floor ));
        else if( ctx->root_slot!=FD_FAILOVER_SLOT_NULL && saved->tip<=ctx->root_slot )
          FD_LOG_NOTICE(( "operator promotion: %s ends at slot %lu at or below the local root %lu, skipping it", stored, saved->tip, ctx->root_slot ));
      }
      if( alpenglow ) FD_LOG_NOTICE(( "operator promotion: no eligible saved final state is available, selecting an empty history" ));
      else            FD_LOG_NOTICE(( "operator promotion: no eligible saved final tower is available, selecting the vote account" ));
    } else {
      fd_failover_tower_t const * saved = &ctx->peer_tower;
      FD_LOG_NOTICE(( "operator promotion: selecting %s through slot %lu, the %s must validate and adopt it before the staked identity is installed",
                      source_name( ctx->mode, source ), saved->tip, alpenglow ? "votor" : "tower tile" ));
    }
    /* The accepted operator command starts the replay and adoption sequence. */
    start_promotion( ctx, source, NULL, 0UL, force );
    return FD_ADMINCTL_RESULT_SUCCESS;
  }

  default: break;
  }
  return FD_ADMINCTL_RESULT_UNSUPPORTED;
}

/* The failover status response, what the controller knows and what
   promote would do now. */
static void
status_snapshot( fd_failover_tile_ctx_t const *       ctx,
                 long                                 now,
                 fd_adminctl_failover_status_resp_t * resp ) {
  fd_adminctl_failover_status_resp_init( resp );
  resp->enabled    = 1;
  resp->role       = (uchar)ctx->role;
  resp->action     = (uchar)ctx->action;
  resp->stuck      = (uchar)!!ctx->stuck;
  resp->link_state = (uchar)fd_failover_channel_state( ctx->channel );
  if( FD_UNLIKELY( fd_failover_channel_state( ctx->channel )==FD_FAILOVER_SESSION_PAIRED ) ) {
    resp->peer_role_valid = 1;
    resp->peer_role       = (uchar)ctx->session.peer_role;
  }
  resp->peer_boot_id   = ctx->session.peer_boot_id;
  /* An open handoff request shows the address it dials, else we show
     the active's address from gossip. */
  resp->peer_addr      = ctx->request.id ? ctx->request.addr : ctx->staked_addr;
  resp->peer_addr_cmd  = (uchar)( ctx->request.id && ctx->cmd_addr );
  resp->peer_port      = ctx->request.id ? dial_port( ctx ) : ctx->port;
  resp->handoff_id     = ctx->last_requested ? ctx->request.last_id : ctx->handoff.id;
  resp->handoff_result = (uchar)( ctx->last_requested ? ctx->request.result : ctx->handoff.result );
  resp->mode           = (uchar)ctx->mode;
  resp->promote_source = (uchar)promote_source( ctx );
  resp->promote_floor  = coverage_floor( ctx );
  resp->promote_result = promote_guard( ctx, now, 0 );
  resp->mode           = ctx->hello.mode;
  resp->request_paused = (uchar)request_paused( ctx );
  /* Vote-account eligibility is known only after the tower tile responds. */
}

/* Respond to one bus request.  The admin tile validated the ABI already.
   The response goes out in its own chunk, never aliased to the request. */
static void
serve_bus_request( fd_failover_tile_ctx_t * ctx,
                   fd_stem_context_t *      stem,
                   long                     now ) {
  fd_adminctl_failover_req_t req;
  fd_memcpy( &req, ctx->bus_req.payload, sizeof(req) );
  fd_failover_bus_msg_t * out = fd_chunk_to_laddr( ctx->admin_out_mem, ctx->admin_out_chunk );
  fd_memset( out, 0, sizeof(*out) );
  out->nonce = ctx->bus_req.nonce;

  if( FD_UNLIKELY( req.cmd==FD_ADMINCTL_FAILOVER_CMD_STATUS ) ) {
    fd_adminctl_failover_status_resp_t status;
    status_snapshot( ctx, now, &status );
    out->result = FD_ADMINCTL_RESULT_SUCCESS;
    fd_memcpy( out->payload, &status, sizeof(status) );
  } else {
    char const * cmd_name = fd_adminctl_failover_cmd_typed( req.cmd );
    FD_LOG_NOTICE(( "`failover %s%s%s` received", cmd_name,
                    ( req.flags & FD_ADMINCTL_FAILOVER_FLAG_YES   ) ? " --yes"   : "",
                    ( req.flags & FD_ADMINCTL_FAILOVER_FLAG_FORCE ) ? " --force" : "" ));
    ulong result = apply_control( ctx, &req, now );
    if( FD_UNLIKELY( result!=FD_ADMINCTL_RESULT_SUCCESS ) ) {
      char const * hint;
      char const * name = control_refusal( result, ctx->mode, &hint );
      FD_LOG_WARNING(( "`failover %s` refused with %s, %s", cmd_name, name, hint ));
    }
    /* An accepted promote says which handoff to follow. */
    ulong handoff_id = 0UL;
    if( FD_LIKELY( result==FD_ADMINCTL_RESULT_SUCCESS ) ) {
      if( req.cmd==FD_ADMINCTL_FAILOVER_CMD_HANDOFF ) handoff_id = ctx->request.id;
    }
    fd_adminctl_failover_control_resp_t response = {
      .version    = FD_ADMINCTL_FAILOVER_PAYLOAD_VERSION,
      .role       = (uchar)ctx->role,
      .action     = (uchar)ctx->action,
      .handoff_id = handoff_id,
    };
    out->result = result;
    fd_memcpy( out->payload, &response, sizeof(response) );
  }

  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, ctx->admin_out_idx, FD_FAILOVER_BUS_RESPONSE, ctx->admin_out_chunk, sizeof(*out), 0UL, tspub, tspub );
  ctx->admin_out_chunk = fd_dcache_compact_next( ctx->admin_out_chunk, sizeof(*out), ctx->admin_out_chunk0, ctx->admin_out_wmark );
}

/* The active's address comes from gossip, from the newest staked
   contact info that is not ours, which is how the active shows up.  A
   remove, IPv6 or zero address never clears what we know.  The member
   certificate authenticates the peer, so a wrong address only costs the
   pairing.  We dial it when the standby requests a handoff without
   `--address`. */
static void
gossip_commit( fd_failover_tile_ctx_t * ctx,
               long                     now ) {
  uint addr = ctx->gossip_socket.addr;
  if( FD_UNLIKELY( !addr ) ) return;
  if( FD_LIKELY( !fd_memeq( ctx->gossip_origin, ctx->hello.staked_pubkey, 32UL ) ) ) return;
  if( FD_UNLIKELY( addr==ctx->own_gossip.addr && ctx->gossip_socket.port==ctx->own_gossip.port ) ) return;
  ctx->staked_seen_at = now;
  /* Gossip can be the only observation of a peer tenure in on-demand
     mode. Its freshness timer is a holder guard, not a cache lifetime.
     An adoption already in flight has its own copy and holder check. */
  if( FD_UNLIKELY( ctx->peer_tower.valid ) )
    FD_LOG_NOTICE(( "gossip shows the staked identity at another host, discarding saved final state from before its voting tenure, keeping coverage floors" ));
  ctx->peer_tower.valid = 0;

  if( FD_LIKELY( addr==ctx->staked_addr ) ) return;
  uint old_addr = ctx->staked_addr;
  ctx->staked_addr = addr;
  if( FD_LIKELY( !old_addr ) ) {
    FD_LOG_NOTICE(( "gossip shows the staked identity at `" FD_IP4_ADDR_FMT "`, a handoff from this machine dials it", FD_IP4_ADDR_FMT_ARGS( addr ) ));
  } else {
    FD_LOG_NOTICE(( "gossip shows the staked identity moved from `" FD_IP4_ADDR_FMT "` to `" FD_IP4_ADDR_FMT "`, the next handoff uses the new address",
                    FD_IP4_ADDR_FMT_ARGS( old_addr ), FD_IP4_ADDR_FMT_ARGS( addr ) ));
  }
}

static inline int
before_frag( fd_failover_tile_ctx_t * ctx,
             ulong                    in_idx,
             ulong                    seq,
             ulong                    sig ) {
  if( FD_LIKELY( in_idx==ctx->gossip_in_idx ) ) {
    return sig!=FD_GOSSIP_UPDATE_TAG_CONTACT_INFO && sig!=FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE;
  }
  if( FD_LIKELY( in_idx==ctx->tower_in_idx ) ) {
    /* A skipped frag may have been a vote.  A slot done counts toward the
       watermark in after_frag, once the stem has checked the copy.  One
       abandoned to an overrun must not count, or the final tower would be
       taken from the cache with that vote missing.  Other frags hold no
       vote and count here.  Every votor_hist frame counts in after_frag. */
    if( FD_UNLIKELY( ctx->tower_seen_seq!=ULONG_MAX && seq!=fd_seq_inc( ctx->tower_seen_seq, 1UL ) ) ) ctx->tower_gap = 1;
    if( FD_UNLIKELY( ctx->mode==FD_FAILOVER_MODE_TOWER && sig!=FD_TOWER_SIG_SLOT_DONE ) ) {
      ctx->tower_seen_seq = seq;
      return 1;
    }
    return 0;
  }
  if( FD_UNLIKELY( in_idx==ctx->admin_in_idx ) ) {
    /* Commands, switch responses and set-identity.  Dropping a switch
       response here would leave the switch hanging forever. */
    return sig!=FD_FAILOVER_BUS_REQUEST && sig!=FD_FAILOVER_BUS_SWITCH_RESP && sig!=FD_FAILOVER_BUS_OPERATOR;
  }
  return 0;
}

static void
during_frag( fd_failover_tile_ctx_t * ctx,
             ulong                    in_idx,
             ulong                    seq FD_PARAM_UNUSED,
             ulong                    sig,
             ulong                    chunk,
             ulong                    sz,
             ulong                    ctl FD_PARAM_UNUSED ) {
  if( FD_UNLIKELY( in_idx==ctx->adopt_in_idx ) ) {
    ulong result_sz = ctx->mode==FD_FAILOVER_MODE_TOWER ? sizeof(fd_tower_adopt_result_t) : sizeof(fd_votor_adopt_result_t);
    if( FD_UNLIKELY( chunk<ctx->adopt_in_chunk0 || chunk>ctx->adopt_in_wmark || sz!=result_sz ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->adopt_in_chunk0, ctx->adopt_in_wmark ));
    }
    fd_memcpy( &ctx->adopt_result, fd_chunk_to_laddr_const( ctx->adopt_in_mem, chunk ), result_sz );
    return;
  }
  if( FD_UNLIKELY( in_idx==ctx->admin_in_idx ) ) {
    if( FD_UNLIKELY( chunk<ctx->admin_in_chunk0 || chunk>ctx->admin_in_wmark || sz!=sizeof(fd_failover_bus_msg_t) ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->admin_in_chunk0, ctx->admin_in_wmark ));
    }
    fd_failover_bus_msg_t const * msg = fd_chunk_to_laddr_const( ctx->admin_in_mem, chunk );
    if( FD_UNLIKELY( sig==FD_FAILOVER_BUS_SWITCH_RESP ) ) {
      fd_memcpy( &ctx->id_switch.response, msg->payload, sizeof(ctx->id_switch.response) );
      ctx->id_switch.response_nonce = msg->nonce;
      return;
    }
    if( FD_UNLIKELY( sig==FD_FAILOVER_BUS_OPERATOR ) ) {
      fd_memcpy( &ctx->bus_operator, msg->payload, sizeof(ctx->bus_operator) );
      return;
    }
    fd_memcpy( &ctx->bus_req, msg, sizeof(fd_failover_bus_msg_t) );
    return;
  }
  if( FD_UNLIKELY( in_idx==ctx->tower_in_idx ) ) {
    ulong frame_sz = ctx->mode==FD_FAILOVER_MODE_TOWER ? sizeof(fd_tower_msg_t) : sizeof(fd_votor_hist_msg_t);
    if( FD_UNLIKELY( chunk<ctx->tower_in_chunk0 || chunk>ctx->tower_in_wmark || sz!=frame_sz ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->tower_in_chunk0, ctx->tower_in_wmark ));
    }
    if( FD_LIKELY( ctx->mode==FD_FAILOVER_MODE_TOWER ) ) fd_memcpy( &ctx->slot_done, fd_chunk_to_laddr_const( ctx->tower_in_mem, chunk ), sizeof(fd_tower_slot_done_t) );
    else                                                fd_memcpy( &ctx->hist,      fd_chunk_to_laddr_const( ctx->tower_in_mem, chunk ), sizeof(fd_votor_hist_msg_t)  );
    return;
  }
  if( FD_UNLIKELY( in_idx!=ctx->gossip_in_idx ) ) return;
  if( FD_UNLIKELY( chunk<ctx->gossip_in_chunk0 || chunk>ctx->gossip_in_wmark || sz>ctx->gossip_in_mtu ) ) {
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->gossip_in_chunk0, ctx->gossip_in_wmark ));
  }
  /* The link is unreliable, so we only copy here and after_frag commits
     once the stem has checked the copy.  A remove leaves the socket
     zero. */
  fd_gossip_update_message_t const * msg = fd_chunk_to_laddr_const( ctx->gossip_in_mem, chunk );
  fd_memcpy( ctx->gossip_origin, msg->origin, 32UL );
  ctx->gossip_socket.addr = 0U;
  ctx->gossip_socket.port = (ushort)0;
  if( FD_LIKELY( sig==FD_GOSSIP_UPDATE_TAG_CONTACT_INFO ) ) {
    fd_gossip_socket_t const * socket = &msg->contact_info->value->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ];
    ctx->gossip_socket.addr = fd_uint_if  ( !socket->is_ipv6, socket->ip4,  0U        );
    ctx->gossip_socket.port = fd_ushort_if( !socket->is_ipv6, socket->port, (ushort)0 );
  }
}

/* The votor's codes are the tower tile's, and STALE, a history older
   than the votes this identity sent from here, keeps its own.  Anything
   else reads as invalid. */
static ulong
votor_adopt_code( ulong result ) {
  return result<=FD_VOTOR_ADOPT_ERR_STALE ? result : FD_TOWER_ADOPT_ERR_INVALID;
}

static void
after_frag( fd_failover_tile_ctx_t * ctx,
            ulong                    in_idx,
            ulong                    seq,
            ulong                    sig,
            ulong                    sz     FD_PARAM_UNUSED,
            ulong                    tsorig FD_PARAM_UNUSED,
            ulong                    tspub  FD_PARAM_UNUSED,
            fd_stem_context_t *      stem   FD_PARAM_UNUSED ) {
  if( FD_UNLIKELY( in_idx==ctx->adopt_in_idx ) ) {
    if( FD_UNLIKELY( ctx->mode==FD_FAILOVER_MODE_ALPENGLOW ) ) ctx->adopt_result.result = votor_adopt_code( ctx->adopt_result.result );
    ctx->adopt_result_id    = sig;
    ctx->adopt_result_fresh = 1;
    return;
  }
  if( FD_UNLIKELY( in_idx==ctx->admin_in_idx ) ) {
    if( FD_UNLIKELY( sig==FD_FAILOVER_BUS_SWITCH_RESP ) ) {
      /* The accepted result can remain live while the tower drains.
         Commit the payload only after the stem and nonce checks pass. */
      if( FD_LIKELY( switch_answer( ctx, ctx->id_switch.response_nonce ) ) ) ctx->id_switch.result = ctx->id_switch.response;
      /* A refusal from before we saw set-identity says what it did. */
      if( FD_UNLIKELY( ctx->id_switch.response.result==FD_FAILOVER_SWITCH_ERR_STALE ) ) operator_switched( ctx, &ctx->id_switch.response.operator );
      return;
    }
    if( FD_UNLIKELY( sig==FD_FAILOVER_BUS_OPERATOR ) ) {
      operator_switched( ctx, &ctx->bus_operator );
      return;
    }
    /* Send the response from after_credit, where a publish credit is available. */
    ctx->bus_req_fresh = 1;
    return;
  }
  if( FD_UNLIKELY( in_idx==ctx->tower_in_idx ) ) {
    /* after_credit folds the slot done in before it steps the controller,
       so the barrier never counts a frag whose tower is not in the cache. */
    ctx->slot_done_fresh = 1;
    ctx->tower_seen_seq  = seq;
    return;
  }
  if( FD_UNLIKELY( in_idx!=ctx->gossip_in_idx ) ) return;
  gossip_commit( ctx, fd_failover_clock() );
}

static inline void
after_credit( fd_failover_tile_ctx_t * ctx,
              fd_stem_context_t *      stem,
              int *                    opt_poll_in FD_PARAM_UNUSED,
              int *                    charge_busy ) {
  if( FD_UNLIKELY( !ctx->member_cert_set ) ) request_member_cert( ctx );
  if( FD_UNLIKELY( ctx->slot_done_fresh ) ) {
    ctx->slot_done_fresh = 0;
    if( FD_LIKELY( ctx->mode==FD_FAILOVER_MODE_TOWER ) ) consume_slot_done( ctx, &ctx->slot_done );
    else                                                consume_hist( ctx, &ctx->hist );
  }
  step_controller( ctx, stem );

  /* Each socket poll is a syscall or two for a protocol that only talks
     during a handoff, so while nothing arrives the socket is asked every
     FD_FAILOVER_TILE_POLL_NANOS.  Traffic brings the next ask forward. */
  long now = fd_failover_clock();
  if( FD_LIKELY( now>=ctx->poll_at ) ) {
    int busy = 0;
    peer_poll( ctx, now, &busy );
    ctx->poll_at = busy ? now : now+FD_FAILOVER_TILE_POLL_NANOS;
    if( busy ) *charge_busy = 1;
  }
  pending_flush( ctx, now );
  if( FD_UNLIKELY( ctx->bus_req_fresh ) ) {
    ctx->bus_req_fresh = 0;
    serve_bus_request( ctx, stem, now );
    *charge_busy = 1;
  }

  /* A cause-specific warning already explained stuck.  Log recovery
     once, without repeating that warning on every state transition. */
  if( FD_UNLIKELY( ctx->stuck!=ctx->stuck_logged ) ) {
    ctx->stuck_logged = ctx->stuck;
    if( !ctx->stuck ) FD_LOG_NOTICE(( "failover is no longer stuck, %s", ctx->role==FD_FAILOVER_ROLE_ACTIVE ? "this machine is active" : "this machine is standby" ));
  }
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  fd_failover_tile_ctx_t const * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  populate_sock_filter_policy_fd_failover_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)fd_failover_channel_listen_fd( ctx->channel ) );
  return sock_filter_policy_fd_failover_tile_instr_cnt;
}

/* Candidates, the listener and the tile's own descriptors. */
static ulong
rlimit_file_cnt( fd_topo_t const *      topo FD_PARAM_UNUSED,
                 fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return FD_FAILOVER_CHANNEL_CANDIDATE_MAX + 1UL + 8UL;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  fd_failover_tile_ctx_t const * ctx        = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  int                            logfile_fd = fd_log_private_logfile_fd();
  int                            listen_fd  = fd_failover_channel_listen_fd( ctx->channel );

  ulong required_fds = 1UL + (ulong)(-1!=logfile_fd) + (ulong)(-1!=listen_fd);
  if( FD_UNLIKELY( out_fds_cnt<required_fds ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY(   -1!=logfile_fd ) ) out_fds[ out_cnt++ ] = logfile_fd; /* logfile */
  if( FD_UNLIKELY( -1!=listen_fd  ) ) out_fds[ out_cnt++ ] = listen_fd;  /* failover listener */
  return out_cnt;
}

/* Worst case per iteration is an adopt request, a switch request and a
   bus response, so the burst is 3. */
#define STEM_BURST (3UL)
#define STEM_LAZY  ((long)1e6) /* 1ms */

/* A frame on our sockets does not wake a parked tile, so we never park. */
#define STEM_NEVER_PARK 1

#define STEM_CALLBACK_CONTEXT_TYPE  fd_failover_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_failover_tile_ctx_t)

#define STEM_CALLBACK_AFTER_CREDIT after_credit
#define STEM_CALLBACK_BEFORE_FRAG  before_frag
#define STEM_CALLBACK_DURING_FRAG  during_frag
#define STEM_CALLBACK_AFTER_FRAG   after_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_failov = {
  .name                     = "failov",
  .keep_host_networking     = 1,
  .allow_connect            = 1,
  .rlimit_file_cnt_fn       = rlimit_file_cnt,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
