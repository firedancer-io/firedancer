#include "../../disco/topo/fd_topo.h"
#include "../../disco/topo/fd_dns_resolve.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/keyguard/fd_keyguard.h"
#include "../../disco/keyguard/fd_keyguard_client.h"
#include "../../flamenco/gossip/fd_gossip_message.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/hex/fd_hex.h"
#include "../../util/fd_version.h"
#include "../../util/net/fd_ip4.h"
#include "../votor/fd_votor_tile.h"

#include "fd_failover_bus.h"
#include "fd_failover_channel.h"

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>  /* IPPROTO_TCP (seccomp) */
#include <netinet/tcp.h> /* TCP_NODELAY (seccomp) */

#include "generated/fd_failover_tile_seccomp.h"

/* The failov tile owns the sockets to the other failover machine, keeps
   host networking for them and holds no private keys.  The sign tile
   signs the admission proofs and our TLS handshakes with the failover
   identity, and the admin tile does the identity switch and stays off
   the network. */

#define FD_FAILOVER_TILE_POLL_NANOS (50000L) /* 50us */

/* A state gives up this many replay slots after it was entered, or as
   many seconds of our clock if replay stalls. */
#define FD_FAILOVER_DEADLINE_SLOTS (64UL)
#define FD_FAILOVER_DEADLINE_NANOS ((long)FD_FAILOVER_DEADLINE_SLOTS*(long)FD_FAILOVER_NANOS_PER_SECOND)

#define FD_FAILOVER_GOSSIP_FRESH_NANOS (15000000000L)
#define FD_FAILOVER_REQUEST_RETRIES    (3UL)
#define FD_FAILOVER_STEP_CNT           (8UL)  /* steps kept for the admin tile */

/* apply_control's result for a pending command */
#define FD_FAILOVER_CMD_PENDING (ULONG_MAX)

/* What the controller is doing right now */
#define FD_FAILOVER_ACTION_IDLE                (0UL) /* no local transition is running */
#define FD_FAILOVER_ACTION_DEMOTE_SWITCH       (1UL) /* waiting for the junk key to be installed */
#define FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK     (2UL) /* DEMOTED sent, waiting for the peer */
#define FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY (3UL) /* waiting for replay to reach the finality anchor */
#define FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT  (4UL) /* waiting for votor to adopt */
#define FD_FAILOVER_ACTION_PROMOTE_SWITCH      (5UL) /* waiting for the staked key to be installed */
#define FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER   (6UL) /* requesting the final history from the machine running the identity */
#define FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT (7UL) /* waiting for the machine that handed it over to record our response */
#define FD_FAILOVER_ACTION_DEMOTE_DRAIN        (8UL) /* junk key installed, waiting for votor history to drain */
#define FD_FAILOVER_ACTION_CNT                 (9UL)

/* The history sources a promotion can adopt */
#define FD_FAILOVER_SOURCE_PEER  (0UL) /* the history the peer's DEMOTED gave us */
#define FD_FAILOVER_SOURCE_EMPTY (1UL) /* forced empty history with a vote bound */

/* How a handoff this machine requested or gave ended */
#define FD_FAILOVER_HANDOFF_NONE       (0UL) /* nothing requested or sent */
#define FD_FAILOVER_HANDOFF_PENDING    (1UL) /* requested or sent, no answer yet */
#define FD_FAILOVER_HANDOFF_TAKEN      (2UL) /* the requesting machine took the identity */
#define FD_FAILOVER_HANDOFF_DECLINED   (3UL) /* it did not take the identity, or the machine that handed it over did not record that it did */
#define FD_FAILOVER_HANDOFF_RESTARTED  (4UL) /* the peer came back with a new boot_id */
#define FD_FAILOVER_HANDOFF_CANCELLED  (5UL) /* `failover promote --force` stopped waiting for the peer */
#define FD_FAILOVER_HANDOFF_NOT_HOLDER (6UL) /* the machine we dialed does not run the identity */
#define FD_FAILOVER_HANDOFF_CNT        (7UL)

/* Which key a switch installs, CNT if no switch is in flight */
#define FD_FAILOVER_SWITCH_KEY_JUNK   (0UL) /* The junk identity. */
#define FD_FAILOVER_SWITCH_KEY_STAKED (1UL) /* The staked identity. */
#define FD_FAILOVER_SWITCH_KEY_CNT    (2UL) /* No identity switch is pending. */

/* Our DEMOTED to the handoff target */
#define FD_FAILOVER_DELIVERY_NONE    (0UL) /* Nothing to send. */
#define FD_FAILOVER_DELIVERY_PENDING (1UL) /* Not sent on this session yet. */
#define FD_FAILOVER_DELIVERY_SENT    (2UL) /* Sent on this session, a new session sends it again. */

/* Our last response to a DEMOTED */
#define FD_FAILOVER_REPLY_NONE    (0UL) /* No response yet. */
#define FD_FAILOVER_REPLY_KEPT    (1UL) /* Kept, the same DEMOTED again gets it again. */
#define FD_FAILOVER_REPLY_PENDING (2UL) /* Kept, not queued yet (pending) because the control slot was busy. */

/* A serialized Alpenglow vote history. */
struct fd_failover_history {
  int   valid;                          /* holds a history */
  ulong tip;                            /* slot of its last vote */
  ulong sz;                             /* bytes used in state */
  uchar state[ FD_FAILOVER_STATE_MAX ]; /* the serialized history */
};

typedef struct fd_failover_history fd_failover_history_t;

/* A peer is a boot of the other machine.  Both authenticate as the
   identity they hand off, so only the boot id tells them apart. */
struct fd_failover_peer {
  ulong boot_id; /* the peer's boot */
};

typedef struct fd_failover_peer fd_failover_peer_t;

static inline int
is_same_peer( fd_failover_peer_t const * bound,
              ulong                      boot_id ) {
  return bound->boot_id==boot_id;
}

struct fd_failover_session {
  ulong state;            /* last seen session state */
  ulong generation;       /* catches a replacement paired during one poll */
  ulong peer_boot_id;     /* boot of the peer on this session */
  int   close_after_send; /* hang up once the queued message is sent */
};

typedef struct fd_failover_session fd_failover_session_t;

/* A handoff request sent by the machine that wants the identity. */
struct fd_failover_request {
  ulong              id;             /* zero when none is open */
  fd_failover_peer_t peer;           /* the boot we authenticated for it, which runs the identity */
  uint               addr;           /* the address we dial, a resume may replace it */
  long               until;          /* when the request pauses, zero while paused */
  int                sent;           /* sent on this session */
  int                peer_restarted; /* paused because the authenticated member or boot changed */
  ulong              send_cnt;       /* how many times we sent it */
};

typedef struct fd_failover_request fd_failover_request_t;

/* A demotion. */
struct fd_failover_handoff {
  ulong              id;                                         /* id of our latest demotion */
  fd_failover_peer_t target;                                     /* peer boot it is for */
  ulong              result;                                     /* FD_FAILOVER_HANDOFF_* of the latest DEMOTED */
  ulong              delivery;                                   /* FD_FAILOVER_DELIVERY_* */
  ulong              payload_sz;                                 /* bytes used in payload */
  uchar              payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ]; /* our DEMOTED, resent on a new session */
};

typedef struct fd_failover_handoff fd_failover_handoff_t;

/* A promotion in progress. */
struct fd_failover_promotion {
  char                  label[ 48 ];  /* handoff ID or operator promotion, fixed for every step */
  ulong                 source;       /* FD_FAILOVER_SOURCE_* we adopt from */
  int                   from_peer;    /* the peer's DEMOTED requested it, we send the response */
  fd_failover_peer_t    peer;         /* that DEMOTED's member boot, it gets our response */
  ulong                 handoff_id;   /* and its handoff id */
  ulong                 floor;        /* coverage floor when it started */
  int                   force;        /* `failover promote --force`, we skip the peer checks and accept incomplete or empty history */
  int                   holder_seen;  /* a peer running the identity authenticated after promotion started */
  fd_failover_history_t adopt;        /* history or the bound sent to votor */
  ulong                 adopt_id;     /* id of the adoption we asked the votor for */
  int                   retry;        /* ask the votor again once replay passes retry_slot */
  ulong                 retry_slot;   /* replay slot that retry waits for */
};

typedef struct fd_failover_promotion fd_failover_promotion_t;

/* Our last response to a DEMOTED.  The same DEMOTED again gets the same
   response, so a peer that missed it is not left waiting. */
struct fd_failover_reply {
  ulong              state;      /* FD_FAILOVER_REPLY_* */
  fd_failover_peer_t peer;       /* the member boot it goes to */
  ulong              handoff_id; /* the handoff it answers */
  ushort             type;       /* PROMOTE_ACK or PROMOTE_REJECTED */
  uchar              reason;     /* for a rejected reply */
};

typedef struct fd_failover_reply fd_failover_reply_t;

struct fd_failover_tx {
  ushort             type;                                       /* FD_FAILOVER_MSG_* */
  ushort             sz;                                         /* bytes used in payload */
  int                valid;                                      /* a message is waiting */
  fd_failover_peer_t to;                                         /* the member boot it goes to */
  uchar              payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ]; /* the encoded message */
};

typedef struct fd_failover_tx fd_failover_tx_t;

/* State of the identity switch we asked the admin tile for.  It
   selects a key preloaded by the signing tile by its public key, and
   success means the old key is gone from every tile's installed identity. */
struct fd_failover_id_switch {
  ulong                     request_id;     /* nonce of our latest switch request */
  ulong                     pending_key;    /* FD_FAILOVER_SWITCH_KEY_*, or CNT when idle */
  fd_failover_switch_resp_t result;         /* the committed response */
  fd_failover_switch_resp_t response;       /* uncommitted input frame */
  ulong                     response_nonce; /* nonce of the frame being consumed */
  int                       fresh;          /* a response frame arrived and is not handled yet */
  int                       overdue;        /* the switch in flight passed its deadline, we still wait for it */
  int                       discard;        /* set-identity ran while it was in flight, its answer is dropped */
  ulong                     epoch;          /* failover epoch we last saw, sent with every request */
};

typedef struct fd_failover_id_switch fd_failover_id_switch_t;

struct fd_failover_tile_ctx {
  /* Networking */  
  fd_keyguard_client_t    keyguard_client[ 1 ]; /* signs admission proofs and TLS */
  fd_failover_hello_t     hello;       /* the HELLO we send */
  uchar                   installed[ 32 ];    /* the identity this machine signs with now */
  uchar                   spare_pubkey[ 32 ]; /* the junk key generated at boot, a handoff installs it */
  uint                    cmd_addr;    /* from `failover promote --address`, 0 when gossip finds the identity */
  ushort                  cmd_port;    /* from `failover promote --port`, 0 for the default port */
  fd_failover_channel_t * channel;     /* the TLS channel to the peer */
  fd_failover_session_t   session;     /* the session we last saw on the channel */
  long                    poll_at;     /* next idle socket poll */

  fd_failover_request_t request;               /* our handoff request */

  ulong peer_floor; /* highest last vote the peer reported for the target, kept across sessions */
  ulong own_floor;  /* highest vote this machine signed as the target */
  int   own_voted;  /* a vote this machine signed as the target arrived since boot or since the target changed */

  /* Gossip */
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
  ulong action;        /* FD_FAILOVER_ACTION_* */
  int   stuck;         /* a transition failed or is overdue */
  int   stuck_logged;  /* the stuck value we last logged */
  ulong deadline_slot; /* replay slot past which the current state is overdue, SLOT_NULL before replay started */
  long  deadline_at;   /* our clock past which it is overdue */

  /* Hand-offs */
  ulong                 handoff_base; /* random base for our handoff ids */
  ulong                 handoff_cnt;  /* handoff ids issued since boot */
  fd_failover_handoff_t handoff;      /* our demotion */

  fd_failover_history_t   peer_history; /* stored peer history, from a DEMOTED */
  fd_failover_promotion_t promotion;    /* the promotion in progress */
  fd_failover_reply_t     reply;        /* our last response to a DEMOTED */
  fd_failover_tx_t        tx;           /* the control message waiting to go out */

  /* The admin tile forwards operator commands over the bus and waits for one response frame per request. */
  ulong                  admin_in_idx;
  fd_wksp_t *            admin_in_mem;
  ulong                  admin_in_chunk0;
  ulong                  admin_in_wmark;
  ulong                  admin_out_idx;
  fd_wksp_t *            admin_out_mem;
  ulong                  admin_out_chunk0;
  ulong                  admin_out_wmark;
  ulong                  admin_out_chunk;

  fd_failover_bus_msg_t  bus_req;       /* the operator command copied in during_frag */
  int                    bus_req_fresh; /* bus_req arrived and is not handled yet */
  fd_failover_operator_t bus_operator;  /* copied in during_frag */

  ulong cmd_nonce;  /* nonce of the command, 0 none */
  ulong cmd_result; /* cmd outcome once cmd_done */
  int   cmd_done;   /* cmd is done after_credit publishes it */
  ulong cmd_step_head; /* steps logged */
  ulong cmd_step_tail; /* steps sent to the admin tile or dropped */
  char  cmd_step[ FD_FAILOVER_STEP_CNT ][ FD_FAILOVER_BUS_STEP_MAX ]; /* the last steps, sent while the command waits */

  fd_failover_id_switch_t id_switch; /* the identity switch we asked the admin tile for */

  /* Votor history adoption */
  ulong                   adopt_out_idx;
  fd_wksp_t *             adopt_out_mem;
  ulong                   adopt_out_chunk0;
  ulong                   adopt_out_wmark;
  ulong                   adopt_out_chunk;
  ulong                   adopt_request_id;   /* id of our latest adoption request */
  ulong                   adopt_in_idx;
  fd_wksp_t *             adopt_in_mem;
  ulong                   adopt_in_chunk0;
  ulong                   adopt_in_wmark;

  fd_votor_adopt_result_t adopt_result;
  ulong                   adopt_result_id;
  int                     adopt_result_fresh; /* adopt_result arrived and is not handled yet */

  /* Vote history input. */
  ulong       hist_in_idx;
  fd_wksp_t * hist_in_mem;
  ulong       hist_in_chunk0;
  ulong       hist_in_wmark;

  int         hist_fresh;     /* a history frame arrived and is not handled yet */
  ulong       hist_seen_seq;  /* seq of the last votor_hist frag taken in, ULONG_MAX before any */

  /* Votor history and adoption bounds. */
  fd_votor_hist_msg_t hist;             /* the votor_hist frame copied in during_frag */
  ulong               adopt_anchor;     /* finality anchor of the history being adopted, SLOT_NULL when none */
  ulong               empty_vote_after; /* an empty history votes only past this slot, SLOT_NULL until known */
  int                 hist_warned;      /* we warned of a bad frame and no good one came since */

  ulong replay_slot;    /* latest replayed slot */
  ulong root_slot;      /* latest root */
  ulong last_vote_slot; /* our latest vote */

  fd_failover_history_t current_history; /* history of our latest vote */

  uchar rx[ FD_FAILOVER_PAYLOAD_MAX ]; /* the control message being decoded */
};

typedef struct fd_failover_tile_ctx fd_failover_tile_ctx_t;

/* Whether this machine currently runs the staked identity it hands off. */
static inline int
holds_identity( fd_failover_tile_ctx_t const * ctx ) {
  return fd_memeq( ctx->installed, ctx->hello.staked_pubkey, 32UL );
}

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

/* TLS CertificateVerify */
static void
sign_ed25519( void *      signer_ctx,
              uchar       sig[ static FD_ED25519_SIG_SZ ],
              uchar const msg[ static FD_TLS_CV_SIGN_SZ ] ) {
  fd_failover_tile_ctx_t * ctx = signer_ctx;
  fd_keyguard_client_sign( ctx->keyguard_client, sig, msg, FD_TLS_CV_SIGN_SZ, FD_KEYGUARD_SIGN_TYPE_ED25519 );
}

/* Pre-admission proof */
static void
sign_proof( void *      signer_ctx,
            uchar       sig[ 64 ],
            uchar const msg[ FD_KEYGUARD_FAILOVER_PROOF_SZ ] ) {
  fd_failover_tile_ctx_t * ctx = signer_ctx;
  fd_keyguard_client_sign( ctx->keyguard_client, sig, msg, FD_KEYGUARD_FAILOVER_PROOF_SZ, FD_KEYGUARD_SIGN_TYPE_ED25519 );
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
  ctx->hist_seen_seq         = ULONG_MAX;
  FD_TEST( fd_rng_secure( &ctx->handoff_base, sizeof(ulong) ) );

  /* The junk key generated at boot is the spare a handoff installs.
     The configured identity is the key we hand off. */
  uchar const * spare_pubkey = fd_keyload_load( FD_KEYLOAD_FAILOVER_JUNK, 1 );
  fd_memcpy( ctx->spare_pubkey, spare_pubkey, 32UL );
  fd_keyload_unload( spare_pubkey, 1 );

  uchar const * target_pubkey = fd_keyload_load( tile->failov.target_key_path, 1 );
  fd_memcpy( ctx->hello.staked_pubkey, target_pubkey, 32UL );
  fd_keyload_unload( target_pubkey, 1 );

  uchar const * identity_pubkey = fd_keyload_load( tile->failov.identity_key_path, 1 );
  fd_memcpy( ctx->installed, identity_pubkey, 32UL );
  fd_keyload_unload( identity_pubkey, 1 );

  if( FD_UNLIKELY( fd_memeq( ctx->spare_pubkey, ctx->hello.staked_pubkey, 32UL ) ) ) {
    FD_LOG_ERR(( "the failover junk key must differ from [paths.identity_key]" ));
  }

  ctx->adopt_anchor     = FD_FAILOVER_SLOT_NULL;
  ctx->empty_vote_after = FD_FAILOVER_SLOT_NULL;

  ctx->hello.version = (ushort)FD_FAILOVER_VERSION;
  ctx->hello.holds   = (uchar)holds_identity( ctx );
  ctx->hello.mode    = (uchar)FD_FAILOVER_MODE_ALPENGLOW;
  while( FD_UNLIKELY( !ctx->hello.boot_id ) ) FD_TEST( fd_rng_secure( &ctx->hello.boot_id, sizeof(ulong) ) );

  /* The git commit field with the hash bytes. */
  if( FD_LIKELY( strlen( fd_commit_ref_cstr )==2UL*sizeof(ctx->hello.commit) &&
                 fd_hex_decode( ctx->hello.commit, fd_commit_ref_cstr, sizeof(ctx->hello.commit) )!=sizeof(ctx->hello.commit) ) ) {
    fd_memset( ctx->hello.commit, 0, sizeof(ctx->hello.commit) );
  }

  ctx->own_gossip = tile->failov.gossip_addr;
  if( FD_UNLIKELY( tile->failov.gossip_host[ 0 ]!='\0' ) ) {
    if( FD_UNLIKELY( !fd_dns_resolve_address( tile->failov.gossip_host, &ctx->own_gossip.addr ) ) ) {
      FD_LOG_ERR(( "could not resolve [gossip.host] `%s`", tile->failov.gossip_host ));
    }
  }

  ctx->channel = fd_failover_channel_join( fd_failover_channel_new( channel_mem ) );
  FD_TEST( ctx->channel );
  fd_tls_sign_t signer = { .ctx=ctx, .sign_fn=sign_ed25519 };
  if( FD_UNLIKELY( fd_failover_channel_set_identity( ctx->channel, signer, (fd_failover_proof_signer_t){ .ctx=ctx, .sign_fn=sign_proof }, &ctx->hello ) ) ) {
    FD_LOG_ERR(( "failover TLS setup failed" ));
  }

  fd_failover_channel_init_listener( ctx->channel, tile->failov.listen_addr, tile->failov.port );
  ctx->session.state = fd_failover_channel_state( ctx->channel );

  char junk_b58  [ FD_BASE58_ENCODED_32_SZ ];
  char staked_b58[ FD_BASE58_ENCODED_32_SZ ];
  fd_base58_encode_32( ctx->spare_pubkey,        NULL, junk_b58   );
  fd_base58_encode_32( ctx->hello.staked_pubkey, NULL, staked_b58 );
  if( FD_UNLIKELY( !holds_identity( ctx ) ) ) {
    FD_LOG_NOTICE(( "failover is on, booting as a standby under junk key `%s` for identity `%s`, listening on `" FD_IP4_ADDR_FMT ":%u`, "
                    "this machine does not vote until `failover promote` here takes the identity from the machine running it.",
                    junk_b58, staked_b58, FD_IP4_ADDR_FMT_ARGS( tile->failov.listen_addr ), (uint)tile->failov.port ));
  } else {
    FD_LOG_NOTICE(( "failover is on, listening on `" FD_IP4_ADDR_FMT ":%u` with junk key `%s`, a handoff from this machine gives up `%s` for the junk key, "
                    "`failover promote <keypair>` here takes the identity in that keypair from the machine running it",
                    FD_IP4_ADDR_FMT_ARGS( tile->failov.listen_addr ), (uint)tile->failov.port, junk_b58, staked_b58 ));
  }

  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, scratch_align() )==(ulong)scratch+scratch_footprint( tile ) );
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  fd_failover_tile_ctx_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  ctx->gossip_in_idx = ULONG_MAX;
  ctx->hist_in_idx   = ULONG_MAX;
  ctx->admin_in_idx  = ULONG_MAX;
  ctx->adopt_in_idx  = ULONG_MAX;
  ctx->adopt_out_idx = fd_topo_find_tile_out_link( topo, tile, "failov_votor", 0UL );
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
    if( FD_LIKELY( !strcmp( link->name, "votor_failov" ) ) ) {
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
    if( FD_LIKELY( !strcmp( link->name, "votor_hist" ) ) ) {
      ctx->hist_in_idx    = i;
      ctx->hist_in_mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      ctx->hist_in_chunk0 = fd_dcache_compact_chunk0( ctx->hist_in_mem, link->dcache );
      ctx->hist_in_wmark  = fd_dcache_compact_wmark ( ctx->hist_in_mem, link->dcache, link->mtu );
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

#include "fd_failover_controller.c"

static inline int
before_frag( fd_failover_tile_ctx_t * ctx,
             ulong                    in_idx,
             ulong                    seq FD_PARAM_UNUSED,
             ulong                    sig ) {
  if( FD_LIKELY( in_idx==ctx->gossip_in_idx ) ) {
    return sig!=FD_GOSSIP_UPDATE_TAG_CONTACT_INFO && sig!=FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE;
  }
  if( FD_LIKELY( in_idx==ctx->hist_in_idx ) ) {
    return 0;
  }
  if( FD_UNLIKELY( in_idx==ctx->admin_in_idx ) ) {
    /* Commands, switch responses and set-identity. */
    return sig!=FD_FAILOVER_BUS_REQUEST && sig!=FD_FAILOVER_BUS_SWITCH_RESP && sig!=FD_FAILOVER_BUS_OPERATOR_ACTION;
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
    if( FD_UNLIKELY( chunk<ctx->adopt_in_chunk0 || chunk>ctx->adopt_in_wmark || sz!=sizeof(fd_votor_adopt_result_t) ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->adopt_in_chunk0, ctx->adopt_in_wmark ));
    }
    fd_memcpy( &ctx->adopt_result, fd_chunk_to_laddr_const( ctx->adopt_in_mem, chunk ), sizeof(fd_votor_adopt_result_t) );
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
    if( FD_UNLIKELY( sig==FD_FAILOVER_BUS_OPERATOR_ACTION ) ) {
      fd_memcpy( &ctx->bus_operator, msg->payload, sizeof(ctx->bus_operator) );
      return;
    }
    fd_memcpy( &ctx->bus_req, msg, sizeof(fd_failover_bus_msg_t) );
    return;
  }
  if( FD_UNLIKELY( in_idx==ctx->hist_in_idx ) ) {
    ulong frame_sz = sizeof(fd_votor_hist_msg_t);
    if( FD_UNLIKELY( chunk<ctx->hist_in_chunk0 || chunk>ctx->hist_in_wmark || sz!=frame_sz ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->hist_in_chunk0, ctx->hist_in_wmark ));
    }
    fd_memcpy( &ctx->hist, fd_chunk_to_laddr_const( ctx->hist_in_mem, chunk ), sizeof(fd_votor_hist_msg_t) );
    return;
  }
  if( FD_UNLIKELY( in_idx!=ctx->gossip_in_idx ) ) return;
  if( FD_UNLIKELY( chunk<ctx->gossip_in_chunk0 || chunk>ctx->gossip_in_wmark || sz>ctx->gossip_in_mtu ) ) {
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->gossip_in_chunk0, ctx->gossip_in_wmark ));
  }
  /* Copy here and commit in after_frag. */
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

/* Unknown adoption results are invalid. */
static ulong
validate_adopt_code( ulong result ) {
  return result<FD_VOTOR_ADOPT_RESULT_CNT ? result : FD_VOTOR_ADOPT_ERR_INVALID;
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
    ctx->adopt_result.result = validate_adopt_code( ctx->adopt_result.result );
    ctx->adopt_result_id     = sig;
    ctx->adopt_result_fresh  = 1;
    return;
  }
  if( FD_UNLIKELY( in_idx==ctx->admin_in_idx ) ) {
    if( FD_UNLIKELY( sig==FD_FAILOVER_BUS_SWITCH_RESP ) ) {
      /* The drain still reads the last switch result, so we copy a
         response into it only after the stem and nonce checks pass. */
      if( FD_LIKELY( on_switch_resp_msg( ctx, ctx->id_switch.response_nonce ) ) ) ctx->id_switch.result = ctx->id_switch.response;
      if( FD_UNLIKELY( ctx->id_switch.response.result==FD_FAILOVER_SWITCH_ERR_STALE ) ) on_operator_action_msg( ctx, &ctx->id_switch.response.operator );
      return;
    }
    if( FD_UNLIKELY( sig==FD_FAILOVER_BUS_OPERATOR_ACTION ) ) {
      on_operator_action_msg( ctx, &ctx->bus_operator );
      return;
    }
    /* Send the response from after_credit, where a publish credit is available. */
    ctx->bus_req_fresh = 1;
    return;
  }
  if( FD_UNLIKELY( in_idx==ctx->hist_in_idx ) ) {
    ctx->hist_fresh    = 1;
    ctx->hist_seen_seq = seq;
    return;
  }
  if( FD_UNLIKELY( in_idx!=ctx->gossip_in_idx ) ) return;
  on_contact_info_msg( ctx, fd_failover_clock() );
}

static inline void
after_credit( fd_failover_tile_ctx_t * ctx,
              fd_stem_context_t *      stem,
              int *                    opt_poll_in FD_PARAM_UNUSED,
              int *                    charge_busy ) {
  if( FD_UNLIKELY( ctx->hist_fresh ) ) {
    ctx->hist_fresh = 0;
    on_votor_hist_msg( ctx, &ctx->hist );
  }
  step_controller( ctx, stem );

  long now = fd_failover_clock();
  if( FD_LIKELY( now>=ctx->poll_at ) ) {
    int busy = 0;
    poll_peer( ctx, now, &busy );
    ctx->poll_at = busy ? now : now+FD_FAILOVER_TILE_POLL_NANOS;
    if( busy ) *charge_busy = 1;
  }
  flush_pending( ctx, now );
  if( FD_UNLIKELY( ctx->cmd_nonce && ctx->cmd_step_tail!=ctx->cmd_step_head ) ) {
    if( stem->cr_avail[ ctx->admin_out_idx ]>=stem->depths[ ctx->admin_out_idx ] ) {
      publish_cmd_step( ctx, stem );
      *charge_busy = 1;
    }
  } else if( FD_UNLIKELY( ctx->cmd_done ) ) {
    publish_cmd_answer( ctx, stem );
    *charge_busy = 1;
  }
  if( FD_UNLIKELY( ctx->bus_req_fresh ) ) {
    ctx->bus_req_fresh = 0;
    serve_bus_request( ctx, stem, now );
    *charge_busy = 1;
  }

  if( FD_UNLIKELY( ctx->stuck!=ctx->stuck_logged ) ) {
    ctx->stuck_logged = ctx->stuck;
    if( !ctx->stuck ) FD_LOG_NOTICE(( "failover is no longer stuck, %s", holds_identity( ctx ) ? "this machine runs the identity" : "this machine does not run the identity" ));
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

#define STEM_BURST (3UL)
#define STEM_LAZY  ((long)1e6) /* 1ms */

#define STEM_NEVER_PARK 1

#define STEM_CALLBACK_CONTEXT_TYPE       fd_failover_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN      alignof(fd_failover_tile_ctx_t)

#define STEM_CALLBACK_AFTER_CREDIT       after_credit
#define STEM_CALLBACK_BEFORE_FRAG        before_frag
#define STEM_CALLBACK_DURING_FRAG        during_frag
#define STEM_CALLBACK_AFTER_FRAG         after_frag

#include "../../disco/stem/fd_stem.c"

/* A serialized history has to fit within the DEMOTED payload. */
FD_STATIC_ASSERT( AG_HIST_SER_MAX<=FD_FAILOVER_ALPENGLOW_STATE_MAX, alpenglow_state_max );

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
