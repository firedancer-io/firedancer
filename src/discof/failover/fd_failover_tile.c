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

#include "generated/fd_failover_tile_seccomp.h"

/* The failov tile owns the sockets to the other failover machine, keeps
   host networking for them and holds no private keys.  The sign tile
   signs fresh admission proofs with the failover identity and our TLS
   handshakes with the junk key, and the admin tile does the identity
   switch and stays off the network. */

/* Idle socket poll spacing */
#define FD_FAILOVER_TILE_POLL_NANOS (50000L) /* 50us */

/* A transition gives up once replay passes this many slots past its
   start. */
#define FD_FAILOVER_DEADLINE_SLOTS (64UL)

/* The promotion's replay and adopt waits also end on our clock, one
   second per deadline slot, so a machine whose replay froze eventually
   stops. */
#define FD_FAILOVER_DEADLINE_SLOT_NANOS ((long)FD_FAILOVER_NANOS_PER_SECOND)

/* A contact info for the identity from another host newer than this
   means that host runs it, two gossip refreshes of 7.5s. */
#define FD_FAILOVER_GOSSIP_FRESH_NANOS (15000000000L)
#define FD_FAILOVER_REQUEST_RETRIES    (3UL) /* sends of one request before a missing final history ends it */

/* The controller actions, promotion sources and handoff results are
   in fd_adminctl.h, `failover status` reports them. */

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

/* A serialized Alpenglow vote history and its tip. */
struct fd_failover_history {
  int   valid;                          /* holds a history */
  ulong tip;                            /* slot of its last vote */
  ulong sz;                             /* bytes used in state */
  uchar state[ FD_FAILOVER_STATE_MAX ]; /* the serialized history */
};

typedef struct fd_failover_history fd_failover_history_t;

/* The member and boot a message or request is bound to. */
struct fd_failover_peer {
  ulong boot_id;    /* the peer's boot */
  uchar junk[ 32 ]; /* the peer's junk key */
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
  ulong state;            /* last seen session state */
  ulong generation;       /* catches a replacement paired during one poll */
  ulong peer_boot_id;     /* boot of the peer on this session */
  int   peer_holds;       /* the peer runs the identity, from its HELLO or an accepted handoff on this session */
  int   close_after_send; /* hang up once the queued message is sent */
  ulong close_handoff_id; /* the handoff that hang up is for, for the log */
};

typedef struct fd_failover_session fd_failover_session_t;

/* Our handoff request, sent by the machine that wants the identity. */
struct fd_failover_request {
  ulong              id;             /* zero when none is open */
  fd_failover_peer_t peer;           /* the boot we authenticated for it, which runs the identity */
  uint               addr;           /* the address we dial, a resume may replace it */
  long               until;          /* when the request pauses, zero while paused */
  int                sent;           /* sent on this session */
  int                peer_restarted; /* paused because the authenticated member or boot changed */
  ulong              last_id;        /* id of our latest request, kept for status */
  ulong              result;         /* FD_FAILOVER_HANDOFF_* of our latest request */
  ulong              send_cnt;       /* how many times we sent it */
  long               log_at;         /* when we may log a resend again */
};

typedef struct fd_failover_request fd_failover_request_t;

/* Our demotion. */
struct fd_failover_handoff {
  ulong              id;                                         /* id of our latest demotion */
  fd_failover_peer_t target;                                     /* peer boot it is for */
  ulong              result;                                     /* FD_FAILOVER_HANDOFF_* of the latest DEMOTED */
  ulong              delivery;                                   /* FD_FAILOVER_DELIVERY_* */
  long               until;                                      /* the demotion step's deadline on our clock, for when replay stops */
  long               log_at;                                     /* when we may log a resend again */
  long               result_log_at;                              /* when we may log the result again */
  ulong              payload_sz;                                 /* bytes used in payload */
  uchar              payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ]; /* our DEMOTED, resent on a new session */
};

typedef struct fd_failover_handoff fd_failover_handoff_t;

/* The promotion in progress. */
struct fd_failover_promotion {
  char                  label[ 48 ];  /* handoff ID or operator promotion, fixed for every step */
  ulong                 source;       /* FD_FAILOVER_SOURCE_* we adopt from */
  int                   from_peer;    /* the peer's DEMOTED requested it, we send the response */
  fd_failover_peer_t    peer;         /* that DEMOTED's member boot, it gets our response */
  ulong                 handoff_id;   /* and its handoff id */
  ulong                 floor;        /* coverage floor when it started */
  int                   force;        /* `failover promote --force`, we skip the peer checks and accept incomplete or empty history */
  int                   holder_seen;  /* a peer running the identity authenticated after promotion started */
  long                  until;        /* our clock when the replay and adopt waits give up, 0 until set */
  fd_failover_history_t adopt;        /* history or the bound sent to votor */
  ulong                 adopt_id;     /* id of the adoption we asked the votor for */
  int                   retry;        /* ask the votor again once replay passes retry_slot */
  ulong                 retry_slot;   /* replay slot that retry waits for */
  int                   floor_logged; /* we said once that we wait for the floor */
  int                   retry_logged; /* and that we ask the votor again as replay moves */
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
  long               log_at;     /* when we may log a resend again */
};

typedef struct fd_failover_reply fd_failover_reply_t;

/* The one control message waiting to go out, if any. */
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
  fd_keyguard_client_t  keyguard_client[ 1 ]; /* signs admission proofs and TLS */
  int                   input_lost;           /* input overrun disables failover until restart */
  int                   read_pending;         /* cleared only after STEM validates the fragment */
  fd_failover_hello_t     hello;       /* the HELLO we send */
  int                     holds;       /* we run the target identity, hello.staked_pubkey */
  uchar                   installed[ 32 ]; /* the identity this machine signs with now, from the switches we asked for and set-identity */
  uint                    cmd_addr;    /* from `failover promote --address`, 0 when gossip finds the identity */
  ushort                  cmd_port;    /* from `failover promote --port`, 0 for the default port */
  fd_failover_channel_t * channel;     /* the TLS channel to the peer */
  fd_failover_session_t   session;     /* the session we last saw on the channel */
  long                    poll_at;     /* next idle socket poll */

  fd_failover_request_t request;               /* our handoff request */
  int                   last_requested;        /* status describes our request rather than our demotion */
  long                  handoff_refuse_log_at; /* when we may log a refused handoff request again */

  ulong peer_floor; /* highest last vote the peer reported for the target, kept across sessions */
  ulong own_floor;  /* highest vote this machine signed as the target */

  /* gossip_ciseen, contact info updates */
  ulong       gossip_in_idx;    /* gossip_ciseen in link */
  fd_wksp_t * gossip_in_mem;    /* its workspace */
  ulong       gossip_in_chunk0; /* its first chunk */
  ulong       gossip_in_wmark;  /* its last chunk */
  ulong       gossip_in_mtu;    /* its largest frag */

  fd_ip4_port_t own_gossip;          /* our own gossip socket */
  uchar         gossip_origin[ 32 ]; /* copied in during_frag */
  fd_ip4_port_t gossip_socket;       /* copied in during_frag, zero for a remove or IPv6 */
  uint          staked_addr;         /* from a staked contact info that is not ours, 0 none */
  long          staked_seen_at;      /* our clock when that one arrived, 0 never */

  /* Controller */
  ulong action;        /* FD_FAILOVER_ACTION_* */
  int   stuck;         /* a transition failed or is overdue, shown to the operator */
  int   stuck_logged;  /* the stuck value we last told the operator about */
  ulong deadline_slot; /* replay slot past which the current step is overdue */

  /* Handoff ids count up from a random base per boot, so ids from
     different boots of ours do not collide. */
  ulong                 handoff_base; /* random base for our handoff ids */
  ulong                 handoff_cnt;  /* handoff ids issued since boot */
  fd_failover_handoff_t handoff;      /* our demotion */
  int                   taken;        /* the peer took the identity, our next tenure or a set-identity clears this */

  fd_failover_history_t peer_history; /* stored peer history, from a DEMOTED */

  fd_failover_promotion_t promotion; /* the promotion in progress */
  fd_failover_reply_t     reply;     /* our last response to a DEMOTED */
  fd_failover_tx_t        tx;        /* the control message waiting to go out */

  /* The admin tile forwards operator commands over the bus and waits for
     one response frame per request. */
  ulong                  admin_in_idx;     /* admin_failov in link */
  fd_wksp_t *            admin_in_mem;     /* its workspace */
  ulong                  admin_in_chunk0;  /* its first chunk */
  ulong                  admin_in_wmark;   /* its last chunk */
  ulong                  admin_out_idx;    /* failov_admin out link */
  fd_wksp_t *            admin_out_mem;    /* its workspace */
  ulong                  admin_out_chunk0; /* its first chunk */
  ulong                  admin_out_wmark;  /* its last chunk */
  ulong                  admin_out_chunk;  /* next chunk we publish to */
  fd_failover_bus_msg_t  bus_req;          /* the operator command copied in during_frag */
  int                    bus_req_fresh;    /* bus_req arrived and is not handled yet */
  fd_failover_operator_t bus_operator;     /* copied in during_frag */

  fd_failover_id_switch_t id_switch; /* the identity switch we asked the admin tile for */

  /* Adoption request to the votor and its response. */
  ulong                   adopt_out_idx;      /* adoption request out link */
  fd_wksp_t *             adopt_out_mem;      /* its workspace */
  ulong                   adopt_out_chunk0;   /* its first chunk */
  ulong                   adopt_out_wmark;    /* its last chunk */
  ulong                   adopt_out_chunk;    /* next chunk we publish to */
  ulong                   adopt_request_id;   /* id of our latest adoption request */
  ulong                   adopt_in_idx;       /* adoption response in link */
  fd_wksp_t *             adopt_in_mem;       /* its workspace */
  ulong                   adopt_in_chunk0;    /* its first chunk */
  ulong                   adopt_in_wmark;     /* its last chunk */
  fd_votor_adopt_result_t adopt_result;       /* the adoption response copied in during_frag */
  ulong                   adopt_result_id;    /* the request it answers */
  int                     adopt_result_fresh; /* adopt_result arrived and is not handled yet */

  /* Vote history input. */
  ulong       hist_in_idx;    /* votor_hist in link */
  fd_wksp_t * hist_in_mem;    /* its workspace */
  ulong       hist_in_chunk0; /* its first chunk */
  ulong       hist_in_wmark;  /* its last chunk */

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

  /* The junk key generated at boot goes into HELLO and TLS, and a
     handoff switches to it.  Only Sign holds its private key.  The boot
     identity is what we hand off until set-identity or failover promote
     <keypair> picks another. */
  uchar const * junk_pubkey = fd_keyload_load( FD_KEYLOAD_FAILOVER_JUNK, 1 );
  fd_memcpy( ctx->hello.junk_pubkey, junk_pubkey, 32UL );
  fd_keyload_unload( junk_pubkey, 1 );
  uchar const * boot_pubkey = fd_keyload_load( tile->failov.identity_key_path, 1 );
  fd_memcpy( ctx->hello.staked_pubkey, boot_pubkey, 32UL );
  fd_memcpy( ctx->installed,           boot_pubkey, 32UL );
  fd_keyload_unload( boot_pubkey, 1 );

  if( FD_UNLIKELY( fd_memeq( ctx->hello.junk_pubkey, ctx->hello.staked_pubkey, 32UL ) ) ) {
    FD_LOG_ERR(( "the failover junk key must differ from [paths.identity_key]" ));
  }

  /* The vote key is a base58 pubkey or a keypair file, same as in the
     votor. */
  if( FD_UNLIKELY( tile->failov.vote_account_path[ 0 ] && !fd_base58_decode_32( tile->failov.vote_account_path, ctx->hello.vote_account ) ) ) {
    uchar const * vote_account = fd_keyload_load( tile->failov.vote_account_path, 1 );
    fd_memcpy( ctx->hello.vote_account, vote_account, 32UL );
    fd_keyload_unload( vote_account, 1 );
  }

  ctx->adopt_anchor     = FD_FAILOVER_SLOT_NULL;
  ctx->empty_vote_after = FD_FAILOVER_SLOT_NULL;

  /* We run the boot identity, which is the target. */
  ctx->holds         = 1;
  ctx->hello.version = (ushort)FD_FAILOVER_VERSION;
  ctx->hello.holds   = (uchar)ctx->holds;
  ctx->hello.mode    = (uchar)FD_FAILOVER_MODE_ALPENGLOW;
  while( FD_UNLIKELY( !ctx->hello.boot_id ) ) FD_TEST( fd_rng_secure( &ctx->hello.boot_id, sizeof(ulong) ) );
  /* The commit field has the hash bytes, a build without one leaves it
     zero. */
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
  if( FD_UNLIKELY( fd_failover_channel_set_identity( ctx->channel, ctx->hello.junk_pubkey, signer, (fd_failover_proof_signer_t){ .ctx=ctx, .sign_fn=sign_proof }, &ctx->hello ) ) ) {
    FD_LOG_ERR(( "failover TLS setup failed for the junk key" ));
  }

  fd_failover_channel_init_listener( ctx->channel, tile->failov.listen_addr, tile->failov.port );
  ctx->session.state = fd_failover_channel_state( ctx->channel );

  char junk_b58  [ FD_BASE58_ENCODED_32_SZ ];
  char staked_b58[ FD_BASE58_ENCODED_32_SZ ];
  fd_base58_encode_32( ctx->hello.junk_pubkey,   NULL, junk_b58   );
  fd_base58_encode_32( ctx->hello.staked_pubkey, NULL, staked_b58 );
  FD_LOG_NOTICE(( "failover is on, listening on `" FD_IP4_ADDR_FMT ":%u` with junk key `%s`, a handoff from this machine gives up `%s` for the junk key, "
                  "`failover promote <keypair>` here takes the identity in that keypair from the machine running it",
                  FD_IP4_ADDR_FMT_ARGS( tile->failov.listen_addr ), (uint)tile->failov.port, junk_b58, staked_b58 ));

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

/* Updates our session state when the channel's session changes. */
static void
sync_session( fd_failover_tile_ctx_t * ctx ) {
  ulong state      = fd_failover_channel_state( ctx->channel );
  ulong generation = fd_failover_channel_generation( ctx->channel );
  if( FD_LIKELY( state==ctx->session.state && generation==ctx->session.generation ) ) return;
  ctx->session.state      = state;
  ctx->session.generation = generation;
  ctx->request.sent             = 0;
  ctx->session.close_after_send = 0;
  if( ctx->tx.valid && ctx->tx.type==(ushort)FD_FAILOVER_MSG_HANDOFF_RESULT ) ctx->tx.valid = 0;
  if( FD_UNLIKELY( state==FD_FAILOVER_SESSION_PAIRED ) ) {
    fd_failover_hello_t const * peer = fd_failover_channel_peer_hello( ctx->channel );
    ctx->session.peer_boot_id = peer->boot_id;
    ctx->session.peer_holds   = !!peer->holds;
    if( ctx->handoff.delivery==FD_FAILOVER_DELIVERY_SENT ) ctx->handoff.delivery = FD_FAILOVER_DELIVERY_PENDING;
    if( FD_UNLIKELY( ( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY ||
                       ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT ) &&
                     peer->holds ) ) ctx->promotion.holder_seen = 1;
    if( FD_UNLIKELY( peer->holds && ( ctx->peer_history.valid ) ) )
      FD_LOG_NOTICE(( "peer boot %016lx authenticated running the identity, discarding saved final state from before its voting tenure, keeping coverage floors", peer->boot_id ));
    if( FD_UNLIKELY( peer->holds ) ) {
      ctx->peer_history.valid = 0;
    }
  }
}

/* Returns the port a handoff dials, from `failover promote --port` if
   given, else the default port. */
static inline ushort
dial_port( fd_failover_tile_ctx_t const * ctx ) {
  return ctx->cmd_port ? ctx->cmd_port : FD_FAILOVER_DEFAULT_PORT;
}

static void
set_holds( fd_failover_tile_ctx_t * ctx,
           int                      holds ) {
  /* Publish whether the completed identity switch installed the target. */
  ctx->holds       = holds;
  ctx->hello.holds = (uchar)holds;
  fd_failover_channel_set_holds( ctx->channel, holds );
}

/* Sets the replay slot past which the current step is overdue. */
static void
deadline_start( fd_failover_tile_ctx_t * ctx,
                ulong                    slots ) {
  ctx->deadline_slot = ( ctx->replay_slot==FD_FAILOVER_SLOT_NULL )
                     ? FD_FAILOVER_SLOT_NULL
                     : fd_ulong_sat_add( ctx->replay_slot, slots );
}

/* Sets the slot deadline to slots past the current replay slot, unless
   it is already set or no replay slot has been seen yet. */
static void
set_step_deadline( fd_failover_tile_ctx_t * ctx,
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

/* Sets the promotion deadline in slots and on the monotonic clock. */
static void
set_promote_deadline( fd_failover_tile_ctx_t * ctx,
                      long                     now ) {
  set_step_deadline( ctx, FD_FAILOVER_DEADLINE_SLOTS );
  if( FD_UNLIKELY( !ctx->promotion.until ) )
    ctx->promotion.until = fd_long_sat_add( now, (long)FD_FAILOVER_DEADLINE_SLOTS*FD_FAILOVER_DEADLINE_SLOT_NANOS );
}

/* Returns whether the promotion passed its slot deadline or its clock
   deadline. */
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

/* Marks the identity switch in flight as overdue, flags stuck and warns
   once.  We keep waiting for the admin tile's answer. */
static void
switch_overdue( fd_failover_tile_ctx_t * ctx ) {
  ctx->stuck = 1;
  if( FD_LIKELY( ctx->id_switch.overdue ) ) return;
  ctx->id_switch.overdue = 1;
  char demotion[ 48 ];
  fd_cstr_printf( demotion, sizeof(demotion), NULL, "handoff %lu", ctx->handoff.id );
  FD_LOG_WARNING(( "%s: identity switch %lu to %s is overdue, its outcome is unknown, we keep waiting and refuse another switch, check the admin and sign tile logs",
                   ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_STAKED ? ctx->promotion.label : demotion,
                   ctx->id_switch.request_id, ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_STAKED ? "the target identity" : "the junk key" ));
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

/* Tells the requester, whose member and boot are in to, that we recorded
   its answer to our DEMOTED or that its handoff cannot go ahead. */
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
   is busy the response stays pending and step_controller tries again once
   the slot drains. */
static void
queue_reply( fd_failover_tile_ctx_t * ctx ) {
  uchar payload[ sizeof(fd_failover_promote_rejected_t) ];
  ulong payload_sz = ctx->reply.type==(ushort)FD_FAILOVER_MSG_PROMOTE_ACK
                   ? fd_failover_promote_ack_encode( payload, ctx->reply.handoff_id )
                   : fd_failover_promote_rejected_encode( payload, ctx->reply.handoff_id, ctx->reply.reason );
  ctx->reply.state = queue_control( ctx, ctx->reply.type, &ctx->reply.peer, payload, payload_sz ) ? FD_FAILOVER_REPLY_PENDING : FD_FAILOVER_REPLY_KEPT;
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

/* The name of a result the machine running the identity sent us for our
   handoff request, or the one we sent, and what the operator can do about
   it. */
static char const *
control_result( ulong         result,
                char const ** hint ) {
  switch( result ) {
  case FD_ADMINCTL_RESULT_SUCCESS:
    *hint = "the other machine recorded that we took the identity but this machine does not run it, check `failover status` on both machines";
    return "SUCCESS";
  case FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY:
    *hint = "the other machine could not finish this handoff and may have given up the identity, check `failover status` there";
    return "PEER_UNREADY";
  case FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS:
    *hint = "the other machine is busy with another transition, run `failover promote` here again once `failover status` there shows it idle";
    return "IN_PROGRESS";
  case FD_FAILOVER_CONTROL_RESULT_WRONG_HOLDER:
    *hint = "the machine we dialed does not run the identity any more, check `failover status` on both machines";
    return "WRONG_HOLDER";
  case FD_FAILOVER_CONTROL_RESULT_NO_FINAL_HISTORY:
    *hint = "the other machine has no eligible final vote state to hand over and keeps the identity, its log says why";
    return "NO_FINAL_HISTORY";
  case FD_FAILOVER_CONTROL_RESULT_REPLAY_BEHIND:
    *hint = "this machine's replay is too far behind the other machine's last vote and it keeps the identity, run `failover promote` here again once this machine has caught up";
    return "REPLAY_BEHIND";
  default:
    *hint = "the other machine answered with a result this machine does not know, run the same Firedancer version on both machines";
    return "UNKNOWN";
  }
}

/* What a control message we just sent changes on our side. */
static void
control_sent( fd_failover_tile_ctx_t * ctx,
              long                     now ) {
  switch( ctx->tx.type ) {
  case (ushort)FD_FAILOVER_MSG_DEMOTED:
    if( ctx->handoff.delivery==FD_FAILOVER_DELIVERY_PENDING ) ctx->handoff.delivery = FD_FAILOVER_DELIVERY_SENT;
    if( now>=ctx->handoff.log_at ) {
      ctx->handoff.log_at = fd_long_sat_add( now, FD_FAILOVER_LOG_INTERVAL_NANOS );
      FD_LOG_NOTICE(( "handoff %lu: sent final state (DEMOTED) to peer boot %016lx, last vote slot %lu, we run the junk key and wait for its answer",
                      ctx->handoff.id, ctx->handoff.target.boot_id, ctx->last_vote_slot ));
    }
    break;
  case (ushort)FD_FAILOVER_MSG_PROMOTE_ACK:
  case (ushort)FD_FAILOVER_MSG_PROMOTE_REJECTED:
    if( now>=ctx->reply.log_at ) {
      ctx->reply.log_at = fd_long_sat_add( now, FD_FAILOVER_LOG_INTERVAL_NANOS );
      FD_LOG_NOTICE(( "handoff %lu: sent %s to peer boot %016lx, %s, waiting for its final confirmation",
                      ctx->reply.handoff_id, ctx->tx.type==FD_FAILOVER_MSG_PROMOTE_ACK ? "ACK" : "refusal",
                      ctx->reply.peer.boot_id, ctx->holds ? "we run the identity" : "we do not run the identity" ));
    }
    break;
  case (ushort)FD_FAILOVER_MSG_HANDOFF_RESULT: {
    fd_failover_handoff_result_t result;
    fd_memcpy( &result, ctx->tx.payload, sizeof(result) );
    if( now>=ctx->handoff.result_log_at ) {
      ctx->handoff.result_log_at = fd_long_sat_add( now, FD_FAILOVER_LOG_INTERVAL_NANOS );
      char const * hint;
      FD_LOG_NOTICE(( "handoff %lu: sent %s confirmation%s%s%s to peer boot %016lx, closing connection after queued bytes drain",
                      result.handoff_id, result.result==FD_ADMINCTL_RESULT_SUCCESS ? "success" : "refusal",
                      result.result==FD_ADMINCTL_RESULT_SUCCESS ? "" : " (",
                      result.result==FD_ADMINCTL_RESULT_SUCCESS ? "" : control_result( result.result, &hint ),
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
  /* We send a queued message only to the member and boot it was queued for. */
  if( FD_UNLIKELY( !peer_eq( &ctx->tx.to, ctx->session.peer_boot_id, fd_failover_channel_peer_hello( ctx->channel )->junk_pubkey ) ) ) return;
  if( FD_UNLIKELY( fd_failover_channel_send( ctx->channel, now, ctx->tx.type, ctx->tx.payload, ctx->tx.sz ) ) ) return;
  control_sent( ctx, now );
  ctx->tx.valid = 0;
}

static void
prepare_history( fd_failover_tile_ctx_t *     ctx,
                 fd_votor_hist_msg_t const * hist ) {
  uchar state[ FD_FAILOVER_ALPENGLOW_STATE_MAX ];
  ulong state_sz = 0UL;
  if( FD_UNLIKELY( ag_hist_ser( &hist->hist, state, FD_FAILOVER_ALPENGLOW_STATE_MAX, &state_sz ) ||
                   ag_hist_tip( &hist->hist )!=hist->vote_slot ) ) {
    /* Warn once until a good frame arrives. */
    if( FD_UNLIKELY( !ctx->hist_warned ) ) FD_LOG_WARNING(( "votor produced a vote history that does not match its slot metadata, until a good one arrives a handoff hands over nothing" ));
    ctx->hist_warned = 1;
    return;
  }
  ctx->hist_warned = 0;
  fd_memcpy( ctx->current_history.state, state, state_sz );
  ctx->current_history.valid = 1;
  ctx->current_history.tip   = hist->vote_slot;
  ctx->current_history.sz    = state_sz;
}

/* Takes in a votor_hist frame: replay and root slots, and the history
   of the identity we hand off once the votor streams it in full. */
static void
on_votor_hist_msg( fd_failover_tile_ctx_t *    ctx,
                   fd_votor_hist_msg_t const * hist ) {
  if( FD_LIKELY( hist->replay_slot!=FD_FAILOVER_SLOT_NULL &&
                 ( ctx->replay_slot==FD_FAILOVER_SLOT_NULL || hist->replay_slot>ctx->replay_slot ) ) )
    ctx->replay_slot = hist->replay_slot;
  if( FD_LIKELY( hist->root_slot!=FD_FAILOVER_SLOT_NULL ) ) ctx->root_slot = hist->root_slot;
  /* Histories of another key can arrive during preparation or after the
     switch. */
  if( FD_UNLIKELY( !fd_memeq( hist->identity.uc, ctx->hello.staked_pubkey, 32UL ) ) ) return;
  int producing = ctx->holds || ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH;
  if( FD_LIKELY( hist->has_vote && hist->vote_slot!=FD_FAILOVER_SLOT_NULL ) ) {
    /* Every vote here is one we signed, so a later promotion has to cover it. */
    ctx->last_vote_slot = hist->vote_slot;
    if( FD_LIKELY( ctx->own_floor==FD_FAILOVER_SLOT_NULL || hist->vote_slot>ctx->own_floor ) ) ctx->own_floor = hist->vote_slot;
    prepare_history( ctx, hist );
  } else if( FD_UNLIKELY( producing && hist->vote_slot!=FD_FAILOVER_SLOT_NULL && ctx->last_vote_slot==FD_FAILOVER_SLOT_NULL ) ) {
    /* The first history with a vote in it while we run the identity,
       cast before we tracked our votes. */
    ctx->last_vote_slot = hist->vote_slot;
    if( FD_LIKELY( ctx->own_floor==FD_FAILOVER_SLOT_NULL || hist->vote_slot>ctx->own_floor ) ) ctx->own_floor = hist->vote_slot;
    prepare_history( ctx, hist );
  } else if( FD_UNLIKELY( producing && ctx->current_history.valid && hist->vote_slot!=FD_FAILOVER_SLOT_NULL && hist->vote_slot>=ctx->last_vote_slot ) ) {
    /* A frame with no new vote can still change the history, after a LEADER or
       a vote marked unsent. */
    ctx->last_vote_slot = hist->vote_slot;
    prepare_history( ctx, hist );
  }
}

/* Sends history or a forced empty-history bound to votor, for the target
   identity.  The response carries the request ID to distinguish late
   replies.  Returns that ID, or ULONG_MAX if there was no request to
   send. */
static ulong
publish_adopt_state( fd_failover_tile_ctx_t * ctx,
                     fd_stem_context_t *      stem ) {
  if( FD_UNLIKELY( ctx->adopt_out_idx==ULONG_MAX ||
                   !ctx->promotion.adopt.sz ) ) return ULONG_MAX;

  if( FD_UNLIKELY( !++ctx->adopt_request_id ) ) ctx->adopt_request_id++;
  uchar * req = fd_chunk_to_laddr( ctx->adopt_out_mem, ctx->adopt_out_chunk );
  ulong   sz  = FD_VOTOR_ADOPT_REQ_HDR_SZ+ctx->promotion.adopt.sz;
  fd_memcpy( req,                           ctx->hello.staked_pubkey,   FD_VOTOR_ADOPT_REQ_HDR_SZ );
  fd_memcpy( req+FD_VOTOR_ADOPT_REQ_HDR_SZ, ctx->promotion.adopt.state, ctx->promotion.adopt.sz  );
  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, ctx->adopt_out_idx, ctx->adopt_request_id, ctx->adopt_out_chunk, sz, 0UL, tspub, tspub );
  ctx->adopt_out_chunk    = fd_dcache_compact_next( ctx->adopt_out_chunk, sz, ctx->adopt_out_chunk0, ctx->adopt_out_wmark );
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

/* Ends the switch in flight when nonce answers it and returns 1 if the
   caller should take the result.  We drop a reply to another request,
   and the reply to a switch that set-identity overtook. */
static int
on_switch_resp_msg( fd_failover_tile_ctx_t * ctx,
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

/* set-identity installed a key, or failover promote <keypair> picked a
   target, so we start over as if this machine had rebooted.  We take a
   new boot id, so the other machine treats anything bound to the old one
   as from a restarted peer, drop everything in flight, and take the
   target that admin left.  A peer with another target fails HELLO. */
static void
on_operator_action_msg( fd_failover_tile_ctx_t *       ctx,
                        fd_failover_operator_t const * operator ) {
  if( FD_UNLIKELY( operator->epoch<=ctx->id_switch.epoch ) ) return;
  ctx->id_switch.epoch   = operator->epoch;
  ctx->id_switch.discard = ctx->id_switch.pending_key!=FD_FAILOVER_SWITCH_KEY_CNT;
  ctx->id_switch.fresh   = 0;
  ctx->id_switch.overdue = 0;

  long now = fd_failover_clock();
  fd_failover_channel_init_dialer( ctx->channel, 0U, 0 );
  fd_failover_channel_hangup( ctx->channel, now );

  /* Whatever was in flight with the other machine is dropped here, but
     the other machine may already have acted on it. */
  int promoting = ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY ||
                  ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT  ||
                  ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH;
  int requesting = !!ctx->request.id;
  int handing    = ctx->handoff.delivery!=FD_FAILOVER_DELIVERY_NONE;
  int replying   = ctx->reply.state==FD_FAILOVER_REPLY_PENDING;
  if( FD_UNLIKELY( requesting || handing || promoting || replying ) ) {
    char request[ 64 ], handoff[ 64 ], reply[ 64 ]; /* a 20 digit id fits */
    fd_cstr_printf( request, sizeof(request), NULL, " our handoff request %lu,",            ctx->request.id       );
    fd_cstr_printf( handoff, sizeof(handoff), NULL, " our handoff %lu awaiting its answer,", ctx->handoff.id       );
    fd_cstr_printf( reply,   sizeof(reply),   NULL, " our unsent reply to handoff %lu,",      ctx->reply.handoff_id );
    FD_LOG_WARNING(( "the identity changed while failover was busy, dropping%s%s%s%s%s%s the other machine may already run the identity, "
                     "check `failover status` on both machines",
                     requesting ? request : "", handing ? handoff : "",
                     promoting ? " the " : "", promoting ? ctx->promotion.label : "", promoting ? " in progress," : "",
                     replying ? reply : "" ));
  }

  fd_memset( &ctx->request,   0, sizeof(ctx->request)   );
  fd_memset( &ctx->handoff,   0, sizeof(ctx->handoff)   );
  fd_memset( &ctx->promotion, 0, sizeof(ctx->promotion) );
  fd_memset( &ctx->reply,     0, sizeof(ctx->reply)     );
  fd_memset( &ctx->tx,        0, sizeof(ctx->tx)        );
  ctx->peer_history.valid       = 0;
  ctx->current_history.valid    = 0;
  ctx->last_vote_slot           = FD_FAILOVER_SLOT_NULL;
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
    ctx->peer_floor     = FD_FAILOVER_SLOT_NULL;
    ctx->own_floor      = FD_FAILOVER_SLOT_NULL;
  }

  ulong boot_id = ctx->hello.boot_id;
  do FD_TEST( fd_rng_secure( &ctx->hello.boot_id, sizeof(ulong) ) ); while( FD_UNLIKELY( !ctx->hello.boot_id || ctx->hello.boot_id==boot_id ) );
  fd_memcpy( ctx->hello.staked_pubkey, operator->failover_identity, 32UL );
  fd_memcpy( ctx->installed,           operator->identity,          32UL );
  ctx->holds       = fd_memeq( operator->identity, operator->failover_identity, 32UL );
  ctx->hello.holds = (uchar)ctx->holds;
  fd_tls_sign_t signer = { .ctx=ctx, .sign_fn=sign_ed25519 };
  if( FD_UNLIKELY( fd_failover_channel_set_identity( ctx->channel, ctx->hello.junk_pubkey, signer, (fd_failover_proof_signer_t){ .ctx=ctx, .sign_fn=sign_proof }, &ctx->hello ) ) ) {
    FD_LOG_ERR(( "failover TLS setup failed after the identity changed" ));
  }
  sync_session( ctx );

  FD_BASE58_ENCODE_32_BYTES( operator->identity,          identity );
  FD_BASE58_ENCODE_32_BYTES( operator->failover_identity, failover_identity );
  FD_LOG_NOTICE(( "failover now hands off `%s` and this machine runs `%s`, with a new boot %016lx, "
                  "anything in progress was dropped and the other machine sees a restart",
                  failover_identity, identity, ctx->hello.boot_id ));
}

/* Our DEMOTED got its response or cannot get one any more. */
static void
handoff_resolved( fd_failover_tile_ctx_t * ctx,
                  ulong                    result ) {
  if( FD_UNLIKELY( ctx->tx.valid && ctx->tx.type==(ushort)FD_FAILOVER_MSG_DEMOTED ) ) ctx->tx.valid = 0;
  /* The handoff outcome ends the ACK wait, this machine keeps its junk key. */
  if( FD_LIKELY( ctx->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK ) ) ctx->action = FD_FAILOVER_ACTION_IDLE;
  ctx->handoff.delivery = FD_FAILOVER_DELIVERY_NONE;
  ctx->handoff.result   = result;
}

/* A demotion that ends without sending final state.  Nobody can
   promote on it, and the machine that asked is told at once rather than
   at its deadline. */
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

/* Each demotion step gets a full deadline, in slots and on our clock. */
static void
demotion_deadline_start( fd_failover_tile_ctx_t * ctx ) {
  deadline_start( ctx, FD_FAILOVER_DEADLINE_SLOTS );
  ctx->handoff.until = fd_long_sat_add( fd_failover_clock(), FD_FAILOVER_CHANNEL_IDLE_NANOS );
}

/* Give up the identity for the peer that asked, on the session it asked
   on.  The switch itself is asked for from step_controller,
   DEMOTED goes to the peer boot we see now. */
static void
start_demotion( fd_failover_tile_ctx_t * ctx,
                ulong                    handoff_id ) {
  fd_memset( &ctx->handoff, 0, sizeof(ctx->handoff) );
  ctx->handoff.id             = handoff_id;
  ctx->handoff.result         = FD_FAILOVER_HANDOFF_NONE; /* until its DEMOTED goes out */
  ctx->handoff.delivery       = FD_FAILOVER_DELIVERY_PENDING;
  ctx->handoff.target.boot_id = ctx->session.peer_boot_id;
  fd_memcpy( ctx->handoff.target.junk, fd_failover_channel_peer_hello( ctx->channel )->junk_pubkey, 32UL );
  ctx->last_requested = 0;
  ctx->stuck          = 0;
  demotion_deadline_start( ctx );
  /* Start the junk key switch before sending any final state. */
  ctx->action = FD_FAILOVER_ACTION_DEMOTE_SWITCH;
}

/* Returns the slot the other machine's replay has to reach before it
   adopts what we hand over. */
static ulong
ready_slot( fd_failover_tile_ctx_t const * ctx ) {
  ag_hist_t hist[1];
  if( FD_UNLIKELY( ag_hist_de( ctx->current_history.state, ctx->current_history.sz, hist ) ) ) return ctx->last_vote_slot;
  return hist->anchor;
}

/* The final history has to be the history of our last vote. */
static int
final_history_ok( fd_failover_tile_ctx_t const * ctx ) {
  return ctx->current_history.valid && ctx->current_history.sz &&
         ctx->last_vote_slot!=FD_FAILOVER_SLOT_NULL &&
         ctx->current_history.tip==ctx->last_vote_slot;
}

/* Called once the junk key is installed everywhere. Our latest history is
   the final one, we hand it to the peer. */
static void
demotion_switched( fd_failover_tile_ctx_t * ctx ) {
  /* The junk key is installed and votor has drained. */
  set_holds( ctx, 0 );
  FD_LOG_NOTICE(( "handoff %lu: the vote history stream drained, this machine runs its junk key now", ctx->handoff.id ));

  int final_ok = final_history_ok( ctx );

  ctx->handoff.payload_sz = !final_ok ? 0UL :
    fd_failover_demoted_encode( ctx->handoff.payload, ctx->handoff.id, ctx->handoff.target.boot_id, ctx->last_vote_slot,
                               ctx->current_history.state, ctx->current_history.sz );
  if( FD_UNLIKELY( !ctx->handoff.payload_sz ) ) {
    /* We have no final history to hand over, or the one we have is not the
       history of our last vote.  The peer gets no final state and cannot
       promote. */
    FD_LOG_WARNING(( "handoff %lu has no final vote history for its last vote %lu, sending nothing, nobody votes until `failover promote --force` runs on the one whose status shows a coverage floor, never both", ctx->handoff.id, ctx->last_vote_slot ));
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

/* Returns the name of a refusal reason for the log. */
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
  case FD_VOTOR_ADOPT_ERR_DECODE:          return "decode error";
  case FD_VOTOR_ADOPT_ERR_INVALID:         return "invalid";
  case FD_VOTOR_ADOPT_ERR_UNREPLAYED_ROOT: return "finality anchor not replayed";
  case FD_VOTOR_ADOPT_ERR_UNREPLAYED:      return "consensus not initialized";
  case FD_VOTOR_ADOPT_ERR_STALE:           return "older than the votes this machine sent as this identity";
  case FD_VOTOR_ADOPT_ERR_CAPACITY:        return "insufficient slot state capacity";
  default:                                 return "unknown";
  }
}

static char const *
source_name( ulong source ) {
  switch( source ) {
  case FD_FAILOVER_SOURCE_PEER:  return "the vote history the peer gave us";
  case FD_FAILOVER_SOURCE_EMPTY: return "an empty history";
  default:                       return "unknown";
  }
}

/* Formats a slot for the log, or none for FD_FAILOVER_SLOT_NULL. */
static char const *
slot_text( ulong slot, char text[ 32 ] ) {
  if( FD_UNLIKELY( slot==FD_FAILOVER_SLOT_NULL ) ) return "none";
  fd_cstr_printf( text, 32UL, NULL, "%lu", slot );
  return text;
}

/* The name of a refusal and what the operator can do about it. */
static char const *
control_refusal( ulong         result,
                 char const ** hint ) {
  switch( result ) {
  case FD_FAILOVER_CONTROL_RESULT_INPUT_LOST:
    *hint = "failover lost an input update and is disabled until restart, validator processing continues";
    return "INPUT_LOST";
  case FD_FAILOVER_CONTROL_RESULT_WRONG_HOLDER:
    *hint = "this machine already runs the identity, `failover promote <keypair>` with another keypair is refused on the machine running the identity unless --force";
    return "WRONG_HOLDER";
  case FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS:
    *hint = "a transition or key switch is running, wait for it, `failover status` shows it";
    return "IN_PROGRESS";
  case FD_FAILOVER_CONTROL_RESULT_NO_HOLDER_ADDRESS:
    *hint = "gossip has no address for the machine running the identity yet, gossip refreshes within about a minute, retry or pass `--address`, "
            "if `failover status` on every machine shows `runs target identity: no` and no promotion in progress, "
            "run `failover promote --force` only on the machine whose status shows a coverage floor, never on both";
    return "NO_HOLDER_ADDRESS";
  case FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY:
    *hint = "the peer could not finish this request, see `failover status` on the peer";
    return "PEER_UNREADY";
  case FD_FAILOVER_CONTROL_RESULT_PEER_HOLDS:
    *hint = "the peer runs the identity or said so recently, run `failover promote` here, or `failover promote --force` if it cannot sign";
    return "PEER_HOLDS";
  case FD_FAILOVER_CONTROL_RESULT_HANDOFF_PENDING:
    *hint = "the peer has not answered our handoff, its request pauses at its deadline and `failover promote` on the requester resumes it, "
            "`failover promote --force` only when its status shows `runs target identity: no` and no promotion in progress, "
            "and only on the machine whose status shows a coverage floor, never both";
    return "HANDOFF_PENDING";
  case FD_FAILOVER_CONTROL_RESULT_TAKEN:
    *hint = "the peer took our last handoff and may be voting, run `failover promote` here, or `failover promote --force` if it cannot sign";
    return "TAKEN";
  case FD_FAILOVER_CONTROL_RESULT_STAKED_SEEN:
    *hint = "gossip showed the identity at another host within 15 seconds, stop it or wait, or `failover promote --force` if it cannot sign";
    return "STAKED_SEEN";
  case FD_FAILOVER_CONTROL_RESULT_NO_FINAL_HISTORY:
    *hint = "the other machine has no eligible final vote state to hand over and keeps the identity, its log explains whether no vote is known or history is missing, check its voting progress before retrying";
    return "NO_FINAL_HISTORY";
  default:
    *hint = "the failover tile does not know this command";
    return "UNSUPPORTED";
  }
}

/* Wait for the other machine to confirm our response to its DEMOTED.  A
   request that paused during the promotion dials again, and if the boot
   we answered restarted, peer_poll ends the request when it pairs with
   the new one. */
static void
request_wait_result( fd_failover_tile_ctx_t * ctx ) {
  if( FD_UNLIKELY( !ctx->request.until ) ) fd_failover_channel_init_dialer( ctx->channel, ctx->request.addr, dial_port( ctx ) );
  ctx->action        = FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT;
  ctx->request.until = fd_long_sat_add( fd_failover_clock(), FD_FAILOVER_CHANNEL_IDLE_NANOS );
}

/* Give up the promotion.  If the peer's DEMOTED asked for it, we tell it
   why and drop the history it handed us, because after a refusal
   either machine may recover on its own without reporting its later
   votes. */
static void
reject_promotion( fd_failover_tile_ctx_t * ctx,
                  uchar                    reason,
                  int                      bad_history ) {
  if( FD_UNLIKELY( bad_history && ctx->promotion.source==FD_FAILOVER_SOURCE_PEER ) ) ctx->peer_history.valid = 0;
  ctx->stuck  = 1;
  /* A failed promotion returns to idle without the identity. */
  ctx->action = FD_FAILOVER_ACTION_IDLE;
  if( FD_UNLIKELY( !ctx->promotion.from_peer ) ) {
    FD_LOG_WARNING(( "%s: promotion failed (%s), this machine does not take the identity, check that one machine votes and see `failover status`, "
                     "run `failover promote --force` again once this machine has caught up and the other cannot sign", ctx->promotion.label, reject_name( reason ) ));
    return;
  }
  ctx->peer_history.valid  = 0;
  ctx->promotion.from_peer = 0;
  /* A failed handoff waits for the other machine to confirm our refusal. */
  request_wait_result( ctx );
  if( FD_UNLIKELY( reason==FD_FAILOVER_REJECT_HOLDS_IDENTITY ) ) {
    FD_LOG_WARNING(( "refusing the peer's handoff %lu (%s), this machine does not take the identity, another machine may run it, "
                     "check `failover status` on both machines", ctx->promotion.handoff_id, reject_name( reason ) ));
  } else {
    FD_LOG_WARNING(( "refusing the peer's handoff %lu (%s), this machine does not take the identity and the peer already gave it up, "
                     "nothing votes until `failover promote --force` runs on the one whose status shows a coverage floor, never both, check `failover status` on both machines first",
                     ctx->promotion.handoff_id, reject_name( reason ) ));
  }
  finish_reply( ctx, &ctx->promotion.peer, ctx->promotion.handoff_id, (ushort)FD_FAILOVER_MSG_PROMOTE_REJECTED, reason );
}

/* The coverage floor is the higher of the peer's reported last vote and our highest signed vote. */
static ulong
coverage_floor( fd_failover_tile_ctx_t const * ctx ) {
  if( FD_UNLIKELY( ctx->peer_floor==FD_FAILOVER_SLOT_NULL ) ) return ctx->own_floor;
  if( FD_UNLIKELY( ctx->own_floor ==FD_FAILOVER_SLOT_NULL ) ) return ctx->peer_floor;
  return fd_ulong_max( ctx->peer_floor, ctx->own_floor );
}

/* Records the finality anchor of the saved history we adopt, which replay
   has to reach first. */
static void
promote_start( fd_failover_tile_ctx_t * ctx ) {
  ctx->adopt_anchor     = FD_FAILOVER_SLOT_NULL;
  ctx->empty_vote_after = FD_FAILOVER_SLOT_NULL;
  if( FD_LIKELY( ctx->promotion.source!=FD_FAILOVER_SOURCE_EMPTY ) ) {
    ag_hist_t hist[1];
    if( FD_LIKELY( !ag_hist_de( ctx->promotion.adopt.state, ctx->promotion.adopt.sz, hist ) ) ) ctx->adopt_anchor = hist->anchor;
  }
}

static int
replay_ready( fd_failover_tile_ctx_t * ctx ) {
  if( FD_LIKELY( ctx->promotion.source!=FD_FAILOVER_SOURCE_EMPTY ) )
    return ctx->adopt_anchor==FD_FAILOVER_SLOT_NULL || ctx->replay_slot>=ctx->adopt_anchor;
  ulong floor = ctx->promotion.floor;
  ctx->empty_vote_after = floor==FD_FAILOVER_SLOT_NULL ? ctx->replay_slot : fd_ulong_max( ctx->replay_slot, floor );
  if( FD_UNLIKELY( floor==FD_FAILOVER_SLOT_NULL ) ) {
    FD_LOG_WARNING(( "%s: --force accepts empty Alpenglow history, no vote or leader window at or below replay slot %lu, no earlier vote as the identity "
                     "is known, so a vote the peer cast above that slot is not covered, local vote marks and stronger local bounds remain",
                     ctx->promotion.label, ctx->empty_vote_after ));
  } else {
    FD_LOG_WARNING(( "%s: --force accepts empty Alpenglow history, no vote or leader window at or below slot %lu, which covers replay at slot %lu and the "
                     "last vote known as the identity at slot %lu, local vote marks and stronger local bounds remain",
                     ctx->promotion.label, ctx->empty_vote_after, ctx->replay_slot, floor ));
  }
  FD_STORE( ulong, ctx->promotion.adopt.state, ctx->empty_vote_after );
  ctx->promotion.adopt.sz = FD_VOTOR_ADOPT_EMPTY_SZ;
  return 1;
}

/* Logs what the votor adopted. */
static void
log_adopted( fd_failover_tile_ctx_t const * ctx ) {
  ulong bound = ctx->adopt_result.vote_bound;
  if( FD_UNLIKELY( ctx->promotion.source==FD_FAILOVER_SOURCE_EMPTY ) ) {
    FD_LOG_NOTICE(( "%s: the votor started an empty vote history, no vote at or below slot %lu", ctx->promotion.label, bound ));
  } else if( FD_LIKELY( bound==FD_FAILOVER_SLOT_NULL ) ) {
    FD_LOG_NOTICE(( "%s: the votor adopted the vote history ending at slot %lu, finality anchor at slot %lu", ctx->promotion.label, ctx->adopt_result.vote_slot, ctx->adopt_anchor ));
  } else {
    FD_LOG_NOTICE(( "%s: the votor adopted the vote history ending at slot %lu, finality anchor at slot %lu, no vote at or below slot %lu", ctx->promotion.label,
                    ctx->adopt_result.vote_slot, ctx->adopt_anchor, bound ));
  }
}

/* Take the identity with the history from source.  A peer is given
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
  if( source==FD_FAILOVER_SOURCE_PEER ) ctx->promotion.adopt = ctx->peer_history;
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
  /* Until this tenure votes, its final history is exactly the adopted one,
     not a history cached from an earlier tenure. */
  ctx->current_history = ctx->promotion.adopt;
  ctx->last_vote_slot  = ctx->promotion.adopt.tip;
  ctx->stuck           = 0;
  promote_start( ctx );
  deadline_start( ctx, FD_FAILOVER_DEADLINE_SLOTS );
  /* Replay must reach the selected history before adoption. */
  ctx->action = FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY;
  /* A vote history waits for replay to reach its finality anchor. */
  if( FD_UNLIKELY( from_peer && ctx->adopt_anchor!=FD_FAILOVER_SLOT_NULL &&
                   ( ctx->replay_slot==FD_FAILOVER_SLOT_NULL || ctx->replay_slot<ctx->adopt_anchor ) ) ) {
    FD_LOG_NOTICE(( "%s: the promotion waits for replay to reach the finality anchor at slot %lu before it adopts %s", ctx->promotion.label, ctx->adopt_anchor, source_name( source ) ));
  }
}

/* Forced promotion tries saved peer history, then bounded empty history.
   Enter only before adoption is sent or after its response.  A planned
   handoff adopts its bound final state or refuses. */
static int
promote_fallback( fd_failover_tile_ctx_t * ctx,
                  char const *             reason ) {
  if( FD_UNLIKELY( ctx->promotion.from_peer || !ctx->promotion.force ) ) return 0;
  if( ctx->promotion.source!=FD_FAILOVER_SOURCE_EMPTY ) {
    FD_LOG_NOTICE(( "%s: %s is not eligible (%s), trying %s", ctx->promotion.label,
                    source_name( ctx->promotion.source ), reason, source_name( FD_FAILOVER_SOURCE_EMPTY ) ));
    if( ctx->promotion.source==FD_FAILOVER_SOURCE_PEER ) ctx->peer_history.valid = 0;
    /* Forced recovery falls back to a bound covering known votes. */
    ctx->promotion.source = FD_FAILOVER_SOURCE_EMPTY;
  } else {
    return 0;
  }
  ctx->promotion.adopt.valid = 0;
  ctx->promotion.adopt.tip   = FD_FAILOVER_SLOT_NULL;
  ctx->promotion.adopt.sz    = 0UL;
  ctx->current_history       = ctx->promotion.adopt;
  ctx->last_vote_slot        = FD_FAILOVER_SLOT_NULL;
  ctx->promotion.retry       = 0;
  ctx->adopt_result_fresh    = 0;
  promote_start( ctx );
  /* Retry adoption from the fallback source after the prior attempt has ended. */
  ctx->action             = FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY;
  return 1;
}

/* Returns whether adoption covers the highest vote the peer reported or
   we signed.  Forced empty history covers it through its vote bound. */
static int
floor_covered( fd_failover_tile_ctx_t const * ctx ) {
  ulong floor = ctx->promotion.floor;
  ulong tip   = ctx->promotion.source==FD_FAILOVER_SOURCE_EMPTY ? ctx->adopt_result.vote_bound
                                                             : ctx->adopt_result.vote_slot;
  return floor==FD_FAILOVER_SLOT_NULL || ( tip!=FD_FAILOVER_SLOT_NULL && tip>=floor );
}

/* Whether a peer running the identity authenticated after this
   promotion started, which stops it unless it is forced. */
static int
promote_holder_seen( fd_failover_tile_ctx_t const * ctx ) {
  if( FD_UNLIKELY( ctx->promotion.force ) ) return 0;
  if( FD_UNLIKELY( ctx->promotion.holder_seen ) ) return 1;
  return 0;
}

static void
step_demote_drain( fd_failover_tile_ctx_t * ctx ) {
  set_step_deadline( ctx, FD_FAILOVER_DEADLINE_SLOTS );
  int expired = deadline_expired( ctx ) || ( ctx->handoff.until && fd_failover_clock()>=ctx->handoff.until );
  /* The watermark is the votor's output sequence when it stopped
     signing. */
  if( FD_UNLIKELY( !fd_seq_ge( fd_seq_inc( ctx->hist_seen_seq, 1UL ), ctx->id_switch.result.history_watermark ) ) ) {
    if( FD_UNLIKELY( expired ) ) {
      FD_LOG_WARNING(( "handoff %lu: the vote history stream did not report its last votes in time, up to seq %lu, sending nothing, nobody votes until `failover promote --force` runs on the one whose status shows a coverage floor, never both", ctx->handoff.id, ctx->id_switch.result.history_watermark ));
      ctx->id_switch.fresh   = 0;
      ctx->id_switch.overdue = 0;
      set_holds( ctx, 0 );
      demotion_abort( ctx );
    }
    return;
  }
  ctx->id_switch.fresh   = 0;
  ctx->id_switch.overdue = 0;
  demotion_switched( ctx );
}

static void
step_demote_switch( fd_failover_tile_ctx_t * ctx,
                    fd_stem_context_t *      stem ) {
  set_step_deadline( ctx, FD_FAILOVER_DEADLINE_SLOTS );
  int expired = deadline_expired( ctx ) || ( ctx->handoff.until && fd_failover_clock()>=ctx->handoff.until );
  if( FD_UNLIKELY( ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_CNT && !ctx->id_switch.fresh ) ) {
    if( FD_UNLIKELY( request_switch( ctx, stem, FD_FAILOVER_SWITCH_KEY_JUNK )==ULONG_MAX ) ) {
      /* The switch request did not go out and we still have the
         identity, so we send no final state. */
      FD_LOG_WARNING(( "an identity switch could not be requested, this machine keeps the identity" ));
      /* End demotion without sending final state. */
      demotion_abort( ctx );
      return;
    }
    FD_LOG_NOTICE(( "handoff %lu: asked the admin tile to install the junk identity", ctx->handoff.id ));
    return;
  }
  if( FD_LIKELY( !ctx->id_switch.fresh ) ) {
    /* No response yet, keep waiting.  Past the deadline we raise stuck. */
    if( FD_UNLIKELY( expired ) ) switch_overdue( ctx );
    return;
  }
  if( FD_UNLIKELY( ctx->id_switch.result.result!=FD_FAILOVER_SWITCH_OK ) ) {
    /* The switch failed and we still have the identity, so we send no
       final state. */
    ctx->id_switch.fresh   = 0;
    ctx->id_switch.overdue = 0;
    FD_LOG_WARNING(( "the identity switch for handoff %lu failed (%s), this machine keeps the identity", ctx->handoff.id,
                     ctx->id_switch.result.result==FD_FAILOVER_SWITCH_ERR_DISABLED         ? "failover disabled" :
                     ctx->id_switch.result.result==FD_FAILOVER_SWITCH_ERR_AUTHORIZED_VOTER ? "the identity is an authorized voter" : "unknown" ));
    /* End demotion without sending final state. */
    demotion_abort( ctx );
    return;
  }
  /* The junk key is installed everywhere. */
  fd_memcpy( ctx->installed, ctx->hello.junk_pubkey, 32UL );
  FD_LOG_NOTICE(( "handoff %lu: the junk identity is installed, waiting for the vote history stream to drain up to seq %lu", ctx->handoff.id, ctx->id_switch.result.history_watermark ));
  ctx->action = FD_FAILOVER_ACTION_DEMOTE_DRAIN;
  demotion_deadline_start( ctx );
  step_demote_drain( ctx );
}

static void
step_demote_wait_ack( fd_failover_tile_ctx_t * ctx ) {
  /* If the peer goes quiet we do not undo the demotion, we only raise
     the alarm.  The identity is already gone from this machine. */
  set_step_deadline( ctx, FD_FAILOVER_DEADLINE_SLOTS );
  /* A new peer boot cannot respond to this DEMOTED. Its earlier boot may
     already have taken the identity and voted before losing its ACK.
     The junk key is generated at every boot, so a paired peer with
     another boot id is the member's new boot: pairing proved it holds
     the same staked key. */
  if( FD_UNLIKELY( fd_failover_channel_state( ctx->channel )==FD_FAILOVER_SESSION_PAIRED &&
                   ctx->session.peer_boot_id!=ctx->handoff.target.boot_id ) ) {
    FD_LOG_WARNING(( "the peer restarted before it answered handoff %lu and may have voted before it restarted, neither machine runs the identity now, "
                     "nothing votes until `failover promote --force` runs on the one whose status shows a coverage floor, never both", ctx->handoff.id ));
    ctx->peer_history.valid = 0;
    /* A new peer boot ends this ACK wait without proving whether it voted. */
    handoff_resolved( ctx, FD_FAILOVER_HANDOFF_RESTARTED );
    return;
  }
  /* A reconnect from the same member can finish its handoff. */
  if( FD_UNLIKELY( ctx->handoff.delivery==FD_FAILOVER_DELIVERY_PENDING && !ctx->tx.valid ) ) {
    (void)queue_demoted( ctx );
  }
  if( FD_UNLIKELY( deadline_expired( ctx ) || ( ctx->handoff.until && fd_failover_clock()>=ctx->handoff.until ) ) ) {
    if( FD_UNLIKELY( !ctx->stuck ) )
      FD_LOG_WARNING(( "the peer has not answered handoff %lu, we run the junk key, the requester's request pauses at its deadline and "
                       "`failover promote` on the requester resumes it, `failover promote --force` only when its status shows `runs target identity: no` "
                       "and no promotion in progress, and only on the machine whose status shows a coverage floor, never both", ctx->handoff.id ));
    ctx->stuck = 1;
  }
  return;
}

static void
step_promote_wait_replay( fd_failover_tile_ctx_t * ctx,
                          fd_stem_context_t *      stem ) {
  long now = fd_failover_clock();
  set_promote_deadline( ctx, now );
  if( FD_UNLIKELY( promote_expired( ctx, now ) ) ) {
    /* Replay timed out, fail the promotion without taking the identity. */
    reject_promotion( ctx, FD_FAILOVER_REJECT_REPLAY_BEHIND, 0 );
    return;
  }
  /* Replay must start and reach the history's finality anchor. */
  if( FD_UNLIKELY( ctx->replay_slot==FD_FAILOVER_SLOT_NULL ) ) return;
  if( FD_UNLIKELY( !replay_ready( ctx ) ) ) {
    if( ctx->promotion.source!=FD_FAILOVER_SOURCE_EMPTY ) (void)promote_fallback( ctx, "replay has not reached its finality anchor" );
    return;
  }
  ulong id = publish_adopt_state( ctx, stem );
  if( FD_UNLIKELY( id==ULONG_MAX ) ) {
    /* End the failed adoption attempt without taking the identity. */
    reject_promotion( ctx, FD_FAILOVER_REJECT_ADOPTION_FAILED, 0 );
    return;
  }
  FD_LOG_NOTICE(( "%s: asking the votor to adopt %s", ctx->promotion.label, source_name( ctx->promotion.source ) ));
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
  set_promote_deadline( ctx, now );
  if( FD_UNLIKELY( promote_expired( ctx, now ) ) ) {
    /* Adoption timed out, fail promotion without taking the identity. */
    reject_promotion( ctx, FD_FAILOVER_REJECT_ADOPTION_FAILED, 0 );
    return;
  }
  if( FD_UNLIKELY( ctx->promotion.retry ) ) {
    /* Wait for replay before retrying a recoverable adoption error. */
    if( FD_LIKELY( ctx->replay_slot<=ctx->promotion.retry_slot ) ) return;
    ulong id = publish_adopt_state( ctx, stem );
    if( FD_UNLIKELY( id==ULONG_MAX ) ) {
      /* End the failed adoption attempt without taking the identity. */
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
  if( FD_UNLIKELY( ctx->adopt_result.result==FD_VOTOR_ADOPT_ERR_UNREPLAYED ||
                   ctx->adopt_result.result==FD_VOTOR_ADOPT_ERR_CAPACITY ) ) {
    /* Operator promotion tries a fallback before waiting for more replay. */
    if( promote_fallback( ctx, adopt_err_name( ctx->adopt_result.result ) ) ) return;
    if( FD_UNLIKELY( !ctx->promotion.from_peer ) ) {
      /* End the failed adoption attempt without taking the identity. */
      reject_promotion( ctx, FD_FAILOVER_REJECT_ADOPTION_FAILED, 0 );
      return;
    }
    if( FD_UNLIKELY( !ctx->promotion.retry_logged ) ) {
      FD_LOG_NOTICE(( "%s: the votor is not ready to adopt the vote history (%s), asking again as replay moves", ctx->promotion.label, adopt_err_name( ctx->adopt_result.result ) ));
      ctx->promotion.retry_logged = 1;
    }
    /* Keep the bound final state and wait for replay before retrying. */
    ctx->promotion.retry      = 1;
    ctx->promotion.retry_slot = ctx->replay_slot;
    return;
  }
  if( FD_UNLIKELY( ctx->adopt_result.result!=FD_VOTOR_ADOPT_SUCCESS ) ) {
    /* Try the next permitted source before failing promotion. */
    if( promote_fallback( ctx, adopt_err_name( ctx->adopt_result.result ) ) ) return;
    FD_LOG_WARNING(( "%s: the votor refused %s (%s)", ctx->promotion.label, source_name( ctx->promotion.source ), adopt_err_name( ctx->adopt_result.result ) ));
    ulong result = ctx->adopt_result.result;
    /* Votor rejected the history, stop promotion and report any handoff refusal. */
    reject_promotion( ctx, FD_FAILOVER_REJECT_ADOPTION_FAILED,
                      result==FD_VOTOR_ADOPT_ERR_DECODE || result==FD_VOTOR_ADOPT_ERR_INVALID || result==FD_VOTOR_ADOPT_ERR_STALE );
    return;
  }
  if( FD_UNLIKELY( ctx->promotion.adopt.tip!=FD_FAILOVER_SLOT_NULL && ctx->adopt_result.vote_slot!=ctx->promotion.adopt.tip ) ) {
    /* Operator promotion may retry a different source after a tip mismatch. */
    if( promote_fallback( ctx, "adoption did not retain its final vote" ) ) return;
    FD_LOG_WARNING(( "%s: the adopted vote history ends at slot %lu, the history says %lu, so it is a mismatch", ctx->promotion.label, ctx->adopt_result.vote_slot, ctx->promotion.adopt.tip ));
    /* The adopted tip differs, fail promotion without installing the identity. */
    reject_promotion( ctx, FD_FAILOVER_REJECT_ADOPTION_MISMATCH, 1 );
    return;
  }
  log_adopted( ctx );
  int covered = floor_covered( ctx );
  if( FD_UNLIKELY( !covered && !ctx->promotion.from_peer && ctx->promotion.source!=FD_FAILOVER_SOURCE_EMPTY ) ) {
    if( promote_fallback( ctx, "its votes do not cover the known signing history" ) ) return;
  }
  if( FD_UNLIKELY( !covered && !ctx->promotion.force ) ) {
    /* Only a handoff gets here.  The tip of the peer's history does not
       change, so we do not ask again and the deadline ends that wait. */
    if( FD_UNLIKELY( !ctx->promotion.floor_logged ) ) {
      FD_LOG_WARNING(( "%s: %s ends at slot %lu, short of the coverage floor at slot %lu, the promotion stops at its deadline", ctx->promotion.label,
                       source_name( ctx->promotion.source ), ctx->adopt_result.vote_slot, ctx->promotion.floor ));
      ctx->promotion.floor_logged = 1;
    }
    /* Stay in the adoption wait until the deadline expires. */
    ctx->promotion.retry      = 1;
    ctx->promotion.retry_slot = FD_FAILOVER_SLOT_NULL;
    return;
  }
  if( FD_UNLIKELY( promote_holder_seen( ctx ) ) ) {
    /* The identity may be held elsewhere now, so we do not install it
       too. */
    FD_LOG_WARNING(( "%s: another machine may run the identity now, a peer running it authenticated during this promotion, "
                     "not installing it, check `failover status` on both machines", ctx->promotion.label ));
    /* Another holder was seen, stop before installing the identity. */
    reject_promotion( ctx, FD_FAILOVER_REJECT_HOLDS_IDENTITY, 0 );
    return;
  }
  if( FD_UNLIKELY( ctx->promotion.adopt.tip==FD_FAILOVER_SLOT_NULL ) ) ctx->last_vote_slot = ctx->adopt_result.vote_slot;
  if( FD_UNLIKELY( request_switch( ctx, stem, FD_FAILOVER_SWITCH_KEY_STAKED )==ULONG_MAX ) ) {
    /* The switch was not submitted, fail promotion without taking the identity. */
    reject_promotion( ctx, FD_FAILOVER_REJECT_ADOPTION_FAILED, 0 );
    return;
  }
  FD_LOG_NOTICE(( "%s: asking the admin tile to install the identity", ctx->promotion.label ));
  /* Adoption passed, wait for admin to install the identity. */
  ctx->action = FD_FAILOVER_ACTION_PROMOTE_SWITCH;
  return;
}

static void
step_promote_switch( fd_failover_tile_ctx_t * ctx ) {
  set_step_deadline( ctx, FD_FAILOVER_DEADLINE_SLOTS );
  if( FD_LIKELY( !ctx->id_switch.fresh ) ) {
    /* No response yet.  Standing down here would tell the peer nobody
       promoted while the identity may well be installed.  So we keep
       waiting and raise stuck past the deadline, the late response still
       counts. */
    if( FD_UNLIKELY( deadline_expired( ctx ) || ( ctx->promotion.until && fd_failover_clock()>=ctx->promotion.until ) ) ) switch_overdue( ctx );
    return;
  }
  ctx->id_switch.fresh   = 0;
  ctx->id_switch.overdue = 0;
  if( FD_UNLIKELY( ctx->id_switch.result.result!=FD_FAILOVER_SWITCH_OK ) ) {
    /* Admin refused the switch, fail the promotion without the identity. */
    reject_promotion( ctx, FD_FAILOVER_REJECT_SWITCH_FAILED, 0 );
    return;
  }
  /* A local recovery installs the identity outside a handoff.
     Reauthenticate so a background session cannot retain our old HELLO. */
  if( !ctx->promotion.from_peer ) {
    fd_failover_channel_init_dialer( ctx->channel, 0U, 0 );
    fd_failover_channel_hangup( ctx->channel, fd_failover_clock() );
    sync_session( ctx );
  }
  /* Admin confirmed the identity is installed. */
  fd_memcpy( ctx->installed, ctx->hello.staked_pubkey, 32UL );
  set_holds( ctx, 1 );
  /* A new tenure starts, the peer history we kept is older than its votes. */
  ctx->peer_history.valid = 0;
  ctx->taken              = 0;
  /* Local promotion is complete. */
  ctx->action           = FD_FAILOVER_ACTION_IDLE;
  ctx->stuck            = 0;
  if( FD_LIKELY( ctx->promotion.source!=FD_FAILOVER_SOURCE_EMPTY ) ) {
    FD_LOG_NOTICE(( "%s: this machine runs the identity now, the adopted vote history ends at slot %lu", ctx->promotion.label, ctx->last_vote_slot ));
  } else {
    FD_LOG_NOTICE(( "%s: this machine runs the identity now with an empty history, no vote at or below slot %lu", ctx->promotion.label, ctx->empty_vote_after ));
  }
  if( FD_UNLIKELY( ctx->promotion.from_peer ) ) {
    /* The ACK tells the other machine its handoff is done.  We keep it as
       our response, so the same DEMOTED again gets the ACK again. */
    ctx->promotion.from_peer  = 0;
    /* Keep the identity while the other machine confirms our ACK. */
    request_wait_result( ctx );
    finish_reply( ctx, &ctx->promotion.peer, ctx->promotion.handoff_id, (ushort)FD_FAILOVER_MSG_PROMOTE_ACK, (uchar)FD_FAILOVER_REJECT_NONE );
  }
  return;
}

/* Whether we can hand off now to a machine whose replay is at
   replay_slot.  Returns the refusal code or FD_ADMINCTL_RESULT_SUCCESS. */
static ulong
handoff_check( fd_failover_tile_ctx_t * ctx,
               ulong                    handoff_id,
               ulong                    replay_slot,
               long                     now ) {
  ulong result = FD_ADMINCTL_RESULT_SUCCESS;
  if( !final_history_ok( ctx ) ) result = FD_FAILOVER_CONTROL_RESULT_NO_FINAL_HISTORY;
  /* A machine this far behind could not reach the slot its promotion
     waits for before the deadline. */
  else if( replay_slot==FD_FAILOVER_SLOT_NULL ||
           fd_ulong_sat_add( replay_slot, FD_FAILOVER_DEADLINE_SLOTS )<ready_slot( ctx ) ) result = FD_FAILOVER_CONTROL_RESULT_REPLAY_BEHIND;
  if( result==FD_FAILOVER_CONTROL_RESULT_NO_FINAL_HISTORY && now>=ctx->handoff_refuse_log_at ) {
    ctx->handoff_refuse_log_at = fd_long_sat_add( now, FD_FAILOVER_LOG_INTERVAL_NANOS );
    char tip[ 32 ], last[ 32 ];
    char const * why = ctx->last_vote_slot==FD_FAILOVER_SLOT_NULL ? "no vote is known to the failover controller, it cannot determine whether this machine has not voted or is unable to vote" :
                       !ctx->current_history.valid || !ctx->current_history.sz ? "a vote is known but its final state is unavailable" :
                       "the saved final state does not match the latest known vote";
    FD_LOG_WARNING(( "handoff %lu refused: %s (latest known vote %s, saved history tip %s), this machine keeps the identity, check local voting progress and vote-history logs before retrying",
                     handoff_id, why, slot_text( ctx->last_vote_slot, last ),
                     slot_text( ctx->current_history.valid ? ctx->current_history.tip : FD_FAILOVER_SLOT_NULL, tip ) ));
  } else if( result==FD_FAILOVER_CONTROL_RESULT_REPLAY_BEHIND && now>=ctx->handoff_refuse_log_at ) {
    ctx->handoff_refuse_log_at = fd_long_sat_add( now, FD_FAILOVER_LOG_INTERVAL_NANOS );
    char replay[ 32 ];
    FD_LOG_WARNING(( "handoff %lu refused: the other machine's replay is at slot %s, more than %lu slots behind our finality anchor at slot %lu, this machine keeps the identity, "
                     "run `failover promote` there again once it has caught up",
                     handoff_id, slot_text( replay_slot, replay ), FD_FAILOVER_DEADLINE_SLOTS, ready_slot( ctx ) ));
  }
  return result;
}

/* Starts giving up the identity for the handoff a peer asked for on the
   current session. */
static void
accept_handoff( fd_failover_tile_ctx_t * ctx,
                ulong                    handoff_id ) {
  start_demotion( ctx, handoff_id );
  char member[ FD_BASE58_ENCODED_32_SZ ];
  fd_base58_encode_32( ctx->handoff.target.junk, NULL, member );
  FD_LOG_NOTICE(( "handoff %lu: accepted request from member %s boot %016lx, preparing to give up the identity", ctx->handoff.id, member, ctx->handoff.target.boot_id ));
}

/* Advances the current failover step. */
static void
step_controller( fd_failover_tile_ctx_t * ctx,
                 fd_stem_context_t *      stem ) {
  if( FD_UNLIKELY( ctx->reply.state==FD_FAILOVER_REPLY_PENDING && !ctx->tx.valid ) ) queue_reply( ctx );
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

/* Describes what our handoff request is waiting for, for logging. */
static char const *
request_wait( fd_failover_tile_ctx_t const * ctx ) {
  switch( ctx->action ) {
  case FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER:
    if( !ctx->request.peer.boot_id ) return "no peer authenticated, no handoff request sent, we do not run the identity";
    if( !ctx->request.send_cnt )     return "peer authenticated, no handoff request sent, we do not run the identity";
    return "waiting for final state, the peer may still run the identity";
  case FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY: return "replay catch-up continues locally, we do not run the identity";
  case FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT:  return "adoption continues locally, we do not run the identity";
  case FD_FAILOVER_ACTION_PROMOTE_SWITCH:      return "the identity switch continues locally, its outcome is still unknown";
  case FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT:
    return ctx->holds ? "we run the identity, waiting for the peer to confirm our ACK"
                      : "we do not run the identity, waiting for the peer to confirm our refusal";
  default: return "the local transition is retained";
  }
}

/* What the operator can do about a paused request. */
static char const *
request_next( fd_failover_tile_ctx_t const * ctx ) {
  if( FD_UNLIKELY( ctx->request.peer_restarted ) ) {
    if( ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT ) return "the authenticated peer changed, `failover promote` here ends the confirmation wait without changing our identity";
    return "the authenticated member or boot changed, `failover promote` here starts a new handoff";
  }
  switch( ctx->action ) {
  case FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER:
    if( !ctx->request.send_cnt ) return "nothing was sent and the other machine still runs the identity, `failover promote` here resumes the request, "
                                        "and if that machine is down and cannot sign `failover promote --force` takes over";
    return "the other machine may already have given up the identity, check `failover status` there, `failover promote` here resumes the request";
  case FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT:
    if( ctx->holds ) return "this machine runs the identity and votes, `failover promote` here asks the other machine again to confirm";
    if( ctx->reply.reason==FD_FAILOVER_REJECT_HOLDS_IDENTITY ) return "this machine refused the handoff because another machine may run the identity, "
                                                                      "check `failover status` on both machines, `failover promote` here asks the other machine again to confirm";
    return "neither machine runs the identity, `failover promote` here asks the other machine again to confirm, "
           "and `failover promote --force` on the one whose status shows a coverage floor, never both, takes the identity";
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

/* handoff_result_to for the member and boot of the current session. */
static void
handoff_result( fd_failover_tile_ctx_t * ctx,
                ulong                    id,
                ulong                    result ) {
  fd_failover_hello_t const * peer = fd_failover_channel_peer_hello( ctx->channel );
  fd_failover_peer_t          to   = { .boot_id=peer->boot_id };
  fd_memcpy( to.junk, peer->junk_pubkey, 32UL );
  handoff_result_to( ctx, &to, id, result );
}

/* An ACK or refusal counts only for the DEMOTED we sent, from the member
   and boot it went to. */
static int
demoted_answer_bound( fd_failover_tile_ctx_t const * ctx,
                      ulong                          handoff_id ) {
  return ctx->handoff.delivery!=FD_FAILOVER_DELIVERY_NONE && handoff_id==ctx->handoff.id &&
         peer_eq( &ctx->handoff.target, ctx->session.peer_boot_id, fd_failover_channel_peer_hello( ctx->channel )->junk_pubkey ) &&
         ctx->action!=FD_FAILOVER_ACTION_DEMOTE_SWITCH && ctx->action!=FD_FAILOVER_ACTION_DEMOTE_DRAIN;
}

/* The peer's message handlers.  Each returns 1 when the message was
   handled, including one it ignored on purpose, and 0 when it was
   malformed, which drops the session: these messages hand off the
   identity so we do not guess at them. */

/* HANDOFF_REQUEST, the peer asks us to give up the identity. */
static int
on_handoff_request_msg( fd_failover_tile_ctx_t * ctx,
                        ulong                    payload_sz,
                        long                     now ) {
  fd_failover_handoff_request_t request;
  if( FD_UNLIKELY( !fd_failover_handoff_request_decode( &request, ctx->rx, payload_sz ) ) ) return 0;
  fd_failover_hello_t const * peer = fd_failover_channel_peer_hello( ctx->channel );
  if( FD_UNLIKELY( request.target_boot_id!=ctx->hello.boot_id ) ) {
    handoff_result( ctx, request.handoff_id, FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY );
    return 1;
  }
  if( FD_UNLIKELY( request.handoff_id==ctx->handoff.id && peer_eq( &ctx->handoff.target, peer->boot_id, peer->junk_pubkey ) ) ) {
    /* A duplicate request keeps the same demotion and reuses its eventual response. */
    if( ctx->action==FD_FAILOVER_ACTION_DEMOTE_SWITCH || ctx->action==FD_FAILOVER_ACTION_DEMOTE_DRAIN ) return 1;
    if( ctx->handoff.delivery!=FD_FAILOVER_DELIVERY_NONE && ctx->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK ) {
      if( !ctx->tx.valid ) (void)queue_demoted( ctx );
    } else {
      handoff_result( ctx, request.handoff_id, ctx->handoff.result==FD_FAILOVER_HANDOFF_TAKEN
                                             ? FD_ADMINCTL_RESULT_SUCCESS : FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY );
    }
    return 1;
  }
  ulong result = FD_ADMINCTL_RESULT_SUCCESS;
  if( ctx->action!=FD_FAILOVER_ACTION_IDLE || ctx->id_switch.pending_key!=FD_FAILOVER_SWITCH_KEY_CNT || ctx->tx.valid || ctx->session.close_after_send ) result = FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS;
  else if( !ctx->holds || peer->holds ) result = FD_FAILOVER_CONTROL_RESULT_WRONG_HOLDER;
  /* Decline the request without changing the installed identity or action. */
  if( FD_UNLIKELY( result!=FD_ADMINCTL_RESULT_SUCCESS ) ) {
    handoff_result( ctx, request.handoff_id, result );
    return 1;
  }
  result = handoff_check( ctx, request.handoff_id, request.replay_slot, now );
  if( FD_UNLIKELY( result!=FD_ADMINCTL_RESULT_SUCCESS ) ) {
    handoff_result( ctx, request.handoff_id, result );
    return 1;
  }
  accept_handoff( ctx, request.handoff_id );
  return 1;
}

/* HANDOFF_RESULT, the peer recorded how our request ended. */
static int
on_handoff_result_msg( fd_failover_tile_ctx_t * ctx,
                       ulong                    payload_sz,
                       long                     now ) {
  fd_failover_handoff_result_t result;
  if( FD_UNLIKELY( !fd_failover_handoff_result_decode( &result, ctx->rx, payload_sz ) ) ) return 0;
  fd_failover_hello_t const * peer = fd_failover_channel_peer_hello( ctx->channel );
  if( FD_UNLIKELY( !ctx->request.id || result.handoff_id!=ctx->request.id ||
                   !peer_eq( &ctx->request.peer, peer->boot_id, peer->junk_pubkey ) ) ) return 1;
  if( FD_UNLIKELY( ctx->action!=FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER &&
                   ctx->action!=FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT ) ) return 1;
  int failed = result.result!=FD_ADMINCTL_RESULT_SUCCESS || !ctx->holds;
  if( FD_UNLIKELY( failed && ctx->holds ) ) {
    FD_LOG_WARNING(( "handoff %lu: the other machine did not record that we took the identity and may run it again, check `failover status` on both machines at once", result.handoff_id ));
  } else if( FD_UNLIKELY( failed && ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT && ctx->reply.reason==FD_FAILOVER_REJECT_HOLDS_IDENTITY ) ) {
    FD_LOG_WARNING(( "handoff %lu ended, this machine refused the final state (%s) because another machine may run the identity, and the other machine "
                     "recorded it, check `failover status` on both machines", result.handoff_id, reject_name( ctx->reply.reason ) ));
  } else if( FD_UNLIKELY( failed && ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT ) ) {
    FD_LOG_WARNING(( "handoff %lu ended, this machine refused the final state (%s) and the other machine recorded it, neither machine runs the identity, "
                     "nothing votes until `failover promote --force` runs on the one whose status shows a coverage floor, never both", result.handoff_id, reject_name( ctx->reply.reason ) ));
  } else if( FD_UNLIKELY( failed && result.result==FD_FAILOVER_CONTROL_RESULT_NO_FINAL_HISTORY &&
                          ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER && ctx->request.send_cnt<FD_FAILOVER_REQUEST_RETRIES ) ) {
    /* The other machine may not have voted since it booted, so a request
       can arrive before its first history with a vote.  It hung up on
       us, the next session resends. */
    FD_LOG_NOTICE(( "handoff %lu: the other machine has no final vote state yet, asking again (send %lu)", result.handoff_id, ctx->request.send_cnt ));
    return 1;
  } else if( FD_UNLIKELY( failed ) ) {
    char const * hint;
    char const * name = control_result( result.result, &hint );
    FD_LOG_WARNING(( "handoff %lu ended (%s), %s", result.handoff_id, name, hint ));
  }
  /* A bound final result ends the request without changing our installed identity. */
  request_end( ctx, now, failed ? FD_FAILOVER_HANDOFF_DECLINED : FD_FAILOVER_HANDOFF_TAKEN );
  if( !failed )
    FD_LOG_NOTICE(( "handoff %lu complete: the other machine confirmed our ACK, we run the identity, connection closed", result.handoff_id ));
  else
    FD_LOG_NOTICE(( "handoff %lu: request ended, %s, connection closed", result.handoff_id,
                    ctx->holds ? "we still run the identity" : "we do not run the identity" ));
  return 1;
}

/* DEMOTED, the peer gave up the identity and hands us its final history. */
static int
on_demoted_msg( fd_failover_tile_ctx_t * ctx,
                ulong                    payload_sz ) {
  /* The peer says it can no longer sign and hands us its history. */
  fd_failover_demoted_t demoted;
  if( FD_UNLIKELY( !fd_failover_demoted_decode( &demoted, ctx->rx, payload_sz ) ) ) return 0;
  /* HELLO pairs only members in the same mode, so a DEMOTED in the
     other mode is malformed. */
  if( FD_UNLIKELY( demoted.mode!=(uchar)FD_FAILOVER_MODE_ALPENGLOW ) ) return 0;
  ulong                       boot_id = ctx->session.peer_boot_id;
  fd_failover_hello_t const * peer    = fd_failover_channel_peer_hello( ctx->channel );
  /* Bind before deduplication.  An unsolicited DEMOTED cannot change
     this operation or replace its cached response. */
  if( FD_UNLIKELY( !ctx->request.id || ctx->request.id!=demoted.handoff_id ||
                   !peer_eq( &ctx->request.peer, boot_id, peer->junk_pubkey ) ) ) return 1;
  if( FD_UNLIKELY( demoted.target_boot_id!=ctx->hello.boot_id ) ) return 0;
  /* The same DEMOTED again.  Once we are done with it we repeat our
     response. */
  if( FD_UNLIKELY( ctx->promotion.from_peer && ctx->promotion.peer.boot_id==boot_id && ctx->promotion.handoff_id==demoted.handoff_id ) ) return 1;
  if( FD_UNLIKELY( ctx->reply.state!=FD_FAILOVER_REPLY_NONE && ctx->reply.handoff_id==demoted.handoff_id && peer_eq( &ctx->reply.peer, boot_id, peer->junk_pubkey ) ) ) {
    queue_reply( ctx );
    return 1;
  }
  fd_failover_history_t history = { .valid=1, .tip=demoted.last_vote_slot, .sz=(ulong)demoted.state_len };
  fd_memcpy( history.state, ctx->rx+sizeof(fd_failover_demoted_t), history.sz );
  uchar        reason = FD_FAILOVER_REJECT_NONE;
  char const * why    = NULL;
  if( FD_UNLIKELY( ctx->holds ) ) {
    reason = FD_FAILOVER_REJECT_HOLDS_IDENTITY;
    why    = "we run the identity";
  } else if( FD_UNLIKELY( ctx->action!=FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER ||
                          ctx->id_switch.pending_key!=FD_FAILOVER_SWITCH_KEY_CNT ) ) {
    reason = FD_FAILOVER_REJECT_BUSY;
    why    = "a transition or key switch is running here";
  }
  if( FD_UNLIKELY( reason!=FD_FAILOVER_REJECT_NONE ) ) {
    FD_LOG_WARNING(( "refusing the peer's handoff %lu (%s), %s, check `failover status` on both machines", demoted.handoff_id, reject_name( reason ), why ));
    finish_reply( ctx, &ctx->request.peer, demoted.handoff_id, (ushort)FD_FAILOVER_MSG_PROMOTE_REJECTED, reason );
    return 1;
  }
  FD_LOG_NOTICE(( "handoff %lu: accepted the peer's final vote history ending at slot %lu, waiting for local adoption before taking the identity", demoted.handoff_id, history.tip ));
  if( ctx->peer_floor==FD_FAILOVER_SLOT_NULL || history.tip>ctx->peer_floor ) ctx->peer_floor = history.tip;
  ctx->peer_history       = history;
  ctx->session.peer_holds = 0;
  /* The bound final state moves us from peer wait to replay wait. */
  start_promotion( ctx, FD_FAILOVER_SOURCE_PEER, &ctx->request.peer, demoted.handoff_id, 0 );
  return 1;
}

/* PROMOTE_ACK, the peer took the identity we handed off. */
static int
on_promote_ack_msg( fd_failover_tile_ctx_t * ctx,
                    ulong                    payload_sz ) {
  /* The peer took the identity, so our DEMOTED did its job.  An ACK
     after the deadline still counts, and we ignore an ACK we are not
     waiting for rather than drop the session. */
  fd_failover_promote_ack_t ack;
  if( FD_UNLIKELY( !fd_failover_promote_ack_decode( &ack, ctx->rx, payload_sz ) ) ) return 0;
  if( FD_UNLIKELY( !demoted_answer_bound( ctx, ack.handoff_id ) ) ) return 1;
  FD_LOG_NOTICE(( "handoff %lu: received ACK, the peer took the identity, we keep the junk key", ack.handoff_id ));
  /* The peer ACK ends the demotion wait and records that it took the identity. */
  handoff_resolved( ctx, FD_FAILOVER_HANDOFF_TAKEN );
  ctx->taken              = 1;
  ctx->session.peer_holds = 1;
  ctx->stuck              = 0;
  /* The peer votes past the final history we handed it from here on. */
  ctx->peer_history.valid = 0;
  handoff_result( ctx, ack.handoff_id, FD_ADMINCTL_RESULT_SUCCESS );
  return 1;
}

/* PROMOTE_REJECTED, the peer did not take the identity we handed off. */
static int
on_promote_rejected_msg( fd_failover_tile_ctx_t * ctx,
                         ulong                    payload_sz ) {
  /* The peer did not take the identity.  Either machine may now recover
     without telling the other, so we drop any history the peer handed us
     earlier. */
  fd_failover_promote_rejected_t rej;
  if( FD_UNLIKELY( !fd_failover_promote_rejected_decode( &rej, ctx->rx, payload_sz ) ) ) return 0;
  if( FD_UNLIKELY( !demoted_answer_bound( ctx, rej.handoff_id ) ) ) return 1;
  if( FD_UNLIKELY( rej.reason==FD_FAILOVER_REJECT_HOLDS_IDENTITY ) ) {
    FD_LOG_WARNING(( "the peer declined handoff %lu (%s), it saw another machine that may run the identity, this machine gave it up, "
                     "check `failover status` on both machines and the peer's log", rej.handoff_id, reject_name( rej.reason ) ));
  } else {
    FD_LOG_WARNING(( "the peer declined handoff %lu (%s), neither machine runs the identity now, nothing votes until `failover promote --force` runs on the one whose status shows a coverage floor, never both, "
                     "see the peer's log first", rej.handoff_id, reject_name( rej.reason ) ));
  }
  ctx->peer_history.valid = 0;
  /* The peer refusal ends the demotion wait, this machine keeps its junk key. */
  handoff_resolved( ctx, FD_FAILOVER_HANDOFF_DECLINED );
  ctx->stuck = 1;
  handoff_result( ctx, rej.handoff_id, FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY );
  return 1;
}

/* Handle a controller message.  Anything malformed drops the session,
   these messages hand off the identity so we do not guess at them. */
static void
handle_control( fd_failover_tile_ctx_t * ctx,
                ushort                   type,
                ulong                    payload_sz,
                long                     now ) {
  int handled;
  switch( type ) {
  case (ushort)FD_FAILOVER_MSG_HANDOFF_REQUEST:  handled = on_handoff_request_msg ( ctx, payload_sz, now ); break;
  case (ushort)FD_FAILOVER_MSG_HANDOFF_RESULT:   handled = on_handoff_result_msg  ( ctx, payload_sz, now ); break;
  case (ushort)FD_FAILOVER_MSG_DEMOTED:          handled = on_demoted_msg         ( ctx, payload_sz      ); break;
  case (ushort)FD_FAILOVER_MSG_PROMOTE_ACK:      handled = on_promote_ack_msg     ( ctx, payload_sz      ); break;
  case (ushort)FD_FAILOVER_MSG_PROMOTE_REJECTED: handled = on_promote_rejected_msg( ctx, payload_sz      ); break;
  default:                                       handled = 0;                                               break;
  }
  if( FD_LIKELY( handled ) ) return;

  /* Malformed control traffic drops the connection and retains local work. */
  fd_failover_channel_protocol_error( ctx->channel, now );
  sync_session( ctx );
}

/* End our handoff request with result, an FD_FAILOVER_HANDOFF_*, and
   hang up. */
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
  if( ctx->reply.state==FD_FAILOVER_REPLY_PENDING ) ctx->reply.state = FD_FAILOVER_REPLY_KEPT;
  /* Return to idle after a response or cancellation. */
  ctx->action           = FD_FAILOVER_ACTION_IDLE;
  ctx->stuck            = failed;
  fd_failover_channel_init_dialer( ctx->channel, 0U, 0 );
  fd_failover_channel_hangup( ctx->channel, now );
  sync_session( ctx );
}

/* An idle machine that does not run the identity authenticates to the
   one that does ahead of an operator command.  Merely pairing never
   creates a request or changes the installed identity. */
static void
preconnect( fd_failover_tile_ctx_t * ctx,
            long                     now ) {
  if( ctx->request.id || ctx->stuck || ctx->tx.valid || ctx->session.close_after_send ||
      ctx->action!=FD_FAILOVER_ACTION_IDLE || ctx->id_switch.pending_key!=FD_FAILOVER_SWITCH_KEY_CNT ) return;
  /* A stale gossip address may name a validator that does not run the
     identity any more.  Do not keep that session open.  Retain the dial
     backoff. */
  if( !ctx->holds &&
      fd_failover_channel_state( ctx->channel )==FD_FAILOVER_SESSION_PAIRED &&
      !fd_failover_channel_peer_hello( ctx->channel )->holds )
    fd_failover_channel_hangup( ctx->channel, now );
  int ready = !ctx->holds &&
              ctx->staked_addr && ctx->staked_seen_at && now>=ctx->staked_seen_at &&
              now-ctx->staked_seen_at<FD_FAILOVER_GOSSIP_FRESH_NANOS;
  if( !ready ) fd_failover_channel_init_dialer( ctx->channel, 0U, 0 );
  else if( fd_failover_channel_state( ctx->channel )!=FD_FAILOVER_SESSION_PAIRED )
    fd_failover_channel_init_dialer( ctx->channel, ctx->staked_addr, FD_FAILOVER_DEFAULT_PORT );
}

/* An operator command is required before sending a handoff request. */
static void
peer_poll( fd_failover_tile_ctx_t * ctx,
           long                     now,
           int *                    charge_busy ) {
  preconnect( ctx, now );
  sync_session( ctx );
  if( FD_UNLIKELY( ctx->request.id && ctx->request.until && now>=ctx->request.until &&
                   ( ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER ||
                     ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT ) ) ) {
    /* The network deadline pauses this request without cancelling it. */
    request_pause( ctx, now, !ctx->request.peer.boot_id ? "no peer authenticated before the deadline" :
                            !ctx->request.send_cnt ? "no handoff request sent before the deadline" :
                                                        "no final answer before the deadline" );
    return;
  }
  if( FD_UNLIKELY( ctx->session.close_after_send && !ctx->tx.valid && !fd_failover_channel_tx_pending( ctx->channel ) ) ) {
    /* The result drained, close the session without changing role or action. */
    ctx->session.close_after_send = 0;
    fd_failover_channel_hangup( ctx->channel, now );
    FD_LOG_NOTICE(( "handoff %lu: confirmation drained, connection closed, listener ready for the next request", ctx->session.close_handoff_id ));
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
  if( FD_LIKELY( !ctx->request.id || fd_failover_channel_state( ctx->channel )!=FD_FAILOVER_SESSION_PAIRED ) ) return;
  fd_failover_hello_t const * peer = fd_failover_channel_peer_hello( ctx->channel );
  /* The peer restarted before it confirmed our answer, so it can no
     longer confirm this handoff and the wait ends.  A paused request
     ends too, else the old holder's next request is refused as in
     progress until the operator runs `failover promote` here. */
  if( FD_UNLIKELY( ctx->request.peer.boot_id && !peer_eq( &ctx->request.peer, peer->boot_id, peer->junk_pubkey ) &&
                   ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT &&
                   ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_CNT ) ) {
    int holds      = ctx->holds;
    int peer_holds = !!peer->holds;
    FD_LOG_WARNING(( "handoff %lu: the peer restarted before it confirmed our %s, ending the request, %s, %s", ctx->request.id,
                     holds ? "ACK" : "refusal", holds ? "we run the identity" : "we do not run the identity",
                     holds && peer_holds ? "and its new boot says it runs the identity too, check `failover status` on both machines at once" :
                     holds               ? "its new boot does not run the identity" :
                     peer_holds          ? "its new boot runs the identity" :
                                           "its new boot does not run it either, nothing votes until `failover promote --force` runs on the one whose status shows a coverage floor, never both" ));
    request_end( ctx, now, holds ? FD_FAILOVER_HANDOFF_TAKEN : FD_FAILOVER_HANDOFF_DECLINED );
    return;
  }
  if( FD_LIKELY( !ctx->request.until || ctx->request.sent ) ) return;
  if( FD_UNLIKELY( !ctx->request.peer.boot_id ) ) {
    if( FD_UNLIKELY( !peer->holds ) ) {
      FD_LOG_WARNING(( "handoff %lu dialed `" FD_IP4_ADDR_FMT ":%hu`, which does not run the identity, give the address of the machine running it with `failover promote --address`, "
                       "and if both machines show `runs target identity: no` no machine runs it and `failover promote --force` on the one whose status shows a coverage floor, never both, takes it",
                       ctx->request.id, FD_IP4_ADDR_FMT_ARGS( ctx->request.addr ), dial_port( ctx ) ));
      /* End the peer wait without changing the installed identity. */
      request_end( ctx, now, FD_FAILOVER_HANDOFF_NOT_HOLDER );
      return;
    }
    /* Bind the request to the first authenticated member and boot running
       the identity. */
    ctx->request.peer.boot_id = peer->boot_id;
    fd_memcpy( ctx->request.peer.junk, peer->junk_pubkey, 32UL );
  } else if( FD_UNLIKELY( !peer_eq( &ctx->request.peer, peer->boot_id, peer->junk_pubkey ) ) ) {
    /* Keep the old binding until the operator ends this request, without
       accepting another boot's final state or acknowledgement for it. */
    ctx->request.peer_restarted = 1;
    request_pause( ctx, now, "authenticated member or boot changed" );
    return;
  }
  fd_failover_handoff_request_t request = { .handoff_id=ctx->request.id, .target_boot_id=ctx->request.peer.boot_id, .replay_slot=ctx->replay_slot };
  if( FD_LIKELY( !fd_failover_channel_send( ctx->channel, now, FD_FAILOVER_MSG_HANDOFF_REQUEST,
                                            (uchar const *)&request, sizeof(request) ) ) ) {
    /* The request is sent, keep waiting for final state or confirmation. */
    ctx->request.sent     = 1;
    ctx->request.send_cnt = fd_ulong_sat_add( ctx->request.send_cnt, 1UL );
    if( now>=ctx->request.log_at ) {
      ctx->request.log_at = fd_long_sat_add( now, FD_FAILOVER_LOG_INTERVAL_NANOS );
      char member[ FD_BASE58_ENCODED_32_SZ ];
      fd_base58_encode_32( ctx->request.peer.junk, NULL, member );
      FD_LOG_NOTICE(( "handoff %lu: sent REQUEST to authenticated member %s boot %016lx, %s (send %lu)",
                      ctx->request.id, member, ctx->request.peer.boot_id, request_wait( ctx ), ctx->request.send_cnt ));
    }
    *charge_busy = 1;
  }
}


/* Checks whether a promotion may go ahead now.  Returns
   FD_ADMINCTL_RESULT_SUCCESS or the refusal. */
static ulong
promote_guard( fd_failover_tile_ctx_t const * ctx,
               long                           now,
               int                            force ) {
  if( FD_UNLIKELY( ctx->input_lost ) ) return FD_FAILOVER_CONTROL_RESULT_INPUT_LOST;
  int paired = fd_failover_channel_state( ctx->channel )==FD_FAILOVER_SESSION_PAIRED;

  if( FD_UNLIKELY( ctx->holds ) )                                                    return FD_FAILOVER_CONTROL_RESULT_WRONG_HOLDER;
  if( FD_UNLIKELY( ctx->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK && !force ) )     return FD_FAILOVER_CONTROL_RESULT_HANDOFF_PENDING;
  int request_wait = ctx->request.id &&
                     ( ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER ||
                       ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT );
  if( FD_UNLIKELY( ( ctx->action!=FD_FAILOVER_ACTION_IDLE && ctx->action!=FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK &&
                     !( force && request_wait ) ) ||
                   ctx->id_switch.pending_key!=FD_FAILOVER_SWITCH_KEY_CNT ) )           return FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS;
  if( FD_UNLIKELY( force ) ) return FD_ADMINCTL_RESULT_SUCCESS;
  /* The peer took the identity in our last handoff. */
  if( FD_UNLIKELY( ctx->taken ) ) return FD_FAILOVER_CONTROL_RESULT_TAKEN;
  if( FD_UNLIKELY( paired && fd_failover_channel_peer_hello( ctx->channel )->holds ) )
    return FD_FAILOVER_CONTROL_RESULT_PEER_HOLDS;
  /* Another host is publishing the identity in gossip. */
  if( FD_UNLIKELY( ctx->staked_seen_at && now>=ctx->staked_seen_at &&
                   now-ctx->staked_seen_at<FD_FAILOVER_GOSSIP_FRESH_NANOS ) ) return FD_FAILOVER_CONTROL_RESULT_STAKED_SEEN;
  /* No check found another machine running the identity. */
  return FD_ADMINCTL_RESULT_SUCCESS;
}

/* The history source a promotion would adopt now. */
static ulong
promote_source( fd_failover_tile_ctx_t const * ctx ) {
  /* The peer may already vote past our unanswered DEMOTED. */
  if( FD_UNLIKELY( ctx->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK ) ) return FD_FAILOVER_SOURCE_EMPTY;
  ulong floor = coverage_floor( ctx );
  ulong root  = ctx->root_slot;
  int   peer_ok = ctx->peer_history.valid && ( floor==FD_FAILOVER_SLOT_NULL || ctx->peer_history.tip>=floor ) &&
                                           ( root ==FD_FAILOVER_SLOT_NULL || ctx->peer_history.tip> root  );
  return peer_ok ? FD_FAILOVER_SOURCE_PEER : FD_FAILOVER_SOURCE_EMPTY;
}

/* Whether our handoff request is paused at its deadline. */
static inline int
request_paused( fd_failover_tile_ctx_t const * ctx ) {
  return ctx->request.id && !ctx->request.until &&
         ( ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER || ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT );
}

/* `failover promote` without --force: ask the machine running the
   identity to hand it over, or resume a paused request. */
static ulong
control_cmd_handoff( fd_failover_tile_ctx_t *           ctx,
                     fd_adminctl_failover_req_t const * req,
                     long                               now ) {
  int paused = request_paused( ctx ) && ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_CNT;
  if( FD_UNLIKELY( paused && ctx->request.peer_restarted ) ) {
    if( ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT ) {
      /* Local adoption is already settled.  This command ends only
         our wait, without confirming anything on the old peer. */
      FD_LOG_WARNING(( "handoff %lu: the authenticated peer changed before it confirmed our answer, ending the confirmation wait, %s, the old peer's acknowledgement remains unknown",
                       ctx->request.id, ctx->holds ? "we run the identity" : "we do not run the identity" ));
      request_end( ctx, now, ctx->holds ? FD_FAILOVER_HANDOFF_TAKEN : FD_FAILOVER_HANDOFF_DECLINED );
      return FD_ADMINCTL_RESULT_SUCCESS;
    }
    FD_LOG_NOTICE(( "handoff %lu was bound to peer boot %016lx, the authenticated peer changed, ending it and starting a new handoff", ctx->request.id, ctx->request.peer.boot_id ));
    request_end( ctx, now, FD_FAILOVER_HANDOFF_RESTARTED );
    paused = 0;
  }
  if( FD_UNLIKELY( paused ) ) {
    /* Refresh the destination while retaining the authenticated member
       and boot.  An explicit address takes precedence over gossip. */
    ctx->request.until = fd_long_sat_add( now, FD_FAILOVER_CHANNEL_IDLE_NANOS );
    ctx->request.sent  = 0;
    ctx->stuck         = 0;
    if( req->addr ) ctx->cmd_addr = req->addr;
    if( req->port ) ctx->cmd_port = req->port;
    if(      ctx->cmd_addr    ) ctx->request.addr = ctx->cmd_addr;
    else if( ctx->staked_addr ) ctx->request.addr = ctx->staked_addr;
    fd_failover_channel_init_dialer( ctx->channel, ctx->request.addr, dial_port( ctx ) );
    FD_LOG_NOTICE(( "resuming handoff %lu at `" FD_IP4_ADDR_FMT ":%hu` from %s, %s, %s",
                    ctx->request.id, FD_IP4_ADDR_FMT_ARGS( ctx->request.addr ), dial_port( ctx ),
                    ctx->cmd_addr ? "`failover promote --address`" : "gossip",
                    ctx->request.peer.boot_id ? "same authenticated member and boot" : "the other machine has not authenticated yet",
                    request_wait( ctx ) ));
    return FD_ADMINCTL_RESULT_SUCCESS;
  }
  if( FD_UNLIKELY( ctx->action!=FD_FAILOVER_ACTION_IDLE || ctx->id_switch.pending_key!=FD_FAILOVER_SWITCH_KEY_CNT ) )
    return FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS;
  if( FD_UNLIKELY( ctx->holds ) ) return FD_FAILOVER_CONTROL_RESULT_WRONG_HOLDER;
  uint addr = req->addr ? req->addr : ctx->staked_addr;
  if( FD_UNLIKELY( !addr ) ) return FD_FAILOVER_CONTROL_RESULT_NO_HOLDER_ADDRESS;
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
  /* Start a new handoff and wait for the machine running the identity. */
  ctx->action                   = FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER;
  ctx->session.close_after_send = 0;
  fd_failover_channel_init_dialer( ctx->channel, addr, dial_port( ctx ) );
  FD_LOG_NOTICE(( "requesting handoff %lu from the machine running the identity at `" FD_IP4_ADDR_FMT ":%hu` using %s, authenticating the peer before requesting final state",
                  ctx->request.id, FD_IP4_ADDR_FMT_ARGS( addr ), dial_port( ctx ), ctx->cmd_addr ? "`failover promote --address`" : "gossip" ));
  return FD_ADMINCTL_RESULT_SUCCESS;
}

/* `failover promote --force`: take the identity without the peer. */
static ulong
control_cmd_promote( fd_failover_tile_ctx_t *           ctx,
                     fd_adminctl_failover_req_t const * req,
                     long                               now ) {
  /* --force takes over without dialing the peer and accepts incomplete
     or empty history. */
  int   force  = !!( req->flags & FD_ADMINCTL_FAILOVER_FLAG_FORCE );
  /* Admin sends an unforced promote as a handoff, so this one did not
     come through it. */
  if( FD_UNLIKELY( !force ) ) {
    FD_LOG_WARNING(( "refusing a promote without --force, it did not come through admin" ));
    return FD_ADMINCTL_RESULT_UNKNOWN_COMMAND;
  }
  ulong result = promote_guard( ctx, now, force );
  if( FD_UNLIKELY( result!=FD_ADMINCTL_RESULT_SUCCESS ) ) return result;
  ulong source = promote_source( ctx );
  /* The operator fenced the peer.  Only a request with no local
     adoption or key switch in flight can be cancelled for recovery. */
  if( force && !ctx->holds && ctx->request.id &&
      ( ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER || ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT ) &&
      ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_CNT ) {
    FD_LOG_NOTICE(( "handoff %lu cancelled by `failover promote --force` on the operator's word that the peer cannot sign, proceeding with local recovery", ctx->request.id ));
    /* Forced recovery ends the peer wait without changing the installed identity. */
    request_end( ctx, now, FD_FAILOVER_HANDOFF_CANCELLED );
  }
  if( FD_UNLIKELY( ctx->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK ) ) {
    FD_LOG_WARNING(( "`failover promote --force` stops waiting for the peer's answer to handoff %lu, discarding saved final state because the peer may have voted, coverage floors retained", ctx->handoff.id ));
    ctx->peer_history.valid = 0;
    /* Forced recovery ends the ACK wait before starting local promotion. */
    handoff_resolved( ctx, FD_FAILOVER_HANDOFF_CANCELLED );
  }
  if( force ) FD_LOG_WARNING(( "operator promotion: --force asserts the peer cannot sign, peer checks are bypassed and incomplete or empty vote history is permitted if needed" ));
  if( source==FD_FAILOVER_SOURCE_EMPTY ) {
    fd_failover_history_t const * saved  = &ctx->peer_history;
    char const *                stored = "the stored peer vote history";
    if( saved->valid ) {
      ulong floor = coverage_floor( ctx );
      if( floor!=FD_FAILOVER_SLOT_NULL && saved->tip<floor )
        FD_LOG_NOTICE(( "operator promotion: %s ends at slot %lu below the known signing floor %lu, skipping it", stored, saved->tip, floor ));
      else if( ctx->root_slot!=FD_FAILOVER_SLOT_NULL && saved->tip<=ctx->root_slot )
        FD_LOG_NOTICE(( "operator promotion: %s ends at slot %lu at or below the local root %lu, skipping it", stored, saved->tip, ctx->root_slot ));
    }
    FD_LOG_NOTICE(( "operator promotion: no eligible saved final state is available, selecting an empty history" ));
  } else {
    fd_failover_history_t const * saved = &ctx->peer_history;
    FD_LOG_NOTICE(( "operator promotion: selecting %s through slot %lu, the %s must validate and adopt it before the identity is installed",
                    source_name( source ), saved->tip, "votor" ));
  }
  /* The accepted operator command starts the replay and adoption sequence. */
  start_promotion( ctx, source, NULL, 0UL, force );
  return FD_ADMINCTL_RESULT_SUCCESS;
}

/* Run an operator command.  If we refuse it we say why. */
static ulong
apply_control( fd_failover_tile_ctx_t *           ctx,
               fd_adminctl_failover_req_t const * req,
               long                               now ) {
  if( FD_UNLIKELY( ctx->input_lost ) ) return FD_FAILOVER_CONTROL_RESULT_INPUT_LOST;
  switch( req->cmd ) {
  case FD_ADMINCTL_FAILOVER_CMD_HANDOFF: return control_cmd_handoff( ctx, req, now );
  case FD_ADMINCTL_FAILOVER_CMD_PROMOTE: return control_cmd_promote( ctx, req, now );
  default:                               return FD_ADMINCTL_RESULT_UNSUPPORTED;
  }
}

/* The `failover status` response. */
static void
status_snapshot( fd_failover_tile_ctx_t const *       ctx,
                 long                                 now,
                 fd_adminctl_failover_status_resp_t * resp ) {
  fd_adminctl_failover_status_resp_init( resp );
  resp->enabled    = 1;
  resp->holds      = (uchar)ctx->holds;
  resp->action     = (uchar)ctx->action;
  resp->stuck      = (uchar)!!ctx->stuck;
  resp->link_state = (uchar)fd_failover_channel_state( ctx->channel );
  if( FD_UNLIKELY( fd_failover_channel_state( ctx->channel )==FD_FAILOVER_SESSION_PAIRED ) ) {
    resp->peer_holds_valid = 1;
    resp->peer_holds       = (uchar)ctx->session.peer_holds;
  }
  resp->peer_boot_id   = ctx->session.peer_boot_id;
  resp->peer_addr      = ctx->request.id ? ctx->request.addr : ctx->staked_addr;
  resp->peer_addr_cmd  = (uchar)( ctx->request.id && ctx->cmd_addr );
  resp->peer_port      = ctx->request.id ? dial_port( ctx ) : FD_FAILOVER_DEFAULT_PORT;
  resp->handoff_id     = ctx->last_requested ? ctx->request.last_id : ctx->handoff.id;
  resp->handoff_result = (uchar)( ctx->last_requested ? ctx->request.result : ctx->handoff.result );
  resp->promote_source = (uchar)promote_source( ctx );
  resp->promote_floor  = coverage_floor( ctx );
  resp->promote_result = ctx->input_lost ? FD_FAILOVER_CONTROL_RESULT_INPUT_LOST : promote_guard( ctx, now, 0 );
  resp->mode           = ctx->hello.mode;
  resp->request_paused = (uchar)request_paused( ctx );
  fd_memcpy( resp->target,    ctx->hello.staked_pubkey, 32UL );
  fd_memcpy( resp->installed, ctx->installed,           32UL );
  fd_memcpy( resp->junk,      ctx->hello.junk_pubkey,   32UL );
}

/* Respond to one bus request.  The admin tile validated the ABI already.
   The response goes out in its own chunk. */
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
    FD_LOG_NOTICE(( "`%s%s%s` received", cmd_name,
                    ( req.flags & FD_ADMINCTL_FAILOVER_FLAG_YES   ) ? " --yes"   : "",
                    ( req.flags & FD_ADMINCTL_FAILOVER_FLAG_FORCE ) ? " --force" : "" ));
    ulong result = apply_control( ctx, &req, now );
    if( FD_UNLIKELY( result!=FD_ADMINCTL_RESULT_SUCCESS ) ) {
      char const * hint;
      char const * name = control_refusal( result, &hint );
      FD_LOG_WARNING(( "`%s` refused with %s, %s", cmd_name, name, hint ));
    }
    ulong handoff_id = 0UL;
    if( FD_LIKELY( result==FD_ADMINCTL_RESULT_SUCCESS ) ) {
      /* Ending a paused confirmation wait zeroes request.id and keeps
         last_id, which is the handoff the command acted on. */
      if( req.cmd==FD_ADMINCTL_FAILOVER_CMD_HANDOFF ) handoff_id = ctx->request.id ? ctx->request.id : ctx->request.last_id;
    }
    fd_adminctl_failover_control_resp_t response = {
      .version    = FD_ADMINCTL_FAILOVER_PAYLOAD_VERSION,
      .holds      = (uchar)ctx->holds,
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

/* The address of the machine running the identity comes from gossip,
   from the newest contact info for the identity that is not ours. */
static void
on_contact_info_msg( fd_failover_tile_ctx_t * ctx,
                     long                     now ) {
  uint addr = ctx->gossip_socket.addr;
  if( FD_UNLIKELY( !addr ) ) return;
  if( FD_LIKELY( !fd_memeq( ctx->gossip_origin, ctx->hello.staked_pubkey, 32UL ) ) ) return;
  if( FD_UNLIKELY( addr==ctx->own_gossip.addr && ctx->gossip_socket.port==ctx->own_gossip.port ) ) return;
  ctx->staked_seen_at = now;
  /* Gossip may be the only sign of a peer tenure, so we drop the peer's
     history for good, not only while the contact info is fresh. */
  if( FD_UNLIKELY( ctx->peer_history.valid ) )
    FD_LOG_NOTICE(( "gossip shows the identity at another host, discarding saved final state from before its voting tenure, keeping coverage floors" ));
  ctx->peer_history.valid = 0;

  if( FD_LIKELY( addr==ctx->staked_addr ) ) return;
  uint old_addr = ctx->staked_addr;
  ctx->staked_addr = addr;
  if( FD_LIKELY( !old_addr ) ) {
    FD_LOG_NOTICE(( "gossip shows the identity at `" FD_IP4_ADDR_FMT "`, a handoff from this machine dials it", FD_IP4_ADDR_FMT_ARGS( addr ) ));
  } else {
    FD_LOG_NOTICE(( "gossip shows a new address for the identity, `" FD_IP4_ADDR_FMT "` before and `" FD_IP4_ADDR_FMT "` now, the next handoff uses the new address",
                    FD_IP4_ADDR_FMT_ARGS( old_addr ), FD_IP4_ADDR_FMT_ARGS( addr ) ));
  }
}

/* Failover must not backpressure validator work.  Losing an input instead
   disables transitions because cached history or switch results may be stale. */
static void
input_overrun( fd_failover_tile_ctx_t * ctx ) {
  if( FD_UNLIKELY( ctx->input_lost ) ) return;
  ctx->input_lost    = 1;
  ctx->stuck         = 1;
  ctx->hist_fresh    = 0;
  ctx->bus_req_fresh = 0;
  fd_failover_channel_init_dialer( ctx->channel, 0U, 0 );
  fd_failover_channel_hangup( ctx->channel, fd_failover_clock() );
  FD_LOG_WARNING(( "failover input overrun, failover is disabled until restart, validator processing continues" ));
}

static inline int
before_frag( fd_failover_tile_ctx_t * ctx,
             ulong                    in_idx,
             ulong                    seq FD_PARAM_UNUSED,
             ulong                    sig ) {
  if( FD_UNLIKELY( ctx->input_lost ) ) return in_idx!=ctx->admin_in_idx || sig!=FD_FAILOVER_BUS_REQUEST;
  if( FD_LIKELY( in_idx==ctx->gossip_in_idx ) ) {
    return sig!=FD_GOSSIP_UPDATE_TAG_CONTACT_INFO && sig!=FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE;
  }
  if( FD_LIKELY( in_idx==ctx->hist_in_idx ) ) {
    /* Every history frame counts toward the drain watermark after the
       stem validates it. */
    return 0;
  }
  if( FD_UNLIKELY( in_idx==ctx->admin_in_idx ) ) {
    /* Commands, switch responses and set-identity.  Dropping a switch
       response here would leave the switch hanging forever. */
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
  ctx->read_pending = 1;
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
  /* Copy here and commit in after_frag.  A remove leaves the socket
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

/* Unknown adoption results are invalid. */
static ulong
votor_adopt_code( ulong result ) {
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
  ctx->read_pending = 0;
  if( FD_UNLIKELY( in_idx==ctx->adopt_in_idx ) ) {
    ctx->adopt_result.result = votor_adopt_code( ctx->adopt_result.result );
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
  /* STEM skips after_frag if the fragment was overwritten during the read. */
  if( FD_UNLIKELY( ctx->read_pending ) ) input_overrun( ctx );
  if( FD_UNLIKELY( ctx->input_lost ) ) {
    if( FD_UNLIKELY( ctx->bus_req_fresh ) ) {
      ctx->bus_req_fresh = 0;
      serve_bus_request( ctx, stem, fd_failover_clock() );
      *charge_busy = 1;
    }
    return;
  }
  if( FD_UNLIKELY( ctx->hist_fresh ) ) {
    ctx->hist_fresh = 0;
    on_votor_hist_msg( ctx, &ctx->hist );
  }
  step_controller( ctx, stem );

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

  if( FD_UNLIKELY( ctx->stuck!=ctx->stuck_logged ) ) {
    ctx->stuck_logged = ctx->stuck;
    if( !ctx->stuck ) FD_LOG_NOTICE(( "failover is no longer stuck, %s", ctx->holds ? "this machine runs the identity" : "this machine does not run the identity" ));
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

/* An iteration publishes at most an adopt or switch request and a bus
   response, within the burst of 3. */
#define STEM_BURST (3UL)
#define STEM_LAZY  ((long)1e6) /* 1ms */

/* A frame on our sockets does not wake a parked tile, so we do not park. */
#define STEM_NEVER_PARK 1

#define STEM_CALLBACK_CONTEXT_TYPE       fd_failover_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN      alignof(fd_failover_tile_ctx_t)

#define STEM_CALLBACK_AFTER_POLL_OVERRUN input_overrun
#define STEM_CALLBACK_AFTER_CREDIT       after_credit
#define STEM_CALLBACK_BEFORE_FRAG        before_frag
#define STEM_CALLBACK_DURING_FRAG        during_frag
#define STEM_CALLBACK_AFTER_FRAG         after_frag

#include "../../disco/stem/fd_stem.c"

/* A serialized history fits the DEMOTED payload. */
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
