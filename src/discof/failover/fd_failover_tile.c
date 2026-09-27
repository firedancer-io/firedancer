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

#include "fd_failover_bus.h"
#include "fd_failover_channel.h"
#include "fd_failover_log.h"

#include <string.h>
#include <sys/socket.h>

#include "generated/fd_failover_tile_seccomp.h"

/* The failov tile owns the socket to the other failover machine and is
   the only tile that keeps host networking for it.  It holds this
   machine's junk keypair for TLS and nothing else, the staked key never
   enters this tile.  The sign tile signs our member certificate.  The
   admin tile keeps the identity switch and stays off the network. */

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
   in fd_adminctl.h, failover status reports them. */

/* Which key a switch installs, CNT while none is in flight */
#define FD_FAILOVER_SWITCH_KEY_JUNK   (0UL)
#define FD_FAILOVER_SWITCH_KEY_STAKED (1UL)
#define FD_FAILOVER_SWITCH_KEY_CNT    (2UL)

/* A compact tower and the slot of its last vote. */
struct fd_failover_tower {
  int   valid;
  ulong tip;
  ulong sz;
  uchar state[ FD_FAILOVER_TOWER_STATE_MAX ];
};

typedef struct fd_failover_tower fd_failover_tower_t;

struct fd_failover_tile_ctx {
  fd_keyguard_client_t    keyguard_client[ 1 ];
  int                     member_cert_set;

  fd_failover_hello_t     hello;
  ulong                   role;
  uint                    config_addr;   /* [failover.peer_address] resolved, 0 when gossip finds the active */
  ushort                  port;
  fd_failover_channel_t * channel;
  ulong                   channel_state; /* last seen session state, for edge detection */
  ulong                   channel_pair_cnt; /* catches a replacement paired during one poll */
  long                    poll_at;       /* next idle socket poll */

  ulong                   peer_boot_id;
  ulong                   peer_role; /* latest HELLO or accepted handoff evidence on this session */

  ulong request_id;       /* our handoff request, zero when none is open */
  ulong request_boot_id;  /* the active boot we authenticated for it */
  uchar request_junk[32];
  uint  request_addr;     /* kept until the exchange finishes */
  long  request_until;    /* retry deadline, zero while the operator must retry */
  int   request_sent;     /* sent on this session */
  ulong request_last_id;
  ulong request_result;
  int   last_requested;   /* status describes our request rather than our demotion */
  int   close_after_send;
  ulong close_handoff_id;
  fd_failover_log_t request_tx_log;
  fd_failover_log_t demoted_tx_log;
  fd_failover_log_t reply_tx_log;
  fd_failover_log_t result_tx_log;

  ulong                   peer_floor;        /* highest last vote the peer reported, kept across sessions */
  ulong                   own_floor;         /* highest vote we signed while ACTIVE this boot */

  /* gossip_out, polled unreliably for contact infos */
  ulong                   gossip_in_idx;
  fd_wksp_t *             gossip_in_mem;
  ulong                   gossip_in_chunk0;
  ulong                   gossip_in_wmark;
  ulong                   gossip_in_mtu;

  fd_ip4_port_t           own_gossip;          /* our own gossip socket */
  uchar                   gossip_origin[ 32 ]; /* copied in during_frag */
  fd_ip4_port_t           gossip_socket;       /* copied in during_frag, zero for a remove or IPv6 */
  uint                    staked_addr;         /* from a staked contact info that is not ours, 0 none */
  long                    staked_seen_at;      /* our clock when that one arrived, 0 never */

  /* Controller */
  ulong action;
  int   stuck;          /* a transition failed or is overdue, shown to the operator */
  int   stuck_logged;   /* the stuck value we last told the operator about */
  ulong deadline_slot;  /* replay slot at which this attempt aborts */
  long  demote_until;   /* also bound the drain when replay stops */

  /* Our demotion.  Handoff ids count up from a random base per boot, so
     ids from two boots of ours do not collide. */
  ulong handoff_base;
  ulong handoff_cnt;
  ulong handoff_id;      /* id of our latest demotion */
  ulong handoff_target;  /* peer boot_id it is for, 0 for a demote */
  uchar handoff_junk[32];
  ulong handoff_result;  /* FD_FAILOVER_HANDOFF_* of the latest DEMOTED */
  int   send_demoted;    /* DEMOTED is owed to the target */
  int   demoted_sent;    /* it went out on this session */
  int   drain_logged;    /* we said once that the junk key is in and we wait for the tower */
  ulong demoted_sz;
  uchar demoted[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];
  int   taken;           /* the peer took the identity; only a new tenure clears this */
  ulong taken_boot_id;

  /* Towers a promotion can adopt */
  fd_failover_tower_t peer_tower; /* stored peer tower, from a DEMOTED */
  fd_failover_tower_t own_tower;  /* our own final tower from this boot */

  /* The promotion in progress */
  char                promote_label[48]; /* handoff ID or operator promotion, fixed for every step */
  ulong               promote_source;
  int                 promote_peer;       /* the peer's DEMOTED asked for it, we answer it */
  ulong               promote_boot_id;    /* that DEMOTED's peer boot_id */
  ulong               promote_handoff_id; /* and its handoff id */
  ulong               promote_floor;      /* coverage floor when it started */
  int                 promote_force;      /* promote --force, the checks on the peer are skipped */
  long                promote_staked_at;  /* staked_seen_at when it started */
  int                 promote_active_seen; /* an ACTIVE peer authenticated after promotion started */
  long                promote_until;      /* our clock when the replay and adopt waits give up, 0 until armed */
  fd_failover_tower_t adopt;              /* what goes to the tower tile, empty for the vote account */
  ulong               adopt_expected_id;
  int                 adopt_retry;        /* ask the tower tile again once replay passes adopt_retry_slot */
  ulong               adopt_retry_slot;
  ulong               floor_acct;         /* the account's last vote in the latest answer short of the floor */
  int                 floor_logged;       /* we said once that we wait for the floor */
  int                 retry_logged;       /* and that we ask the tower tile again as replay moves */

  /* Our last answer to a DEMOTED.  The same DEMOTED again gets the same
     answer, so a peer that missed it is not left waiting. */
  int    reply_valid;
  ulong  reply_boot_id;
  ulong  reply_handoff_id;
  uchar  reply_junk[32];
  ushort reply_type;   /* PROMOTE_ACK or PROMOTE_REJECTED */
  uchar  reply_reason; /* for a rejected reply */
  int    reply_owed;   /* the reply could not be queued yet, the slot was busy */

  /* The one control message waiting to go out, if any. */
  ushort pending_type;
  ushort pending_sz;
  int    pending_valid;
  ulong  pending_boot_id;
  uchar  pending_junk[32];
  uchar  pending[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];

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
  ulong                 bus_req_sig;   /* FD_FAILOVER_BUS_CONTROL_REQ or STATUS_REQ */
  int                   bus_req_fresh;

  /* State of the identity switch we asked the admin tile for.  It
     selects a key preloaded by the signing tile by its public key, and
     success means the old key is gone from every tile's active identity. */
  ulong                     switch_request_id;
  ulong                     switch_pending_key;  /* FD_FAILOVER_SWITCH_KEY_*, or CNT when idle */
  fd_failover_switch_resp_t switch_result;
  fd_failover_switch_resp_t switch_response;     /* uncommitted input frame */
  ulong                     switch_answer_nonce; /* nonce of the frame being consumed */
  ulong                     switch_result_id;
  int                       switch_result_fresh;
  int                       switch_overdue;      /* the switch in flight passed its deadline, we still wait for it */

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

  /* tower_out, polled unreliably */
  ulong       tower_in_idx;
  fd_wksp_t * tower_in_mem;
  ulong       tower_in_chunk0;
  ulong       tower_in_wmark;

  fd_tower_slot_done_t slot_done;
  int                  slot_done_fresh;
  ulong                tower_seen_seq; /* seq of the last tower_out frag taken in, ULONG_MAX before any */
  int                  tower_gap;      /* a tower_out frag was skipped since the cached tower was built */

  ulong replay_slot;
  ulong root_slot;
  ulong last_vote_slot;

  fd_failover_tower_t cs; /* tower of our latest vote */

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

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_failover_tile_ctx_t * ctx         = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_failover_tile_ctx_t), sizeof(fd_failover_tile_ctx_t)  );
  void *                   channel_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_failover_channel_align(),     fd_failover_channel_footprint() );
  fd_memset( ctx, 0, sizeof(fd_failover_tile_ctx_t) );
  ctx->switch_pending_key = FD_FAILOVER_SWITCH_KEY_CNT;
  ctx->deadline_slot      = FD_FAILOVER_SLOT_NULL;
  ctx->peer_floor         = FD_FAILOVER_SLOT_NULL;
  ctx->own_floor          = FD_FAILOVER_SLOT_NULL;
  ctx->replay_slot        = FD_FAILOVER_SLOT_NULL;
  ctx->root_slot          = FD_FAILOVER_SLOT_NULL;
  ctx->last_vote_slot     = FD_FAILOVER_SLOT_NULL;
  ctx->tower_seen_seq     = ULONG_MAX;
  FD_TEST( fd_rng_secure( &ctx->handoff_base, sizeof(ulong) ) );

  /* [failover.junk_identity_key] is this machine's junk key, the keypair
     goes into HELLO and TLS.  We read only the public half of the staked
     [paths.identity_key]. */
  uchar const * junk_keypair  = fd_keyload_load( tile->failov.identity_key_path, 0 );
  uchar const * staked_pubkey = fd_keyload_load( tile->failov.staked_key_path,   1 ); /* public key only, like the other tiles' identity loads */
  fd_memcpy( ctx->hello.junk_pubkey,   junk_keypair+32UL, 32UL );
  fd_memcpy( ctx->hello.staked_pubkey, staked_pubkey,     32UL );
  fd_keyload_unload( staked_pubkey, 1 );

  if( FD_UNLIKELY( fd_memeq( ctx->hello.junk_pubkey, ctx->hello.staked_pubkey, 32UL ) ) ) {
    FD_LOG_ERR(( "[failover.junk_identity_key] `%s` is the staked [paths.identity_key], each failover machine boots under its own key", tile->failov.identity_key_path ));
  }

  /* The vote key is a base58 pubkey or a keypair file, same as in the
     tower tile. */
  if( FD_UNLIKELY( !fd_base58_decode_32( tile->failov.vote_account_path, ctx->hello.vote_account ) ) ) {
    if( FD_UNLIKELY( !strcmp( tile->failov.vote_account_path, "" ) ) ) FD_LOG_ERR(( "missing [paths.vote_account]" ));
    uchar const * vote_account = fd_keyload_load( tile->failov.vote_account_path, 1 );
    fd_memcpy( ctx->hello.vote_account, vote_account, 32UL );
    fd_keyload_unload( vote_account, 1 );
  }

  /* Every boot runs the junk key, so we start as a standby. */
  ctx->role          = FD_FAILOVER_ROLE_STANDBY;
  ctx->hello.version = (ushort)FD_FAILOVER_VERSION;
  ctx->hello.role    = (uchar)ctx->role;
  ctx->hello.mode    = (uchar)FD_FAILOVER_MODE_TOWER;
  while( FD_UNLIKELY( !ctx->hello.boot_id ) ) FD_TEST( fd_rng_secure( &ctx->hello.boot_id, sizeof(ulong) ) );
  /* The commit field has the hash bytes, a build without one leaves it
     zero. */
  if( FD_LIKELY( strlen( fd_commit_ref_cstr )==2UL*sizeof(ctx->hello.commit) &&
                 fd_hex_decode( ctx->hello.commit, fd_commit_ref_cstr, sizeof(ctx->hello.commit) )!=sizeof(ctx->hello.commit) ) ) {
    fd_memset( ctx->hello.commit, 0, sizeof(ctx->hello.commit) );
  }
  ctx->hello.cfg_hash = fd_failover_cfg_hash( ctx->hello.staked_pubkey, ctx->hello.vote_account, ctx->hello.mode );
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
  if( FD_UNLIKELY( fd_failover_channel_set_identity( ctx->channel, junk_keypair, &ctx->hello ) ) ) {
    FD_LOG_ERR(( "failover TLS setup failed for [failover.junk_identity_key] `%s`", tile->failov.identity_key_path ));
  }
  fd_keyload_unload( junk_keypair, 0 );

  /* Every member listens on all interfaces, and the sandbox forbids
     bind.  A configured peer address is dialed for a handoff and
     keeps its room on the listener.  Without one we dial nothing until
     gossip gives us the active's address. */
  fd_failover_channel_init_listener( ctx->channel, 0U, tile->failov.port );
  if( FD_UNLIKELY( tile->failov.peer_address[ 0 ]!='\0' ) ) {
    if( FD_UNLIKELY( !fd_dns_resolve_address( tile->failov.peer_address, &ctx->config_addr ) || !ctx->config_addr ) ) {
      FD_LOG_ERR(( "could not resolve [failover.peer_address] `%s`", tile->failov.peer_address ));
    }
    if( FD_UNLIKELY( ctx->config_addr==ctx->own_gossip.addr || ctx->config_addr==tile->failov.gossip_addr.addr ) ) {
      FD_LOG_ERR(( "[failover.peer_address] `%s` is this machine's own address `" FD_IP4_ADDR_FMT "`, set it to the other failover machine",
                   tile->failov.peer_address, FD_IP4_ADDR_FMT_ARGS( ctx->config_addr ) ));
    }
    fd_failover_channel_expect_peer( ctx->channel, ctx->config_addr );
    FD_LOG_NOTICE(( "failover peer is `%s` at `" FD_IP4_ADDR_FMT "` from [failover.peer_address], we dial it for a handoff",
                    tile->failov.peer_address, FD_IP4_ADDR_FMT_ARGS( ctx->config_addr ) ));
  } else {
    FD_LOG_NOTICE(( "no [failover.peer_address], we find the active through the staked identity's contact info in gossip" ));
  }
  ctx->channel_state = fd_failover_channel_state( ctx->channel );

  char junk_b58  [ FD_BASE58_ENCODED_32_SZ ];
  char staked_b58[ FD_BASE58_ENCODED_32_SZ ];
  fd_base58_encode_32( ctx->hello.junk_pubkey,   NULL, junk_b58   );
  fd_base58_encode_32( ctx->hello.staked_pubkey, NULL, staked_b58 );
  FD_LOG_NOTICE(( "failover is on, booting as a standby under junk identity `%s` for staked identity `%s`, listening on [failover.port] `%u`, "
                  "this machine votes only after `failover promote` or a handoff", junk_b58, staked_b58, (uint)tile->failov.port ));

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
    if( FD_LIKELY( !strcmp( link->name, "gossip_out" ) ) ) {
      ctx->gossip_in_idx    = i;
      ctx->gossip_in_mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      ctx->gossip_in_chunk0 = fd_dcache_compact_chunk0( ctx->gossip_in_mem, link->dcache );
      ctx->gossip_in_wmark  = fd_dcache_compact_wmark ( ctx->gossip_in_mem, link->dcache, link->mtu );
      ctx->gossip_in_mtu    = link->mtu;
      continue;
    }
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

/* Before we pair, the sign tile signs our member certificate with the
   staked key.  It checks the message is the cert prefix and its own
   junk pubkey. */
static void
request_member_cert( fd_failover_tile_ctx_t * ctx ) {
  uchar msg [ FD_KEYGUARD_MEMBER_CERT_MSG_SZ ];
  uchar cert[ 64 ];
  fd_failover_member_cert_msg( msg, ctx->hello.junk_pubkey );
  fd_keyguard_client_sign( ctx->keyguard_client, cert, msg, sizeof(msg), FD_KEYGUARD_SIGN_TYPE_ED25519 );
  if( FD_UNLIKELY( fd_failover_channel_set_member_cert( ctx->channel, cert ) ) ) {
    FD_LOG_ERR(( "the sign tile signed our member certificate with a key other than the staked [paths.identity_key]" ));
  }
  ctx->member_cert_set = 1;
  FD_LOG_NOTICE(( "the sign tile signed our member certificate with the staked identity, we can pair now" ));
}

/* A new connection repeats the request for the same handoff. */
static void
sync_session( fd_failover_tile_ctx_t * ctx ) {
  ulong state = fd_failover_channel_state( ctx->channel );
  ulong pairs = fd_failover_channel_metrics( ctx->channel )->paired_cnt;
  if( FD_LIKELY( state==ctx->channel_state && pairs==ctx->channel_pair_cnt ) ) return;
  ctx->channel_state = state;
  ctx->channel_pair_cnt = pairs;
  ctx->request_sent  = 0;
  if( state!=FD_FAILOVER_SESSION_PAIRED ) ctx->close_after_send = 0;
  if( FD_UNLIKELY( state==FD_FAILOVER_SESSION_PAIRED ) ) {
    fd_failover_hello_t const * peer = fd_failover_channel_peer_hello( ctx->channel );
    ctx->peer_boot_id = peer->boot_id;
    ctx->peer_role = peer->role;
    ctx->demoted_sent = 0;
    if( FD_UNLIKELY( ( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY ||
                       ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT ) &&
                     peer->role==(uchar)FD_FAILOVER_ROLE_ACTIVE ) ) ctx->promote_active_seen = 1;
  }
}

static void
set_role( fd_failover_tile_ctx_t * ctx,
          ulong                    role ) {
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
  if( FD_UNLIKELY( ctx->promote_source==FD_FAILOVER_SOURCE_VOTE_ACCOUNT &&
                   ctx->promote_floor!=FD_FAILOVER_SLOT_NULL &&
                   ctx->deadline_slot!=FD_FAILOVER_SLOT_NULL ) ) {
    ctx->deadline_slot = fd_ulong_max( ctx->deadline_slot,
                                       fd_ulong_sat_add( ctx->promote_floor, FD_FAILOVER_FLOOR_SLACK_SLOTS+FD_FAILOVER_DEADLINE_SLOTS ) );
  }
  if( FD_UNLIKELY( !ctx->promote_until ) ) {
    ulong slots = FD_FAILOVER_DEADLINE_SLOTS;
    if( FD_UNLIKELY( ctx->promote_source==FD_FAILOVER_SOURCE_VOTE_ACCOUNT &&
                     ctx->promote_floor!=FD_FAILOVER_SLOT_NULL ) ) slots += FD_FAILOVER_FLOOR_SLACK_SLOTS;
    ctx->promote_until = fd_long_sat_add( now, (long)slots*FD_FAILOVER_DEADLINE_SLOT_NANOS );
  }
}

/* A promotion wait ends at the slot deadline or on our clock, a replay
   that froze never reaches the slot deadline. */
static int
promote_expired( fd_failover_tile_ctx_t const * ctx,
                 long                           now ) {
  if( FD_LIKELY( now<ctx->promote_until ) ) return deadline_expired( ctx );
  FD_LOG_WARNING(( "%s: the promotion ran out of time with replay at slot %lu, replay may be stuck, check it before another `failover promote`", ctx->promote_label, ctx->replay_slot ));
  return 1;
}

/* A switch in flight is never abandoned, its outcome is unknown until the
   admin tile answers.  We warn once and flag stuck. */
static void
switch_overdue( fd_failover_tile_ctx_t * ctx ) {
  ctx->stuck = 1;
  if( FD_LIKELY( ctx->switch_overdue ) ) return;
  ctx->switch_overdue = 1;
  char demotion[48];
  fd_cstr_printf( demotion, sizeof(demotion), NULL, "demotion %lu", ctx->handoff_id );
  FD_LOG_WARNING(( "%s: identity switch %lu to %s is overdue; its outcome is unknown, we keep waiting and refuse another switch; check the admin and sign tile logs",
                   ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_STAKED ? ctx->promote_label : demotion,
                   ctx->switch_request_id, ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_STAKED ? "staked" : "junk" ));
}

/* Only one control message can be outstanding at a time.  Its recipient
   is fixed even if the connection changes before it is sent. */
static int
queue_control( fd_failover_tile_ctx_t * ctx,
               ushort                   type,
               void const *             payload,
               ulong                    payload_sz ) {
  if( FD_UNLIKELY( ctx->pending_valid || !payload_sz || payload_sz>sizeof(ctx->pending) ) ) return -1;
  ctx->pending_type  = type;
  ctx->pending_sz    = (ushort)payload_sz;
  ctx->pending_valid = 1;
  fd_failover_hello_t const * peer = fd_failover_channel_peer_hello( ctx->channel );
  ctx->pending_boot_id = peer->boot_id;
  fd_memcpy( ctx->pending_junk, peer->junk_pubkey, 32UL );
  if( type==FD_FAILOVER_MSG_DEMOTED ) {
    ctx->pending_boot_id = ctx->handoff_target;
    fd_memcpy( ctx->pending_junk, ctx->handoff_junk, 32UL );
  } else if( type==FD_FAILOVER_MSG_PROMOTE_ACK || type==FD_FAILOVER_MSG_PROMOTE_REJECTED ) {
    ctx->pending_boot_id = ctx->reply_boot_id;
    fd_memcpy( ctx->pending_junk, ctx->reply_junk, 32UL );
  }
  fd_memcpy( ctx->pending, payload, payload_sz );
  return 0;
}

/* queue_reply queues our last answer to a DEMOTED.  If the control slot
   is busy the answer stays owed and step_controller tries again once
   the slot drains, the peer waits on it and sends its DEMOTED only once
   per session, so nothing else would ask for it. */
static void
queue_reply( fd_failover_tile_ctx_t * ctx ) {
  uchar payload[ sizeof(fd_failover_promote_rejected_t) ];
  ulong payload_sz = ctx->reply_type==(ushort)FD_FAILOVER_MSG_PROMOTE_ACK
                   ? fd_failover_promote_ack_encode( payload, ctx->reply_handoff_id )
                   : fd_failover_promote_rejected_encode( payload, ctx->reply_handoff_id, ctx->reply_reason );
  ctx->reply_owed = !!queue_control( ctx, ctx->reply_type, payload, payload_sz );
}

/* Remembers our answer to the DEMOTED with handoff_id from peer boot
   boot_id, then queues it. */
static void
finish_reply( fd_failover_tile_ctx_t * ctx,
              ulong                    boot_id,
              ulong                    handoff_id,
              ushort                   type,
              uchar                    reason ) {
  if( !ctx->reply_valid || ctx->reply_boot_id!=boot_id || ctx->reply_handoff_id!=handoff_id || ctx->reply_type!=type )
    fd_memset( &ctx->reply_tx_log, 0, sizeof(ctx->reply_tx_log) );
  ctx->reply_valid      = 1;
  ctx->reply_boot_id    = boot_id;
  ctx->reply_handoff_id = handoff_id;
  ctx->reply_type       = type;
  ctx->reply_reason     = reason;
  fd_memcpy( ctx->reply_junk, ctx->request_junk, 32UL );
  queue_reply( ctx );
}

static void
pending_flush( fd_failover_tile_ctx_t * ctx,
               long                     now ) {
  if( FD_LIKELY( !ctx->pending_valid ) ) return;
  if( FD_UNLIKELY( fd_failover_channel_state( ctx->channel )!=FD_FAILOVER_SESSION_PAIRED ||
                   fd_failover_channel_tx_pending( ctx->channel ) ) ) return;
  /* A resumed handoff still belongs to the same member and boot. */
  if( FD_UNLIKELY( ctx->peer_boot_id!=ctx->pending_boot_id ||
                   !fd_memeq( fd_failover_channel_peer_hello( ctx->channel )->junk_pubkey, ctx->pending_junk, 32UL ) ) ) return;
  if( FD_LIKELY( !fd_failover_channel_send( ctx->channel, now, ctx->pending_type, ctx->pending, ctx->pending_sz ) ) ) {
    if( FD_UNLIKELY( ctx->pending_type==(ushort)FD_FAILOVER_MSG_DEMOTED ) ) {
      ctx->demoted_sent = 1;
      ulong suppressed;
      if( fd_failover_log_take( &ctx->demoted_tx_log, now, &suppressed ) )
        FD_LOG_NOTICE(( "handoff %lu: sent final state (DEMOTED) to peer boot %016lx, last vote slot %lu; we remain standby waiting for its answer (send %lu, %lu repeats suppressed)",
                        ctx->handoff_id, ctx->handoff_target, ctx->last_vote_slot, ctx->demoted_tx_log.count, suppressed ));
    }
    if( ctx->pending_type==FD_FAILOVER_MSG_PROMOTE_ACK || ctx->pending_type==FD_FAILOVER_MSG_PROMOTE_REJECTED ) {
      ulong suppressed;
      if( fd_failover_log_take( &ctx->reply_tx_log, now, &suppressed ) )
        FD_LOG_NOTICE(( "handoff %lu: sent %s to peer boot %016lx; %s, waiting for its final confirmation (send %lu, %lu repeats suppressed)",
                        ctx->reply_handoff_id, ctx->pending_type==FD_FAILOVER_MSG_PROMOTE_ACK ? "ACK" : "refusal",
                        ctx->reply_boot_id, ctx->role==FD_FAILOVER_ROLE_ACTIVE ? "we hold the staked identity" : "we remain standby",
                        ctx->reply_tx_log.count, suppressed ));
    } else if( ctx->pending_type==FD_FAILOVER_MSG_HANDOFF_RESULT ) {
      fd_failover_handoff_result_t result;
      fd_memcpy( &result, ctx->pending, sizeof(result) );
      ulong suppressed;
      if( fd_failover_log_take( &ctx->result_tx_log, now, &suppressed ) )
        FD_LOG_NOTICE(( "handoff %lu: sent %s confirmation to peer boot %016lx; %s (send %lu, %lu repeats suppressed)",
                        result.handoff_id, result.result==FD_ADMINCTL_RESULT_SUCCESS ? "success" : "refusal", ctx->pending_boot_id,
                        FD_FAILOVER_ON_DEMAND ? "closing connection after queued bytes drain" : "persistent connection retained for status and snapshots",
                        ctx->result_tx_log.count, suppressed ));
    }
    ctx->pending_valid = 0;
  }
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

  /* Encode aside so a failed encode leaves the previous tower whole. */
  uchar state[ FD_FAILOVER_TOWER_STATE_MAX ];
  ulong state_sz = 0UL;
  if( FD_UNLIKELY( fd_compact_tower_sync_ser( &serde, state, sizeof(state), &state_sz ) ) ) {
    FD_LOG_WARNING(( "tower vote transaction exceeds the failover state limit" ));
    return;
  }

  fd_memcpy( ctx->cs.state, state, state_sz );
  ctx->cs.valid  = 1;
  ctx->cs.tip    = done->vote_slot;
  ctx->cs.sz     = state_sz;
  ctx->tower_gap = 0; /* anything skipped before this vote is superseded by it */
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
    if( FD_LIKELY( ctx->role==FD_FAILOVER_ROLE_ACTIVE || ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH ) ) {
      /* Any later promotion has to cover the votes we signed. */
      if( FD_LIKELY( ctx->own_floor==FD_FAILOVER_SLOT_NULL || done->vote_slot>ctx->own_floor ) ) ctx->own_floor = done->vote_slot;
      prepare_consensus( ctx, done );
    }
  }
}

/* Sends the tower we adopt to the tower tile, empty for the vote
   account.  The answer comes back with the request id so we can tell a
   late one apart.  Returns the id, or ULONG_MAX if nothing went out. */
static ulong
publish_adopt_state( fd_failover_tile_ctx_t * ctx,
                     fd_stem_context_t *      stem ) {
  if( FD_UNLIKELY( ctx->adopt_out_idx==ULONG_MAX ||
                   ( !ctx->adopt.sz && ctx->promote_source!=FD_FAILOVER_SOURCE_VOTE_ACCOUNT ) ) ) return ULONG_MAX;

  if( FD_UNLIKELY( !++ctx->adopt_request_id ) ) ctx->adopt_request_id++;
  fd_memcpy( fd_chunk_to_laddr( ctx->adopt_out_mem, ctx->adopt_out_chunk ), ctx->adopt.state, ctx->adopt.sz );
  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, ctx->adopt_out_idx, ctx->adopt_request_id, ctx->adopt_out_chunk, ctx->adopt.sz, 0UL, tspub, tspub );
  ctx->adopt_out_chunk    = fd_dcache_compact_next( ctx->adopt_out_chunk, ctx->adopt.sz, ctx->adopt_out_chunk0, ctx->adopt_out_wmark );
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
  if( FD_UNLIKELY( ctx->admin_out_idx==ULONG_MAX || ctx->switch_pending_key!=FD_FAILOVER_SWITCH_KEY_CNT ) ) return ULONG_MAX;

  if( FD_UNLIKELY( !++ctx->switch_request_id ) ) ctx->switch_request_id++;
  fd_failover_bus_msg_t * out = fd_chunk_to_laddr( ctx->admin_out_mem, ctx->admin_out_chunk );
  fd_memset( out, 0, sizeof(*out) );
  out->nonce = ctx->switch_request_id;
  fd_failover_switch_req_t req;
  fd_memcpy( req.identity, key==FD_FAILOVER_SWITCH_KEY_STAKED ? ctx->hello.staked_pubkey : ctx->hello.junk_pubkey, 32UL );
  fd_memcpy( out->payload, &req, sizeof(req) );
  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, ctx->admin_out_idx, FD_FAILOVER_BUS_SWITCH_REQ, ctx->admin_out_chunk, sizeof(*out), 0UL, tspub, tspub );
  ctx->admin_out_chunk     = fd_dcache_compact_next( ctx->admin_out_chunk, sizeof(*out), ctx->admin_out_chunk0, ctx->admin_out_wmark );
  ctx->switch_pending_key  = key;
  ctx->switch_result_fresh = 0;
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

/* Our DEMOTED got its answer or cannot get one any more. */
static void
handoff_resolved( fd_failover_tile_ctx_t * ctx,
                  ulong                    result ) {
  if( FD_UNLIKELY( ctx->pending_valid && ctx->pending_type==(ushort)FD_FAILOVER_MSG_DEMOTED ) ) ctx->pending_valid = 0;
  if( FD_LIKELY( ctx->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK ) ) ctx->action = FD_FAILOVER_ACTION_IDLE;
  ctx->send_demoted   = 0;
  ctx->handoff_result = result;
}

/* A demotion that ends without sending anything.  Nobody can promote
   on it. */
static void
demotion_abort( fd_failover_tile_ctx_t * ctx ) {
  ctx->action       = FD_FAILOVER_ACTION_IDLE;
  ctx->stuck        = 1;
  ctx->send_demoted = 0;
}

/* Give up the staked identity.  The switch itself is asked for from
   step_controller, after the command's answer went out.  A handoff
   sends DEMOTED to the peer boot we see now, a demote sends nothing. */
static void
start_demotion( fd_failover_tile_ctx_t * ctx,
                int                      handoff ) {
  int send = handoff && fd_failover_channel_state( ctx->channel )==FD_FAILOVER_SESSION_PAIRED;
  ctx->handoff_id     = ctx->handoff_base+(++ctx->handoff_cnt);
  ctx->handoff_target = send ? ctx->peer_boot_id : 0UL;
  if( send ) fd_memcpy( ctx->handoff_junk, fd_failover_channel_peer_hello( ctx->channel )->junk_pubkey, 32UL );
  ctx->handoff_result = FD_FAILOVER_HANDOFF_NONE; /* until its DEMOTED goes out */
  ctx->last_requested = 0;
  ctx->send_demoted   = send;
  ctx->demoted_sent   = 0;
  ctx->drain_logged   = 0;
  fd_memset( &ctx->demoted_tx_log, 0, sizeof(ctx->demoted_tx_log) );
  fd_memset( &ctx->result_tx_log, 0, sizeof(ctx->result_tx_log) );
  ctx->stuck          = 0;
  if( FD_UNLIKELY( !send ) ) FD_LOG_NOTICE(( "demotion %lu started without a handoff, giving up the staked identity, no DEMOTED will be sent", ctx->handoff_id ));
  deadline_start( ctx, FD_FAILOVER_DEADLINE_SLOTS );
  ctx->action = FD_FAILOVER_ACTION_DEMOTE_SWITCH;
  ctx->demote_until = fd_long_sat_add( fd_failover_clock(), FD_FAILOVER_CHANNEL_IDLE_NANOS );
}

/* The final tower has to be the tower of our last vote, with no tower
   frag skipped since it was built. */
static int
final_tower_ok( fd_failover_tile_ctx_t const * ctx ) {
  return ctx->cs.valid && ctx->cs.sz &&
         ctx->last_vote_slot!=FD_FAILOVER_SLOT_NULL &&
         ctx->cs.tip==ctx->last_vote_slot && !ctx->tower_gap;
}

/* Called once the junk key is installed everywhere.  Our latest tower is
   the final one, we keep it for a later promote, and a handoff hands it
   to the peer. */
static void
demotion_switched( fd_failover_tile_ctx_t * ctx ) {
  set_role( ctx, FD_FAILOVER_ROLE_STANDBY );
  FD_LOG_NOTICE(( "handoff/demotion %lu: the tower drained, we are a standby now", ctx->handoff_id ));

  int final_ok = final_tower_ok( ctx );
  if( FD_LIKELY( final_ok ) ) ctx->own_tower = ctx->cs;

  if( FD_UNLIKELY( !ctx->send_demoted ) ) {
    if( FD_UNLIKELY( !final_ok ) ) {
      /* A demote without a final tower leaves no own final tower either,
         so a later promote here needs the vote account. */
      FD_LOG_WARNING(( "demotion %lu has no final tower for its last vote %lu, nobody votes until `failover promote --yes` runs on one machine", ctx->handoff_id, ctx->last_vote_slot ));
      demotion_abort( ctx );
      return;
    }
    FD_LOG_NOTICE(( "demotion %lu is done, nobody votes until `failover promote` runs here or `failover promote --yes` on the other machine", ctx->handoff_id ));
    ctx->action = FD_FAILOVER_ACTION_IDLE;
    return;
  }

  ctx->demoted_sz = final_ok
                  ? fd_failover_demoted_encode( ctx->demoted, ctx->handoff_id, ctx->handoff_target, ctx->last_vote_slot,
                                                ctx->cs.state, ctx->cs.sz )
                  : 0UL;
  if( FD_UNLIKELY( !ctx->demoted_sz ) ) {
    /* We have no final tower to hand over, or the one we have is not the
       tower of our last vote.  The peer gets nothing and cannot promote. */
    FD_LOG_WARNING(( "demotion %lu has no final tower for its last vote %lu, sending nothing, nobody votes until `failover promote --yes` runs on one machine", ctx->handoff_id, ctx->last_vote_slot ));
    demotion_abort( ctx );
    return;
  }

  ctx->handoff_result = FD_FAILOVER_HANDOFF_PENDING;
  /* The control slot may still be holding an unsent answer, so if this
     fails we retry from the wait. */
  (void)queue_control( ctx, (ushort)FD_FAILOVER_MSG_DEMOTED, ctx->demoted, ctx->demoted_sz );
  ctx->action = FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK;
  deadline_start( ctx, FD_FAILOVER_DEADLINE_SLOTS );
}

/* Names for the log, never numbers. */
static char const *
reject_name( uint reason ) {
  static char const * const names[ FD_FAILOVER_REJECT_CNT ] = {
    "none", "busy", "holds identity", "wrong target", "replay behind",
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
  default:                                 return "unknown";
  }
}

static char const *
source_name( ulong source ) {
  switch( source ) {
  case FD_FAILOVER_SOURCE_PEER:         return "the tower the peer gave us";
  case FD_FAILOVER_SOURCE_OWN:          return "our own final tower";
  case FD_FAILOVER_SOURCE_VOTE_ACCOUNT: return "the vote account";
  default:                              return "unknown";
  }
}

/* The name of a refusal and what the operator can do about it. */
static char const *
control_refusal( ulong         result,
                 char const ** hint ) {
  switch( result ) {
  case FD_FAILOVER_CONTROL_RESULT_BAD_ROLE:
    *hint = "`handoff` and `promote` run on a standby, `demote` on the active, see `failover status`";
    return "BAD_ROLE";
  case FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS:
    *hint = "a transition or key switch is running, wait for it, `failover status` shows it";
    return "IN_PROGRESS";
  case FD_FAILOVER_CONTROL_RESULT_NO_ACTIVE_ADDRESS:
    *hint = "wait for gossip to show the staked identity, or set [failover.peer_address] to the active";
    return "NO_ACTIVE_ADDRESS";
  case FD_FAILOVER_CONTROL_RESULT_NOT_PAIRED:
    *hint = "no standby is paired with us, check that it runs and reaches [failover.port] here";
    return "NOT_PAIRED";
  case FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY:
    *hint = "the peer could not finish this request, see `failover status` on the peer";
    return "PEER_UNREADY";
  case FD_FAILOVER_CONTROL_RESULT_PEER_ACTIVE:
    *hint = "the peer holds the identity or said so recently, run `failover handoff` here, or `failover promote --force` if it cannot sign";
    return "PEER_ACTIVE";
  case FD_FAILOVER_CONTROL_RESULT_HANDOFF_PENDING:
    *hint = "the peer has not answered our handoff, wait for it, or `failover promote --force` if the peer cannot sign";
    return "HANDOFF_PENDING";
  case FD_FAILOVER_CONTROL_RESULT_TAKEN:
    *hint = "the peer took our last handoff and may be voting, run `failover handoff` here, or `failover promote --force` if it cannot sign";
    return "TAKEN";
  case FD_FAILOVER_CONTROL_RESULT_STAKED_SEEN:
    *hint = "gossip showed the staked identity at another host within 15 seconds, stop it or wait, or `failover promote --force` if it cannot sign";
    return "STAKED_SEEN";
  case FD_FAILOVER_CONTROL_RESULT_NO_TOWER:
    *hint = "there is no tower to adopt, `failover promote --yes` adopts the vote account";
    return "NO_TOWER";
  case FD_FAILOVER_CONTROL_RESULT_NO_FINAL_TOWER:
    *hint = "the tower of our last vote is not known yet, retry after the next vote";
    return "NO_FINAL_TOWER";
  default:
    *hint = "the failover tile does not know this command";
    return "UNSUPPORTED";
  }
}

/* Stand back down.  If the peer's DEMOTED asked for the promotion we
   tell it why.  A tower the tower tile found invalid or mismatched is
   not kept for another try. */
static void
reject_promotion( fd_failover_tile_ctx_t * ctx,
                  uchar                    reason,
                  int                      bad_tower ) {
  if( FD_UNLIKELY( bad_tower && ctx->promote_source==FD_FAILOVER_SOURCE_PEER ) ) ctx->peer_tower.valid = 0;
  ctx->stuck  = 1;
  ctx->action = FD_FAILOVER_ACTION_IDLE;
  if( FD_UNLIKELY( !ctx->promote_peer ) ) {
    FD_LOG_WARNING(( "%s: promotion failed (%s), we stay a standby, check that one machine votes and see `failover status` before another `failover promote`", ctx->promote_label, reject_name( reason ) ));
    return;
  }
  ctx->promote_peer = 0;
  ctx->action = FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT;
  ctx->request_until = fd_long_sat_add( fd_failover_clock(), FD_FAILOVER_CHANNEL_IDLE_NANOS );
  FD_LOG_WARNING(( "refusing the peer's handoff %lu (%s), we stay a standby; check `failover status` on both machines before recovery", ctx->promote_handoff_id, reject_name( reason ) ));
  finish_reply( ctx, ctx->promote_boot_id, ctx->promote_handoff_id, (ushort)FD_FAILOVER_MSG_PROMOTE_REJECTED, reason );
}

/* The floor joins the final votes handed to us and our own signed votes. */
static ulong
coverage_floor( fd_failover_tile_ctx_t const * ctx ) {
  if( FD_UNLIKELY( ctx->peer_floor==FD_FAILOVER_SLOT_NULL ) ) return ctx->own_floor;
  if( FD_UNLIKELY( ctx->own_floor ==FD_FAILOVER_SLOT_NULL ) ) return ctx->peer_floor;
  return fd_ulong_max( ctx->peer_floor, ctx->own_floor );
}

/* Take the staked identity with the tower from source.  from_peer is set
   when the peer's DEMOTED asked for it, the caller set promote_boot_id
   and promote_handoff_id for the answer. */
static void
start_promotion( fd_failover_tile_ctx_t * ctx,
                 ulong                    source,
                 int                      from_peer ) {
  fd_failover_tower_t const * tower = source==FD_FAILOVER_SOURCE_PEER ? &ctx->peer_tower :
                                      source==FD_FAILOVER_SOURCE_OWN  ? &ctx->own_tower  : NULL;
  if( FD_LIKELY( tower ) ) {
    ctx->adopt = *tower;
  } else {
    ctx->adopt.valid = 0;
    ctx->adopt.tip   = FD_FAILOVER_SLOT_NULL;
    ctx->adopt.sz    = 0UL;
  }
  if( from_peer ) fd_cstr_printf( ctx->promote_label, sizeof(ctx->promote_label), NULL, "handoff %lu", ctx->promote_handoff_id );
  else            fd_cstr_printf( ctx->promote_label, sizeof(ctx->promote_label), NULL, "operator promotion" );
  ctx->promote_source = source;
  ctx->promote_peer   = from_peer;
  ctx->promote_floor  = coverage_floor( ctx );
  ctx->promote_force  = 0;
  ctx->promote_until  = 0L; /* armed by the first wait */
  /* What we knew of another holder at the start, promote_holder_seen
     looks for anything newer. */
  ctx->promote_staked_at = ctx->staked_seen_at;
  ctx->promote_active_seen = 0;
  /* Until this tenure votes, its final tower is exactly the adopted one,
     never a tower cached from an earlier tenure. */
  ctx->cs             = ctx->adopt;
  ctx->tower_gap      = 0;
  ctx->last_vote_slot = ctx->adopt.tip;
  ctx->adopt_retry    = 0;
  ctx->floor_acct     = FD_FAILOVER_SLOT_NULL;
  ctx->floor_logged   = 0;
  ctx->retry_logged   = 0;
  ctx->stuck          = 0;
  deadline_start( ctx, FD_FAILOVER_DEADLINE_SLOTS );
  ctx->action = FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY;
  if( FD_UNLIKELY( ctx->adopt.tip!=FD_FAILOVER_SLOT_NULL &&
                   ( ctx->replay_slot==FD_FAILOVER_SLOT_NULL || ctx->replay_slot<ctx->adopt.tip ) ) ) {
    FD_LOG_NOTICE(( "%s: the promotion waits for replay to reach slot %lu before it adopts %s", ctx->promote_label, ctx->adopt.tip, source_name( source ) ));
  }
}

/* Coverage floor.  The peer reported or we signed votes up to the
   floor, an adopted tower short of them could vote against their
   lockouts.  For the vote account its own last vote counts, votes our
   root already passed are on the chain we replayed.  The vote account
   may also go ahead once replay passed the floor by the slack.  With no
   floor known we go ahead, like an upstream restart. */
static int
floor_covered( fd_failover_tile_ctx_t const * ctx ) {
  ulong floor = ctx->promote_floor;
  ulong tip   = ctx->promote_source==FD_FAILOVER_SOURCE_VOTE_ACCOUNT ? ctx->adopt_result.acct_vote_slot
                                                                     : ctx->adopt_result.vote_slot;
  if( FD_LIKELY( floor==FD_FAILOVER_SLOT_NULL ) ) return 1;
  if( FD_LIKELY( tip!=FD_FAILOVER_SLOT_NULL && tip>=floor ) ) return 1;
  return ctx->promote_source==FD_FAILOVER_SOURCE_VOTE_ACCOUNT &&
         ctx->replay_slot!=FD_FAILOVER_SLOT_NULL &&
         ctx->replay_slot>fd_ulong_sat_add( floor, FD_FAILOVER_FLOOR_SLACK_SLOTS );
}

/* The bound DEMOTED supersedes that session's initial ACTIVE HELLO.
   A later ACTIVE authentication is new evidence, retained if the
   connection drops.  An operator promote also watches gossip. */
static int
promote_holder_seen( fd_failover_tile_ctx_t const * ctx ) {
  if( FD_UNLIKELY( ctx->promote_force ) ) return 0;
  if( FD_UNLIKELY( ctx->promote_active_seen ) ) return 1;
  if( FD_UNLIKELY( ctx->promote_peer ) ) return 0;
  return ctx->staked_seen_at!=ctx->promote_staked_at;
}

/* Move the current transition along.  Each step waits on one thing, the
   admin tile, the tower tile, replay reaching a slot, or the peer.  If a
   step misses its deadline we stand down, except that a key switch in
   flight is always waited for. */
static void
step_controller( fd_failover_tile_ctx_t * ctx,
                 fd_stem_context_t *      stem ) {
  /* An answer that could not be queued while another control message
     held the slot is still owed to the peer, send it once the slot is
     free. */
  if( FD_UNLIKELY( ctx->reply_owed && !ctx->pending_valid ) ) queue_reply( ctx );
  if( FD_LIKELY( ctx->action==FD_FAILOVER_ACTION_IDLE ) ) return;

  switch( ctx->action ) {

  case FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER:
  case FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT:
    return;

  case FD_FAILOVER_ACTION_DEMOTE_SWITCH: {
    deadline_arm( ctx, FD_FAILOVER_DEADLINE_SLOTS );
    int expired = deadline_expired( ctx ) || ( ctx->demote_until && fd_failover_clock()>=ctx->demote_until );
    if( FD_UNLIKELY( ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_CNT && !ctx->switch_result_fresh ) ) {
      if( FD_UNLIKELY( request_switch( ctx, stem, FD_FAILOVER_SWITCH_KEY_JUNK )==ULONG_MAX ) ) {
        /* The request never went out and we still have the identity, so
           nothing is owed to the peer. */
        FD_LOG_WARNING(( "an identity switch could not be requested, remaining the active" ));
        demotion_abort( ctx );
        return;
      }
      FD_LOG_NOTICE(( "handoff/demotion %lu: asked the admin tile to install the junk identity", ctx->handoff_id ));
      return;
    }
    if( FD_LIKELY( !ctx->switch_result_fresh ) ) {
      /* No answer yet.  We do not know whether the junk key got installed,
         so we claim nothing and keep waiting, the late answer still counts.
         Past the deadline we raise stuck for the operator. */
      if( FD_UNLIKELY( expired ) ) switch_overdue( ctx );
      return;
    }
    if( FD_UNLIKELY( ctx->switch_result.result!=FD_FAILOVER_SWITCH_OK ) ) {
      /* The switch failed and we still have the identity, so we send
         nothing. */
      ctx->switch_result_fresh = 0;
      ctx->switch_overdue      = 0;
      FD_LOG_WARNING(( "the identity switch for demotion %lu failed (%s), we keep the staked identity and stay the active", ctx->handoff_id,
                       ctx->switch_result.result==FD_FAILOVER_SWITCH_ERR_DISABLED ? "failover disabled" : "unknown" ));
      demotion_abort( ctx );
      return;
    }
    /* The watermark is the tower tile's output sequence when it stopped
       signing.  Every frag it published before that is consumed before the
       final tower is taken from the cache, or the last vote it signed could
       be missing from DEMOTED.  Same link, same counter, so the wait is
       exact. */
    if( FD_UNLIKELY( !ctx->drain_logged ) ) {
      FD_LOG_NOTICE(( "handoff/demotion %lu: the junk identity is installed, waiting for the tower to drain up to seq %lu", ctx->handoff_id, ctx->switch_result.tower_watermark ));
      ctx->drain_logged = 1;
    }
    if( FD_UNLIKELY( !fd_seq_ge( fd_seq_inc( ctx->tower_seen_seq, 1UL ), ctx->switch_result.tower_watermark ) ) ) {
      if( FD_UNLIKELY( expired ) ) {
        /* The identity is gone from here, so we stand by and send
           nothing, nobody can promote on it. */
        FD_LOG_WARNING(( "the tower stream never reached the watermark %lu, demotion %lu sends nothing, nobody votes until `failover promote --yes` runs on one machine", ctx->switch_result.tower_watermark, ctx->handoff_id ));
        ctx->switch_result_fresh = 0;
        ctx->switch_overdue      = 0;
        set_role( ctx, FD_FAILOVER_ROLE_STANDBY );
        demotion_abort( ctx );
      }
      return;
    }
    ctx->switch_result_fresh = 0;
    ctx->switch_overdue      = 0;
    demotion_switched( ctx );
    return;
  }

  case FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK: {
    /* If the peer goes quiet we do not undo the demotion, we only raise
       the alarm.  The identity is already gone from this machine. */
    deadline_arm( ctx, FD_FAILOVER_DEADLINE_SLOTS );
    /* A new peer boot came back on its junk key, it never took the
       identity from this DEMOTED. */
    if( FD_UNLIKELY( fd_failover_channel_state( ctx->channel )==FD_FAILOVER_SESSION_PAIRED &&
                     fd_memeq( fd_failover_channel_peer_hello( ctx->channel )->junk_pubkey, ctx->handoff_junk, 32UL ) &&
                     ctx->peer_boot_id!=ctx->handoff_target ) ) {
      FD_LOG_WARNING(( "the peer restarted before it answered handoff %lu; it may have voted before restarting, nobody votes until `failover promote` runs here", ctx->handoff_id ));
      handoff_resolved( ctx, FD_FAILOVER_HANDOFF_RESTARTED );
      return;
    }
    /* A reconnect from the same member can finish its handoff. */
    if( FD_UNLIKELY( ctx->send_demoted && !ctx->demoted_sent && !ctx->pending_valid ) ) {
      (void)queue_control( ctx, (ushort)FD_FAILOVER_MSG_DEMOTED, ctx->demoted, ctx->demoted_sz );
    }
    if( FD_UNLIKELY( deadline_expired( ctx ) || ( ctx->demote_until && fd_failover_clock()>=ctx->demote_until ) ) ) {
      if( FD_UNLIKELY( !ctx->stuck ) )
        FD_LOG_WARNING(( "the peer has not answered handoff %lu; we remain standby and will resend final state when it reconnects; check `failover status` and the log on the peer", ctx->handoff_id ));
      ctx->stuck = 1;
    }
    return;
  }

  case FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY: {
    long now = fd_failover_clock();
    promote_deadline_arm( ctx, now );
    if( FD_UNLIKELY( promote_expired( ctx, now ) ) ) {
      reject_promotion( ctx, FD_FAILOVER_REJECT_REPLAY_BEHIND, 0 );
      return;
    }
    /* Wait for replay to reach the tower's tip before adopting, otherwise
       the tower refers to blocks we have not seen yet. */
    if( FD_UNLIKELY( ctx->replay_slot==FD_FAILOVER_SLOT_NULL ||
                     ( ctx->adopt.tip!=FD_FAILOVER_SLOT_NULL && ctx->replay_slot<ctx->adopt.tip ) ) ) return;
    ulong id = publish_adopt_state( ctx, stem );
    if( FD_UNLIKELY( id==ULONG_MAX ) ) {
      reject_promotion( ctx, FD_FAILOVER_REJECT_ADOPTION_FAILED, 0 );
      return;
    }
    FD_LOG_NOTICE(( "%s: asking the tower tile to adopt %s", ctx->promote_label, source_name( ctx->promote_source ) ));
    ctx->adopt_expected_id = id;
    ctx->adopt_retry       = 0;
    ctx->action            = FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT;
    return;
  }

  case FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT: {
    long now = fd_failover_clock();
    promote_deadline_arm( ctx, now );
    if( FD_UNLIKELY( promote_expired( ctx, now ) ) ) {
      reject_promotion( ctx, FD_FAILOVER_REJECT_ADOPTION_FAILED, 0 );
      return;
    }
    if( FD_UNLIKELY( ctx->adopt_retry ) ) {
      /* The tower tile has not replayed every block the tower votes on, or
         the adopted tip is short of the floor.  Ask again once replay
         passes adopt_retry_slot, the deadline above bounds the wait. */
      if( FD_LIKELY( ctx->replay_slot<=ctx->adopt_retry_slot ) ) return;
      ulong id = publish_adopt_state( ctx, stem );
      if( FD_UNLIKELY( id==ULONG_MAX ) ) {
        reject_promotion( ctx, FD_FAILOVER_REJECT_ADOPTION_FAILED, 0 );
        return;
      }
      ctx->adopt_expected_id = id;
      ctx->adopt_retry       = 0;
      return;
    }
    if( FD_LIKELY( !ctx->adopt_result_fresh ) ) return;
    ctx->adopt_result_fresh = 0;
    if( FD_UNLIKELY( ctx->adopt_result_id!=ctx->adopt_expected_id ) ) return;
    if( FD_UNLIKELY( ctx->adopt_result.result==FD_TOWER_ADOPT_ERR_UNREPLAYED ) ) {
      if( FD_UNLIKELY( !ctx->retry_logged ) ) {
        FD_LOG_NOTICE(( "%s: the tower tile has not replayed every block the tower votes on, asking again as replay moves", ctx->promote_label ));
        ctx->retry_logged = 1;
      }
      ctx->adopt_retry      = 1;
      ctx->adopt_retry_slot = ctx->replay_slot;
      return;
    }
    if( FD_UNLIKELY( ctx->adopt_result.result!=FD_TOWER_ADOPT_SUCCESS ) ) {
      FD_LOG_WARNING(( "%s: the tower tile refused %s (%s)", ctx->promote_label, source_name( ctx->promote_source ), adopt_err_name( ctx->adopt_result.result ) ));
      ulong result = ctx->adopt_result.result;
      reject_promotion( ctx, result==FD_TOWER_ADOPT_ERR_BLOCK_MISMATCH ? FD_FAILOVER_REJECT_ADOPTION_MISMATCH
                                                                       : FD_FAILOVER_REJECT_ADOPTION_FAILED,
                        result==FD_TOWER_ADOPT_ERR_BLOCK_MISMATCH || result==FD_TOWER_ADOPT_ERR_DECODE ||
                        result==FD_TOWER_ADOPT_ERR_INVALID );
      return;
    }
    if( FD_UNLIKELY( ctx->adopt.tip!=FD_FAILOVER_SLOT_NULL && ctx->adopt_result.vote_slot!=ctx->adopt.tip ) ) {
      /* The tower tile keeps the prefix replay has produced, so a tower
         that ends short of its last vote would leave lockouts behind.
         That is a mismatch, not a promotion. */
      FD_LOG_WARNING(( "%s: the adopted tower ends at slot %lu, the tower says %lu, replay does not have its last vote, so it is a mismatch", ctx->promote_label, ctx->adopt_result.vote_slot, ctx->adopt.tip ));
      reject_promotion( ctx, FD_FAILOVER_REJECT_ADOPTION_MISMATCH, 1 );
      return;
    }
    if( FD_UNLIKELY( !floor_covered( ctx ) ) ) {
      /* We see the account's last vote only in an answer.  While it moves
         votes are still landing, so we ask again once replay moves.  Once
         it stops, asking again only adopts the same tower, so we ask once
         replay passes the floor by the slack.  The tip of a peer or own
         tower never changes, so it is not asked for again and the
         deadline ends that wait. */
      int acct  = ctx->promote_source==FD_FAILOVER_SOURCE_VOTE_ACCOUNT;
      int moved = acct && ctx->adopt_result.acct_vote_slot!=ctx->floor_acct;
      if( FD_UNLIKELY( !ctx->floor_logged ) ) {
        if( FD_LIKELY( acct ) ) {
          if( FD_UNLIKELY( ctx->adopt_result.acct_vote_slot==FD_FAILOVER_SLOT_NULL ) ) {
            FD_LOG_NOTICE(( "%s: the vote account has no vote yet, waiting for one at or past the coverage floor at slot %lu, or for replay to pass slot %lu", ctx->promote_label,
                            ctx->promote_floor, fd_ulong_sat_add( ctx->promote_floor, FD_FAILOVER_FLOOR_SLACK_SLOTS ) ));
          } else {
            FD_LOG_NOTICE(( "%s: the vote account's last vote is slot %lu, waiting for it to reach the coverage floor at slot %lu, or for replay to pass slot %lu", ctx->promote_label,
                            ctx->adopt_result.acct_vote_slot, ctx->promote_floor, fd_ulong_sat_add( ctx->promote_floor, FD_FAILOVER_FLOOR_SLACK_SLOTS ) ));
          }
        } else {
          FD_LOG_WARNING(( "%s: %s ends at slot %lu, short of the coverage floor at slot %lu, the promotion stops at its deadline", ctx->promote_label,
                           source_name( ctx->promote_source ), ctx->adopt_result.vote_slot, ctx->promote_floor ));
        }
        ctx->floor_logged = 1;
      }
      ctx->floor_acct       = ctx->adopt_result.acct_vote_slot;
      ctx->adopt_retry      = 1;
      ctx->adopt_retry_slot = moved ? ctx->replay_slot :
                              acct  ? fd_ulong_max( ctx->replay_slot, fd_ulong_sat_add( ctx->promote_floor, FD_FAILOVER_FLOOR_SLACK_SLOTS ) ) :
                                      FD_FAILOVER_SLOT_NULL;
      return;
    }
    if( FD_UNLIKELY( promote_holder_seen( ctx ) ) ) {
      /* The identity may be held elsewhere now, so we do not install it
         too. */
      FD_LOG_WARNING(( "%s: another machine may hold the identity now, %s; "
                       "not installing the staked key, check `failover status` on both machines", ctx->promote_label,
                       ctx->promote_active_seen ? "a peer authenticated as ACTIVE during this promotion"
                                                : "gossip showed the staked identity at another host" ));
      reject_promotion( ctx, FD_FAILOVER_REJECT_HOLDS_IDENTITY, 0 );
      return;
    }
    if( FD_UNLIKELY( ctx->adopt.tip==FD_FAILOVER_SLOT_NULL ) ) ctx->last_vote_slot = ctx->adopt_result.vote_slot;
    if( FD_UNLIKELY( request_switch( ctx, stem, FD_FAILOVER_SWITCH_KEY_STAKED )==ULONG_MAX ) ) {
      reject_promotion( ctx, FD_FAILOVER_REJECT_ADOPTION_FAILED, 0 );
      return;
    }
    FD_LOG_NOTICE(( "%s: the tower tile adopted %s, asking the admin tile to install the staked identity", ctx->promote_label, source_name( ctx->promote_source ) ));
    ctx->action = FD_FAILOVER_ACTION_PROMOTE_SWITCH;
    return;
  }

  case FD_FAILOVER_ACTION_PROMOTE_SWITCH: {
    deadline_arm( ctx, FD_FAILOVER_DEADLINE_SLOTS );
    if( FD_LIKELY( !ctx->switch_result_fresh ) ) {
      /* No answer yet.  Standing down here would tell the peer nobody
         promoted while the staked key may well be installed.  So we keep
         waiting and raise stuck past the deadline, the late answer still
         counts. */
      if( FD_UNLIKELY( deadline_expired( ctx ) || ( ctx->promote_until && fd_failover_clock()>=ctx->promote_until ) ) ) switch_overdue( ctx );
      return;
    }
    ctx->switch_result_fresh = 0;
    ctx->switch_overdue      = 0;
    if( FD_UNLIKELY( ctx->switch_result.result!=FD_FAILOVER_SWITCH_OK ) ) {
      reject_promotion( ctx, FD_FAILOVER_REJECT_SWITCH_FAILED, 0 );
      return;
    }
    set_role( ctx, FD_FAILOVER_ROLE_ACTIVE );
    /* A new tenure starts, the towers we kept are older than its votes. */
    ctx->peer_tower.valid = 0;
    ctx->own_tower.valid  = 0;
    ctx->taken            = 0;
    ctx->action           = FD_FAILOVER_ACTION_IDLE;
    ctx->stuck            = 0;
    if( FD_UNLIKELY( ctx->last_vote_slot==FD_FAILOVER_SLOT_NULL ) ) {
      FD_LOG_NOTICE(( "%s: we are the active now, the staked identity is installed with the vote account's tower", ctx->promote_label ));
    } else {
      FD_LOG_NOTICE(( "%s: we are the active now, the staked identity is installed and the adopted tower ends at slot %lu", ctx->promote_label, ctx->last_vote_slot ));
    }
    if( FD_UNLIKELY( ctx->promote_peer ) ) {
      /* The ACK tells the old active its handoff is done.  We keep it as
         our answer, so the same DEMOTED again gets the ACK again. */
      ctx->promote_peer = 0;
      ctx->action = FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT;
      ctx->request_until = fd_long_sat_add( fd_failover_clock(), FD_FAILOVER_CHANNEL_IDLE_NANOS );
      finish_reply( ctx, ctx->promote_boot_id, ctx->promote_handoff_id, (ushort)FD_FAILOVER_MSG_PROMOTE_ACK, (uchar)FD_FAILOVER_REJECT_NONE );
    }
    return;
  }

  default: FD_LOG_ERR(( "unexpected failover action %lu", ctx->action ));
  }
}

static void
request_end( fd_failover_tile_ctx_t * ctx, long now, int failed );

/* A lost answer is not a cancellation.  Keep the request and its member
   binding so another handoff command resumes the same operation. */
static char const *
request_wait( fd_failover_tile_ctx_t const * ctx ) {
  switch( ctx->action ) {
  case FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER:   return "waiting for final state; the peer may still hold the identity";
  case FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY: return "replay catch-up continues locally; we remain standby";
  case FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT:  return "adoption continues locally; we remain standby";
  case FD_FAILOVER_ACTION_PROMOTE_SWITCH:     return "the staked key switch continues locally; its outcome is still unknown";
  case FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT:
    return ctx->role==FD_FAILOVER_ROLE_ACTIVE ? "we hold the staked identity; waiting for the peer to confirm our ACK"
                                               : "we remain standby; waiting for the peer to confirm our refusal";
  default: return "the local transition is retained";
  }
}

static void
request_pause( fd_failover_tile_ctx_t * ctx,
               long                     now,
               char const *             why ) {
  FD_LOG_WARNING(( "handoff %lu paused (%s): %s; dialing stopped, request ID and authenticated binding retained; check both machines with `failover status`, then repeat `failover handoff` here after local work finishes; recovery requires the peer to be fenced",
                   ctx->request_id, why, request_wait( ctx ) ));
  ctx->request_until = 0L;
  ctx->stuck         = 1;
  fd_failover_channel_init_dialer( ctx->channel, 0U, 0 );
  fd_failover_channel_hangup( ctx->channel, now );
  sync_session( ctx );
}

/* The old active confirms that it recorded the handoff answer. */
static void
handoff_result( fd_failover_tile_ctx_t * ctx,
                ulong                    id,
                ulong                    result ) {
  fd_failover_handoff_result_t answer = { .handoff_id=id, .result=result };
  if( FD_LIKELY( !queue_control( ctx, FD_FAILOVER_MSG_HANDOFF_RESULT, &answer, sizeof(answer) ) ) ) {
    ctx->close_after_send = 1;
    ctx->close_handoff_id = id;
  }
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
    if( FD_UNLIKELY( request.handoff_id==ctx->handoff_id && peer->boot_id==ctx->handoff_target &&
                     fd_memeq( peer->junk_pubkey, ctx->handoff_junk, 32UL ) ) ) {
      if( ctx->action==FD_FAILOVER_ACTION_DEMOTE_SWITCH ) return;
      if( ctx->send_demoted && ctx->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK ) {
        if( !ctx->pending_valid ) (void)queue_control( ctx, FD_FAILOVER_MSG_DEMOTED, ctx->demoted, ctx->demoted_sz );
      } else {
        handoff_result( ctx, request.handoff_id, ctx->handoff_result==FD_FAILOVER_HANDOFF_TAKEN
                                               ? FD_ADMINCTL_RESULT_SUCCESS : FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY );
      }
      return;
    }
    ulong result = FD_ADMINCTL_RESULT_SUCCESS;
    if( ctx->action!=FD_FAILOVER_ACTION_IDLE || ctx->switch_pending_key!=FD_FAILOVER_SWITCH_KEY_CNT || ctx->pending_valid || ctx->close_after_send ) result = FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS;
    else if( ctx->role!=FD_FAILOVER_ROLE_ACTIVE || peer->role!=FD_FAILOVER_ROLE_STANDBY ) result = FD_FAILOVER_CONTROL_RESULT_BAD_ROLE;
    else if( !final_tower_ok( ctx ) ) result = FD_FAILOVER_CONTROL_RESULT_NO_FINAL_TOWER;
    if( FD_UNLIKELY( result!=FD_ADMINCTL_RESULT_SUCCESS ) ) {
      handoff_result( ctx, request.handoff_id, result );
      return;
    }
    start_demotion( ctx, 1 );
    ctx->handoff_id = request.handoff_id;
    char member[ FD_BASE58_ENCODED_32_SZ ];
    fd_base58_encode_32( peer->junk_pubkey, NULL, member );
    FD_LOG_NOTICE(( "handoff %lu: accepted request from member %s boot %016lx; preparing to give up the staked identity", ctx->handoff_id, member, ctx->handoff_target ));
    return;
  }

  case (ushort)FD_FAILOVER_MSG_HANDOFF_RESULT: {
    fd_failover_handoff_result_t result;
    if( FD_UNLIKELY( !fd_failover_handoff_result_decode( &result, ctx->rx, payload_sz ) ) ) break;
    fd_failover_hello_t const * peer = fd_failover_channel_peer_hello( ctx->channel );
    if( FD_UNLIKELY( !ctx->request_id || result.handoff_id!=ctx->request_id ||
                     ctx->request_boot_id!=peer->boot_id || !fd_memeq( ctx->request_junk, peer->junk_pubkey, 32UL ) ) ) return;
    if( FD_UNLIKELY( ctx->action!=FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER &&
                     ctx->action!=FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT ) ) return;
    int failed = result.result!=FD_ADMINCTL_RESULT_SUCCESS || ctx->role!=FD_FAILOVER_ROLE_ACTIVE;
    if( failed ) {
      char const * hint;
      char const * name = control_refusal( result.result, &hint );
      FD_LOG_WARNING(( "handoff %lu ended (%s), %s", result.handoff_id, name, hint ));
    }
    request_end( ctx, now, failed );
    if( !failed )
      FD_LOG_NOTICE(( "handoff %lu complete: the old active confirmed our ACK; we hold the staked identity; %s (request sends %lu)",
                      result.handoff_id, FD_FAILOVER_ON_DEMAND ? "on-demand connection closed" : "persistent connection retained for status and snapshots", ctx->request_tx_log.count ));
    else
      FD_LOG_NOTICE(( "handoff %lu: request ended; %s; %s", result.handoff_id,
                      ctx->role==FD_FAILOVER_ROLE_ACTIVE ? "we still hold the staked identity" : "we remain standby",
                      FD_FAILOVER_ON_DEMAND ? "on-demand connection closed" : "persistent connection retained" ));
    return;
  }

  case (ushort)FD_FAILOVER_MSG_DEMOTED: {
    /* The peer says it can no longer sign and hands us its tower. */
    fd_failover_demoted_t demoted;
    if( FD_UNLIKELY( !fd_failover_demoted_decode( &demoted, ctx->rx, payload_sz ) ) ) break;
    ulong boot_id = ctx->peer_boot_id;
    fd_failover_hello_t const * peer = fd_failover_channel_peer_hello( ctx->channel );
    /* Bind before deduplication.  An unsolicited DEMOTED cannot change
       this operation or replace its cached answer. */
    if( FD_UNLIKELY( !ctx->request_id || ctx->request_id!=demoted.handoff_id ||
                     ctx->request_boot_id!=boot_id ||
                     !fd_memeq( ctx->request_junk, peer->junk_pubkey, 32UL ) ) ) return;
    if( FD_UNLIKELY( demoted.target_boot_id!=ctx->hello.boot_id ) ) break;
    /* The same DEMOTED again.  While we still work on it we say nothing,
       once we are done we repeat our answer. */
    if( FD_UNLIKELY( ctx->promote_peer && ctx->promote_boot_id==boot_id && ctx->promote_handoff_id==demoted.handoff_id ) ) return;
    if( FD_UNLIKELY( ctx->reply_valid && ctx->reply_boot_id==boot_id && ctx->reply_handoff_id==demoted.handoff_id &&
                     fd_memeq( ctx->reply_junk, peer->junk_pubkey, 32UL ) ) ) {
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
                            ctx->switch_pending_key!=FD_FAILOVER_SWITCH_KEY_CNT ) ) {
      reason = FD_FAILOVER_REJECT_BUSY;
      why    = "a transition or key switch is running here";
    }
    if( FD_UNLIKELY( reason!=FD_FAILOVER_REJECT_NONE ) ) {
      FD_LOG_WARNING(( "refusing the peer's handoff %lu (%s), %s; check `failover status` on both machines", demoted.handoff_id, reject_name( reason ), why ));
      finish_reply( ctx, boot_id, demoted.handoff_id, (ushort)FD_FAILOVER_MSG_PROMOTE_REJECTED, reason );
      return;
    }
    FD_LOG_NOTICE(( "handoff %lu: accepted the peer's final tower ending at slot %lu; waiting for local adoption before taking the identity", demoted.handoff_id, tower.tip ));
    if( ctx->peer_floor==FD_FAILOVER_SLOT_NULL || tower.tip>ctx->peer_floor ) ctx->peer_floor = tower.tip;
    ctx->peer_tower         = tower;
    ctx->promote_boot_id    = boot_id;
    ctx->promote_handoff_id = demoted.handoff_id;
    ctx->peer_role          = FD_FAILOVER_ROLE_STANDBY;
    start_promotion( ctx, FD_FAILOVER_SOURCE_PEER, 1 );
    return;
  }

  case (ushort)FD_FAILOVER_MSG_PROMOTE_ACK: {
    /* The peer took the identity, so our DEMOTED did its job.  An ACK that
       arrives after the deadline still counts.  An ACK we were not
       expecting is ignored, it is not a reason to drop the session. */
    fd_failover_promote_ack_t ack;
    if( FD_UNLIKELY( !fd_failover_promote_ack_decode( &ack, ctx->rx, payload_sz ) ) ) break;
    /* Nothing went out yet while the junk switch is in flight, so an ACK
       here answers nothing and must not end the demotion early. */
    if( FD_UNLIKELY( !ctx->send_demoted || ack.handoff_id!=ctx->handoff_id ||
                     ctx->peer_boot_id!=ctx->handoff_target ||
                     !fd_memeq( fd_failover_channel_peer_hello( ctx->channel )->junk_pubkey, ctx->handoff_junk, 32UL ) ||
                     ctx->action==FD_FAILOVER_ACTION_DEMOTE_SWITCH ) ) return;
    FD_LOG_NOTICE(( "handoff %lu: received ACK, the peer took the staked identity; recording TAKEN and staying standby", ack.handoff_id ));
    handoff_resolved( ctx, FD_FAILOVER_HANDOFF_TAKEN );
    ctx->taken         = 1;
    ctx->taken_boot_id = ctx->handoff_target;
    ctx->peer_role     = FD_FAILOVER_ROLE_ACTIVE;
    ctx->stuck         = 0;
    handoff_result( ctx, ack.handoff_id, FD_ADMINCTL_RESULT_SUCCESS );
    return;
  }

  case (ushort)FD_FAILOVER_MSG_PROMOTE_REJECTED: {
    /* Nobody promoted on our DEMOTED, that is for the operator. */
    fd_failover_promote_rejected_t rej;
    if( FD_UNLIKELY( !fd_failover_promote_rejected_decode( &rej, ctx->rx, payload_sz ) ) ) break;
    if( FD_UNLIKELY( !ctx->send_demoted || rej.handoff_id!=ctx->handoff_id ||
                     ctx->peer_boot_id!=ctx->handoff_target ||
                     !fd_memeq( fd_failover_channel_peer_hello( ctx->channel )->junk_pubkey, ctx->handoff_junk, 32UL ) ||
                     ctx->action==FD_FAILOVER_ACTION_DEMOTE_SWITCH ) ) return;
    FD_LOG_WARNING(( "the peer declined handoff %lu (%s), we stay a standby; see the peer's log and check `failover status` on both machines before recovery", rej.handoff_id, reject_name( rej.reason ) ));
    handoff_resolved( ctx, FD_FAILOVER_HANDOFF_DECLINED );
    ctx->stuck = 1;
    handoff_result( ctx, rej.handoff_id, FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY );
    return;
  }

  default: break;
  }

  fd_failover_channel_protocol_error( ctx->channel, now );
  sync_session( ctx );
}

/* Finish an answered operation or a recovery explicitly accepted by the operator. */
static void
request_end( fd_failover_tile_ctx_t * ctx,
             long                     now,
             int                      failed ) {
  FD_TEST( ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_CNT &&
           ( ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER || ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT ) );
  ctx->request_result   = failed ? FD_FAILOVER_HANDOFF_DECLINED : FD_FAILOVER_HANDOFF_TAKEN;
  ctx->request_id       = 0UL;
  ctx->request_until    = 0L;
  ctx->pending_valid    = 0;
  ctx->reply_owed       = 0;
  ctx->close_after_send = 0;
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
  if( FD_UNLIKELY( ctx->request_id && ctx->request_until && now>=ctx->request_until &&
                   ( ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER ||
                     ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT ) ) ) {
    request_pause( ctx, now, "no final answer before the 64-second deadline" );
    return;
  }
  if( FD_UNLIKELY( ctx->close_after_send && !ctx->pending_valid && !fd_failover_channel_tx_pending( ctx->channel ) ) ) {
    ctx->close_after_send = 0;
    fd_failover_channel_hangup( ctx->channel, now );
    FD_LOG_NOTICE(( "handoff %lu: confirmation drained, on-demand connection closed; listener ready for the next request", ctx->close_handoff_id ));
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
  if( FD_LIKELY( !ctx->request_id || !ctx->request_until || ctx->request_sent ||
                 fd_failover_channel_state( ctx->channel )!=FD_FAILOVER_SESSION_PAIRED ) ) return;
  fd_failover_hello_t const * peer = fd_failover_channel_peer_hello( ctx->channel );
  if( FD_UNLIKELY( !ctx->request_boot_id ) ) {
    if( FD_UNLIKELY( peer->role!=FD_FAILOVER_ROLE_ACTIVE ) ) {
      FD_LOG_WARNING(( "the address for handoff %lu is a standby, wait for gossip to show the active and retry", ctx->request_id ));
      request_end( ctx, now, 1 );
      return;
    }
    ctx->request_boot_id = peer->boot_id;
    fd_memcpy( ctx->request_junk, peer->junk_pubkey, 32UL );
  } else if( FD_UNLIKELY( peer->boot_id!=ctx->request_boot_id || !fd_memeq( peer->junk_pubkey, ctx->request_junk, 32UL ) ) ) {
    request_pause( ctx, now, "authenticated member or boot changed" );
    return;
  }
  fd_failover_handoff_request_t request = { .handoff_id=ctx->request_id, .target_boot_id=ctx->request_boot_id };
  if( FD_LIKELY( !fd_failover_channel_send( ctx->channel, now, FD_FAILOVER_MSG_HANDOFF_REQUEST,
                                          (uchar const *)&request, sizeof(request) ) ) ) {
    ctx->request_sent = 1;
    ulong suppressed;
    if( fd_failover_log_take( &ctx->request_tx_log, now, &suppressed ) ) {
      char member[ FD_BASE58_ENCODED_32_SZ ];
      fd_base58_encode_32( ctx->request_junk, NULL, member );
      FD_LOG_NOTICE(( "handoff %lu: sent REQUEST to authenticated member %s boot %016lx at `" FD_IP4_ADDR_FMT ":%hu`; %s (send %lu, %lu retries suppressed)",
                      ctx->request_id, member, ctx->request_boot_id, FD_IP4_ADDR_FMT_ARGS( ctx->request_addr ), ctx->port,
                      request_wait( ctx ), ctx->request_tx_log.count, suppressed ));
    }
    *charge_busy = 1;
  }
}


/* Whether an operator promote may go ahead now.  Returns the refusal,
   or FD_ADMINCTL_RESULT_SUCCESS.  failover status asks the same for a
   plain promote.  force skips every check on the peer and our own
   unanswered handoff, never a promotion or switch in flight. */
static ulong
promote_guard( fd_failover_tile_ctx_t const * ctx,
               long                           now,
               int                            force ) {
  int paired = fd_failover_channel_state( ctx->channel )==FD_FAILOVER_SESSION_PAIRED;

  if( FD_UNLIKELY( ctx->role!=FD_FAILOVER_ROLE_STANDBY ) )                           return FD_FAILOVER_CONTROL_RESULT_BAD_ROLE;
  if( FD_UNLIKELY( ctx->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK && !force ) )     return FD_FAILOVER_CONTROL_RESULT_HANDOFF_PENDING;
  int request_wait = ctx->request_id &&
                     ( ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER ||
                       ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT );
  if( FD_UNLIKELY( ( ctx->action!=FD_FAILOVER_ACTION_IDLE && ctx->action!=FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK &&
                     !( force && request_wait ) ) ||
                   ctx->switch_pending_key!=FD_FAILOVER_SWITCH_KEY_CNT ) )           return FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS;
  if( FD_UNLIKELY( force ) ) return FD_ADMINCTL_RESULT_SUCCESS;
  /* Losing a session does not prove that the peer stopped voting. */
  if( FD_UNLIKELY( ctx->taken ) ) return FD_FAILOVER_CONTROL_RESULT_TAKEN;
  if( FD_UNLIKELY( paired && fd_failover_channel_peer_hello( ctx->channel )->role==FD_FAILOVER_ROLE_ACTIVE ) )
    return FD_FAILOVER_CONTROL_RESULT_PEER_ACTIVE;
  /* Gossip has a fresh contact info for the staked identity from
     another host, an active is publishing right now. */
  if( FD_UNLIKELY( ctx->staked_seen_at && now>=ctx->staked_seen_at &&
                   now-ctx->staked_seen_at<FD_FAILOVER_GOSSIP_FRESH_NANOS ) ) return FD_FAILOVER_CONTROL_RESULT_STAKED_SEEN;
  return FD_ADMINCTL_RESULT_SUCCESS;
}

/* The tower a promote would adopt now.  A tower that ends below the
   floor can never cover it, and one that ends at or under our root
   would adopt no votes, so we skip either for the vote account. */
static ulong
promote_source( fd_failover_tile_ctx_t const * ctx ) {
  ulong floor   = coverage_floor( ctx );
  ulong root    = ctx->root_slot;
  int   peer_ok = ctx->peer_tower.valid && ( floor==FD_FAILOVER_SLOT_NULL || ctx->peer_tower.tip>=floor ) &&
                                           ( root ==FD_FAILOVER_SLOT_NULL || ctx->peer_tower.tip> root  );
  int   own_ok  = ctx->own_tower.valid  && ( floor==FD_FAILOVER_SLOT_NULL || ctx->own_tower.tip >=floor ) &&
                                           ( root ==FD_FAILOVER_SLOT_NULL || ctx->own_tower.tip > root  );
  return peer_ok ? FD_FAILOVER_SOURCE_PEER :
         own_ok  ? FD_FAILOVER_SOURCE_OWN  : FD_FAILOVER_SOURCE_VOTE_ACCOUNT;
}

/* Run an operator command.  If we refuse it we say why. */
static ulong
apply_control( fd_failover_tile_ctx_t *               ctx,
               fd_adminctl_failover_control_t const * req,
               long                                   now ) {
  /* A new command clears stuck, else a standby whose promotion failed
     shows it until a restart and the active refuses every handoff.  A
     transition or switch that still runs keeps it. */
  if( FD_LIKELY( ctx->action==FD_FAILOVER_ACTION_IDLE && ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_CNT ) ) ctx->stuck = 0;

  switch( req->cmd ) {

  case FD_ADMINCTL_FAILOVER_CMD_DEMOTE: {
    if( ctx->role==FD_FAILOVER_ROLE_ACTIVE && ctx->request_id &&
        ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT && ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_CNT ) {
      FD_LOG_NOTICE(( "handoff %lu: operator demote ends the wait for confirmation; giving up the staked identity locally", ctx->request_id ));
      request_end( ctx, now, 1 );
    }
    /* Drop the identity without handing it over.  The peer is not asked
       or told anything, the other machine then needs promote --yes. */
    if( FD_UNLIKELY( ctx->action!=FD_FAILOVER_ACTION_IDLE ) ) return FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS;
    if( FD_UNLIKELY( ctx->role!=FD_FAILOVER_ROLE_ACTIVE ) )   return FD_FAILOVER_CONTROL_RESULT_BAD_ROLE;
    start_demotion( ctx, 0 );
    return FD_ADMINCTL_RESULT_SUCCESS;
  }

  case FD_ADMINCTL_FAILOVER_CMD_HANDOFF: {
    if( FD_UNLIKELY( ctx->request_id && !ctx->request_until &&
                     ( ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER ||
                       ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT ) &&
                     ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_CNT ) ) {
      ctx->request_until = fd_long_sat_add( now, FD_FAILOVER_CHANNEL_IDLE_NANOS );
      ctx->request_sent  = 0;
      ctx->stuck         = 0;
      if( !ctx->request_boot_id ) {
        uint addr = ctx->config_addr ? ctx->config_addr : ctx->staked_addr;
        if( addr ) ctx->request_addr = addr;
      }
      fd_failover_channel_init_dialer( ctx->channel, ctx->request_addr, ctx->port );
      FD_LOG_NOTICE(( "resuming handoff %lu at `" FD_IP4_ADDR_FMT ":%hu`; %s; %s",
                      ctx->request_id, FD_IP4_ADDR_FMT_ARGS( ctx->request_addr ), ctx->port,
                      ctx->request_boot_id ? "same authenticated member and boot" : "active has not authenticated yet",
                      request_wait( ctx ) ));
      return FD_ADMINCTL_RESULT_SUCCESS;
    }
    if( FD_UNLIKELY( ctx->action!=FD_FAILOVER_ACTION_IDLE || ctx->switch_pending_key!=FD_FAILOVER_SWITCH_KEY_CNT ) )
      return FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS;
    if( FD_UNLIKELY( ctx->role!=FD_FAILOVER_ROLE_STANDBY ) ) return FD_FAILOVER_CONTROL_RESULT_BAD_ROLE;
    uint addr = ctx->config_addr ? ctx->config_addr : ctx->staked_addr;
    if( FD_UNLIKELY( !addr ) ) return FD_FAILOVER_CONTROL_RESULT_NO_ACTIVE_ADDRESS;
    ctx->request_id       = ctx->handoff_base+(++ctx->handoff_cnt);
    if( FD_UNLIKELY( !ctx->request_id ) ) ctx->request_id = ++ctx->handoff_cnt;
    ctx->request_boot_id  = 0UL;
    fd_memset( &ctx->request_tx_log, 0, sizeof(ctx->request_tx_log) );
    ctx->request_last_id  = ctx->request_id;
    ctx->request_result   = FD_FAILOVER_HANDOFF_PENDING;
    ctx->last_requested   = 1;
    ctx->request_addr     = addr;
    ctx->request_until    = fd_long_sat_add( now, FD_FAILOVER_CHANNEL_IDLE_NANOS );
    ctx->request_sent     = 0;
    ctx->action           = FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER;
    ctx->close_after_send = 0;
    fd_failover_channel_init_dialer( ctx->channel, addr, ctx->port );
    FD_LOG_NOTICE(( "requesting handoff %lu from the active at `" FD_IP4_ADDR_FMT ":%hu` using %s; authenticating the peer before requesting final state",
                    ctx->request_id, FD_IP4_ADDR_FMT_ARGS( addr ), ctx->port, ctx->config_addr ? "[failover.peer_address]" : "gossip" ));
    return FD_ADMINCTL_RESULT_SUCCESS;
  }

  case FD_ADMINCTL_FAILOVER_CMD_PROMOTE: {
    /* Take the identity on the operator's word, unpaired this is also
       how the first active is made.  We refuse while the peer holds or
       may hold the identity.  --force is the operator's word that the
       peer cannot sign.  It skips every check on the peer and gives up on
       our own handoff, and is still refused while a promotion or switch
       runs. */
    int   force  = !!( req->flags & FD_ADMINCTL_FAILOVER_FLAG_FORCE );
    ulong result = promote_guard( ctx, now, force );
    if( FD_UNLIKELY( result!=FD_ADMINCTL_RESULT_SUCCESS ) ) return result;
    ulong source = promote_source( ctx );
    if( FD_UNLIKELY( source==FD_FAILOVER_SOURCE_VOTE_ACCOUNT && !( req->flags & FD_ADMINCTL_FAILOVER_FLAG_YES ) ) ) {
      return FD_FAILOVER_CONTROL_RESULT_NO_TOWER;
    }
    /* The operator fenced the peer.  Only a request with no local
       adoption or key switch in flight can be cancelled for recovery. */
    if( force && ctx->role==FD_FAILOVER_ROLE_STANDBY && ctx->request_id &&
        ( ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER || ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT ) &&
        ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_CNT ) {
      FD_LOG_NOTICE(( "handoff %lu cancelled by `promote --force` on the operator's word that the peer cannot sign; proceeding with local recovery", ctx->request_id ));
      request_end( ctx, now, 1 );
      ctx->request_result = FD_FAILOVER_HANDOFF_CANCELLED;
    }
    if( FD_UNLIKELY( ctx->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK ) ) {
      FD_LOG_WARNING(( "promote --force stops waiting for the peer's answer to handoff %lu", ctx->handoff_id ));
      handoff_resolved( ctx, FD_FAILOVER_HANDOFF_CANCELLED );
    }
    FD_LOG_NOTICE(( "promoting on the operator's word%s, adopting %s", force ? " with --force" : "",
                    source==FD_FAILOVER_SOURCE_PEER ? "the tower the peer gave us" :
                    source==FD_FAILOVER_SOURCE_OWN  ? "our own final tower"        : "the vote account" ));
    start_promotion( ctx, source, 0 );
    ctx->promote_force = force;
    return FD_ADMINCTL_RESULT_SUCCESS;
  }

  default: break;
  }
  return FD_ADMINCTL_RESULT_UNSUPPORTED;
}

/* The failover status answer, what the controller knows and what
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
    resp->peer_role       = (uchar)ctx->peer_role;
  }
  resp->peer_boot_id   = ctx->peer_boot_id;
  resp->peer_addr      = ctx->config_addr ? ctx->config_addr : ctx->staked_addr;
  resp->peer_addr_cfg  = (uchar)!!ctx->config_addr;
  resp->peer_port      = ctx->port;
  resp->handoff_id     = ctx->last_requested ? ctx->request_last_id : ctx->handoff_id;
  resp->handoff_result = (uchar)( ctx->last_requested ? ctx->request_result : ctx->handoff_result );
  resp->promote_source = (uchar)promote_source( ctx );
  resp->promote_floor  = coverage_floor( ctx );
  resp->promote_result = promote_guard( ctx, now, 0 );
  /* Without a tower a plain promote is refused too. */
  if( FD_UNLIKELY( resp->promote_result==FD_ADMINCTL_RESULT_SUCCESS &&
                   resp->promote_source==(uchar)FD_FAILOVER_SOURCE_VOTE_ACCOUNT ) ) resp->promote_result = FD_FAILOVER_CONTROL_RESULT_NO_TOWER;
}

/* Answer one bus request.  The admin tile validated the ABI already.
   The answer goes out in its own chunk, never aliased to the request. */
static void
serve_bus_request( fd_failover_tile_ctx_t * ctx,
                   fd_stem_context_t *      stem,
                   long                     now ) {
  if( FD_UNLIKELY( ctx->bus_req_sig==FD_FAILOVER_BUS_STATUS_REQ ) ) {
    fd_adminctl_failover_status_resp_t status;
    status_snapshot( ctx, now, &status );
    fd_failover_bus_msg_t * out = fd_chunk_to_laddr( ctx->admin_out_mem, ctx->admin_out_chunk );
    fd_memset( out, 0, sizeof(*out) );
    out->nonce  = ctx->bus_req.nonce;
    out->result = FD_ADMINCTL_RESULT_SUCCESS;
    fd_memcpy( out->payload, &status, sizeof(status) );
    ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
    fd_stem_publish( stem, ctx->admin_out_idx, FD_FAILOVER_BUS_STATUS_RESP, ctx->admin_out_chunk, sizeof(*out), 0UL, tspub, tspub );
    ctx->admin_out_chunk = fd_dcache_compact_next( ctx->admin_out_chunk, sizeof(*out), ctx->admin_out_chunk0, ctx->admin_out_wmark );
    return;
  }

  fd_adminctl_failover_control_t control;
  fd_memcpy( &control, ctx->bus_req.payload, sizeof(control) );
  static char const * const cmd_names[ FD_ADMINCTL_FAILOVER_CMD_CNT ] = { "handoff", "demote", "promote" };
  char const * cmd_name = control.cmd<FD_ADMINCTL_FAILOVER_CMD_CNT ? cmd_names[ control.cmd ] : "unknown";
  FD_LOG_NOTICE(( "`failover %s%s%s` received", cmd_name,
                  ( control.flags & FD_ADMINCTL_FAILOVER_FLAG_YES   ) ? " --yes"   : "",
                  ( control.flags & FD_ADMINCTL_FAILOVER_FLAG_FORCE ) ? " --force" : "" ));
  ulong result = apply_control( ctx, &control, now );
  if( FD_UNLIKELY( result!=FD_ADMINCTL_RESULT_SUCCESS ) ) {
    char const * hint;
    char const * name = control_refusal( result, &hint );
    FD_LOG_WARNING(( "`failover %s` refused with %s, %s", cmd_name, name, hint ));
  }
  fd_adminctl_failover_control_resp_t answer = {
    .version = FD_ADMINCTL_FAILOVER_CONTROL_PAYLOAD_VERSION,
    .role    = (uchar)ctx->role,
    .action  = (uchar)ctx->action,
  };

  fd_failover_bus_msg_t * out = fd_chunk_to_laddr( ctx->admin_out_mem, ctx->admin_out_chunk );
  fd_memset( out, 0, sizeof(*out) );
  out->nonce  = ctx->bus_req.nonce;
  out->result = result;
  fd_memcpy( out->payload, &answer, sizeof(answer) );
  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, ctx->admin_out_idx, FD_FAILOVER_BUS_CONTROL_RESP, ctx->admin_out_chunk, sizeof(*out), 0UL, tspub, tspub );
  ctx->admin_out_chunk = fd_dcache_compact_next( ctx->admin_out_chunk, sizeof(*out), ctx->admin_out_chunk0, ctx->admin_out_wmark );
}

/* Without [failover.peer_address] the peer's address comes from gossip,
   from the newest staked contact info that is not ours, which is how
   the active shows up.  A remove, IPv6 or zero address never clears what
   we know.  The member certificate authenticates the peer, so a wrong
   address only costs the pairing.  We dial it when the standby requests a handoff.  With a configured address gossip only says when an active
   last published. */
static void
gossip_commit( fd_failover_tile_ctx_t * ctx,
               long                     now ) {
  uint addr = ctx->gossip_socket.addr;
  if( FD_UNLIKELY( !addr ) ) return;
  if( FD_LIKELY( !fd_memeq( ctx->gossip_origin, ctx->hello.staked_pubkey, 32UL ) ) ) return;
  if( FD_UNLIKELY( addr==ctx->own_gossip.addr && ctx->gossip_socket.port==ctx->own_gossip.port ) ) return;
  ctx->staked_seen_at = now;

  if( FD_UNLIKELY( ctx->config_addr ) ) return;
  if( FD_LIKELY( addr==ctx->staked_addr ) ) return;
  uint old_addr = ctx->staked_addr;
  ctx->staked_addr = addr;
  if( FD_LIKELY( !old_addr ) ) {
    FD_LOG_NOTICE(( "gossip shows the staked identity at `" FD_IP4_ADDR_FMT "`, we dial it for a handoff", FD_IP4_ADDR_FMT_ARGS( addr ) ));
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
       vote and count here. */
    if( FD_UNLIKELY( ctx->tower_seen_seq!=ULONG_MAX && seq!=fd_seq_inc( ctx->tower_seen_seq, 1UL ) ) ) ctx->tower_gap = 1;
    if( FD_UNLIKELY( sig!=FD_TOWER_SIG_SLOT_DONE ) ) {
      ctx->tower_seen_seq = seq;
      return 1;
    }
    return 0;
  }
  if( FD_UNLIKELY( in_idx==ctx->admin_in_idx ) ) {
    /* Commands and switch answers.  Dropping a switch answer here would
       leave the switch hanging forever. */
    return sig!=FD_FAILOVER_BUS_CONTROL_REQ && sig!=FD_FAILOVER_BUS_STATUS_REQ && sig!=FD_FAILOVER_BUS_SWITCH_RESP;
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
    if( FD_UNLIKELY( sig==FD_FAILOVER_BUS_SWITCH_RESP ) ) {
      fd_memcpy( &ctx->switch_response, msg->payload, sizeof(ctx->switch_response) );
      ctx->switch_answer_nonce = msg->nonce;
      return;
    }
    fd_memcpy( &ctx->bus_req, msg, sizeof(fd_failover_bus_msg_t) );
    return;
  }
  if( FD_UNLIKELY( in_idx==ctx->tower_in_idx ) ) {
    if( FD_UNLIKELY( chunk<ctx->tower_in_chunk0 || chunk>ctx->tower_in_wmark || sz!=sizeof(fd_tower_msg_t) ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->tower_in_chunk0, ctx->tower_in_wmark ));
    }
    fd_memcpy( &ctx->slot_done, fd_chunk_to_laddr_const( ctx->tower_in_mem, chunk ), sizeof(fd_tower_slot_done_t) );
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
    ctx->adopt_result_id    = sig;
    ctx->adopt_result_fresh = 1;
    return;
  }
  if( FD_UNLIKELY( in_idx==ctx->admin_in_idx ) ) {
    if( FD_UNLIKELY( sig==FD_FAILOVER_BUS_SWITCH_RESP ) ) {
      /* The accepted result can remain live while the tower drains.
         Commit the payload only after the stem and nonce checks pass. */
      if( FD_LIKELY( switch_answer( ctx, ctx->switch_answer_nonce ) ) ) ctx->switch_result = ctx->switch_response;
      return;
    }
    /* Answered from after_credit, where a publish credit is available. */
    ctx->bus_req_sig   = sig;
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
    consume_slot_done( ctx, &ctx->slot_done );
  }
  step_controller( ctx, stem );

  /* Each socket poll is a syscall or two for a protocol that runs at the
     status cadence, so while nothing arrives the socket is asked every
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
    if( !ctx->stuck ) FD_LOG_NOTICE(( "failover is no longer stuck; %s", ctx->role==FD_FAILOVER_ROLE_ACTIVE ? "this machine is active" : "this machine is standby" ));
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
  fd_failover_tile_ctx_t const * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  int logfile_fd = fd_log_private_logfile_fd();
  int listen_fd  = fd_failover_channel_listen_fd( ctx->channel );

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
