#ifndef FD_SRC_APP_FIREDANCER_DEV_COMMANDS_SEND_TEST_HELPERS_C
#define FD_SRC_APP_FIREDANCER_DEV_COMMANDS_SEND_TEST_HELPERS_C

#include "../../../../disco/fd_disco.h"
#include "../../../../choreo/tower/fd_tower.h"
#include "../../../../flamenco/leaders/fd_leaders_base.h"
#include "../../../../disco/pack/fd_microblock.h"
#include "../../../../flamenco/gossip/fd_gossip_types.h"
#include "../../../../util/net/fd_ip4.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MOCK_CI_IDX      0UL
#define MOCK_STAKE_IDX   1UL
#define MOCK_TRIGGER_IDX 2UL
#define MOCK_CNT         3UL

/* Forward declarations for send_test types */
struct send_test_ctx;
typedef struct send_test_ctx send_test_ctx_t;

typedef struct {
  fd_frag_meta_t * mcache;
  ulong *          sync;
  ulong            depth;
  ulong            seq;

  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
} send_test_out_t;

typedef void
(* out_fn_t)( send_test_ctx_t * ctx, send_test_out_t * out );

struct send_test_ctx {
  fd_topo_t   * topo;
  fd_config_t * config;

  send_test_out_t out_links[ MOCK_CNT ];
  out_fn_t        out_fns  [ MOCK_CNT ];

  fd_pubkey_t   identity_key  [ 1 ];
  fd_pubkey_t   vote_acct_addr[ 1 ];

  fd_txn_p_t    txn_buf[ 1 ];

  long last_evt[ MOCK_CNT ];
  long delay   [ MOCK_CNT ];

  ulong epoch;
  ulong slot;

  char gossip_file[256];
  char stake_file[256];
};

/* File paths are now part of the ctx struct */

/* Event handler function implementations */

static inline fd_gossip_update_message_t
parse_gossip_line( char * line ) {
  fd_gossip_update_message_t msg = {0};
  FD_LOG_DEBUG(( "Parsing gossip line: %s", line ));

  /* Parse tokens */
  char * ip_token     = strtok( line, " |\t" );  FD_TEST( ip_token );
  char * pubkey_token = strtok( NULL, " |\t" );  FD_TEST( pubkey_token );
  /* ************* */   strtok( NULL, " |\t" );  /* Skip gossip port */
  char * tpu_udp      = strtok( NULL, " |\t" );  FD_TEST( tpu_udp );
  char * tpu_quic     = strtok( NULL, " |\t" );  FD_TEST( tpu_quic );

  /* solana gossip output does not contain all 4 we care about - for now, use these two */
  fd_ip4_port_t * udp_tpu  = &msg.contact_info.contact_info->sockets[FD_CONTACT_INFO_SOCKET_TPU];
  fd_ip4_port_t * quic_tpu = &msg.contact_info.contact_info->sockets[FD_CONTACT_INFO_SOCKET_TPU_QUIC];

  /* Set pubkey, IP, ports - 'gossip' should send all in net order */
  FD_TEST( fd_base58_decode_32( pubkey_token, msg.origin_pubkey ) );

  uint ip_addr;
  FD_TEST( fd_cstr_to_ip4_addr( ip_token, &ip_addr ) );
  udp_tpu->addr  = ip_addr;
  quic_tpu->addr = ip_addr;

  ushort udp_port_net  = fd_cstr_to_ushort( tpu_udp  ); FD_TEST( udp_port_net  );
  ushort quic_port_net = fd_cstr_to_ushort( tpu_quic ); FD_TEST( quic_port_net );
  udp_tpu->port  = fd_ushort_bswap( udp_port_net  );
  quic_tpu->port = fd_ushort_bswap( quic_port_net );

  return msg;
}

static inline void
send_test_ci( send_test_ctx_t * ctx, send_test_out_t * out ) {
  FILE * file = fopen( ctx->gossip_file, "r" );
  if( !file ) FD_LOG_ERR(( "Failed to open gossip file: %s", ctx->gossip_file ));

  char line[1024];
  while( fgets( line, sizeof(line), file ) ) {
    fd_gossip_update_message_t * msg = fd_chunk_to_laddr( out->mem, out->chunk );
    *msg = parse_gossip_line( line );
    ulong const sz = sizeof(fd_gossip_update_message_t);

    fd_mcache_publish( out->mcache, out->depth, out->seq, 0UL, out->chunk, sz, 0UL, 0UL, 0UL );
    out->seq   = fd_seq_inc( out->seq, 1UL );
    out->chunk = fd_dcache_compact_next( out->chunk, sz, out->chunk0, out->wmark );
  }
  fclose( file );
}

static inline fd_vote_stake_weight_t
parse_stake_weight( char * line ) {
  fd_vote_stake_weight_t weight;
  FD_LOG_DEBUG(( "Parsing stake line: %s", line ));

  /* Set pubkeys */
  char * id_token = strtok( line+3, " \t" );   FD_TEST( id_token );
  char * vote_token = strtok( NULL, " \t" ); FD_TEST( vote_token );
  FD_TEST( fd_base58_decode_32( id_token, weight.id_key.key ) );
  FD_TEST( fd_base58_decode_32( vote_token, weight.vote_key.key ) );

  /* Find staked amount in rest of string */
  char * sol_pos   = strstr( strtok( NULL, "" ), " SOL " ); FD_TEST( sol_pos );
  char * sol_start = sol_pos - 2;
         *sol_pos  = '\0';
  /* Scan backwards from " SOL " to find the start of the number */
  while( sol_start > line && (sol_start[-1] == '.' || (sol_start[-1] >= '0' && sol_start[-1] <= '9')) ) {
    sol_start--;
  }

  /* Set staked amount */
  double sol_amount   = atof( sol_start ); FD_TEST( sol_amount > 0.0 );
         weight.stake = (ulong)(sol_amount * 1000000000UL);
  return weight;
}

static inline void
send_test_stake( send_test_ctx_t * ctx, send_test_out_t * out ) {

  fd_stake_weight_msg_t * msg = fd_chunk_to_laddr( out->mem, out->chunk );

  msg->epoch = ctx->epoch;
  msg->start_slot = ctx->epoch*MAX_SLOTS_PER_EPOCH;
  msg->slot_cnt = MAX_SLOTS_PER_EPOCH;
  msg->excluded_stake = 0;
  msg->vote_keyed_lsched = 0;

  fd_vote_stake_weight_t * stake_weights = msg->weights;
  ulong stake_count = 0;

  FILE * file = fopen( ctx->stake_file, "r" );
  if( !file ) FD_LOG_ERR(( "Failed to open stake file: %s", ctx->stake_file ));

  char line[1024];
  while( fgets( line, sizeof(line), file ) ) {
    stake_weights[stake_count++] = parse_stake_weight( line );
  }
  fclose( file );

  if( stake_count == 0 ) FD_LOG_ERR(( "No valid stake entries found in %s", ctx->stake_file ));

  msg->staked_cnt = stake_count;
  ulong const sz = sizeof(fd_stake_weight_msg_t) + stake_count * sizeof(fd_vote_stake_weight_t);
  FD_TEST( sz <= USHORT_MAX );

  fd_mcache_publish( out->mcache, out->depth, out->seq, 0UL, out->chunk, sz, 0UL, 0UL, 0UL );
  out->seq   = fd_seq_inc( out->seq, 1UL );
  out->chunk = fd_dcache_compact_next( out->chunk, sz, out->chunk0, out->wmark );

  ctx->epoch++;
}

static inline void
send_test_trigger( send_test_ctx_t * ctx, send_test_out_t * out ) {
  uchar * buf = fd_chunk_to_laddr( out->mem, out->chunk );
  fd_memcpy( buf, ctx->txn_buf, sizeof(fd_txn_p_t) );

  ulong const sz = sizeof(fd_txn_p_t);
  ulong const sig = ctx->slot++;
  fd_mcache_publish( out->mcache, out->depth, out->seq, sig, out->chunk, sz, 0UL, 0UL, 0UL );
  out->seq   = fd_seq_inc( out->seq, 1UL );
  out->chunk = fd_dcache_compact_next( out->chunk, sz, out->chunk0, out->wmark );
}

static inline send_test_out_t
setup_test_out_link( fd_topo_t const * topo, char const * name ) {
  ulong idx = fd_topo_find_link( topo, name, 0UL );
  FD_TEST( idx != ULONG_MAX );
  fd_topo_link_t const * link = &topo->links[ idx ];
  send_test_out_t out = { 0 };
  out.mcache = link->mcache;
  out.sync = fd_mcache_seq_laddr( out.mcache );
  out.depth = fd_mcache_depth( out.mcache );
  out.seq = fd_mcache_seq_query( out.sync );
  out.mem = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
  out.chunk0 = fd_dcache_compact_chunk0( out.mem, link->dcache );
  out.wmark = fd_dcache_compact_wmark( out.mem, link->dcache, link->mtu );
  out.chunk = out.chunk0;
  return out;
}

static inline void
encode_vote( send_test_ctx_t * ctx, fd_txn_p_t * txn ) {
  ulong const root = 350284672UL;

  /* Create minimal mock tower with one vote */
  uchar tower_mem[ FD_TOWER_FOOTPRINT ] __attribute__((aligned(FD_TOWER_ALIGN)));
  fd_tower_t * tower = fd_tower_join( fd_tower_new( tower_mem ) );
  fd_tower_votes_push_tail( tower, (fd_tower_vote_t){ .slot = root+1, .conf = 1 } );

  /* Mock values */
  fd_lockout_offset_t lockouts_scratch[1];
  fd_hash_t test_hash;

  /* Use fd_tower_to_vote_txn to generate the transaction */
  fd_tower_to_vote_txn( tower, root, lockouts_scratch, &test_hash,
                        &test_hash, ctx->identity_key,
                        ctx->identity_key, ctx->vote_acct_addr, txn );
}

#endif /* FD_SRC_APP_FIREDANCER_DEV_COMMANDS_SEND_TEST_HELPERS_C */
