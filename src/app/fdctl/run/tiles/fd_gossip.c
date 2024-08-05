/* Gossip tile runs the gossip networking protcol for a Firedancer node. */

#define _GNU_SOURCE

#include "../../../../disco/tiles.h"

#include <unistd.h>
#include <arpa/inet.h>
#include <linux/unistd.h>
#include <sys/random.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "../../../../disco/fd_disco.h"
#include "../../../../disco/keyguard/fd_keyload.h"
#include "../../../../disco/store/util.h"
#include "../../../../flamenco/gossip/fd_gossip.h"
#include "../../../../flamenco/runtime/fd_system_ids.h"
#include "../../../../util/fd_util.h"
#include "../../../../util/net/fd_eth.h"
#include "../../../../util/net/fd_ip4.h"
#include "../../../../util/net/fd_udp.h"
#include "../../../../util/net/fd_net_headers.h"

#include "generated/gossip_seccomp.h"


#define NET_IN_IDX      0
#define VOTER_IN_IDX    1
#define SIGN_IN_IDX     2

#define SHRED_OUT_IDX   0
#define REPAIR_OUT_IDX  1
#define DEDUP_OUT_IDX   2
#define SIGN_OUT_IDX    3
#define VOTER_OUT_IDX   4

#define CONTACT_INFO_PUBLISH_TIME_NS ((long)5e9)

/* Scratch space is used for deserializing a gossip message.
   TODO: update */
#define SCRATCH_MAX (1<<16UL)
/* A minimal number of frames
   TODO: update */
#define SCRATCH_DEPTH (16UL)

static volatile ulong * fd_shred_version;

static int
fd_pubkey_eq( fd_pubkey_t const * key1, fd_pubkey_t const * key2 ) {
  return memcmp( key1->key, key2->key, sizeof(fd_pubkey_t) ) == 0;
}

static ulong
fd_pubkey_hash( fd_pubkey_t const * key, ulong seed ) {
  return fd_hash( seed, key->key, sizeof(fd_pubkey_t) );
}

static void
fd_pubkey_copy( fd_pubkey_t * keyd, fd_pubkey_t const * keys ) {
  memcpy( keyd->key, keys->key, sizeof(fd_pubkey_t) );
}

/* Contact info table */
#define MAP_NAME     fd_contact_info_table
#define MAP_KEY_T    fd_pubkey_t
#define MAP_KEY_EQ   fd_pubkey_eq
#define MAP_KEY_HASH fd_pubkey_hash
#define MAP_KEY_COPY fd_pubkey_copy
#define MAP_T        fd_contact_info_elem_t
#include "../../../../util/tmpl/fd_map_giant.c"

struct fd_gossip_tile_ctx {
  fd_gossip_t * gossip;
  fd_gossip_config_t gossip_config;
  long last_shred_dest_push_time;

  ulong gossip_seed;

  fd_contact_info_elem_t * contact_info_table;

  fd_frag_meta_t * shred_contact_out_mcache;
  ulong *          shred_contact_out_sync;
  ulong            shred_contact_out_depth;
  ulong            shred_contact_out_seq;

  fd_wksp_t * shred_contact_out_mem;
  ulong       shred_contact_out_chunk0;
  ulong       shred_contact_out_wmark;
  ulong       shred_contact_out_chunk;

  fd_frag_meta_t * repair_contact_out_mcache;
  ulong *          repair_contact_out_sync;
  ulong            repair_contact_out_depth;
  ulong            repair_contact_out_seq;

  fd_wksp_t * repair_contact_out_mem;
  ulong       repair_contact_out_chunk0;
  ulong       repair_contact_out_wmark;
  ulong       repair_contact_out_chunk;

  fd_frag_meta_t * voter_contact_out_mcache;
  ulong *          voter_contact_out_sync;
  ulong            voter_contact_out_depth;
  ulong            voter_contact_out_seq;

  fd_wksp_t * voter_contact_out_mem;
  ulong       voter_contact_out_chunk0;
  ulong       voter_contact_out_wmark;
  ulong       voter_contact_out_chunk;

  fd_frag_meta_t * dedup_out_mcache;
  ulong *          dedup_out_sync;
  ulong            dedup_out_depth;
  ulong            dedup_out_seq;

  fd_wksp_t * dedup_out_mem;
  ulong       dedup_out_chunk0;
  ulong       dedup_out_wmark;
  ulong       dedup_out_chunk;

  fd_wksp_t * replay_in_mem;
  ulong       replay_in_chunk0;
  ulong       replay_in_wmark;

  fd_wksp_t *     wksp;
  fd_gossip_peer_addr_t gossip_my_addr;
  fd_gossip_peer_addr_t tvu_my_addr;
  fd_gossip_peer_addr_t tvu_my_fwd_addr;
  fd_gossip_peer_addr_t tpu_my_addr;
  fd_gossip_peer_addr_t tpu_vote_my_addr;
  ushort                gossip_listen_port;

  fd_wksp_t *     net_in_mem;
  ulong           net_in_chunk;
  ulong           net_in_wmark;

  fd_frag_meta_t * net_out_mcache;
  ulong *          net_out_sync;
  ulong            net_out_depth;
  ulong            net_out_seq;

  fd_wksp_t * net_out_mem;
  ulong       net_out_chunk0;
  ulong       net_out_wmark;
  ulong       net_out_chunk;

  uchar         identity_private_key[32];
  fd_pubkey_t   identity_public_key;

  /* Includes Ethernet, IP, UDP headers */
  ulong gossip_buffer_sz;
  uchar gossip_buffer[ FD_NET_MTU ];

  ushort net_id;
  uchar src_mac_addr[6];
  fd_net_hdrs_t hdr[1];

  fd_keyguard_client_t  keyguard_client[1];

  fd_mux_context_t * mux;

  ulong replay_vote_txn_sz;
  uchar replay_vote_txn [ FD_TXN_MTU ];
};
typedef struct fd_gossip_tile_ctx fd_gossip_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return 1UL * FD_SHMEM_GIGANTIC_PAGE_SZ;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_gossip_tile_ctx_t), sizeof(fd_gossip_tile_ctx_t) );
  l = FD_LAYOUT_APPEND( l, fd_gossip_align(), fd_gossip_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_contact_info_table_align(), fd_contact_info_table_footprint( FD_PEER_KEY_MAX ) );
  l = FD_LAYOUT_APPEND( l, fd_scratch_smem_align(), fd_scratch_smem_footprint( SCRATCH_MAX ) );
  l = FD_LAYOUT_APPEND( l, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( SCRATCH_DEPTH ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void*)fd_ulong_align_up( (ulong)scratch, alignof(fd_gossip_tile_ctx_t) );
}

static void
send_packet( fd_gossip_tile_ctx_t * ctx,
             uint                   dst_ip_addr,
             ushort                 dst_port,
             uchar const *          payload,
             ulong                  payload_sz,
             ulong                  tsorig ) {
  uchar * packet = fd_chunk_to_laddr( ctx->net_out_mem, ctx->net_out_chunk );

  fd_memcpy( packet, ctx->hdr, sizeof(fd_net_hdrs_t) );
  fd_net_hdrs_t * hdr = (fd_net_hdrs_t *)packet;

  hdr->udp->net_dport = dst_port;

  memset( hdr->eth->dst, 0U, 6UL );
  memcpy( hdr->ip4->daddr_c, &dst_ip_addr, 4UL );
  hdr->ip4->net_id = fd_ushort_bswap( ctx->net_id++ );
  hdr->ip4->check  = 0U;
  hdr->ip4->net_tot_len  = fd_ushort_bswap( (ushort)(payload_sz + sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t)) );
  hdr->ip4->check  = fd_ip4_hdr_check( ( fd_ip4_hdr_t const *)FD_ADDRESS_OF_PACKED_MEMBER( hdr->ip4 ) );

  ulong packet_sz = payload_sz + sizeof(fd_net_hdrs_t);
  fd_memcpy( packet+sizeof(fd_net_hdrs_t), payload, payload_sz );
  hdr->udp->net_len   = fd_ushort_bswap( (ushort)(payload_sz + sizeof(fd_udp_hdr_t)) );
  hdr->udp->check = fd_ip4_udp_check( *(uint *)FD_ADDRESS_OF_PACKED_MEMBER( hdr->ip4->saddr_c ),
                                      *(uint *)FD_ADDRESS_OF_PACKED_MEMBER( hdr->ip4->daddr_c ),
                                      (fd_udp_hdr_t const *)FD_ADDRESS_OF_PACKED_MEMBER( hdr->udp ),
                                      packet + sizeof(fd_net_hdrs_t) );

  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  ulong sig   = fd_disco_netmux_sig( 0U, 0U, dst_ip_addr, DST_PROTO_OUTGOING, FD_NETMUX_SIG_MIN_HDR_SZ );
  fd_mux_publish( ctx->mux, sig, ctx->net_out_chunk, packet_sz, 0UL, tsorig, tspub );
  ctx->net_out_chunk = fd_dcache_compact_next( ctx->net_out_chunk, packet_sz, ctx->net_out_chunk0, ctx->net_out_wmark );
}

static void
gossip_send_packet( uchar const * msg,
                    size_t msglen,
                    fd_gossip_peer_addr_t const * addr,
                    void * arg ) {
ulong tsorig = fd_frag_meta_ts_comp( fd_tickcount() );
  send_packet( arg, addr->addr, addr->port, msg, msglen, tsorig );
}

static int
is_vote_state_update_instr( uint discriminant ) {
  return discriminant == fd_vote_instruction_enum_vote ||
         discriminant == fd_vote_instruction_enum_vote_switch ||
         discriminant == fd_vote_instruction_enum_update_vote_state ||
         discriminant == fd_vote_instruction_enum_update_vote_state_switch ||
         discriminant == fd_vote_instruction_enum_compact_update_vote_state ||
         discriminant == fd_vote_instruction_enum_compact_update_vote_state_switch;
}

static int
verify_vote_txn( fd_gossip_vote_t const * vote ) {
  fd_txn_t const * parsed_txn = (fd_txn_t const *)fd_type_pun_const( vote->txn.txn );
  ushort instr_data_sz = parsed_txn->instr[0].data_sz;
  uchar const * instr_data = vote->txn.raw + parsed_txn->instr[0].data_off;

  fd_pubkey_t const * txn_accounts = (fd_pubkey_t const *)(vote->txn.raw + parsed_txn->acct_addr_off);
  uchar program_id = parsed_txn->instr[0].program_id;

  if( memcmp( txn_accounts[program_id].uc, &fd_solana_vote_program_id, sizeof(fd_pubkey_t) ) ) {
    return -1;
  }

  fd_vote_instruction_t vote_instr = { 0 };
  fd_bincode_decode_ctx_t decode = {
                                    .data    = instr_data,
                                    .dataend = instr_data + instr_data_sz,
                                    .valloc  = fd_scratch_virtual()
  };
  int decode_result = fd_vote_instruction_decode( &vote_instr, &decode );
  if( decode_result != FD_BINCODE_SUCCESS) {
    return -1;
  } else if ( !is_vote_state_update_instr( vote_instr.discriminant ) ) {
    return -1;
  }

  return 0;
}

static void
gossip_deliver_fun( fd_crds_data_t * data, void * arg ) {
  fd_gossip_tile_ctx_t * ctx = (fd_gossip_tile_ctx_t *)arg;

  if( fd_crds_data_is_vote( data ) ) {
    fd_gossip_vote_t const * gossip_vote = &data->inner.vote;
    if( verify_vote_txn( gossip_vote ) != 0 ) {
      return;
    }

    uchar * vote_txn_msg = fd_chunk_to_laddr( ctx->dedup_out_mem, ctx->dedup_out_chunk );
    ulong vote_txn_sz    = gossip_vote->txn.raw_sz;
    memcpy( vote_txn_msg, gossip_vote->txn.raw, vote_txn_sz );

    ulong sig = 1UL;
    fd_mcache_publish( ctx->dedup_out_mcache, ctx->dedup_out_depth, ctx->dedup_out_seq, sig, ctx->dedup_out_chunk,
      vote_txn_sz, 0UL, 0, 0 );
    ctx->dedup_out_seq   = fd_seq_inc( ctx->dedup_out_seq, 1UL );
    ctx->dedup_out_chunk = fd_dcache_compact_next( ctx->dedup_out_chunk, vote_txn_sz, ctx->dedup_out_chunk0, ctx->dedup_out_wmark );

  } else if( fd_crds_data_is_contact_info_v1( data ) ) {
    fd_gossip_contact_info_v1_t const * contact_info = &data->inner.contact_info_v1;
    FD_LOG_DEBUG(("contact info v1 - ip: " FD_IP4_ADDR_FMT ", port: %u", FD_IP4_ADDR_FMT_ARGS( contact_info->gossip.addr.inner.ip4 ), contact_info->gossip.port ));

    fd_contact_info_elem_t * ele = fd_contact_info_table_query( ctx->contact_info_table, &contact_info->id, NULL );
    if (FD_UNLIKELY(!ele &&
                    !fd_contact_info_table_is_full(ctx->contact_info_table))) {
      ele = fd_contact_info_table_insert(ctx->contact_info_table,
                                         &contact_info->id);
    }
    if (ele) {
      ele->contact_info = *contact_info;
    }
  } else if( fd_crds_data_is_contact_info_v2( data ) ) {
    fd_gossip_contact_info_v2_t const * contact_info_v2 = &data->inner.contact_info_v2;

    fd_gossip_contact_info_v1_t contact_info;
    fd_gossip_contact_info_v2_to_v1( contact_info_v2, &contact_info );
    FD_LOG_DEBUG(("contact info v2 - ip: " FD_IP4_ADDR_FMT ", port: %u", FD_IP4_ADDR_FMT_ARGS( contact_info.gossip.addr.inner.ip4 ), contact_info.gossip.port ));

    fd_contact_info_elem_t * ele = fd_contact_info_table_query( ctx->contact_info_table, &contact_info.id, NULL );
    if (FD_UNLIKELY(!ele &&
                    !fd_contact_info_table_is_full(ctx->contact_info_table))) {
      ele = fd_contact_info_table_insert(ctx->contact_info_table,
                                         &contact_info.id);
    }
    if (ele) {
      ele->contact_info = contact_info;
    }
  }
}

void
gossip_signer( void *        signer_ctx,
               uchar         signature[ static 64 ],
               uchar const * buffer,
               ulong         len,
               int           sign_type ) {
  fd_gossip_tile_ctx_t * ctx = (fd_gossip_tile_ctx_t *)signer_ctx;
  fd_keyguard_client_sign( ctx->keyguard_client, signature, buffer, len, sign_type );
}

static void
before_frag( void * _ctx        FD_PARAM_UNUSED,
             ulong  in_idx      FD_PARAM_UNUSED,
             ulong  seq         FD_PARAM_UNUSED,
             ulong  sig,
             int *  opt_filter ) {
  if( in_idx != VOTER_IN_IDX && fd_disco_netmux_sig_proto( sig ) != DST_PROTO_GOSSIP) {
    *opt_filter = 1;
    return;
  }
}

static void
during_frag( void * _ctx,
             ulong  in_idx      FD_PARAM_UNUSED,
             ulong  seq         FD_PARAM_UNUSED,
             ulong  sig         FD_PARAM_UNUSED,
             ulong  chunk,
             ulong  sz,
             int *  opt_filter ) {
  fd_gossip_tile_ctx_t * ctx = (fd_gossip_tile_ctx_t *)_ctx;

  if ( in_idx == VOTER_IN_IDX ) {
    if( FD_UNLIKELY( chunk<ctx->replay_in_chunk0 || chunk>ctx->replay_in_wmark || sz>USHORT_MAX ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->replay_in_chunk0, ctx->replay_in_wmark ));
    }

    ctx->replay_vote_txn_sz = sz;
    memcpy( ctx->replay_vote_txn, fd_chunk_to_laddr( ctx->replay_in_mem, chunk ), sz );
    return;
  }

  if( in_idx!=NET_IN_IDX ) {
    *opt_filter = 1;
    return;
  }

  if( FD_UNLIKELY( chunk<ctx->net_in_chunk || chunk>ctx->net_in_wmark || sz>FD_NET_MTU ) ) {
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->net_in_chunk, ctx->net_in_wmark ));
    *opt_filter = 1;
    return;
  }

  uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->net_in_mem, chunk );

  ctx->gossip_buffer_sz = sz;
  fd_memcpy( ctx->gossip_buffer, dcache_entry, sz );
}

static void
after_frag( void *             _ctx,
            ulong              in_idx     FD_PARAM_UNUSED,
            ulong              seq        FD_PARAM_UNUSED,
            ulong *            opt_sig,
            ulong *            opt_chunk  FD_PARAM_UNUSED,
            ulong *            opt_sz     FD_PARAM_UNUSED,
            ulong *            opt_tsorig FD_PARAM_UNUSED,
            int *              opt_filter FD_PARAM_UNUSED,
            fd_mux_context_t * mux ) {
  fd_gossip_tile_ctx_t * ctx = (fd_gossip_tile_ctx_t *)_ctx;

  if ( in_idx == VOTER_IN_IDX ) {
    fd_crds_data_t vote_txn_crds;
    vote_txn_crds.discriminant          = fd_crds_data_enum_vote;
    vote_txn_crds.inner.vote.txn.raw_sz = ctx->replay_vote_txn_sz;
    memcpy( vote_txn_crds.inner.vote.txn.raw, ctx->replay_vote_txn, ctx->replay_vote_txn_sz );
    fd_txn_parse( vote_txn_crds.inner.vote.txn.raw, ctx->replay_vote_txn_sz, vote_txn_crds.inner.vote.txn.txn_buf, NULL );

    fd_gossip_push_value( ctx->gossip, &vote_txn_crds, NULL );

    static ulong sent_vote_cnt = 0;
    if ( ( ++sent_vote_cnt % 50 ) == 0 )
      FD_LOG_NOTICE(( "Gossip tile has sent %lu vote txns", sent_vote_cnt ));

    return;
  }

  ctx->mux = mux;
  ulong hdr_sz = fd_disco_netmux_sig_hdr_sz( *opt_sig );
  fd_net_hdrs_t * hdr = (fd_net_hdrs_t *)ctx->gossip_buffer;

  fd_gossip_peer_addr_t peer_addr;
  peer_addr.l    = 0;
  peer_addr.addr = FD_LOAD( uint, hdr->ip4->saddr_c );
  peer_addr.port = hdr->udp->net_sport;

  fd_gossip_recv_packet( ctx->gossip, ctx->gossip_buffer + hdr_sz, ctx->gossip_buffer_sz - hdr_sz, &peer_addr );
}

static void
after_credit( void *             _ctx,
              fd_mux_context_t * mux_ctx,
              int *              opt_poll_in ) {
  (void)opt_poll_in;

  fd_gossip_tile_ctx_t * ctx = (fd_gossip_tile_ctx_t *)_ctx;
  ctx->mux = mux_ctx;
  ulong tsorig = fd_frag_meta_ts_comp( fd_tickcount() );

  fd_mcache_seq_update( ctx->shred_contact_out_sync, ctx->shred_contact_out_seq );
  fd_mcache_seq_update( ctx->repair_contact_out_sync, ctx->repair_contact_out_seq );

  long now = fd_log_wallclock();
  if( ( now - ctx->last_shred_dest_push_time )>CONTACT_INFO_PUBLISH_TIME_NS ) {
    ctx->last_shred_dest_push_time = now;

    ulong tvu_peer_cnt = 0;
    ulong repair_peers_cnt = 0;
    ulong voter_peers_cnt = 0;

    ulong * shred_dest_msg = fd_chunk_to_laddr( ctx->shred_contact_out_mem, ctx->shred_contact_out_chunk );
    fd_shred_dest_wire_t * tvu_peers = (fd_shred_dest_wire_t *)(shred_dest_msg+1);
    fd_shred_dest_wire_t * repair_peers = fd_chunk_to_laddr( ctx->repair_contact_out_mem, ctx->repair_contact_out_chunk );
    fd_shred_dest_wire_t * voter_peers = fd_chunk_to_laddr( ctx->voter_contact_out_mem, ctx->voter_contact_out_chunk );
    for( fd_contact_info_table_iter_t iter = fd_contact_info_table_iter_init( ctx->contact_info_table );
         !fd_contact_info_table_iter_done( ctx->contact_info_table, iter );
         iter = fd_contact_info_table_iter_next( ctx->contact_info_table, iter ) ) {
      fd_contact_info_elem_t const * ele = fd_contact_info_table_iter_ele_const( ctx->contact_info_table, iter );

      if( ele->contact_info.shred_version!=fd_gossip_get_shred_version( ctx->gossip ) ) {
        continue;
      }

      {
        if( !fd_gossip_ip_addr_is_ip4( &ele->contact_info.tvu.addr ) ) {
          continue;
        }

        // TODO: add a consistency check function for IP addresses
        if( ele->contact_info.tvu.addr.inner.ip4==0 ) {
          continue;
        }

        tvu_peers[tvu_peer_cnt].ip4_addr = ele->contact_info.tvu.addr.inner.ip4;
        tvu_peers[tvu_peer_cnt].udp_port = ele->contact_info.tvu.port;
        memcpy( tvu_peers[tvu_peer_cnt].pubkey, ele->contact_info.id.key, sizeof(fd_pubkey_t) );

        tvu_peer_cnt++;
      }

      {
        if( !fd_gossip_ip_addr_is_ip4( &ele->contact_info.repair.addr ) ) {
          continue;
        }

        // TODO: add a consistency check function for IP addresses
        if( ele->contact_info.serve_repair.addr.inner.ip4 == 0 ) {
          continue;
        }

        repair_peers[repair_peers_cnt].ip4_addr = ele->contact_info.serve_repair.addr.inner.ip4;
        repair_peers[repair_peers_cnt].udp_port = ele->contact_info.serve_repair.port;
        memcpy( repair_peers[repair_peers_cnt].pubkey, ele->contact_info.id.key, sizeof(fd_pubkey_t) );

        repair_peers_cnt++;
      }

      {
        if( !fd_gossip_ip_addr_is_ip4( &ele->contact_info.tpu_vote.addr ) ) {
          continue;
        }

        // TODO: add a consistency check function for IP addresses
        if( ele->contact_info.tpu_vote.addr.inner.ip4 == 0 ) {
          continue;
        }

        voter_peers[voter_peers_cnt].ip4_addr = ele->contact_info.tpu_vote.addr.inner.ip4;
        voter_peers[voter_peers_cnt].udp_port = ele->contact_info.tpu_vote.port;
        memcpy( voter_peers[voter_peers_cnt].pubkey, ele->contact_info.id.key, sizeof(fd_pubkey_t) );

        voter_peers_cnt++;
      }
    }

    ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );

    FD_LOG_INFO(( "publishing peers - tvu: %lu, repair: %lu, tpu_vote: %lu", tvu_peer_cnt, repair_peers_cnt, voter_peers_cnt ));
    if( tvu_peer_cnt>0 ) {
      *shred_dest_msg         = tvu_peer_cnt;
      ulong shred_contact_sz  = sizeof(ulong) + (tvu_peer_cnt * sizeof(fd_shred_dest_wire_t));
      ulong shred_contact_sig = 2UL;
      fd_mcache_publish( ctx->shred_contact_out_mcache, ctx->shred_contact_out_depth, ctx->shred_contact_out_seq, shred_contact_sig, ctx->shred_contact_out_chunk,
        shred_contact_sz, 0UL, tsorig, tspub );
      ctx->shred_contact_out_seq   = fd_seq_inc( ctx->shred_contact_out_seq, 1UL );
      ctx->shred_contact_out_chunk = fd_dcache_compact_next( ctx->shred_contact_out_chunk, shred_contact_sz, ctx->shred_contact_out_chunk0, ctx->shred_contact_out_wmark );
    }

    if( repair_peers_cnt>0 ) {
      ulong repair_contact_sz  = (repair_peers_cnt * sizeof(fd_shred_dest_wire_t));
      ulong repair_contact_sig = 3UL;
      fd_mcache_publish( ctx->repair_contact_out_mcache, ctx->repair_contact_out_depth, ctx->repair_contact_out_seq, repair_contact_sig, ctx->repair_contact_out_chunk,
        repair_peers_cnt, 0UL, tsorig, tspub );
      ctx->repair_contact_out_seq   = fd_seq_inc( ctx->repair_contact_out_seq, 1UL );
      ctx->repair_contact_out_chunk = fd_dcache_compact_next( ctx->repair_contact_out_chunk, repair_contact_sz, ctx->repair_contact_out_chunk0, ctx->repair_contact_out_wmark );
    }

    if( voter_peers_cnt>0 ) {
      ulong voter_contact_sz  = (voter_peers_cnt * sizeof(fd_shred_dest_wire_t));
      ulong voter_contact_sig = 4UL;
      fd_mcache_publish( ctx->voter_contact_out_mcache, ctx->voter_contact_out_depth, ctx->voter_contact_out_seq, voter_contact_sig, ctx->voter_contact_out_chunk,
        voter_peers_cnt, 0UL, tsorig, tspub );
      ctx->voter_contact_out_seq   = fd_seq_inc( ctx->voter_contact_out_seq, 1UL );
      ctx->voter_contact_out_chunk = fd_dcache_compact_next( ctx->voter_contact_out_chunk, voter_contact_sz, ctx->voter_contact_out_chunk0, ctx->voter_contact_out_wmark );
    }
  }

  ushort shred_version = fd_gossip_get_shred_version( ctx->gossip );
  if( shred_version!=0U ) {
    *fd_shred_version = shred_version;
  }
  fd_gossip_settime( ctx->gossip, now );
  fd_gossip_continue( ctx->gossip );
}

static void
privileged_init( fd_topo_t *      topo    FD_PARAM_UNUSED,
                 fd_topo_tile_t * tile,
                 void *           scratch ) {
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_gossip_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_gossip_tile_ctx_t), sizeof(fd_gossip_tile_ctx_t) );

  uchar const * identity_key = fd_keyload_load( tile->gossip.identity_key_path, /* pubkey only: */ 1 );
  fd_memcpy( ctx->identity_public_key.uc, identity_key, sizeof(fd_pubkey_t) );

  FD_TEST( sizeof(ulong) == getrandom( &ctx->gossip_seed, sizeof(ulong), 0 ) );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {
  if( FD_UNLIKELY( tile->in_cnt != 3UL ||
                   strcmp( topo->links[ tile->in_link_id[ NET_IN_IDX   ] ].name, "net_gossip" )   ||
                   strcmp( topo->links[ tile->in_link_id[ VOTER_IN_IDX ] ].name, "voter_gossip" ) ||
                   strcmp( topo->links[ tile->in_link_id[ SIGN_IN_IDX  ] ].name, "sign_gossip" ) ) ) {
    FD_LOG_ERR(( "gossip tile has none or unexpected input links %lu %s %s",
                 tile->in_cnt, topo->links[ tile->in_link_id[ 0 ] ].name, topo->links[ tile->in_link_id[ 1 ] ].name ));
  }

  if( FD_UNLIKELY( tile->out_cnt != 5 ||
                   strcmp( topo->links[ tile->out_link_id[ SHRED_OUT_IDX  ] ].name, "crds_shred" )    ||
                   strcmp( topo->links[ tile->out_link_id[ REPAIR_OUT_IDX ] ].name, "gossip_repai" )  ||
                   strcmp( topo->links[ tile->out_link_id[ DEDUP_OUT_IDX  ] ].name, "gossip_dedup" )  ||
                   strcmp( topo->links[ tile->out_link_id[ SIGN_OUT_IDX   ] ].name, "gossip_sign" )   ||
                   strcmp( topo->links[ tile->out_link_id[ VOTER_OUT_IDX  ] ].name, "gossip_voter" ) ) ) {
    FD_LOG_ERR(( "gossip tile has none or unexpected output links %lu %s %s",
                 tile->out_cnt, topo->links[ tile->out_link_id[ 0 ] ].name, topo->links[ tile->out_link_id[ 1 ] ].name ));
  }

  if( FD_UNLIKELY( tile->out_link_id_primary==ULONG_MAX ) )
    FD_LOG_ERR(( "gossip tile has no primary output link" ));

  /* Scratch mem setup */
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_gossip_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_gossip_tile_ctx_t), sizeof(fd_gossip_tile_ctx_t) );
  ctx->gossip = FD_SCRATCH_ALLOC_APPEND( l, fd_gossip_align(), fd_gossip_footprint() );
  ctx->contact_info_table = fd_contact_info_table_join( fd_contact_info_table_new( FD_SCRATCH_ALLOC_APPEND( l, fd_contact_info_table_align(), fd_contact_info_table_footprint( FD_PEER_KEY_MAX ) ), FD_PEER_KEY_MAX, 0 ) );

  void * smem = FD_SCRATCH_ALLOC_APPEND( l, fd_scratch_smem_align(), fd_scratch_smem_footprint( SCRATCH_MAX ) );
  void * fmem = FD_SCRATCH_ALLOC_APPEND( l, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( SCRATCH_DEPTH ) );

  FD_TEST( ( !!smem ) & ( !!fmem ) );
  fd_scratch_attach( smem, fmem, SCRATCH_MAX, SCRATCH_DEPTH );

  fd_topo_link_t * net_out = &topo->links[ tile->out_link_id_primary ];

  ctx->net_out_mcache = net_out->mcache;
  ctx->net_out_sync   = fd_mcache_seq_laddr( ctx->net_out_mcache );
  ctx->net_out_depth  = fd_mcache_depth( ctx->net_out_mcache );
  ctx->net_out_seq    = fd_mcache_seq_query( ctx->net_out_sync );
  ctx->net_out_chunk0 = fd_dcache_compact_chunk0( fd_wksp_containing( net_out->dcache ), net_out->dcache );
  ctx->net_out_mem    = topo->workspaces[ topo->objs[ net_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->net_out_wmark  = fd_dcache_compact_wmark( ctx->net_out_mem, net_out->dcache, net_out->mtu );
  ctx->net_out_chunk  = ctx->net_out_chunk0;

  ctx->wksp = topo->workspaces[ topo->objs[ tile->tile_obj_id ].wksp_id ].wksp;

  ctx->gossip_my_addr.addr = tile->gossip.ip_addr;
  ctx->gossip_my_addr.port = fd_ushort_bswap( tile->gossip.gossip_listen_port );

  ctx->gossip_listen_port = tile->gossip.gossip_listen_port;

  FD_TEST( ctx->gossip_listen_port!=0 );

  ctx->net_id = (ushort)0;
  fd_memcpy( ctx->src_mac_addr, tile->gossip.src_mac_addr, 6 );

  fd_net_create_packet_header_template( ctx->hdr, FD_NET_MTU, ctx->gossip_my_addr.addr, ctx->src_mac_addr, ctx->gossip_listen_port );

  ctx->last_shred_dest_push_time = 0;

  fd_topo_link_t * sign_in  = &topo->links[ tile->in_link_id[ SIGN_IN_IDX ] ];
  fd_topo_link_t * sign_out = &topo->links[ tile->out_link_id[ SIGN_OUT_IDX ] ];
  if ( fd_keyguard_client_join( fd_keyguard_client_new( ctx->keyguard_client,
                                                            sign_out->mcache,
                                                            sign_out->dcache,
                                                            sign_in->mcache,
                                                            sign_in->dcache ) )==NULL ) {
    FD_LOG_ERR(( "Keyguard join failed" ));
  }

  /* Gossip set up */
  ctx->gossip = fd_gossip_join( fd_gossip_new( ctx->gossip, ctx->gossip_seed ) );

  FD_LOG_NOTICE(( "gossip my addr - addr: " FD_IP4_ADDR_FMT ":%u",
    FD_IP4_ADDR_FMT_ARGS( ctx->gossip_my_addr.addr ), fd_ushort_bswap( ctx->gossip_my_addr.port ) ));
  ctx->gossip_config.my_addr       = ctx->gossip_my_addr;
  ctx->gossip_config.my_version = (fd_gossip_version_v2_t){
    .from = ctx->identity_public_key,
    .major = 42U,
    .minor = 42U,
    .patch = 42U,
    .commit = 0U,
    .has_commit = 0U,
    .feature_set = 0U,
  };
  ctx->gossip_config.private_key   = ctx->identity_private_key;
  ctx->gossip_config.public_key    = &ctx->identity_public_key;
  ctx->gossip_config.deliver_fun   = gossip_deliver_fun;
  ctx->gossip_config.deliver_arg   = ctx;
  ctx->gossip_config.send_fun      = gossip_send_packet;
  ctx->gossip_config.send_arg      = ctx;
  ctx->gossip_config.sign_fun      = gossip_signer;
  ctx->gossip_config.sign_arg      = ctx;
  ctx->gossip_config.shred_version = (ushort)tile->gossip.expected_shred_version;

  if( fd_gossip_set_config( ctx->gossip, &ctx->gossip_config ) ) {
    FD_LOG_ERR( ( "error setting gossip config" ) );
  }

  fd_gossip_set_entrypoints( ctx->gossip, tile->gossip.entrypoints, tile->gossip.entrypoints_cnt, tile->gossip.peer_ports );

  fd_gossip_update_addr( ctx->gossip, &ctx->gossip_config.my_addr );

  ctx->tvu_my_addr.addr      = tile->gossip.ip_addr;
  ctx->tvu_my_addr.port      = fd_ushort_bswap( tile->gossip.tvu_port );
  ctx->tvu_my_fwd_addr.addr  = tile->gossip.ip_addr;
  ctx->tvu_my_fwd_addr.port  = fd_ushort_bswap( tile->gossip.tvu_fwd_port );
  ctx->tpu_my_addr.addr      = tile->gossip.ip_addr;
  ctx->tpu_my_addr.port      = fd_ushort_bswap( tile->gossip.tpu_port );
  ctx->tpu_vote_my_addr.addr = tile->gossip.ip_addr;
  ctx->tpu_vote_my_addr.port = fd_ushort_bswap( tile->gossip.tpu_vote_port );

  fd_gossip_update_tvu_addr( ctx->gossip, &ctx->tvu_my_addr, &ctx->tvu_my_fwd_addr );
  fd_gossip_update_tpu_addr( ctx->gossip, &ctx->tpu_my_addr, &ctx->tpu_my_addr );
  fd_gossip_update_tpu_vote_addr( ctx->gossip, &ctx->tpu_vote_my_addr );
  fd_gossip_settime( ctx->gossip, fd_log_wallclock() );
  fd_gossip_start( ctx->gossip );

  FD_LOG_NOTICE(( "gossip listening on port %u", tile->gossip.gossip_listen_port ));

  fd_topo_link_t * netmux_link = &topo->links[ tile->in_link_id[ NET_IN_IDX ] ];

  ctx->net_in_mem    = topo->workspaces[ topo->objs[ netmux_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->net_in_chunk  = fd_disco_compact_chunk0( ctx->net_in_mem );
  ctx->net_in_wmark  = fd_disco_compact_wmark( ctx->net_in_mem, netmux_link->mtu );

  fd_topo_link_t * replay_in = &topo->links[ tile->in_link_id[ VOTER_IN_IDX ] ];
  ctx->replay_in_mem    = topo->workspaces[ topo->objs[ replay_in->dcache_obj_id ].wksp_id ].wksp;
  ctx->replay_in_chunk0 = fd_dcache_compact_chunk0( ctx->replay_in_mem, replay_in->dcache );
  ctx->replay_in_wmark  = fd_dcache_compact_wmark( ctx->replay_in_mem, replay_in->dcache, replay_in->mtu );

  /* Set up shred contact info tile output */
  fd_topo_link_t * shred_contact_out = &topo->links[ tile->out_link_id[ SHRED_OUT_IDX ] ];
  ctx->shred_contact_out_mcache      = shred_contact_out->mcache;
  ctx->shred_contact_out_sync        = fd_mcache_seq_laddr( ctx->shred_contact_out_mcache );
  ctx->shred_contact_out_depth       = fd_mcache_depth( ctx->shred_contact_out_mcache );
  ctx->shred_contact_out_seq         = fd_mcache_seq_query( ctx->shred_contact_out_sync );
  ctx->shred_contact_out_mem         = topo->workspaces[ topo->objs[ shred_contact_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->shred_contact_out_chunk0      = fd_dcache_compact_chunk0( ctx->shred_contact_out_mem, shred_contact_out->dcache );
  ctx->shred_contact_out_wmark       = fd_dcache_compact_wmark ( ctx->shred_contact_out_mem, shred_contact_out->dcache, shred_contact_out->mtu );
  ctx->shred_contact_out_chunk       = ctx->shred_contact_out_chunk0;

  /* Set up repair contact info tile output */
  fd_topo_link_t * repair_contact_out = &topo->links[ tile->out_link_id[ REPAIR_OUT_IDX ] ];
  ctx->repair_contact_out_mcache      = repair_contact_out->mcache;
  ctx->repair_contact_out_sync        = fd_mcache_seq_laddr( ctx->repair_contact_out_mcache );
  ctx->repair_contact_out_depth       = fd_mcache_depth( ctx->repair_contact_out_mcache );
  ctx->repair_contact_out_seq         = fd_mcache_seq_query( ctx->repair_contact_out_sync );
  ctx->repair_contact_out_mem         = topo->workspaces[ topo->objs[ repair_contact_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->repair_contact_out_chunk0      = fd_dcache_compact_chunk0( ctx->repair_contact_out_mem, repair_contact_out->dcache );
  ctx->repair_contact_out_wmark       = fd_dcache_compact_wmark ( ctx->repair_contact_out_mem, repair_contact_out->dcache, repair_contact_out->mtu );
  ctx->repair_contact_out_chunk       = ctx->repair_contact_out_chunk0;

  /* Set up dedup tile output */
  fd_topo_link_t * dedup_out = &topo->links[ tile->out_link_id[ DEDUP_OUT_IDX ] ];
  ctx->dedup_out_mcache      = dedup_out->mcache;
  ctx->dedup_out_sync        = fd_mcache_seq_laddr( ctx->dedup_out_mcache );
  ctx->dedup_out_depth       = fd_mcache_depth( ctx->dedup_out_mcache );
  ctx->dedup_out_seq         = fd_mcache_seq_query( ctx->dedup_out_sync );
  ctx->dedup_out_mem         = topo->workspaces[ topo->objs[ dedup_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->dedup_out_chunk0      = fd_dcache_compact_chunk0( ctx->dedup_out_mem, dedup_out->dcache );
  ctx->dedup_out_wmark       = fd_dcache_compact_wmark ( ctx->dedup_out_mem, dedup_out->dcache, dedup_out->mtu );
  ctx->dedup_out_chunk       = ctx->dedup_out_chunk0;

  /* Set up crds vote voter tile output  */
  fd_topo_link_t * voter_out = &topo->links[ tile->out_link_id[ VOTER_OUT_IDX ] ];
  ctx->voter_contact_out_mcache      = voter_out->mcache;
  ctx->voter_contact_out_sync        = fd_mcache_seq_laddr( ctx->voter_contact_out_mcache );
  ctx->voter_contact_out_depth       = fd_mcache_depth( ctx->voter_contact_out_mcache );
  ctx->voter_contact_out_seq         = fd_mcache_seq_query( ctx->voter_contact_out_sync );
  ctx->voter_contact_out_mem         = topo->workspaces[ topo->objs[ voter_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->voter_contact_out_chunk0      = fd_dcache_compact_chunk0( ctx->voter_contact_out_mem, voter_out->dcache );
  ctx->voter_contact_out_wmark       = fd_dcache_compact_wmark ( ctx->voter_contact_out_mem, voter_out->dcache, voter_out->mtu );
  ctx->voter_contact_out_chunk       = ctx->voter_contact_out_chunk0;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top>( (ulong)scratch + scratch_footprint( tile ) ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));

  ulong poh_shred_obj_id = fd_pod_query_ulong( topo->props, "poh_shred", ULONG_MAX );
  FD_TEST( poh_shred_obj_id!=ULONG_MAX );

  fd_shred_version = fd_fseq_join( fd_topo_obj_laddr( topo, poh_shred_obj_id ) );
  FD_TEST( fd_shred_version );
}

static ulong
populate_allowed_seccomp( void *               scratch FD_PARAM_UNUSED,
                          ulong                out_cnt,
                          struct sock_filter * out ) {
  populate_sock_filter_policy_gossip( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_gossip_instr_cnt;
}

static ulong
populate_allowed_fds( void * scratch      FD_PARAM_UNUSED,
                      ulong  out_fds_cnt,
                      int *  out_fds ) {
  if( FD_UNLIKELY( out_fds_cnt<2 ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

fd_topo_run_tile_t fd_tile_gossip = {
  .name                     = "gossip",
  .mux_flags                = FD_MUX_FLAG_MANUAL_PUBLISH | FD_MUX_FLAG_COPY,
  .burst                    = 1UL,
  .loose_footprint          = loose_footprint,
  .mux_ctx                  = mux_ctx,
  .mux_after_credit         = after_credit,
  .mux_before_frag          = before_frag,
  .mux_during_frag          = during_frag,
  .mux_after_frag           = after_frag,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
};
