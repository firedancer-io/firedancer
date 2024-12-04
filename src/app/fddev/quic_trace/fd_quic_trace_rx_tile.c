/* fd_quic_trace_rx_tile.c does passive decryption of incoming QUIC
   packets.

   It mocks the setup procedure and run loop of a real fd_quic_tile. */

#include "fd_quic_trace.h"
#include "../../../waltz/quic/fd_quic_private.h"
#include "../../../waltz/quic/templ/fd_quic_parse_util.h"
#include "../../../waltz/quic/fd_quic_proto.c"
#include "../../../util/net/fd_eth.h"
#include "../../../util/net/fd_ip4.h"
#include "../../../util/net/fd_udp.h"

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  fd_quic_state_t * state = fd_quic_get_state( fd_quic_trace_ctx.quic );
  FD_LOG_INFO(( "fd_quic_t conn_map raddr %p", (void *)state->conn_map ));
  FD_LOG_INFO(( "fd_quic_t conn map laddr %p", (void *)translate_ptr( state->conn_map ) ));
  (void)topo; (void)tile;
}

static int
before_frag( void * _ctx FD_FN_UNUSED,
             ulong  in_idx,
             ulong  seq,
             ulong  sig ) {
  (void)sig;

  /* Skip non-QUIC packets */
  ulong proto = fd_disco_netmux_sig_proto( sig );
  if( proto!=DST_PROTO_TPU_QUIC ) return 1;

  /* Delay receive until fd_quic_tile is caught up */
  ulong * tgt_fseq = fd_quic_trace_target_fseq[ in_idx ];
  for(;;) {
    ulong tgt_seq = fd_fseq_query( tgt_fseq );
    if( FD_LIKELY( tgt_seq>=seq ) ) break;
    FD_SPIN_PAUSE();
  }

  return 0;
}

static void
during_frag( void * _ctx FD_FN_UNUSED,
             ulong  in_idx,
             ulong  seq,
             ulong  sig,
             ulong  chunk,
             ulong  sz ) {
  (void)in_idx; (void)seq; (void)sig;
  fd_quic_ctx_t * ctx = &fd_quic_trace_ctx;
  fd_memcpy( ctx->buffer, (uchar *)fd_chunk_to_laddr( ctx->in_mem, chunk ), sz );
}

static void
fd_quic_trace_1rtt( uchar * data,
                    ulong   data_sz,
                    uint    ip4_saddr,
                    ushort  udp_sport ) {
  fd_quic_ctx_t *      ctx      = &fd_quic_trace_ctx;
  fd_quic_t *          quic     = ctx->quic;
  fd_quic_state_t *    state    = fd_quic_get_state( quic );
  fd_quic_conn_map_t * conn_map = translate_ptr( state->conn_map );

  if( FD_UNLIKELY( data_sz < FD_QUIC_SHORTEST_PKT ) ) return;

  /* Look up conn */
  ulong dst_conn_id = fd_ulong_load_8( data+1 );
  fd_quic_conn_map_t * conn_entry = fd_quic_conn_map_query( conn_map, dst_conn_id, NULL );
  if( !conn_entry ) return;
  fd_quic_conn_t *        conn = translate_ptr( conn_entry->conn );
  fd_quic_crypto_keys_t * keys = &conn->keys[ fd_quic_enc_level_appdata_id ][ 0 ];

  ulong pkt_number_off = 9UL;
  int hdr_err = fd_quic_crypto_decrypt_hdr( data, data_sz, pkt_number_off, keys );
  if( hdr_err!=FD_QUIC_SUCCESS ) return;

  ulong pkt_num_sz = fd_quic_h0_pkt_num_len( data[0] )+1u;
  ulong pkt_number = fd_quic_pktnum_decode( data+9UL, pkt_num_sz );
  int crypt_err = fd_quic_crypto_decrypt( data, data_sz, pkt_number_off, pkt_number, keys );
  if( crypt_err!=FD_QUIC_SUCCESS ) return;

  ulong hdr_sz  = pkt_number_off + pkt_num_sz;
  ulong wrap_sz = hdr_sz + FD_QUIC_CRYPTO_TAG_SZ;
  if( FD_UNLIKELY( data_sz<wrap_sz ) ) return;

  fd_quic_trace_frame_ctx_t frame_ctx = {
    .conn_id  = dst_conn_id,
    .pkt_num  = pkt_number,
    .src_ip   = ip4_saddr,
    .src_port = udp_sport,
  };
  fd_quic_trace_frames( &frame_ctx, data+hdr_sz, data_sz-wrap_sz );

  (void)ip4_saddr; (void)conn;
}

static uchar *
fd_quic_trace_initial( uchar * data,
                       ulong   data_sz,
                       uint    ip4_saddr FD_PARAM_UNUSED,
                       ushort  udp_sport FD_PARAM_UNUSED ) {
  uchar * end = data+data_sz;

  fd_quic_initial_t initial[1];
  ulong rc = fd_quic_decode_initial( initial, data, data_sz );
  if( FD_UNLIKELY( rc==FD_QUIC_PARSE_FAIL ) ) return end;
  fd_quic_conn_id_t dcid = fd_quic_conn_id_new( initial->dst_conn_id, initial->dst_conn_id_len );

  ulong pktnum_off = initial->pkt_num_pnoff;
  ulong len        = (ulong)( pktnum_off + initial->len );
  if( FD_UNLIKELY( len>data_sz ) ) return end;

  fd_quic_crypto_secrets_t secrets[1];
  fd_quic_crypto_keys_t    keys[FD_QUIC_NUM_ENC_LEVELS][2];
  fd_quic_gen_initial_secret_and_keys( secrets, keys, &dcid );

  if( FD_UNLIKELY( fd_quic_crypto_decrypt_hdr( data, len, pktnum_off, &keys[0][0] ) != FD_QUIC_SUCCESS ) ) {
    return end;
  }

  ulong pktnum_sz   = fd_quic_h0_pkt_num_len( data[0] ) + 1u;
  ulong pktnum_comp = fd_quic_pktnum_decode( data+pktnum_off, pktnum_sz );
  ulong pktnum      = fd_quic_reconstruct_pkt_num( pktnum_comp, pktnum_sz, 1UL /* FIXME */ );

  if( FD_UNLIKELY( fd_quic_crypto_decrypt( data, len, pktnum_off, pktnum, &keys[0][0] ) != FD_QUIC_SUCCESS ) ) {
    return end;
  }

  ulong hdr_sz  = pktnum_off + pktnum_sz;
  ulong wrap_sz = hdr_sz + FD_QUIC_CRYPTO_TAG_SZ;
  if( FD_UNLIKELY( len<wrap_sz ) ) return end;
  ulong body_sz = len-wrap_sz;

  fd_quic_trace_frame_ctx_t frame_ctx = {
    .pkt_num  = pktnum,
    .src_ip   = ip4_saddr,
    .src_port = udp_sport,
  };
  fd_quic_trace_frames( &frame_ctx, data+hdr_sz, body_sz );

  return data+len;
}

static void
fd_quic_trace_pkt( fd_quic_ctx_t * const ctx FD_PARAM_UNUSED,
                   uchar *         const data,
                   ulong           const data_sz,
                   uint            const ip4_saddr,
                   ushort          const udp_sport ) {
  uchar * cur = data;
  uchar * end = data+data_sz;
  while( cur<end ) {
    ulong cur_sz = (ulong)(end-cur);
    int is_long = fd_quic_h0_hdr_form( cur[0] );
    if( is_long ) {
      uint long_type = fd_quic_h0_long_packet_type( cur[0] );
      if( long_type==FD_QUIC_PKT_TYPE_INITIAL ) {
        cur = fd_quic_trace_initial( cur, cur_sz, ip4_saddr, udp_sport );
      } else {
        /* FIXME todo */
        break;
      }
    } else {
      fd_quic_trace_1rtt( cur, cur_sz, ip4_saddr, udp_sport );
      break;
    }
  }
}

static void
after_frag( void * _ctx FD_FN_UNUSED,
            ulong  in_idx,
            ulong  seq,
            ulong  sig,
            ulong  sz,
            ulong  tsorig,
            fd_stem_context_t * stem ) {
  (void)in_idx; (void)seq; (void)sig; (void)sz; (void)tsorig; (void)stem;

  fd_quic_ctx_t * ctx = &fd_quic_trace_ctx;

  if( sz < FD_QUIC_SHORTEST_PKT ) return;
  if( sz > sizeof(ctx->buffer)  ) return;

  uchar * cur  = ctx->buffer;
  uchar * end  = cur+sz;

  fd_eth_hdr_t const * eth_hdr = fd_type_pun_const( cur );
  cur += sizeof(fd_eth_hdr_t);
  if( FD_UNLIKELY( cur>end ) ) return;
  if( FD_UNLIKELY( fd_ushort_bswap( eth_hdr->net_type )!=FD_ETH_HDR_TYPE_IP ) ) return;

  fd_ip4_hdr_t const * ip4_hdr = fd_type_pun_const( cur );
  if( FD_UNLIKELY( cur+sizeof(fd_ip4_hdr_t) > end ) ) return;
  cur += FD_IP4_GET_LEN( *ip4_hdr );
  if( FD_UNLIKELY( cur>end ) ) return;
  if( FD_UNLIKELY( ip4_hdr->protocol!=FD_IP4_HDR_PROTOCOL_UDP ) ) return;

  fd_udp_hdr_t const * udp_hdr = fd_type_pun_const( cur );
  if( FD_UNLIKELY( cur+sizeof(fd_udp_hdr_t) > end ) ) return;
  cur += sizeof(fd_udp_hdr_t);
  if( FD_UNLIKELY( cur>end ) ) return;
  (void)udp_hdr;

  uint   ip4_saddr = fd_uint_load_4( ip4_hdr->saddr_c );
  ushort udp_sport = fd_ushort_bswap( udp_hdr->net_sport );
  fd_quic_trace_pkt( ctx, cur, (ulong)( end-cur ), ip4_saddr, udp_sport );
}


#define STEM_BURST (1UL)
#define STEM_CALLBACK_CONTEXT_TYPE  void
#define STEM_CALLBACK_CONTEXT_ALIGN 1
#define STEM_CALLBACK_BEFORE_FRAG   before_frag
#define STEM_CALLBACK_DURING_FRAG   during_frag
#define STEM_CALLBACK_AFTER_FRAG    after_frag
#include "../../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_quic_trace_rx = {
  .name            = "quic-trace-rx",
  .privileged_init = privileged_init,
  .run             = stem_run,
};
