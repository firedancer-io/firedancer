/* fd_quic_trace_rx_tile.c does passive decryption of incoming QUIC
   packets.

   It mocks the setup procedure and run loop of a real fd_quic_tile. */

#include "fd_quic_trace.h"

#include "../../../../waltz/quic/fd_quic_private.h"
#include "../../../../waltz/quic/templ/fd_quic_parse_util.h"
#include "../../../../waltz/quic/fd_quic_proto.c"
#include "../../../../util/net/fd_eth.h"
#include "../../../../util/net/fd_ip4.h"
#include "../../../../util/net/fd_udp.h"

static int
before_frag( fd_quic_trace_ctx_t * ctx,
             ulong                 in_idx FD_FN_UNUSED,
             ulong                 seq    FD_FN_UNUSED,
             ulong                 sig ) {
  /* Skip non-QUIC packets, based on the tile we target */
  ulong proto = fd_disco_netmux_sig_proto( sig );
  int   send  = ctx->trace_send;

  switch( proto ) {
    case DST_PROTO_OUTGOING:
      return 0;
    case DST_PROTO_TPU_QUIC:
      return send;
    case DST_PROTO_SEND:
      return !send;
    default:
        return 1;
  }

  return 0;
}

static void
during_frag( fd_quic_trace_ctx_t * ctx,
             ulong                 in_idx FD_PARAM_UNUSED,
             ulong                 seq    FD_PARAM_UNUSED,
             ulong                 sig,
             ulong                 chunk,
             ulong                 sz,
             ulong                 ctl ) {
  ulong proto = fd_disco_netmux_sig_proto( sig );
  if( (proto==DST_PROTO_TPU_QUIC) | (proto==DST_PROTO_SEND) ) {
    fd_memcpy( ctx->buffer, fd_net_rx_translate_frag( &ctx->net_in_bounds[0], chunk, ctl, sz ), sz );
  } else if( proto == DST_PROTO_OUTGOING ) {
    ulong p = ctx->net_out_base + (chunk<<FD_CHUNK_LG_SZ);
    fd_memcpy( ctx->buffer, (void*)p, sz );
  }
}

static int
bounds_check_conn( fd_quic_t      const * quic,
                   fd_quic_conn_t const * conn ) {
  long conn_off = (long)((ulong)conn-(ulong)quic);
  return conn_off >= (long)quic->layout.conns_off && conn_off < (long)quic->layout.conn_map_off;
}

static ulong
fd_quic_trace_initial( fd_quic_trace_ctx_t * ctx,
                       uchar *               data,
                       ulong                 data_sz,
                       uint                  ip4_saddr,
                       ushort                udp_sport,
                       uint                  ip4_daddr,
                       ushort                udp_dport,
                       uint                  key_idx ) {
  fd_quic_t          * quic     = ctx->quic;
  fd_quic_state_t    * state    = fd_quic_get_state( quic );
  fd_quic_conn_map_t * conn_map = translate_ptr( state->conn_map );

  if( FD_UNLIKELY( data_sz < FD_QUIC_SHORTEST_PKT ) ) return FD_QUIC_PARSE_FAIL;

  fd_quic_initial_t initial[1] = {0};
  ulong rc = fd_quic_decode_initial( initial, data, data_sz );
  if( FD_UNLIKELY( rc == FD_QUIC_PARSE_FAIL ) ) {
    FD_LOG_DEBUG(( "fd_quic_decode_initial failed" ));
    return FD_QUIC_PARSE_FAIL;
  }
  ulong len = (ulong)( initial->pkt_num_pnoff + initial->len );
  if( FD_UNLIKELY( len > data_sz ) ) {
    FD_LOG_DEBUG(( "Bogus initial packet length" ));
    return FD_QUIC_PARSE_FAIL;
  }
  if( FD_UNLIKELY( initial->dst_conn_id_len > 20 ) ) {
    FD_LOG_DEBUG(( "Bogus destination connection id length: %u", (uint)initial->dst_conn_id_len ));
  }

  uint conn_idx = ~0u;
  fd_quic_crypto_keys_t _keys[1];
  fd_quic_crypto_keys_t const * keys = NULL;
  if( initial->dst_conn_id_len == FD_QUIC_CONN_ID_SZ ) {
    ulong conn_id = key_idx == 0 ? fd_ulong_load_8( initial->dst_conn_id )
                                 : fd_ulong_load_8( initial->src_conn_id );
    if( conn_id==0 ) return FD_QUIC_PARSE_FAIL;

    fd_quic_conn_map_t * conn_entry = fd_quic_conn_map_query( conn_map, conn_id, NULL );
    if( conn_entry && conn_entry->conn ) {
      fd_quic_conn_t * conn = translate_ptr( conn_entry->conn );
      if( FD_LIKELY( bounds_check_conn( quic, conn ) ) ) {
        conn_idx = conn->conn_idx;
        keys     = &conn->keys[fd_quic_enc_level_initial_id][key_idx];

#       define EMPTY ((uchar[16]){0})
        /* assume this is a new connection, since this is an Initial packet */
        if( keys && memcmp( keys->pkt_key, EMPTY, sizeof( keys->pkt_key ) ) != 0 ) {
          /* load the appropriate cid into peer_conn_id */
          ulong peer_conn_id = key_idx == 0 ? fd_ulong_load_8( initial->src_conn_id )
                                            : fd_ulong_load_8( initial->dst_conn_id );

          /* insert into peer_cid map */
          peer_conn_id_map_t * entry = peer_conn_id_map_insert( fd_quic_trace_peer_map, peer_conn_id );

          /* NULL entry either implies already exists, or full */
          if( entry ) {
            entry->conn_idx = conn->conn_idx;
          }
        }
      } else {
        FD_LOG_WARNING(( "conn out of bounds in fd_quic_trace_initial for conn id %lu with key idx %u", conn_id, key_idx ));
      }
    } else {
      FD_LOG_DEBUG(( "Failed to find conn for conn id %lu with key idx %u", conn_id, key_idx ));
    }
  }

  if( !keys || memcmp( keys->pkt_key, EMPTY, sizeof( keys->pkt_key ) ) == 0 ) {
    int is_client = ctx->trace_send;
    int is_egress = (int)key_idx;

    /* (server,egress) and (client,ingress) don't have the client's orig DCID avail */
    if( is_client==is_egress ) {
      fd_quic_crypto_secrets_t secrets[1];
      fd_quic_gen_initial_secrets(
          secrets,
          initial->dst_conn_id, initial->dst_conn_id_len,
          !is_client );

      /* Derive decryption key */
      fd_quic_gen_keys( _keys, secrets->secret[fd_quic_enc_level_initial_id][key_idx] );
      keys = _keys;
    }
  }

  if( !keys ) return FD_QUIC_PARSE_FAIL;

  ulong pktnum_off = initial->pkt_num_pnoff;
  int hdr_err = fd_quic_crypto_decrypt_hdr( data, data_sz, pktnum_off, keys );
  if( hdr_err!=FD_QUIC_SUCCESS ) return FD_QUIC_PARSE_FAIL;

  ulong pktnum_sz   = fd_quic_h0_pkt_num_len( data[0] )+1u;
  ulong pktnum_comp = fd_quic_pktnum_decode( data+pktnum_off, pktnum_sz );
  ulong pktnum      = pktnum_comp;  /* don't bother decompressing since initial pktnum is usually low */

  ulong body_sz     = initial->len;  /* length of packet number, frames, and auth tag */
  ulong tot_sz      = pktnum_off + body_sz;

  if( tot_sz > data_sz ) return FD_QUIC_PARSE_FAIL;

  int crypt_err = fd_quic_crypto_decrypt( data, tot_sz, pktnum_off, pktnum, keys );
  if( crypt_err!=FD_QUIC_SUCCESS ) {
    return FD_QUIC_PARSE_FAIL;
  }

  ulong hdr_sz  = pktnum_off + pktnum_sz;
  ulong wrap_sz = hdr_sz + FD_QUIC_CRYPTO_TAG_SZ;
  if( FD_UNLIKELY( data_sz<wrap_sz ) ) return FD_QUIC_PARSE_FAIL;

  if( ctx->dump ) {
    fd_quic_pretty_print_t quic_pkt_ctx = {
      .ip4_saddr = ip4_saddr,
      .udp_sport = udp_sport,
      .ip4_daddr = ip4_daddr,
      .udp_dport = udp_dport,
      .flow      = key_idx,
      .conn_idx  = conn_idx };
    fd_quic_pretty_print_quic_pkt( &quic_pkt_ctx,
                                   fd_quic_get_state( quic )->now,
                                   data,
                                   tot_sz );
    fflush( stdout );
  } else {
    uchar conn_id_truncated[24] = {0};
    fd_memcpy( conn_id_truncated, initial->dst_conn_id, initial->dst_conn_id_len );
    fd_quic_trace_frame_ctx_t frame_ctx = {
      .conn_id  = fd_ulong_load_8( &initial->dst_conn_id_len ),
      .pkt_num  = pktnum,
      .src_ip   = ip4_saddr,
      .src_port = udp_sport,
      .pkt_type = FD_QUIC_PKT_TYPE_INITIAL
    };

    fd_quic_trace_frames( &frame_ctx, data+hdr_sz, tot_sz-wrap_sz );
  }

  return tot_sz;
}

static ulong
fd_quic_trace_handshake( fd_quic_trace_ctx_t * ctx,
                         uchar *               data,
                         ulong                 data_sz,
                         uint                  ip4_saddr,
                         ushort                udp_sport,
                         uint                  ip4_daddr,
                         ushort                udp_dport,
                         uint                  key_idx ) {
  fd_quic_t *          quic     = ctx->quic;
  fd_quic_state_t *    state    = fd_quic_get_state( quic );
  fd_quic_conn_map_t * conn_map = translate_ptr( state->conn_map );

  if( FD_UNLIKELY( data_sz < FD_QUIC_SHORTEST_PKT ) ) return FD_QUIC_PARSE_FAIL;

  fd_quic_handshake_t handshake[1] = {0};
  ulong rc = fd_quic_decode_handshake( handshake, data, data_sz );
  if( FD_UNLIKELY( rc == FD_QUIC_PARSE_FAIL ) ) {
    FD_LOG_DEBUG(( "fd_quic_decode_handshake failed" ));
    return FD_QUIC_PARSE_FAIL;
  }
  ulong len = (ulong)( handshake->pkt_num_pnoff + handshake->len );
  if( FD_UNLIKELY( len > data_sz ) ) {
    FD_LOG_DEBUG(( "Bogus handshake packet length" ));
    return FD_QUIC_PARSE_FAIL;
  }

  /* need conn_idx */
  uint conn_idx = ~0u;

  /* keeping this logic similar to the equivalent in fd_quic_trace_initial */
  /* for future merging */
  fd_quic_crypto_keys_t const * keys = NULL;
  if( handshake->dst_conn_id_len == FD_QUIC_CONN_ID_SZ ) {
    ulong conn_id = key_idx == 0 ? fd_ulong_load_8( handshake->dst_conn_id )
                                 : fd_ulong_load_8( handshake->src_conn_id );
    if( conn_id==0 ) return FD_QUIC_PARSE_FAIL;
    fd_quic_conn_map_t * conn_entry = fd_quic_conn_map_query( conn_map, conn_id, NULL );
    if( conn_entry && conn_entry->conn ) {
      fd_quic_conn_t * conn = translate_ptr( conn_entry->conn );
      if( FD_LIKELY( bounds_check_conn( quic, conn ) ) ) {
        keys     = &conn->keys[fd_quic_enc_level_handshake_id][key_idx];
        conn_idx = conn->conn_idx;
      }
    }
  }
  if( !keys || memcmp( keys->pkt_key, EMPTY, sizeof( keys->pkt_key ) ) == 0 ) {
    return FD_QUIC_PARSE_FAIL;
  }

  ulong pktnum_off = handshake->pkt_num_pnoff;
  int hdr_err = fd_quic_crypto_decrypt_hdr( data, data_sz, pktnum_off, keys );
  if( hdr_err!=FD_QUIC_SUCCESS ) return FD_QUIC_PARSE_FAIL;

  ulong pktnum_sz   = fd_quic_h0_pkt_num_len( data[0] )+1u;
  ulong pktnum_comp = fd_quic_pktnum_decode( data+pktnum_off, pktnum_sz );
  ulong pktnum      = pktnum_comp; /* TODO decompress */

  ulong body_sz     = handshake->len;  /* length of packet number, frames, and auth tag */
  ulong tot_sz      = pktnum_off + body_sz;

  if( tot_sz > data_sz ) return FD_QUIC_PARSE_FAIL;

  int crypt_err = fd_quic_crypto_decrypt( data, data_sz, pktnum_off, pktnum, keys );
  if( crypt_err!=FD_QUIC_SUCCESS ) return FD_QUIC_PARSE_FAIL;

  ulong hdr_sz  = pktnum_off + pktnum_sz;
  ulong wrap_sz = hdr_sz + FD_QUIC_CRYPTO_TAG_SZ;
  if( FD_UNLIKELY( data_sz<wrap_sz ) ) return FD_QUIC_PARSE_FAIL;

  if( ctx->dump ) {
    fd_quic_pretty_print_t quic_pkt_ctx = {
      .ip4_saddr = ip4_saddr,
      .udp_sport = udp_sport,
      .ip4_daddr = ip4_daddr,
      .udp_dport = udp_dport,
      .flow      = key_idx,
      .conn_idx  = conn_idx };
    fd_quic_pretty_print_quic_pkt( &quic_pkt_ctx,
                                   fd_quic_get_state( quic )->now,
                                   data,
                                   data_sz );
    fflush( stdout );
  } else {
    uchar conn_id_truncated[8] = {0};
    fd_memcpy( conn_id_truncated, handshake->dst_conn_id, 8 );
    fd_quic_trace_frame_ctx_t frame_ctx = {
      .conn_id  = fd_ulong_load_8( conn_id_truncated ),
      .pkt_num  = pktnum,
      .src_ip   = ip4_saddr,
      .src_port = udp_sport,
      .pkt_type = FD_QUIC_PKT_TYPE_HANDSHAKE
    };

    fd_quic_trace_frames( &frame_ctx, data+hdr_sz, data_sz-wrap_sz );
  }

  return FD_QUIC_PARSE_FAIL;
}

static void
fd_quic_trace_1rtt( fd_quic_trace_ctx_t * ctx,
                    uchar *               data,
                    ulong                 data_sz,
                    uint                  ip4_saddr,
                    ushort                udp_sport,
                    uint                  ip4_daddr,
                    ushort                udp_dport,
                    uint                  key_idx ) {
  fd_quic_t *          quic     = ctx->quic;
  fd_quic_state_t *    state    = fd_quic_get_state( quic );
  fd_quic_conn_map_t * conn_map = translate_ptr( state->conn_map );

  if( FD_UNLIKELY( data_sz < FD_QUIC_SHORTEST_PKT ) ) return;

  fd_quic_conn_t const * conn        = NULL;
  ulong                  dst_conn_id = 0UL;

  /* key_idx 0 is ingress, key_idx 1 is egress */
  if( key_idx == 0 ) {
    /* Look up conn */
    dst_conn_id = fd_ulong_load_8( data+1 );
    fd_quic_conn_map_t * conn_entry = fd_quic_conn_map_query( conn_map, dst_conn_id, NULL );

    if( conn_entry && dst_conn_id && conn_entry->conn ) {
      conn = translate_ptr( conn_entry->conn );
      if( FD_UNLIKELY( !bounds_check_conn( quic, conn ) ) ) return;
    }
  } else {

    /* we use the first 8 bytes of the peer conn_id for the key
       since we don't actually know the length */

    ulong peer_conn_id = fd_ulong_load_8( data+1 );

    /* look up connection id in peer conn_id map */
    uint                 conn_idx = 0;
    peer_conn_id_map_t * peer_entry = peer_conn_id_map_query( fd_quic_trace_peer_map, peer_conn_id, NULL );

    if( FD_LIKELY( peer_entry ) ) {
      conn_idx = peer_entry->conn_idx;
    } else {
      /* report packet with unavailable connection */
      char time_str[FD_LOG_WALLCLOCK_CSTR_BUF_SZ];
      printf( "{ "
              "\"type\": \"packet\", "
              "\"flow\": \"%s\", "
              "\"trace_time\": \"%s\", "
              "\"src_ip_addr\": \"" FD_IP4_ADDR_FMT "\", "
              "\"src_udp_port\": \"%u\", "
              "\"dst_ip_addr\": \"" FD_IP4_ADDR_FMT "\", "
              "\"dst_udp_port\": \"%u\", "
              "\"hdr_type\": \"1-rtt\", "
              "\"err\": \"no-trace-connection\", "
              "\"dst_conn_id\": \"%lx\" "
              "}, ] }\n",
         key_idx == 0 ? "ingress" : "egress",
         fd_log_wallclock_cstr( fd_log_wallclock(), time_str ),
         FD_IP4_ADDR_FMT_ARGS( ip4_saddr ),
         (uint)udp_sport,
         FD_IP4_ADDR_FMT_ARGS( ip4_daddr ),
         (uint)udp_dport,
         peer_conn_id
        );
      return;
    }

    conn = fd_quic_trace_conn_at_idx( quic, conn_idx );
  }

  if( !conn ) return;

  fd_quic_crypto_keys_t const * keys = &conn->keys[ fd_quic_enc_level_appdata_id ][ key_idx ];

  ulong pktnum_off = 9UL;
  int hdr_err = fd_quic_crypto_decrypt_hdr( data, data_sz, pktnum_off, keys );
  if( hdr_err!=FD_QUIC_SUCCESS ) return;

  ulong pktnum_sz   = fd_quic_h0_pkt_num_len( data[0] )+1u;
  ulong pktnum_comp = fd_quic_pktnum_decode( data+9UL, pktnum_sz );
  ulong pktnum      = fd_quic_reconstruct_pkt_num( pktnum_comp, pktnum_sz, conn->exp_pkt_number[2] );
  int crypt_err = fd_quic_crypto_decrypt( data, data_sz, pktnum_off, pktnum, keys );
  if( crypt_err!=FD_QUIC_SUCCESS ) return;

  ulong hdr_sz  = pktnum_off + pktnum_sz;
  ulong wrap_sz = hdr_sz + FD_QUIC_CRYPTO_TAG_SZ;
  if( FD_UNLIKELY( data_sz<wrap_sz ) ) return;

  if( ctx->dump ) {
    fd_quic_pretty_print_t quic_pkt_ctx = {
      .ip4_saddr = ip4_saddr,
      .udp_sport = udp_sport,
      .ip4_daddr = ip4_daddr,
      .udp_dport = udp_dport,
      .flow      = key_idx,
      .conn_idx  = conn->conn_idx };
    fd_quic_pretty_print_quic_pkt( &quic_pkt_ctx,
                                   fd_quic_get_state( quic )->now,
                                   data,
                                   data_sz );
    fflush( stdout );
  } else if( key_idx == 0 ) {
    fd_quic_trace_frame_ctx_t frame_ctx = {
      .conn_id  = dst_conn_id,
      .pkt_num  = pktnum,
      .src_ip   = ip4_saddr,
      .src_port = udp_sport,
      .pkt_type = FD_QUIC_PKT_TYPE_ONE_RTT
    };

    fd_quic_trace_frames( &frame_ctx, data+hdr_sz, data_sz-wrap_sz );
  }
}

static int
is_valid_quic_long_hdr( uchar* data ) {
  if( data[0]>>6 != 0x3 ) return 0;
  uint version = fd_uint_bswap( FD_LOAD( uint, data + 1 ) );
  if( version != 1 ) return 0;

  return 1;
}

static void
fd_quic_trace_pkt( fd_quic_trace_ctx_t * ctx,
                   uchar               * data,
                   ulong                 data_sz,
                   uint                  ip4_saddr,
                   ushort                udp_sport,
                   uint                  ip4_daddr,
                   ushort                udp_dport,
                   uint                  key_idx ) {

  uchar * cur_ptr = data;
  uchar * end_ptr = data + data_sz;
  while( cur_ptr < end_ptr ) {
    int is_long = fd_quic_h0_hdr_form( cur_ptr[0] );
    ulong sz = 0;
    if( is_long ) {
      if( !is_valid_quic_long_hdr( cur_ptr ) ) {
        FD_LOG_NOTICE(( "Invalid quic long hdr with key_idx %u (maybe udp)", key_idx ));
        return;
      };
      switch( fd_quic_h0_long_packet_type( cur_ptr[0] ) ) {
        case FD_QUIC_PKT_TYPE_INITIAL:
          sz = fd_quic_trace_initial( ctx, cur_ptr, (ulong)( end_ptr - cur_ptr ), ip4_saddr, udp_sport, ip4_daddr, udp_dport, key_idx );
          break;
        case FD_QUIC_PKT_TYPE_HANDSHAKE:
          sz = fd_quic_trace_handshake( ctx, cur_ptr, (ulong)( end_ptr - cur_ptr ), ip4_saddr, udp_sport, ip4_daddr, udp_dport, key_idx );
          break;
        case FD_QUIC_PKT_TYPE_RETRY:
          /* TODO fd_quic_trace_retry */
          FD_LOG_NOTICE(( "%s retry packet of data_sz %lu, src: " FD_IP4_ADDR_FMT ":%u, dst: " FD_IP4_ADDR_FMT ":%u", key_idx==0 ? "Received" : "Sent", (ulong)( end_ptr - cur_ptr ), FD_IP4_ADDR_FMT_ARGS( ip4_saddr ), udp_sport, FD_IP4_ADDR_FMT_ARGS( ip4_daddr ), udp_dport ));
          return;
        default:
          FD_LOG_NOTICE(( "Unknown long packet type with key_idx %u, data_sz %lu, src: " FD_IP4_ADDR_FMT ":%u, dst: " FD_IP4_ADDR_FMT ":%u", key_idx, (ulong)( end_ptr - cur_ptr ), FD_IP4_ADDR_FMT_ARGS( ip4_saddr ), udp_sport, FD_IP4_ADDR_FMT_ARGS( ip4_daddr ), udp_dport ));
          return;
      }

      /* TODO TX should support FD_QUIC_PKT_TYPE_RETRY */
      /* FD_QUIC_PKT_TYPE_RETRY    as the server, we shouldn't be receiving RETRY packets */
      /* FD_QUIC_PKT_TYPE_ZERO_RTT we don't support 0-RTT packets */
    } else {
      fd_quic_trace_1rtt( ctx, cur_ptr, (ulong)( end_ptr - cur_ptr ), ip4_saddr, udp_sport, ip4_daddr, udp_dport, key_idx );
      /* one-rtt packets are last in the datagram */
      break;
    }

    if( sz == 0 || sz == FD_QUIC_PARSE_FAIL ) break;

    cur_ptr += sz;
  }
}

static void
after_frag( fd_quic_trace_ctx_t * ctx,
            ulong                 in_idx FD_PARAM_UNUSED,
            ulong                 seq    FD_PARAM_UNUSED,
            ulong                 sig,
            ulong                 sz,
            ulong                 tsorig FD_PARAM_UNUSED,
            ulong                 tspub  FD_PARAM_UNUSED,
            fd_stem_context_t   * stem   FD_PARAM_UNUSED ) {
  ulong proto   = fd_disco_netmux_sig_proto( sig );
  uint  key_idx = proto==DST_PROTO_OUTGOING ? 1 : 0;

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

  uint   ip4_saddr = fd_uint_load_4( ip4_hdr->saddr_c );
  ushort udp_sport = fd_ushort_bswap( udp_hdr->net_sport );
  uint   ip4_daddr = fd_uint_load_4( ip4_hdr->daddr_c );
  ushort udp_dport = fd_ushort_bswap( udp_hdr->net_dport );
  fd_quic_trace_pkt( ctx, cur, (ulong)( end-cur ), ip4_saddr, udp_sport, ip4_daddr, udp_dport, key_idx );
}


#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_quic_trace_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_quic_trace_ctx_t)

#define STEM_CALLBACK_BEFORE_FRAG   before_frag
#define STEM_CALLBACK_DURING_FRAG   during_frag
#define STEM_CALLBACK_AFTER_FRAG    after_frag

#include "../../../../disco/stem/fd_stem.c"

void
fd_quic_trace_rx_tile( fd_quic_trace_ctx_t  * trace_ctx,
                       fd_frag_meta_t const * rx_mcache,
                       fd_frag_meta_t const * tx_mcache ) {

  uchar   fseq_mem[ FD_FSEQ_FOOTPRINT*2 ] __attribute__((aligned(FD_FSEQ_ALIGN)));
  ulong * fseq_tbl[2] = {0};
  for( uint j = 0; j < 2; ++j ){
    ulong * fseq = fd_fseq_join( fd_fseq_new( fseq_mem + j * FD_FSEQ_FOOTPRINT, 0UL ) );
    fseq_tbl[j] = fseq;
  }

  fd_rng_t rng[1];
  FD_TEST( fd_rng_join( fd_rng_new( rng, (uint)fd_tickcount(), 0UL ) ) );

  uchar scratch[ sizeof(fd_stem_tile_in_t)+128 ] __attribute__((aligned(FD_STEM_SCRATCH_ALIGN)));

  fd_frag_meta_t const * in_mcache_tbl[2] = { rx_mcache, tx_mcache };

  stem_run1( /* in_cnt     */ 2UL,
             /* in_mcache  */ in_mcache_tbl,
             /* in_fseq    */ fseq_tbl,
             /* out_cnt    */ 0UL,
             /* out_mcache */ NULL,
             /* cons_cnt   */ 0UL,
             /* cons_out   */ NULL,
             /* cons_fseq  */ NULL,
             /* stem_burst */ 1UL,
             NULL,
             NULL,
             NULL,
             NULL,
             /* stem_lazy  */ 0L,
             /* rng        */ rng,
             /* scratch    */ scratch,
             /* ctx        */ trace_ctx );

  for( int j = 0; j < 2; ++j ){
    fd_fseq_delete( fd_fseq_leave( fseq_tbl[j] ) );
  }
}
