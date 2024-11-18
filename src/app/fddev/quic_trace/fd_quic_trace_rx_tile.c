/* fd_quic_trace_rx_tile.c does passive decryption of incoming QUIC
   packets.

   It mocks the setup procedure and run loop of a real fd_quic_tile. */

#include "fd_quic_trace.h"
#include "../../../waltz/quic/fd_quic_private.h"
#include "../../../waltz/quic/templ/fd_quic_parse_util.h"
#include "../../../util/net/fd_eth.h"
#include "../../../util/net/fd_ip4.h"
#include "../../../util/net/fd_udp.h"

#define translate_ptr( ctx, ptr ) __extension__({ \
    ulong rbase = (ulong)( ctx->self );           \
    ulong rel   = (ulong)(ptr) - rbase;           \
    ulong laddr = (ulong)(ctx) + rel;             \
    (__typeof__(ptr))(laddr);                     \
  })

static int
before_frag( fd_quic_trace_tile_ctx_t * ctx,
             ulong                      in_idx,
             ulong                      seq,
             ulong                      sig ) {
  (void)sig;

  /* Skip non-QUIC packets */
  ulong proto = fd_disco_netmux_sig_proto( sig );
  if( proto!=DST_PROTO_TPU_QUIC ) return 1;

  /* Don't ingress frags until fd_quic_tile is caught up */
  ulong * tgt_fseq = ctx->target_fseq[ in_idx ];
  ulong tgt_seq = fd_fseq_query( tgt_fseq );
  if( FD_UNLIKELY( tgt_seq<seq ) ) return -1;

  return 0;
}

static void
during_frag( fd_quic_trace_tile_ctx_t * ctx,
             ulong                      in_idx,
             ulong                      seq,
             ulong                      sig,
             ulong                      chunk,
             ulong                      sz ) {
  (void)in_idx; (void)seq; (void)sig;
  fd_memcpy( ctx->buffer, (uchar *)fd_chunk_to_laddr( ctx->in_mem[ in_idx ], chunk ), sz );
}

static void
fd_quic_trace_1rtt( fd_quic_trace_tile_ctx_t * ctx,
                    uchar *                    data,
                    ulong                      data_sz,
                    uint                       ip4_saddr ) {
  fd_quic_t *          quic     = ctx->remote_ctx->quic;
  fd_quic_state_t *    state    = fd_quic_get_state( quic );
  fd_quic_conn_map_t * conn_map = translate_ptr( ctx->remote_ctx, state->conn_map );

  if( FD_UNLIKELY( data_sz < FD_QUIC_SHORTEST_PKT ) ) return;

  /* Look up conn */
  ulong dst_conn_id = fd_ulong_load_8( data+1 );
  fd_quic_conn_map_t * conn_entry = fd_quic_conn_map_query( conn_map, dst_conn_id, NULL );
  if( !conn_entry ) return;
  fd_quic_conn_t *        conn = translate_ptr( ctx->remote_ctx, conn_entry->conn );
  fd_quic_crypto_keys_t * keys = &conn->keys[ fd_quic_enc_level_appdata_id ][ 0 ];

  ulong pkt_number_off = 9UL;
  int hdr_err = fd_quic_crypto_decrypt_hdr( data, data_sz, pkt_number_off, keys );
  if( hdr_err!=FD_QUIC_SUCCESS ) return;

  ulong pkt_number = fd_quic_pktnum_decode( data+9UL, fd_quic_h0_pkt_num_len( data[0] )+1u );
  int crypt_err = fd_quic_crypto_decrypt( data, data_sz, pkt_number_off, pkt_number, keys );
  if( crypt_err!=FD_QUIC_SUCCESS ) return;

  static FD_TL ulong trace;
  if( trace++ % 4096 == 0 ) {
    FD_LOG_NOTICE(( "ip4=" FD_IP4_ADDR_FMT " conn=%016lx", FD_IP4_ADDR_FMT_ARGS( ip4_saddr ), dst_conn_id ));
  }

  (void)ip4_saddr; (void)conn;
}

static void
fd_quic_trace_pkt( fd_quic_trace_tile_ctx_t * ctx,
                   uchar *                    data,
                   ulong                      data_sz,
                   uint                       ip4_saddr ) {
  /* FIXME: for now, only handle 1-RTT */
  int is_long = fd_quic_h0_hdr_form( data[0] );
  if( is_long ) return;
  fd_quic_trace_1rtt( ctx, data, data_sz, ip4_saddr );
}

static void
after_frag( fd_quic_trace_tile_ctx_t * ctx,
            ulong                      in_idx,
            ulong                      seq,
            ulong                      sig,
            ulong                      chunk,
            ulong                      sz,
            ulong                      tsorig,
            fd_stem_context_t *        stem ) {
  (void)in_idx; (void)seq; (void)sig; (void)chunk; (void)sz; (void)tsorig; (void)stem;

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

  uint ip4_saddr = fd_uint_load_4( ip4_hdr->saddr_c );
  fd_quic_trace_pkt( ctx, cur, (ulong)( end-cur ), ip4_saddr );
}


#define STEM_BURST (1UL)
#define STEM_CALLBACK_CONTEXT_TYPE  fd_quic_trace_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN 1
#define STEM_CALLBACK_BEFORE_FRAG   before_frag
#define STEM_CALLBACK_DURING_FRAG   during_frag
#define STEM_CALLBACK_AFTER_FRAG    after_frag
#include "../../../disco/stem/fd_stem.c"

void
quic_trace_run( ulong                      in_cnt,
                fd_frag_meta_t const **    in_mcache,
                ulong **                   in_fseq,
                ulong                      out_cnt,
                fd_frag_meta_t **          out_mcache,
                ulong                      cons_cnt,
                ulong *                    _cons_out,
                ulong **                   _cons_fseq,
                ulong                      burst,
                long                       lazy,
                fd_rng_t *                 rng,
                void *                     scratch,
                fd_quic_trace_tile_ctx_t * ctx ) {
  (void)stem_run;

  stem_run1( in_cnt,
             in_mcache,
             in_fseq,
             out_cnt,
             out_mcache,
             cons_cnt,
             _cons_out,
             _cons_fseq,
             burst,
             lazy,
             rng,
             scratch,
             ctx );
}
