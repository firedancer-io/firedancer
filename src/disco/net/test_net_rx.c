#include "fd_net_tile.h"
#include "fd_net_tile_private.h"
#include "../../ballet/txn/fd_txn.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include <stdio.h>

/* Public, signed transaction from run02's runtime-bridge reader-00.bin.
   No private key is needed or included. */
FD_IMPORT_BINARY( wire, "src/disco/net/fixtures/udp_signed_txn.bin" );

static uchar packet[4096] __attribute__((aligned(128)));
static uchar cache_mem[16384] __attribute__((aligned(FD_MCACHE_ALIGN)));

static int
verify_wire( uchar const * data, ulong sz ) {
  uchar txn_mem[FD_TXN_MAX_SZ] __attribute__((aligned(8)));
  fd_txn_t * txn = (fd_txn_t *)txn_mem;
  if( !fd_txn_parse( data, sz, txn, NULL ) ) return 0;
  fd_sha512_t sha[1];
  for( ulong i=0UL; i<txn->signature_cnt; i++ ) {
    if( fd_ed25519_verify( data+txn->message_off, fd_txn_msg_sz( txn, sz ),
                          data+txn->signature_off+64UL*i, data+txn->acct_addr_off+32UL*i,
                          sha )!=FD_ED25519_SUCCESS ) return 0;
  }
  return 1;
}

static int
test_case( char const * name, ulong payload, ulong udp_sz, ulong ip_payload,
           ulong eth_padding, ulong options, ulong gre, ulong outer_missing,
           ulong proto, int non_fd, int expected_publish ) {
  fd_memset( packet, 0, sizeof(packet) );
  ulong const chunk=1UL, initial_ctl=7UL;
  uchar * frame = packet+(chunk<<FD_CHUNK_LG_SZ)+initial_ctl;
  fd_eth_hdr_t * eth = (fd_eth_hdr_t *)frame;
  eth->net_type = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP );
  ulong const ihl = 20UL+options;
  ulong const overhead = gre ? 24UL : 0UL;
  if( gre ) {
    fd_ip4_hdr_t * outer = (fd_ip4_hdr_t *)(eth+1);
    *outer = (fd_ip4_hdr_t){ .verihl=FD_IP4_VERIHL(4,5), .protocol=FD_IP4_HDR_PROTOCOL_GRE,
      .saddr=FD_IP4_ADDR(192,0,2,1), .net_tot_len=fd_ushort_bswap((ushort)(overhead+ihl+ip_payload-outer_missing)) };
    fd_gre_hdr_t * gh = (fd_gre_hdr_t *)(outer+1);
    *gh = (fd_gre_hdr_t){ .flags_version=FD_GRE_HDR_FLG_VER_BASIC, .protocol=fd_ushort_bswap(FD_ETH_HDR_TYPE_IP) };
  }
  fd_ip4_hdr_t * ip = (fd_ip4_hdr_t *)(frame+14UL+overhead);
  *ip = (fd_ip4_hdr_t){ .verihl=FD_IP4_VERIHL(4,(uint)(ihl/4UL)), .protocol=FD_IP4_HDR_PROTOCOL_UDP,
    .saddr=FD_IP4_ADDR(198,51,100,1), .daddr=FD_IP4_ADDR(198,51,100,2),
    .net_tot_len=fd_ushort_bswap((ushort)(ihl+ip_payload)) };
  fd_udp_hdr_t * udp = (fd_udp_hdr_t *)((uchar *)ip+ihl);
  *udp = (fd_udp_hdr_t){ .net_sport=fd_ushort_bswap(4321U), .net_dport=fd_ushort_bswap(9000U),
    .net_len=fd_ushort_bswap((ushort)udp_sz) };
  fd_memcpy( udp+1, wire, payload );
  ip->check=fd_ip4_hdr_check(ip);
  if( gre ) {
    fd_ip4_hdr_t * outer=(fd_ip4_hdr_t *)(eth+1);
    outer->check=fd_ip4_hdr_check(outer);
  }
  ulong const byte_len=14UL+overhead+ihl+8UL+payload+eth_padding;
  fd_net_tile_t ctx = { .pkt_buf_wksp_base=packet, .dst_port_cnt=1UL, .rx_out_cnt=1UL };
  ctx.dst_ports[0]=9000U; ctx.dst_protos[0]=proto; ctx.gre_tunnel_ip[0]=FD_IP4_ADDR(192,0,2,1);
  FD_TEST( fd_mcache_footprint(128UL,0UL)<=sizeof(cache_mem) );
  fd_frag_meta_t * mc = fd_mcache_join(fd_mcache_new(cache_mem,128UL,0UL,0UL));
  FD_TEST(mc);
  mc[0].chunk=33U;
  fd_frag_meta_t * mcaches[]={mc};
  ulong seq=0UL, depth=128UL, credit=9UL, min_credit=9UL;
  int reliable=1;
  fd_stem_context_t stem={ .mcaches=mcaches, .seqs=&seq, .depths=&depth, .out_reliable=&reliable,
    .cr_avail=&credit, .min_cr_avail=&min_credit, .cr_decrement_amount=1UL };
  ulong freed=ULONG_MAX, non_fd_cnt=0UL;
  int published=fd_net_rx_pkt(&ctx,&stem,chunk,initial_ctl,byte_len,123UL,&freed,non_fd ? &non_fd_cnt : NULL);
  ulong expected_sz=14UL+ihl+udp_sz;
  ulong hdr=0UL, data_sz=0UL;
  int legacy_forward=0, native_valid=0;
  int ok=published==expected_publish;
  if( published ) {
    hdr=fd_disco_netmux_sig_hdr_sz(mc[0].sig);
    data_sz=mc[0].sz-hdr;
    /* Adapted size gates and extraction from fd_quic_tile.c:after_frag.
       This is not execution of the full QUIC tile. */
    legacy_forward=proto==DST_PROTO_TPU_UDP && mc[0].sz>hdr &&
                   data_sz>=FD_TXN_MIN_SERIALIZED_SZ && data_sz<=FD_TPU_MTU;
    fd_net_rx_bounds_t bounds={ .base=(ulong)packet, .pkt_lo=(ulong)packet, .pkt_hi=(ulong)(packet+sizeof(packet)) };
    uchar const * received=fd_net_rx_translate_frag(&bounds,mc[0].chunk,mc[0].ctl,mc[0].sz);
    if( legacy_forward ) native_valid=verify_wire(received+hdr,data_sz);
    ok &= mc[0].sz==expected_sz && hdr==14UL+ihl+8UL && mc[0].chunk==chunk &&
          mc[0].ctl==initial_ctl+overhead && freed==33UL && seq==1UL && credit==8UL && min_credit==8UL &&
          mc[0].tsorig==0U && mc[0].tspub==123U && fd_disco_netmux_sig_proto(mc[0].sig)==proto;
    ok &= ctx.metrics.rx_pkt_cnt==1UL && ctx.metrics.rx_gre_cnt==gre && ctx.metrics.rx_bytes_total==byte_len-overhead;
    ok &= 0==memcmp(received+hdr,wire,udp_sz-8UL);
    ok &= legacy_forward==(proto==DST_PROTO_TPU_UDP && udp_sz-8UL>=FD_TXN_MIN_SERIALIZED_SZ && udp_sz-8UL<=FD_TPU_MTU);
    if( proto==DST_PROTO_TPU_UDP ) ok &= native_valid==(udp_sz-8UL==wire_sz);
  } else {
    ok &= freed==chunk && seq==0UL && credit==9UL && min_credit==9UL && mc[0].chunk==33U;
    ok &= ctx.metrics.rx_pkt_cnt==0UL && ctx.metrics.rx_bytes_total==0UL && ctx.metrics.rx_gre_cnt==0UL;
  }
  for( ulong i=0UL; i<FD_METRICS_ENUM_PKT_RX_DROP_REASON_CNT; i++ )
    ok &= ctx.metrics.rx_drop_cnt[i]==(ulong)(!published && i==FD_METRICS_ENUM_PKT_RX_DROP_REASON_V_MALFORMED_IDX);
  ok &= non_fd_cnt==0UL;
  printf("{\"case\":\"%s\",\"proto\":%lu,\"iavf_classification\":%d,\"published\":%d,\"received\":%lu,\"udp_declared\":%lu,\"published_size\":%u,\"expected_size\":%lu,\"legacy_payload\":%lu,\"legacy_forward\":%d,\"native_valid\":%d,\"ok\":%d}\n",
         name,proto,non_fd,published,byte_len,udp_sz,published ? (uint)mc[0].sz : 0U,expected_sz,data_sz,legacy_forward,native_valid,ok);
  fd_mcache_delete(fd_mcache_leave(mc));
  return !ok;
}

int
main( int argc, char ** argv ) {
  fd_boot(&argc,&argv);
  FD_TEST(wire_sz==307UL && verify_wire(wire,wire_sz));
  int failures=0;
#define CASE(n,p,u,ip,e,o,g,m,proto,iavf,pub) failures+=test_case(n,p,u,ip,e,o,g,m,proto,iavf,pub)
  CASE("legal_exact",307UL,315UL,315UL,0UL,0UL,0UL,0UL,DST_PROTO_TPU_UDP,0,1);
  CASE("udp8_signed_wire_in_ip_padding",307UL,8UL,315UL,0UL,0UL,0UL,0UL,DST_PROTO_TPU_UDP,0,1);
  CASE("udp8_plus16_truncated",307UL,24UL,315UL,0UL,0UL,0UL,0UL,DST_PROTO_TPU_UDP,0,1);
  CASE("udp_larger_than_ip",307UL,316UL,315UL,0UL,0UL,0UL,0UL,DST_PROTO_TPU_UDP,0,0);
  CASE("legal_ethernet_padding",307UL,315UL,315UL,12UL,0UL,0UL,0UL,DST_PROTO_TPU_UDP,0,1);
  CASE("udp8_wire_after_ip",307UL,8UL,8UL,0UL,0UL,0UL,0UL,DST_PROTO_TPU_UDP,0,1);
  CASE("empty_udp",0UL,8UL,8UL,0UL,0UL,0UL,0UL,DST_PROTO_TPU_UDP,0,1);
  CASE("udp7_malformed",307UL,7UL,315UL,0UL,0UL,0UL,0UL,DST_PROTO_TPU_UDP,0,0);
  CASE("ip_short_udp_header",307UL,8UL,7UL,0UL,0UL,0UL,0UL,DST_PROTO_TPU_UDP,0,0);
  CASE("legal_ip_options",307UL,315UL,315UL,0UL,4UL,0UL,0UL,DST_PROTO_TPU_UDP,0,1);
  CASE("ip_options_udp8",307UL,8UL,315UL,0UL,4UL,0UL,0UL,DST_PROTO_TPU_UDP,0,1);
  CASE("gre_legal",307UL,315UL,315UL,0UL,0UL,1UL,0UL,DST_PROTO_TPU_UDP,0,1);
  CASE("gre_udp8",307UL,8UL,315UL,0UL,0UL,1UL,0UL,DST_PROTO_TPU_UDP,0,1);
  CASE("gre_udp24",307UL,24UL,315UL,0UL,0UL,1UL,0UL,DST_PROTO_TPU_UDP,0,1);
  CASE("gre_options_eth_padding",307UL,315UL,315UL,12UL,4UL,1UL,0UL,DST_PROTO_TPU_UDP,0,1);
  CASE("gre_inner_exceeds_outer",307UL,315UL,315UL,0UL,0UL,1UL,1UL,DST_PROTO_TPU_UDP,0,0);
  CASE("iavf_udp8",307UL,8UL,315UL,0UL,0UL,0UL,0UL,DST_PROTO_TPU_UDP,1,1);
  ulong const protocols[]={DST_PROTO_TPU_QUIC,DST_PROTO_SHRED,DST_PROTO_GOSSIP,DST_PROTO_REPAIR,DST_PROTO_RSERVE,DST_PROTO_VOTOR};
  for( ulong i=0UL; i<sizeof(protocols)/sizeof(protocols[0]); i++ )
    CASE("shared_protocol_udp24",307UL,24UL,315UL,0UL,0UL,0UL,0UL,protocols[i],1,1);
#undef CASE
  printf("{\"failures\":%d,\"full_quic_tile\":false}\n",failures);
  fd_halt();
  return failures ? 1 : 0;
}
