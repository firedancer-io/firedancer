#include "fd_net_tile.h"
#include "fd_net_tile_private.h"
#include "../../ballet/txn/fd_txn.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include <stdio.h>

/* Reuse the public signed fixture already present in the parent. */
FD_IMPORT_BINARY( wire, "src/disco/net/fixtures/udp_signed_txn.bin" );
static uchar packet[4096] __attribute__((aligned(128)));
static uchar cache_mem[16384] __attribute__((aligned(FD_MCACHE_ALIGN)));

static int
verify_wire( uchar const * data, ulong sz ) {
  uchar txn_mem[FD_TXN_MAX_SZ] __attribute__((aligned(8)));
  fd_txn_t * txn=(fd_txn_t *)txn_mem;
  if( !fd_txn_parse(data,sz,txn,NULL) ) return 0;
  fd_sha512_t sha[1];
  for( ulong i=0UL; i<txn->signature_cnt; i++ )
    if( fd_ed25519_verify(data+txn->message_off,fd_txn_msg_sz(txn,sz),
                         data+txn->signature_off+64UL*i,data+txn->acct_addr_off+32UL*i,
                         sha)!=FD_ED25519_SUCCESS ) return 0;
  return 1;
}

static int
test_case( char const * name, ushort inner_flags, ushort outer_flags,
           ulong options, int gre, int iavf, ulong proto ) {
  fd_memset(packet,0,sizeof(packet));
  ulong const chunk=1UL, ctl=7UL;
  uchar * frame=packet+(chunk<<FD_CHUNK_LG_SZ)+ctl;
  fd_eth_hdr_t * eth=(fd_eth_hdr_t *)frame;
  eth->net_type=fd_ushort_bswap(FD_ETH_HDR_TYPE_IP);
  ulong const ihl=20UL+options, overhead=gre ? 24UL : 0UL;
  /* UDP length is legal and constant in every case.  Five bytes of IP
     padding make the direct MF payload 320 bytes.  GRE tests use IHL=20,
     making the outer MF payload 344 bytes, also a multiple of eight. */
  ulong const ip_payload=320UL;
  if( gre ) {
    fd_ip4_hdr_t * outer=(fd_ip4_hdr_t *)(eth+1);
    *outer=(fd_ip4_hdr_t){ .verihl=FD_IP4_VERIHL(4,5), .protocol=FD_IP4_HDR_PROTOCOL_GRE,
      .saddr=FD_IP4_ADDR(192,0,2,1), .net_frag_off=fd_ushort_bswap(outer_flags),
      .net_tot_len=fd_ushort_bswap((ushort)(overhead+ihl+ip_payload)) };
    fd_gre_hdr_t * gh=(fd_gre_hdr_t *)(outer+1);
    *gh=(fd_gre_hdr_t){ .flags_version=FD_GRE_HDR_FLG_VER_BASIC, .protocol=fd_ushort_bswap(FD_ETH_HDR_TYPE_IP) };
  }
  fd_ip4_hdr_t * ip=(fd_ip4_hdr_t *)(frame+14UL+overhead);
  *ip=(fd_ip4_hdr_t){ .verihl=FD_IP4_VERIHL(4,(uint)(ihl/4UL)), .protocol=FD_IP4_HDR_PROTOCOL_UDP,
    .saddr=FD_IP4_ADDR(198,51,100,1), .daddr=FD_IP4_ADDR(198,51,100,2),
    .net_frag_off=fd_ushort_bswap(inner_flags), .net_tot_len=fd_ushort_bswap((ushort)(ihl+ip_payload)) };
  fd_udp_hdr_t * udp=(fd_udp_hdr_t *)((uchar *)ip+ihl);
  *udp=(fd_udp_hdr_t){ .net_sport=fd_ushort_bswap(4321U), .net_dport=fd_ushort_bswap(9000U),
    .net_len=fd_ushort_bswap((ushort)(8UL+wire_sz)) };
  fd_memcpy(udp+1,wire,wire_sz);
  ulong const byte_len=14UL+overhead+ihl+ip_payload;
  fd_net_tile_t ctx={ .pkt_buf_wksp_base=packet, .dst_port_cnt=1UL, .rx_out_cnt=1UL };
  ctx.dst_ports[0]=9000U;ctx.dst_protos[0]=proto;ctx.gre_tunnel_ip[0]=FD_IP4_ADDR(192,0,2,1);
  FD_TEST(fd_mcache_footprint(128UL,0UL)<=sizeof(cache_mem));
  fd_frag_meta_t * mc=fd_mcache_join(fd_mcache_new(cache_mem,128UL,0UL,0UL));
  FD_TEST(mc);mc[0].chunk=33U;
  fd_frag_meta_t * mcaches[]={mc};
  ulong seq=0UL,depth=128UL,credit=9UL,min_credit=9UL;
  int reliable=1;
  fd_stem_context_t stem={ .mcaches=mcaches,.seqs=&seq,.depths=&depth,.out_reliable=&reliable,
    .cr_avail=&credit,.min_cr_avail=&min_credit,.cr_decrement_amount=1UL };
  ulong freed=ULONG_MAX,non_fd=0UL;
  int published=fd_net_rx_pkt(&ctx,&stem,chunk,ctl,byte_len,123UL,&freed,iavf ? &non_fd : NULL);
  /* Independent expected semantics: DF is allowed, MF and all 13 offset
     bits indicate a fragment.  Reserved-bit policy is outside this test. */
  int fragmented=0!=((inner_flags|outer_flags)&(FD_IP4_HDR_FRAG_OFF_MF|FD_IP4_HDR_FRAG_OFF_MASK));
  int expected_publish=!fragmented,valid=0,forward=0;
  ulong data_sz=0UL;
  int ok=published==expected_publish;
  if( published ) {
    ulong hdr=fd_disco_netmux_sig_hdr_sz(mc[0].sig);
    data_sz=mc[0].sz-hdr;
    fd_net_rx_bounds_t bounds={ .base=(ulong)packet,.pkt_lo=(ulong)packet,.pkt_hi=(ulong)(packet+sizeof(packet)) };
    uchar const * received=fd_net_rx_translate_frag(&bounds,mc[0].chunk,mc[0].ctl,mc[0].sz);
    /* Adapted fd_quic_tile.c legacy size gates/extraction; not full tile execution. */
    forward=proto==DST_PROTO_TPU_UDP && mc[0].sz>hdr && data_sz>=FD_TXN_MIN_SERIALIZED_SZ && data_sz<=FD_TPU_MTU;
    valid=verify_wire(received+hdr,data_sz);
    ok &= valid && data_sz==wire_sz && mc[0].sz==14UL+ihl+8UL+wire_sz && hdr==14UL+ihl+8UL;
    ok &= mc[0].chunk==chunk && mc[0].ctl==ctl+overhead && mc[0].tsorig==0U && mc[0].tspub==123U;
    ok &= fd_disco_netmux_sig_proto(mc[0].sig)==proto && 0==memcmp(received+hdr,wire,wire_sz);
    ok &= freed==33UL && seq==1UL && credit==8UL && min_credit==8UL;
    ok &= ctx.metrics.rx_pkt_cnt==1UL && ctx.metrics.rx_bytes_total==byte_len-overhead && ctx.metrics.rx_gre_cnt==(ulong)gre;
  } else {
    ok &= freed==chunk && mc[0].chunk==33U && seq==0UL && credit==9UL && min_credit==9UL;
    ok &= !ctx.metrics.rx_pkt_cnt && !ctx.metrics.rx_bytes_total && !ctx.metrics.rx_gre_cnt;
  }
  for( ulong i=0UL;i<FD_METRICS_ENUM_PKT_RX_DROP_REASON_CNT;i++ )
    ok &= ctx.metrics.rx_drop_cnt[i]==(ulong)(!published && i==FD_METRICS_ENUM_PKT_RX_DROP_REASON_V_MALFORMED_IDX);
  ok &= !non_fd;
  printf("{\"case\":\"%s\",\"inner_flags\":%u,\"outer_flags\":%u,\"options\":%lu,\"gre\":%d,\"iavf\":%d,\"proto\":%lu,\"expected_publish\":%d,\"published\":%d,\"published_size\":%u,\"payload_size\":%lu,\"legacy_forward\":%d,\"native_valid\":%d,\"ok\":%d}\n",
         name,(uint)inner_flags,(uint)outer_flags,options,gre,iavf,proto,expected_publish,published,published ? (uint)mc[0].sz : 0U,data_sz,forward,valid,ok);
  fd_mcache_delete(fd_mcache_leave(mc));
  return !ok;
}

int
main( int argc,char ** argv ) {
  fd_boot(&argc,&argv);FD_TEST(wire_sz==307UL && verify_wire(wire,wire_sz));
  int failures=0;
  struct { char const * name; ushort flags; } const cases[]={
    {"no_flags",0U},{"df",FD_IP4_HDR_FRAG_OFF_DF},{"mf_first",FD_IP4_HDR_FRAG_OFF_MF},
    {"offset_1",1U},{"mf_offset_1",FD_IP4_HDR_FRAG_OFF_MF|1U},
    {"offset_high_bit",0x1000U},{"offset_max",FD_IP4_HDR_FRAG_OFF_MASK},
    {"df_mf",FD_IP4_HDR_FRAG_OFF_DF|FD_IP4_HDR_FRAG_OFF_MF},
    {"df_offset",FD_IP4_HDR_FRAG_OFF_DF|1U}
  };
  for( ulong i=0UL;i<sizeof(cases)/sizeof(cases[0]);i++ ) {
    for( int iavf=0;iavf<=1;iavf++ )
      failures+=test_case(cases[i].name,cases[i].flags,0U,0UL,0,iavf,DST_PROTO_TPU_UDP);
    failures+=test_case(cases[i].name,cases[i].flags,0U,0UL,1,1,DST_PROTO_TPU_UDP);
    failures+=test_case(cases[i].name,0U,cases[i].flags,0UL,1,1,DST_PROTO_TPU_UDP);
  }
  failures+=test_case("ip_options_no_flags",0U,0U,4UL,0,0,DST_PROTO_TPU_UDP);
  failures+=test_case("ip_options_max_df",FD_IP4_HDR_FRAG_OFF_DF,0U,40UL,0,1,DST_PROTO_TPU_UDP);
  failures+=test_case("ip_options_mf",FD_IP4_HDR_FRAG_OFF_MF,0U,4UL,0,1,DST_PROTO_TPU_UDP);
  failures+=test_case("gre_both_df",FD_IP4_HDR_FRAG_OFF_DF,FD_IP4_HDR_FRAG_OFF_DF,0UL,1,1,DST_PROTO_TPU_UDP);
  failures+=test_case("gre_both_mf",FD_IP4_HDR_FRAG_OFF_MF,FD_IP4_HDR_FRAG_OFF_MF,0UL,1,1,DST_PROTO_TPU_UDP);
  ulong const protocols[]={DST_PROTO_TPU_QUIC,DST_PROTO_SHRED,DST_PROTO_GOSSIP,DST_PROTO_REPAIR,DST_PROTO_RSERVE,DST_PROTO_VOTOR};
  for( ulong i=0UL;i<sizeof(protocols)/sizeof(protocols[0]);i++ )
    failures+=test_case("shared_protocol_mf",FD_IP4_HDR_FRAG_OFF_MF,0U,0UL,0,1,protocols[i]);
  printf("{\"failures\":%d,\"full_quic_tile\":false,\"live_reachability_tested\":false}\n",failures);
  fd_halt();return failures ? 1 : 0;
}
