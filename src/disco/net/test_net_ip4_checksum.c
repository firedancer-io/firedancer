#include "fd_net_tile.h"
#include "fd_net_tile_private.h"
#include "../../ballet/txn/fd_txn.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include <stdio.h>

FD_IMPORT_BINARY( wire, "src/disco/net/fixtures/udp_signed_txn.bin" );
static uchar packet[4096] __attribute__((aligned(128)));
static uchar cache_mem[16384] __attribute__((aligned(FD_MCACHE_ALIGN)));
static ulong cases, failures;

/* Independent bytewise Internet checksum oracle, without padded reads. */
static ushort
checksum( void const * data, ulong len, ulong sum ) {
  uchar const * p=data;
  for( ; len>1UL; len-=2UL,p+=2UL ) sum+=((ulong)p[0]<<8)|p[1];
  if( len ) sum+=(ulong)p[0]<<8;
  while( sum>>16 ) sum=(sum&65535UL)+(sum>>16);
  return (ushort)~sum;
}

static void
ip_check_set( fd_ip4_hdr_t * ip ) {
  ip->check=0U;
  ip->check=fd_ushort_bswap( checksum(ip,FD_IP4_GET_LEN(*ip),0UL) );
}

static int
verify_wire( uchar const * data ) {
  uchar mem[FD_TXN_MAX_SZ] __attribute__((aligned(8)));
  fd_txn_t * txn=(fd_txn_t *)mem;
  if( !fd_txn_parse(data,wire_sz,txn,NULL) ) return 0;
  fd_sha512_t sha[1];
  return fd_ed25519_verify(data+txn->message_off,fd_txn_msg_sz(txn,wire_sz),
                          data+txn->signature_off,data+txn->acct_addr_off,sha)==FD_ED25519_SUCCESS;
}

static void
run_case( char const * name, int iavf, int gre, ulong inner_options, ulong outer_options,
          int corrupt, int udp_zero, int kernel_path, ulong proto ) {
  fd_memset(packet,0,sizeof(packet));
  ulong const chunk=1UL,ctl=7UL,ihl=20UL+inner_options,outer_ihl=20UL+outer_options;
  ulong const overhead=gre ? outer_ihl+4UL : 0UL;
  ulong const inner_sz=ihl+8UL+wire_sz+7UL;
  ulong const frame_sz=14UL+overhead+inner_sz+16UL;
  uchar * frame=packet+FD_CHUNK_SZ+ctl;
  fd_eth_hdr_t * eth=(fd_eth_hdr_t *)frame;eth->net_type=fd_ushort_bswap(FD_ETH_HDR_TYPE_IP);
  fd_ip4_hdr_t * outer=NULL;
  if( gre ) {
    outer=(fd_ip4_hdr_t *)(eth+1);
    *outer=(fd_ip4_hdr_t){.verihl=FD_IP4_VERIHL(4,(uint)(outer_ihl/4UL)),.protocol=47U,.ttl=64U,
      .saddr=FD_IP4_ADDR(192,0,2,1),.daddr=FD_IP4_ADDR(192,0,2,2),
      .net_tot_len=fd_ushort_bswap((ushort)(overhead+inner_sz))};
    fd_memset((uchar *)outer+20UL,1,outer_options);
    fd_gre_hdr_t * gh=(fd_gre_hdr_t *)((uchar *)outer+outer_ihl);
    *gh=(fd_gre_hdr_t){.flags_version=FD_GRE_HDR_FLG_VER_BASIC,.protocol=fd_ushort_bswap(FD_ETH_HDR_TYPE_IP)};
  }
  fd_ip4_hdr_t * ip=(fd_ip4_hdr_t *)(frame+14UL+overhead);
  *ip=(fd_ip4_hdr_t){.verihl=FD_IP4_VERIHL(4,(uint)(ihl/4UL)),.protocol=17U,.ttl=64U,
    .saddr=FD_IP4_ADDR(198,51,100,1),.daddr=FD_IP4_ADDR(198,51,100,2),
    .net_frag_off=fd_ushort_bswap(FD_IP4_HDR_FRAG_OFF_DF),.net_tot_len=fd_ushort_bswap((ushort)inner_sz)};
  fd_memset((uchar *)ip+20UL,1,inner_options);
  fd_udp_hdr_t * udp=(fd_udp_hdr_t *)((uchar *)ip+ihl);
  *udp=(fd_udp_hdr_t){.net_sport=fd_ushort_bswap(4321U),.net_dport=fd_ushort_bswap(kernel_path==1 ? 9001U : 9000U),
                     .net_len=fd_ushort_bswap((ushort)(8UL+wire_sz))};
  fd_memcpy(udp+1,wire,wire_sz);
  ulong sum=17UL+8UL+wire_sz;
  uchar const * addr=(uchar const *)&ip->saddr;
  for( ulong i=0UL;i<8UL;i+=2UL ) sum+=((ulong)addr[i]<<8)|addr[i+1];
  if( !udp_zero ) { ushort c=checksum(udp,8UL+wire_sz,sum);udp->check=fd_ushort_bswap(c ? c : (ushort)65535U); }
  if( kernel_path==2 ) ip->protocol=6U; /* existing iavf TCP handoff */
  ip_check_set(ip);if( outer ) ip_check_set(outer);
  if( corrupt==1 ) ip->check^=1U;
  if( corrupt==2 ) { FD_TEST(inner_options);((uchar *)ip)[ihl-1UL]^=1U; }
  if( corrupt==3 ) { FD_TEST(outer);outer->check^=1U; }
  if( corrupt==4 ) { FD_TEST(outer_options);((uchar *)outer)[outer_ihl-1UL]^=1U; }
  if( corrupt==5 ) ip->check=0U;
  int const inner_valid=!checksum(ip,ihl,0UL),outer_valid=!outer||!checksum(outer,outer_ihl,0UL);
  FD_TEST((udp_zero || !checksum(udp,8UL+wire_sz,sum)) && verify_wire((uchar const *)(udp+1)));
  fd_net_tile_t ctx={0};ctx.pkt_buf_wksp_base=packet;ctx.dst_port_cnt=1UL;ctx.rx_out_cnt=1UL;
  ctx.dst_ports[0]=9000U;ctx.dst_protos[0]=proto;
  if( kernel_path!=3 ) ctx.gre_tunnel_ip[0]=FD_IP4_ADDR(192,0,2,1);
  fd_frag_meta_t * mc=fd_mcache_join(fd_mcache_new(cache_mem,128UL,0UL,0UL));FD_TEST(mc);mc[0].chunk=33U;
  fd_frag_meta_t * mcaches[]={mc};ulong seq=0UL,depth=128UL,credit=9UL,min_credit=9UL;int reliable=1;
  fd_stem_context_t stem={.mcaches=mcaches,.seqs=&seq,.depths=&depth,.out_reliable=&reliable,
    .cr_avail=&credit,.min_cr_avail=&min_credit,.cr_decrement_amount=1UL};
  ulong freed=ULONG_MAX,non_fd=0UL;
  int published=fd_net_rx_pkt(&ctx,&stem,chunk,ctl,frame_sz,123UL,&freed,iavf ? &non_fd : NULL);
  int expected=inner_valid && outer_valid && !kernel_path;
  int ok=published==expected;
  if( published ) {
    uchar const * data=(uchar const *)fd_chunk_to_laddr(packet,mc[0].chunk)+mc[0].ctl;
    ulong hdr=fd_disco_netmux_sig_hdr_sz(mc[0].sig);
    ok &= hdr==14UL+ihl+8UL && mc[0].sz==hdr+wire_sz && mc[0].ctl==ctl+overhead &&
          mc[0].chunk==chunk && freed==33UL && seq==1UL && credit==8UL && min_credit==8UL;
    ok &= !memcmp(data+hdr,wire,wire_sz) && verify_wire(data+hdr) &&
          ctx.metrics.rx_pkt_cnt==1UL && ctx.metrics.rx_bytes_total==frame_sz-overhead && ctx.metrics.rx_gre_cnt==(ulong)gre;
  } else ok &= freed==chunk && mc[0].chunk==33U && !seq && credit==9UL && min_credit==9UL && !ctx.metrics.rx_pkt_cnt;
  if( kernel_path ) ok &= non_fd==(ulong)iavf;
  else {
    ok &= !non_fd;
    for( ulong i=0UL;i<FD_METRICS_ENUM_PKT_RX_DROP_REASON_CNT;i++ )
      ok &= ctx.metrics.rx_drop_cnt[i]==(ulong)(!published && i==FD_METRICS_ENUM_PKT_RX_DROP_REASON_V_MALFORMED_IDX);
  }
  printf("{\"case\":\"%s\",\"iavf\":%d,\"gre\":%d,\"inner_IHL\":%lu,\"outer_IHL\":%lu,\"corrupt\":%d,\"inner_valid\":%d,\"outer_valid\":%d,\"UDP0\":%d,\"signed_payload_unchanged\":true,\"published\":%d,\"expected\":%d,\"ok\":%d}\n",
    name,iavf,gre,ihl,outer_ihl,corrupt,inner_valid,outer_valid,udp_zero,published,expected,ok);
  cases++;failures+=(ulong)!ok;fd_mcache_delete(fd_mcache_leave(mc));
}

int main( int argc, char ** argv ) {
  fd_boot(&argc,&argv);FD_TEST(wire_sz==307UL && verify_wire(wire));
  for( int iavf=0;iavf<=1;iavf++ ) for( int gre=0;gre<=1;gre++ ) for( ulong options=0UL;options<=40UL;options+=20UL ) {
    run_case("valid_nonzero_UDP",iavf,gre,options,options,0,0,0,DST_PROTO_TPU_UDP);
    run_case("bad_inner_IP_checksum",iavf,gre,options,options,1,0,0,DST_PROTO_TPU_UDP);
    run_case("zero_inner_IP_checksum",iavf,gre,options,options,5,0,0,DST_PROTO_TPU_UDP);
    run_case("legal_UDP0",iavf,gre,options,options,0,1,0,DST_PROTO_TPU_UDP);
    run_case("bad_IP_with_UDP0",iavf,gre,options,options,1,1,0,DST_PROTO_TPU_UDP);
    if( options ) run_case("mutated_inner_options",iavf,gre,options,options,2,0,0,DST_PROTO_TPU_UDP);
    if( gre ) {
      run_case("bad_outer_IP_checksum",iavf,gre,options,options,3,0,0,DST_PROTO_TPU_UDP);
      if( options ) run_case("mutated_outer_options",iavf,gre,options,options,4,0,0,DST_PROTO_TPU_UDP);
    }
  }
  run_case("unbound_UDP_bad_IP_kernel_handoff",1,0,0,0,1,0,1,DST_PROTO_TPU_UDP);
  run_case("TCP_bad_IP_kernel_handoff",1,0,0,0,1,0,2,DST_PROTO_TPU_UDP);
  run_case("unconfigured_GRE_bad_outer_kernel_handoff",1,1,0,0,3,0,3,DST_PROTO_TPU_UDP);
  ulong protocols[]={DST_PROTO_TPU_QUIC,DST_PROTO_SHRED,DST_PROTO_GOSSIP,DST_PROTO_REPAIR,DST_PROTO_RSERVE,DST_PROTO_VOTOR};
  for( ulong i=0UL;i<sizeof(protocols)/sizeof(protocols[0]);i++ ) run_case("shared_owned_protocol_bad_IP",1,0,0,0,1,0,0,protocols[i]);
  printf("{\"cases\":%lu,\"failures\":%lu,\"hardware\":false,\"full_quic_tile\":false}\n",cases,failures);
  fd_halt();return failures ? 1 : 0;
}
