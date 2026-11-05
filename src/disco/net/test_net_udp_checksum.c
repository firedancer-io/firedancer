#include "fd_net_tile.h"
#include "fd_net_tile_private.h"
#include "../../ballet/txn/fd_txn.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

FD_IMPORT_BINARY( wire, "src/disco/net/fixtures/udp_signed_txn.bin" );
static uchar packet[8192] __attribute__((aligned(128)));
static uchar cache_mem[16384] __attribute__((aligned(FD_MCACHE_ALIGN)));
static ulong cases,failures;

/* Independent bytewise Internet checksum oracle, including odd-byte padding. */
static ushort
checksum( uchar const * p, ulong sz, ulong sum ) {
  for( ; sz>1UL; sz-=2UL,p+=2UL ) sum += ((ulong)p[0]<<8) | p[1];
  if( sz ) sum += (ulong)p[0]<<8;
  while( sum>>16 ) sum=(sum&65535UL)+(sum>>16);
  return (ushort)~sum;
}
static void
set_checksum( fd_ip4_hdr_t * ip, fd_udp_hdr_t * udp, ulong sz ) {
  uchar pseudo[12];fd_memcpy(pseudo,&ip->saddr,8UL);pseudo[8]=0U;pseudo[9]=17U;pseudo[10]=(uchar)(sz>>8);pseudo[11]=(uchar)sz;
  ulong sum=0UL;for( ulong i=0UL;i<12UL;i+=2UL ) sum+=((ulong)pseudo[i]<<8)|pseudo[i+1];
  udp->check=0U;ushort v=checksum((uchar const *)udp,sz,sum);udp->check=fd_ushort_bswap(v ? v : (ushort)65535U);
}
static int
verify_wire( uchar const * data, ulong sz ) {
  uchar mem[FD_TXN_MAX_SZ] __attribute__((aligned(8)));fd_txn_t * txn=(fd_txn_t *)mem;
  if( !fd_txn_parse(data,sz,txn,NULL) ) return 0;
  fd_sha512_t sha[1];
  for( ulong i=0UL;i<txn->signature_cnt;i++ )
    if( fd_ed25519_verify(data+txn->message_off,fd_txn_msg_sz(txn,sz),data+txn->signature_off+64UL*i,data+txn->acct_addr_off+32UL*i,sha)!=FD_ED25519_SUCCESS ) return 0;
  return 1;
}
static fd_frag_meta_t *
setup( fd_net_tile_t * ctx, fd_stem_context_t * stem, void * base, ulong proto,
       ulong * seq, ulong * credit, ulong * min_credit, int * reliable,
       fd_frag_meta_t ** mcaches, ulong * depth ) {
  fd_memset(ctx,0,sizeof(*ctx));ctx->pkt_buf_wksp_base=base;ctx->dst_port_cnt=1UL;ctx->rx_out_cnt=1UL;
  ctx->dst_ports[0]=9000U;ctx->dst_protos[0]=proto;ctx->gre_tunnel_ip[0]=FD_IP4_ADDR(192,0,2,1);
  fd_frag_meta_t * mc=fd_mcache_join(fd_mcache_new(cache_mem,128UL,0UL,0UL));FD_TEST(mc);mc[0].chunk=33U;mcaches[0]=mc;
  *seq=0UL;*credit=9UL;*min_credit=9UL;*reliable=1;*depth=128UL;
  *stem=(fd_stem_context_t){.mcaches=mcaches,.seqs=seq,.depths=depth,.out_reliable=reliable,.cr_avail=credit,.min_cr_avail=min_credit,.cr_decrement_amount=1UL};return mc;
}
static void
run_case( char const * name, int mode, ulong payload, ulong declared_payload,
          ulong options, int gre, ulong ip_pad, ulong eth_pad, int iavf,
          ulong proto, int expect, int guard ) {
  fd_memset(packet,0,sizeof(packet));ulong chunk=1UL,ctl=7UL,overhead=gre ? 24UL : 0UL,ihl=20UL+options;
  ulong frame_sz=14UL+overhead+ihl+8UL+payload+ip_pad+eth_pad;
  uchar * frame=packet+(chunk<<FD_CHUNK_LG_SZ)+ctl;void * base=packet;void * mapping=NULL;
  if( guard ) {
    ulong page=(ulong)sysconf(_SC_PAGESIZE);mapping=mmap(NULL,page*2UL,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);FD_TEST(mapping!=MAP_FAILED);FD_TEST(!mprotect((uchar *)mapping+page,page,PROT_NONE));
    base=mapping;frame=(uchar *)mapping+page-frame_sz;chunk=((ulong)frame-(ulong)base)>>FD_CHUNK_LG_SZ;ctl=((ulong)frame-(ulong)base)&(FD_CHUNK_SZ-1UL);
  }
  fd_eth_hdr_t * eth=(fd_eth_hdr_t *)frame;eth->net_type=fd_ushort_bswap(FD_ETH_HDR_TYPE_IP);
  if( gre ) {
    fd_ip4_hdr_t * outer=(fd_ip4_hdr_t *)(eth+1);*outer=(fd_ip4_hdr_t){.verihl=FD_IP4_VERIHL(4,5),.protocol=FD_IP4_HDR_PROTOCOL_GRE,.saddr=FD_IP4_ADDR(192,0,2,1),.net_tot_len=fd_ushort_bswap((ushort)(overhead+ihl+8UL+payload+ip_pad))};
    fd_gre_hdr_t * gh=(fd_gre_hdr_t *)(outer+1);*gh=(fd_gre_hdr_t){.flags_version=FD_GRE_HDR_FLG_VER_BASIC,.protocol=fd_ushort_bswap(FD_ETH_HDR_TYPE_IP)};
  }
  fd_ip4_hdr_t * ip=(fd_ip4_hdr_t *)(frame+14UL+overhead);*ip=(fd_ip4_hdr_t){.verihl=FD_IP4_VERIHL(4,(uint)(ihl/4UL)),.protocol=FD_IP4_HDR_PROTOCOL_UDP,.saddr=FD_IP4_ADDR(198,51,100,1),.daddr=FD_IP4_ADDR(198,51,100,2),.net_tot_len=fd_ushort_bswap((ushort)(ihl+8UL+payload+ip_pad))};
  fd_udp_hdr_t * udp=(fd_udp_hdr_t *)((uchar *)ip+ihl);*udp=(fd_udp_hdr_t){.net_sport=fd_ushort_bswap(4321U),.net_dport=fd_ushort_bswap(9000U),.net_len=fd_ushort_bswap((ushort)(8UL+declared_payload))};
  for( ulong i=0UL;i<payload;i++ ) ((uchar *)(udp+1))[i]=wire[i%wire_sz];
  if( mode ) set_checksum(ip,udp,8UL+declared_payload);
  if( mode==2 ) udp->check^=fd_ushort_bswap(1U);
  if( mode==3 ) { udp->check=0U;set_checksum(ip,udp,8UL+payload); } /* checksum over hidden trailing bytes */
  if( mode==4 ) ip->daddr^=1U; /* pseudo-header corruption */
  if( mode==5 ) ((uchar *)(udp+1))[declared_payload-1UL]^=1U; /* odd final byte corruption */
  if( mode==6 ) { udp->check=0U;udp->net_dport=fd_ushort_bswap(9001U); } /* unbound kernel path */
  ip->check=fd_ip4_hdr_check(ip);
  if( gre ) {
    fd_ip4_hdr_t * outer=(fd_ip4_hdr_t *)(eth+1);
    outer->check=fd_ip4_hdr_check(outer);
  }
  fd_net_tile_t ctx;fd_stem_context_t stem;ulong seq,credit,min_credit,depth;int reliable;fd_frag_meta_t * mcaches[1];
  fd_frag_meta_t * mc=setup(&ctx,&stem,base,proto,&seq,&credit,&min_credit,&reliable,mcaches,&depth);
  ulong freed=ULONG_MAX,non_fd=0UL;int published=fd_net_rx_pkt(&ctx,&stem,chunk,ctl,frame_sz,123UL,&freed,iavf ? &non_fd : NULL);
  int ok=published==expect;int native_valid=0;
  if( published ) {
    ulong hdr=fd_disco_netmux_sig_hdr_sz(mc[0].sig);uchar const * received=(uchar const *)fd_chunk_to_laddr(base,mc[0].chunk)+mc[0].ctl;
    ok &= mc[0].sz==14UL+ihl+8UL+declared_payload && hdr==14UL+ihl+8UL && mc[0].ctl==ctl+overhead && mc[0].chunk==chunk && freed==33UL && seq==1UL && credit==8UL && min_credit==8UL;
    ok &= ctx.metrics.rx_pkt_cnt==1UL && ctx.metrics.rx_bytes_total==frame_sz-overhead && ctx.metrics.rx_gre_cnt==(ulong)gre && mc[0].tspub==123U && fd_disco_netmux_sig_proto(mc[0].sig)==proto;
    if( payload==wire_sz && declared_payload==wire_sz && mode!=5 ) { native_valid=verify_wire(received+hdr,declared_payload);ok &= native_valid; }
  } else ok &= freed==chunk && mc[0].chunk==33U && seq==0UL && credit==9UL && min_credit==9UL && !ctx.metrics.rx_pkt_cnt && !ctx.metrics.rx_bytes_total;
  if( mode!=6 ) {
    ok &= !non_fd;
    for( ulong i=0UL;i<FD_METRICS_ENUM_PKT_RX_DROP_REASON_CNT;i++ ) ok &= ctx.metrics.rx_drop_cnt[i]==(ulong)(!published && i==FD_METRICS_ENUM_PKT_RX_DROP_REASON_V_MALFORMED_IDX);
  } else ok &= non_fd==(ulong)iavf;
  printf("{\"case\":\"%s\",\"mode\":%d,\"iavf\":%d,\"gre\":%d,\"payload\":%lu,\"declared_payload\":%lu,\"published\":%d,\"expected\":%d,\"native_signed_valid\":%d,\"ok\":%d}\n",name,mode,iavf,gre,payload,declared_payload,published,expect,native_valid,ok);
  cases++;failures+=(ulong)!ok;fd_mcache_delete(fd_mcache_leave(mc));if(mapping)FD_TEST(!munmap(mapping,(ulong)sysconf(_SC_PAGESIZE)*2UL));
}
static void
live_frame( char const * path ) {
  FILE * f=fopen(path,"rb");FD_TEST(f);ulong sz=fread(packet+FD_CHUNK_SZ,1UL,2048UL,f);FD_TEST(!ferror(f)&&feof(f));fclose(f);
  FD_TEST(sz==314UL);fd_ip4_hdr_t const * ip=(fd_ip4_hdr_t const *)(packet+FD_CHUNK_SZ+14UL);fd_udp_hdr_t const * udp=(fd_udp_hdr_t const *)(ip+1);
  FD_TEST(verify_wire((uchar const *)(udp+1),272UL));int expected;
  uchar pseudo[12];fd_memcpy(pseudo,&ip->saddr,8UL);pseudo[8]=0U;pseudo[9]=17U;pseudo[10]=1U;pseudo[11]=24U;ulong sum=0UL;for(ulong i=0UL;i<12UL;i+=2UL)sum+=((ulong)pseudo[i]<<8)|pseudo[i+1];expected=checksum((uchar const *)udp,280UL,sum)==0U;
  fd_net_tile_t ctx;fd_stem_context_t stem;ulong seq,credit,min_credit,depth;int reliable;fd_frag_meta_t * mcaches[1];fd_frag_meta_t * mc=setup(&ctx,&stem,packet,DST_PROTO_TPU_UDP,&seq,&credit,&min_credit,&reliable,mcaches,&depth);ctx.dst_ports[0]=9001U;
  ulong freed;int pub=fd_net_rx_pkt(&ctx,&stem,1UL,0UL,sz,123UL,&freed,NULL);int ok=pub==expected && (pub ? freed==33UL && seq==1UL : freed==1UL && !seq && mc[0].chunk==33U);
  printf("{\"live_received_fixture\":\"%s\",\"native_signed_valid\":true,\"expected\":%d,\"published\":%d,\"ok\":%d}\n",path,expected,pub,ok);cases++;failures+=(ulong)!ok;fd_mcache_delete(fd_mcache_leave(mc));
}
static void
bench( ulong payload, int nonzero ) {
  fd_memset(packet,0,sizeof(packet));uchar * frame=packet+FD_CHUNK_SZ;fd_eth_hdr_t * eth=(fd_eth_hdr_t *)frame;eth->net_type=fd_ushort_bswap(FD_ETH_HDR_TYPE_IP);fd_ip4_hdr_t * ip=(fd_ip4_hdr_t *)(eth+1);*ip=(fd_ip4_hdr_t){.verihl=FD_IP4_VERIHL(4,5),.protocol=17U,.saddr=FD_IP4_ADDR(198,51,100,1),.daddr=FD_IP4_ADDR(198,51,100,2),.net_tot_len=fd_ushort_bswap((ushort)(28UL+payload))};fd_udp_hdr_t * udp=(fd_udp_hdr_t *)(ip+1);*udp=(fd_udp_hdr_t){.net_sport=fd_ushort_bswap(4321U),.net_dport=fd_ushort_bswap(9000U),.net_len=fd_ushort_bswap((ushort)(8UL+payload))};for(ulong i=0UL;i<payload;i++)((uchar *)(udp+1))[i]=wire[i%wire_sz];if(nonzero)set_checksum(ip,udp,8UL+payload);ip->check=fd_ip4_hdr_check(ip);
  fd_net_tile_t ctx;fd_stem_context_t stem;ulong seq,credit,min_credit,depth;int reliable;fd_frag_meta_t * mcaches[1];fd_frag_meta_t * mc=setup(&ctx,&stem,packet,DST_PROTO_TPU_UDP,&seq,&credit,&min_credit,&reliable,mcaches,&depth);reliable=0;ulong freed,iterations=200000UL;long start=fd_log_wallclock();
  for(ulong i=0UL;i<iterations;i++){FD_COMPILER_MFENCE();FD_TEST(fd_net_rx_pkt(&ctx,&stem,1UL,0UL,42UL+payload,123UL,&freed,NULL));}
  long elapsed=fd_log_wallclock()-start;printf("{\"benchmark_payload\":%lu,\"nonzero\":%d,\"iterations\":%lu,\"ns_per_packet\":%.3f,\"scope\":\"local_parser_stem_mcache_only\"}\n",payload,nonzero,iterations,(double)elapsed/(double)iterations);fd_mcache_delete(fd_mcache_leave(mc));
}
int
main( int argc, char ** argv ) {
  fd_boot(&argc,&argv);FD_TEST(wire_sz==307UL && verify_wire(wire,wire_sz));
  for(int iavf=0;iavf<=1;iavf++)for(int gre=0;gre<=1;gre++) {
    run_case("valid_signed_odd",1,307UL,307UL,0UL,gre,0UL,0UL,iavf,DST_PROTO_TPU_UDP,1,0);
    run_case("omitted_checksum",0,307UL,307UL,0UL,gre,0UL,0UL,iavf,DST_PROTO_TPU_UDP,1,0);
    run_case("invalid_nonzero",2,307UL,307UL,0UL,gre,0UL,0UL,iavf,DST_PROTO_TPU_UDP,0,0);
    run_case("valid_IPoptions_padding",1,307UL,307UL,40UL,gre,7UL,15UL,iavf,DST_PROTO_TPU_UDP,1,0);
    run_case("bad_IPoptions_padding",2,307UL,307UL,4UL,gre,7UL,15UL,iavf,DST_PROTO_TPU_UDP,0,0);
    run_case("declared_short_valid",1,307UL,16UL,0UL,gre,0UL,0UL,iavf,DST_PROTO_TPU_UDP,1,0);
    run_case("checksum_over_hidden_tail",3,307UL,16UL,0UL,gre,0UL,0UL,iavf,DST_PROTO_TPU_UDP,0,0);
    run_case("UDP_larger_than_IP",1,307UL,308UL,0UL,gre,0UL,0UL,iavf,DST_PROTO_TPU_UDP,0,0);
    run_case("pseudoheader_corrupt",4,307UL,307UL,0UL,gre,0UL,0UL,iavf,DST_PROTO_TPU_UDP,0,0);
    run_case("odd_final_byte_corrupt",5,307UL,307UL,0UL,gre,0UL,0UL,iavf,DST_PROTO_TPU_UDP,0,0);
  }
  for(ulong n=0UL;n<8UL;n++)run_case("guard_page_exact_tail",1,n,n,0UL,0,0UL,0UL,0,DST_PROTO_TPU_UDP,1,1);
  run_case("empty_UDP_zero",0,0UL,0UL,0UL,0,0UL,0UL,1,DST_PROTO_TPU_UDP,1,0);
  run_case("unbound_kernel_path",6,307UL,307UL,0UL,0,0UL,0UL,1,DST_PROTO_TPU_UDP,0,0);
  ulong protocols[]={DST_PROTO_TPU_QUIC,DST_PROTO_SHRED,DST_PROTO_GOSSIP,DST_PROTO_REPAIR,DST_PROTO_RSERVE,DST_PROTO_VOTOR};
  for(ulong i=0UL;i<sizeof(protocols)/sizeof(protocols[0]);i++)run_case("shared_protocol_bad",2,307UL,307UL,0UL,0,0UL,0UL,1,protocols[i],0,0);
  for(int i=1;i<argc;i++)live_frame(argv[i]);
  ulong sizes[]={272UL,307UL,1232UL};for(ulong i=0UL;i<3UL;i++)for(int nonzero=0;nonzero<=1;nonzero++)bench(sizes[i],nonzero);
  printf("{\"cases\":%lu,\"failures\":%lu,\"full_quic_tile\":false,\"hardware\":false}\n",cases,failures);fd_halt();return failures ? 1 : 0;
}
