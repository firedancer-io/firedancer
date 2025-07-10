#include "../../../util/fd_util_base.h"
#include "../../../util/net/fd_pcap.h"
#include "../../../ballet/txn/fd_txn.h"
#include "../../../ballet/shred/fd_shred.h"
#include "../../../ballet/hex/fd_hex.h"
#include "../../../disco/pack/fd_microblock.h"
#include "../../../tango/fd_tango_base.h"
#include "../../../disco/tiles.h"
#include "../../../disco/pack/fd_pack_rebate_sum.h"
#include "stdio.h"
#include <unistd.h>

fd_pack_rebate_sum_t _r[1];



int main( int     argc,
          char ** argv ) {
  const char * path = fd_env_strip_cmdline_cstr( &argc, &argv, "--path", NULL, NULL );
  FILE * pcap_file = fopen( path, "r" );
  FILE * fp2 = fopen( path, "r" );
  FD_TEST( pcap_file );

  fd_pcap_iter_t * bank_poh_iter  = fd_pcap_iter_new( pcap_file );
  FD_TEST( bank_poh_iter );
  fd_pcap_iter_t * bank_pack_iter = fd_pcap_iter_new( fp2 );
  FD_TEST( bank_pack_iter );

  uchar pkt[ USHORT_MAX+64UL ] __attribute__((aligned(128)));
  uchar pkt2[ USHORT_MAX+64UL ] __attribute__((aligned(128))) = { 0 };
  long ts[1];
  ulong pkt_sz;
  ulong pkt2_sz = 4UL;
  fd_frag_meta_t const * mcache = (fd_frag_meta_t const *)pkt;
  fd_frag_meta_t const * mcache2 = (fd_frag_meta_t const *)pkt2;

  fd_pack_rebate_sum_t * r = fd_pack_rebate_sum_join( fd_pack_rebate_sum_new( _r ) );
  fd_acct_addr_t const * adtl[31] = { NULL };

  while( 0UL!=(pkt_sz=fd_pcap_iter_next( bank_pack_iter, pkt, USHORT_MAX+64UL, ts ) ) ) {
    FD_TEST( pkt_sz>4UL );
    uint link_hash = FD_LOAD( uint, pkt+pkt_sz-4UL );
    if( FD_UNLIKELY( link_hash!=0x2080d600U ) ) continue;

    while( 1 ) {
      uint link_hash2 = FD_LOAD( uint, pkt2+pkt2_sz-4UL );
      if( link_hash2==0xfe7bbf00U ) {
        if( mcache2->tspub > mcache->tspub ) break;

        fd_txn_p_t const * processed = (fd_txn_p_t const *)(mcache2+1);
        FD_TEST( 0UL==fd_pack_rebate_sum_add_txn( r, processed, adtl, pkt2_sz/sizeof(fd_txn_p_t) ) );
      }

      pkt2_sz=fd_pcap_iter_next( bank_poh_iter, pkt2, USHORT_MAX+64UL, ts );
    }

    union{ fd_pack_rebate_t rebate[1]; uchar footprint[USHORT_MAX]; } out_report[1];
    ulong rebate_sz = fd_pack_rebate_sum_report( r, out_report->rebate );
    FD_TEST( rebate_sz>0UL );
    for( ulong i=0UL; i<(ulong)out_report->rebate->writer_cnt; i++ ) {
      char hex[65];
      fd_hex_encode( hex, out_report->rebate->writer_rebates[i].key.b, 32UL );
      FD_LOG_NOTICE(( "%s %lu", hex, out_report->rebate->writer_rebates[i].rebate_cus ));
    }
    FD_LOG_NOTICE(( "------" ));
  }


  FD_TEST( !fclose( fd_pcap_iter_delete( bank_poh_iter ) ) );
  FD_TEST( !fclose( fd_pcap_iter_delete( bank_pack_iter ) ) );
  return 0;
}
