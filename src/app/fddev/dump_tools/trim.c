#include "../../../util/fd_util_base.h"
#include "../../../util/net/fd_pcap.h"
#include "../../../ballet/txn/fd_txn.h"
#include "../../../ballet/shred/fd_shred.h"
#include "../../../disco/pack/fd_microblock.h"
#include "../../../disco/fd_txn_m.h"
#include "../../../ballet/base64/fd_base64.h"
#include "../../../ballet/base58/fd_base58.h"
#include "../../../tango/fd_tango_base.h"
#include "../../../disco/tiles.h"
#include "stdio.h"

#define SIG_MATCH( sig ) ( (fd_uint_load_4( sig )>0U)? 1 : 1 )


int main( int     argc,
          char ** argv ) {
  fd_boot( &argc, &argv );

  const char * in_path  = fd_env_strip_cmdline_cstr( &argc, &argv, "--in",     NULL, NULL );
  const char * out_path = fd_env_strip_cmdline_cstr( &argc, &argv, "--out",    NULL, NULL );
  long         min_ts   = fd_env_strip_cmdline_long( &argc, &argv, "--min-ts", NULL, 0L   );
  long         max_ts   = fd_env_strip_cmdline_long( &argc, &argv, "--max-ts", NULL, LONG_MAX );
  FILE * pcap_file = fopen( in_path,  "r"  );
  FILE * out_file  = fopen( out_path, "wb" );
  FD_TEST( pcap_file );
  FD_TEST( out_file );

  fseek( pcap_file, 0L, SEEK_END );
  long file_sz = ftell( pcap_file );
  fseek( pcap_file, 0L, SEEK_SET );

  FD_TEST( fd_pcap_fwrite_hdr( out_file, FD_PCAP_LINK_LAYER_USER0 ) );

  fd_pcap_iter_t * iter = fd_pcap_iter_new( pcap_file );
  FD_TEST( iter );

  uchar pkt[ USHORT_MAX+64UL ] __attribute__((aligned(128)));
  long ts[1];
  ulong pkt_sz;

  long last_log = 0L;

  ulong i = 0UL;
  while( 0UL!=(pkt_sz=fd_pcap_iter_next( iter, pkt, USHORT_MAX+64UL, ts ) ) ) {
    i++;

    long tick_count = fd_tickcount();
    if( FD_UNLIKELY( tick_count - last_log>4000000000L ) ) {
      long current_pos = ftell( pcap_file );
      FD_LOG_NOTICE(( "%lu processed. %li B of %li B (%f %%)", i, current_pos, file_sz, (100.0*(double)current_pos)/(double)file_sz ));
      last_log = tick_count;
    }

    if( FD_LIKELY( (*ts<min_ts) | (*ts>max_ts) ) ) continue;

    FD_TEST( pkt_sz>4UL );
    uint link_hash = FD_LOAD( uint, pkt+pkt_sz-4UL );
#define DEDUP_RESOLV 0x409d3f00
#define RESOLV_PACK  0x59bd9100
#define PACK_BANK    0x7b834200

    fd_frag_meta_t const * mcache_entry = (fd_frag_meta_t const *)pkt;

    int keep = 0;
    switch( link_hash ) {
      case DEDUP_RESOLV:
      case RESOLV_PACK: {
        fd_txn_m_t const * txnm = (fd_txn_m_t const *)(mcache_entry+1);
        keep |= SIG_MATCH( fd_txn_m_payload_const( txnm )+1 );
        break;
      }
      case PACK_BANK: {
        fd_txn_p_t const * txnm = (fd_txn_p_t const *)(mcache_entry+1);
        for( ulong j=0UL; j<mcache_entry->sz/sizeof(fd_txn_p_t); j++ ) {
          keep |= SIG_MATCH( txnm[j].payload+1 );
        }
        break;
      }
      default:
        continue;
    }
    if( FD_LIKELY( !keep ) ) continue;

    FD_TEST( fd_pcap_fwrite_pkt( *ts, mcache_entry, sizeof(fd_frag_meta_t), mcache_entry+1, mcache_entry->sz, link_hash, out_file ) );
  }


  FD_TEST( !fclose( fd_pcap_iter_delete( iter ) ) );
  FD_TEST( !fclose( out_file ) );
  fd_halt();
  return 0;
}
