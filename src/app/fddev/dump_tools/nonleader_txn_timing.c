#include "../../../util/fd_util_base.h"
#include "../../../util/net/fd_pcap.h"
#include "../../../ballet/txn/fd_txn.h"
#include "../../../ballet/shred/fd_shred.h"
#include "../../../disco/pack/fd_microblock.h"
#include "../../../tango/fd_tango_base.h"
#include "../../../disco/tiles.h"
#include "stdio.h"

uchar batch[ 32UL*1024UL*1024UL ];

static inline void
process_batch( FILE        * outf,
               uchar const * entry,
               ulong         sz,
               ulong         slot,
               ulong         ref_tick,
               long          t0,
               long          t1,
               ulong       * txn_idx,
               ulong       * hashcnt ) {

  ulong microblock_cnt = FD_LOAD( ulong, entry );
  if( FD_UNLIKELY( microblock_cnt>sz/48UL ) ) {
    FD_LOG_WARNING(( "skipping batch that seems to have microblock_cnt %lu", microblock_cnt ));
    return;
  }
  entry += 8UL;
  sz    -= 8UL;

  double _t0 = (double)t0 / 3097835.715;
  double _t1 = (double)t1 / 3097835.715;
  for( ulong j=0UL; j<microblock_cnt; j++ ) {
    fd_entry_batch_header_t hdr[1];
    memcpy( hdr, entry, sizeof(hdr) );

    *hashcnt += hdr->hashcnt_delta;

    entry += sizeof(hdr);
    sz    -= sizeof(hdr);

    uchar txn[ FD_TXN_MAX_SZ ];
    ulong payload_sz[1] = {0UL};
    fd_txn_parse_counters_t counters[1] = {{ 0 }};
    for( ulong k=0UL; k<hdr->txn_cnt; k++ ) {
      ulong parsed = fd_txn_parse_core( entry, fd_ulong_min( sz, FD_TXN_MTU ), txn, counters, payload_sz );
      FD_TEST( parsed>0UL );
      int vote = fd_txn_is_simple_vote_transaction( (fd_txn_t const *)txn, entry );
      char sig[FD_BASE58_ENCODED_64_SZ];
      fprintf( outf, "%lu,%lu,%lu,%f,%f,%lu,%s,%i\n", slot, ref_tick, *hashcnt, _t0, _t1, *txn_idx, fd_base58_encode_64( entry+1UL, NULL, sig ), vote );
      entry += *payload_sz;
      sz    -= *payload_sz;
      (*txn_idx)++;
    }
  }
}


int main( int     argc,
          char ** argv ) {
  fd_boot( &argc, &argv );
  const char * path  = fd_env_strip_cmdline_cstr( &argc, &argv, "--path",  NULL, NULL );
  ulong        slot0 = fd_env_strip_cmdline_ulong( &argc, &argv, "--slot0", NULL, 0UL );
  FILE * pcap_file = fopen( path, "r" );
  FD_TEST( pcap_file );
  FD_TEST( slot0 );

  char of_path[ 64 ];
  sprintf( of_path, "%lu.csv", slot0 );

  FILE * outf = fopen( of_path, "w" );

  uchar pkt[ USHORT_MAX+64UL ] __attribute__((aligned(128)));
  long ts[1];
  ulong pkt_sz;

  ulong ex_slot = slot0;
  ulong ex_idx  = 0UL;
  ulong offset  = 0UL;
  ulong ref_tick = ULONG_MAX;
  ulong txn_idx  = 0UL;
  ulong hashcnt = 0UL;

  // FD_LOG_NOTICE(( "------------------ %lu -------------------", ex_slot ));

  fprintf( outf, "slot,reftick,hashcnt,t0_millis,t1_millis,idx,sig,is_vote\n" );
  while( ex_slot<slot0+4UL ) {
    fseek( pcap_file, 0L, SEEK_SET );
    fd_pcap_iter_t * iter = fd_pcap_iter_new( pcap_file );
    FD_TEST( iter );

    long t_start = 0L;
    long t_prev  = 0L;
    long t_adj   = LONG_MAX;

    while( 0UL!=(pkt_sz=fd_pcap_iter_next( iter, pkt, USHORT_MAX+64UL, ts ) ) ) {
      FD_TEST( pkt_sz>4UL );
      uint link_hash = FD_LOAD( uint, pkt+pkt_sz-4UL );
      if( FD_UNLIKELY( link_hash!=0x6e5d4100U ) ) continue;

      fd_frag_meta_t const * mcache_entry = (fd_frag_meta_t const *)pkt;
      fd_shred34_t const * shreds = (fd_shred34_t const *)(mcache_entry+1);

      if( shreds->shred_sz==1228UL ) continue; /* Skip parity */
      if( t_adj==LONG_MAX ) t_adj = -(long)mcache_entry->tsorig;

      if( (long)mcache_entry->tsorig+t_adj < t_prev - 100000000L ) t_adj += (long)UINT_MAX;

      for( ulong i=0UL; i<shreds->shred_cnt; i++ ) {
        fd_shred_t const * shred = &(shreds->pkts[i].shred);
        if( FD_UNLIKELY( (shred->slot!=ex_slot) | (shred->idx!=ex_idx) ) )  continue;

        if( FD_UNLIKELY( ref_tick==ULONG_MAX ) ) {
          ref_tick = shred->data.flags & 0x3F;
          t_start  = (long)mcache_entry->tsorig+t_adj;
        }

        FD_TEST( (shred->data.flags & 0x3F)==ref_tick );

        ulong payload_sz = fd_shred_payload_sz( shred );
        memcpy( batch+offset, fd_shred_data_payload( shred ), payload_sz );
        offset += payload_sz;

        if( FD_UNLIKELY( shred->data.flags & 0x40 ) ) {
          process_batch( outf, batch, offset, ex_slot, ref_tick, t_start, (long)mcache_entry->tsorig+t_adj, &txn_idx, &hashcnt );
          offset = 0UL;
          ref_tick = ULONG_MAX;
        }

        if( FD_UNLIKELY( shred->data.flags & 0x80 ) ) {
          ex_slot++;
          FD_LOG_NOTICE(( "------------------ %lu (%lu hashes) -------------", ex_slot, hashcnt ));
          ex_idx = 0UL;
          txn_idx = 0UL;
          hashcnt = 0UL;
        } else {
          ex_idx++;
        }

      }
      t_prev = (long)mcache_entry->tsorig+t_adj;
    }
    FD_LOG_INFO(( "restarting, looking for %lu %lu", ex_slot, ex_idx ));
    fd_pcap_iter_delete( iter );
  }

  FD_TEST( !fclose( pcap_file ) );
  fd_halt();
  return 0;
}
