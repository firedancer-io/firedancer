#include "../../../util/fd_util_base.h"
#include "../../../util/net/fd_pcap.h"
#include "../../../ballet/txn/fd_txn.h"
#include "../../../ballet/shred/fd_shred.h"
#include "../../../disco/pack/fd_microblock.h"
#include "../../../tango/fd_tango_base.h"
#include "../../../disco/tiles.h"
#include "stdio.h"

#define MAX_MICROBLOCKS 32*1024
ulong hashes[ MAX_MICROBLOCKS ];

static inline ulong
process_batch( uchar const * entry,
               ulong         sz,
               int           log_details,
               ulong *       _nontick_cnt,
               ulong *       _hashcnt,
               ulong *       _txn_cnt,
               ulong *       _detail_idx   ) {

  ulong microblock_cnt = FD_LOAD( ulong, entry );
  if( FD_UNLIKELY( microblock_cnt>sz/48UL ) ) {
    FD_LOG_WARNING(( "skipping batch that seems to have microblock_cnt %lu", microblock_cnt ));
    return 0UL;
  }
  entry += 8UL;
  sz    -= 8UL;

  ulong tick_cnt    = 0UL;
  ulong nontick_cnt = 0UL;
  for( ulong j=0UL; j<microblock_cnt; j++ ) {
    fd_entry_batch_header_t hdr[1];
    memcpy( hdr, entry, sizeof(hdr) );
    if( FD_UNLIKELY( hdr->hashcnt_delta>12500UL ) ) {
      FD_LOG_WARNING(( "skipping batch that seems to have hashcnt %lu", hdr->hashcnt_delta ));
      return 0UL;
    }
    if( FD_UNLIKELY( hdr->txn_cnt>31UL ) ) {
      FD_LOG_WARNING(( "skipping batch that seems to have txn_cnt %lu", hdr->txn_cnt ));
      return 0UL;
    }
    if( log_details ) {
      FD_LOG_INFO(( "%lu %lu", hdr->hashcnt_delta, hdr->txn_cnt ));
      hashes[ *_detail_idx - microblock_cnt + j ] = (hdr->hashcnt_delta<<32) | hdr->txn_cnt;
    }

    entry += sizeof(hdr);
    sz    -= sizeof(hdr);

    tick_cnt    += (ulong)(hdr->txn_cnt==0UL);
    nontick_cnt += (ulong)(hdr->txn_cnt> 0UL);
    *_hashcnt   += hdr->hashcnt_delta;

    uchar txn[ FD_TXN_MAX_SZ ];
    ulong payload_sz[1] = {0UL};
    fd_txn_parse_counters_t counters[1] = {{ 0 }};
    for( ulong k=0UL; k<hdr->txn_cnt; k++ ) {
      ulong parsed = fd_txn_parse_core( entry, fd_ulong_min( sz, FD_TXN_MTU ), txn, counters, payload_sz );
      FD_TEST( parsed>0UL );
      entry += *payload_sz;
      sz    -= *payload_sz;
      if( *payload_sz!=178UL ) FD_LOG_INFO(( "txn payload sz=%lu", *payload_sz ));
      (*_txn_cnt)++;
    }
  }
  if( log_details ) {
    FD_LOG_INFO(( "-- %lu", *_hashcnt ));
    *_detail_idx -= microblock_cnt;
  }
  *_nontick_cnt += nontick_cnt;
  return tick_cnt;
}


int main( int     argc,
          char ** argv ) {
  const char * path = fd_env_strip_cmdline_cstr( &argc, &argv, "--path", NULL, NULL );
  FILE * pcap_file = fopen( path, "r" );
  FD_TEST( pcap_file );

  fd_pcap_iter_t * iter = fd_pcap_iter_new( pcap_file );
  FD_TEST( iter );

  uchar pkt[ USHORT_MAX+64UL ] __attribute__((aligned(128)));
  long ts[1];
  ulong pkt_sz;

  ulong last_slot     = 0UL;
  ulong last_tick_cnt = 0UL;
  ulong last_nontick_cnt = 0UL;
  ulong last_hashcnt  = 0UL;

  uchar entry[ USHORT_MAX ];
  ulong last_sig = 0UL;
  ulong populated = 0UL;
  ulong detail_log_idx = MAX_MICROBLOCKS;

  ulong transaction_bytes = 0UL;
  ulong total_transaction_count = 0UL;
  ulong approx_transaction_count = 0UL;
  while( 0UL!=(pkt_sz=fd_pcap_iter_next( iter, pkt, USHORT_MAX+64UL, ts ) ) ) {
    FD_TEST( pkt_sz>4UL );
    uint link_hash = FD_LOAD( uint, pkt+pkt_sz-4UL );
    if( FD_UNLIKELY( link_hash!=0x6e5d4100U ) ) continue;

    fd_frag_meta_t const * mcache_entry = (fd_frag_meta_t const *)pkt;
    fd_shred34_t const * shreds = (fd_shred34_t const *)(mcache_entry+1);

    if( shreds->shred_sz==1228UL ) continue; /* Skip parity */

    ulong sig = FD_LOAD( ulong, shreds->pkts->shred.signature );
    fd_shred_t const * shred0 = &(shreds->pkts->shred);
    fd_shred_t const * shredN = &(shreds->pkts[ shreds->shred_cnt-1UL ].shred);
    ulong this_payload_sz = shreds->shred_cnt * fd_shred_payload_sz( shred0 );

    transaction_bytes += shreds->shred_cnt * fd_shred_payload_sz( shred0 );
    if( 1 /*first*/ ) transaction_bytes -= 8UL + 48UL * FD_LOAD( ulong, fd_shred_data_payload( shred0 ) );
    if( shredN->data.flags & 0x40 ) transaction_bytes -= fd_shred_payload_sz( shred0 ) - fd_shred_payload_sz( shredN );

    if( FD_UNLIKELY( sig==last_sig ) ) {
      FD_LOG_WARNING(( "multiple" ));
      memmove( entry+this_payload_sz, entry, populated );
    } else {
      /* Complete batch */
      last_tick_cnt += process_batch( entry, populated, last_slot==401UL, &last_nontick_cnt, &last_hashcnt, &total_transaction_count, &detail_log_idx );

      approx_transaction_count += transaction_bytes/178UL;
      transaction_bytes = 0UL;

      if( FD_UNLIKELY( shreds->pkts->shred.slot!=last_slot ) ) {
        FD_LOG_NOTICE(( "Slot %lu had %lu ticks, %lu nonticks, %lu hashcnt ", last_slot, last_tick_cnt, last_nontick_cnt, last_hashcnt ));
        last_slot = shreds->pkts->shred.slot;
        last_tick_cnt = 0UL;
        last_nontick_cnt = 0UL;
        last_hashcnt = 0UL;
      }

      populated = 0UL;
      last_sig = sig;
    }

    ulong pop_i = 0UL;
    for( ulong i=0UL; i<shreds->shred_cnt; i++ ) {
      fd_shred_t const * shred = &(shreds->pkts[ i ].shred);
      ulong payload_sz = fd_shred_payload_sz( shred );
      FD_TEST( payload_sz<shreds->shred_sz );
      FD_TEST( shred->slot<1000000UL );
      fd_memcpy( entry+pop_i, fd_shred_data_payload( shred ), payload_sz );
      pop_i += payload_sz;
    }
    populated += pop_i;
  }
  last_tick_cnt += process_batch( entry, populated, 0, &last_nontick_cnt, &last_hashcnt, &total_transaction_count, &detail_log_idx );
  FD_LOG_NOTICE(( "First slot %lu had %lu ticks", last_slot, last_tick_cnt ));

  ulong cumulative = 0UL;
  ulong since_last_tick = 0UL;
  for( ulong i=detail_log_idx; i<MAX_MICROBLOCKS; i++ ) {
    ulong hashes_ = hashes[ i ]>>32;
    cumulative += hashes_;
    since_last_tick += hashes_;
    int is_tick = !(hashes[ i ]&0xFFFFFFFFUL);
    FD_LOG_INFO(( "%8lu %8lu %8lu %i", hashes_, cumulative, since_last_tick, is_tick ));
    if( is_tick ) since_last_tick = 0UL;
  }

  FD_LOG_NOTICE(( "%lu transactions. Approximation gives %lu ", total_transaction_count, approx_transaction_count ));

  FD_TEST( !fclose( fd_pcap_iter_delete( iter ) ) );
  return 0;
}
