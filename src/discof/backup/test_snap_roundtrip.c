#include "fd_ssmanifest_writer.h"
#include "fd_txncache_writer.h"
#include "../restore/utils/fd_ssmanifest_parser.h"
#include "../restore/utils/fd_slot_delta_parser.h"
#include "../../flamenco/runtime/tests/fd_svm_mini.h"
#include "../../flamenco/runtime/fd_txncache.h"
#include "../../flamenco/runtime/fd_txncache_shmem.h"

#include <stdlib.h>
#include <string.h>

#define MAX_LIVE_SLOTS   16UL
#define MAX_TXN_PER_SLOT 4096UL
#define VALIDATOR_CNT    3UL
#define ROOT_SLOT        42UL

static fd_txncache_t *
create_txncache( void ) {
  ulong shmem_fp = fd_txncache_shmem_footprint( MAX_LIVE_SLOTS, MAX_TXN_PER_SLOT );
  void * shmem_raw = aligned_alloc( fd_txncache_shmem_align(), shmem_fp );
  FD_TEST( shmem_raw );
  fd_txncache_shmem_t * shmem = fd_txncache_shmem_join( fd_txncache_shmem_new( shmem_raw, MAX_LIVE_SLOTS, MAX_TXN_PER_SLOT ) );
  FD_TEST( shmem );

  ulong ljoin_fp = fd_txncache_footprint( MAX_LIVE_SLOTS );
  void * ljoin_raw = aligned_alloc( fd_txncache_align(), ljoin_fp );
  FD_TEST( ljoin_raw );
  fd_txncache_t * tc = fd_txncache_join( fd_txncache_new( ljoin_raw, shmem ) );
  FD_TEST( tc );
  return tc;
}

#define NULL_FORK ((fd_txncache_fork_id_t){ .val = USHORT_MAX })

static void
populate_txncache( fd_txncache_t * tc,
                   uchar           blockhashes[ 4 ][ 32 ],
                   uchar           txnhashes[ 6 ][ 20 ] ) {
  for( ulong bh=0UL; bh<3UL; bh++ ) {
    memset( blockhashes[bh], 0, 32UL );
    blockhashes[bh][0] = (uchar)(bh+1U);
    blockhashes[bh][1] = 0xAB;
  }
  memset( blockhashes[3], 0xFF, 32UL );

  /* Build a chain where each slot finalizes with a blockhash,
     making it available for txn inserts in the next slot.
     root  -> finalize(bh0)
     s1    -> insert(bh0, txn0..1) -> finalize(bh1)
     s2    -> insert(bh1, txn2..3) -> finalize(bh2)
     s3    -> insert(bh2, txn4..5) -> finalize(final_bh)
     advance root to s3 */

  fd_txncache_fork_id_t root = fd_txncache_attach_child( tc, NULL_FORK );
  fd_txncache_finalize_fork( tc, root, 0UL, blockhashes[0] );

  fd_txncache_fork_id_t s1 = fd_txncache_attach_child( tc, root );
  for( ulong tx=0UL; tx<2UL; tx++ ) {
    memset( txnhashes[tx], 0, 20UL );
    txnhashes[tx][0] = (uchar)(tx+1U);
    txnhashes[tx][1] = 0xCD;
    fd_txncache_insert( tc, s1, blockhashes[0], txnhashes[tx] );
  }
  fd_txncache_finalize_fork( tc, s1, 0UL, blockhashes[1] );
  fd_txncache_advance_root( tc, s1 );

  fd_txncache_fork_id_t s2 = fd_txncache_attach_child( tc, s1 );
  for( ulong tx=0UL; tx<2UL; tx++ ) {
    ulong idx = 2UL + tx;
    memset( txnhashes[idx], 0, 20UL );
    txnhashes[idx][0] = (uchar)(idx+1U);
    txnhashes[idx][1] = 0xCD;
    fd_txncache_insert( tc, s2, blockhashes[1], txnhashes[idx] );
  }
  fd_txncache_finalize_fork( tc, s2, 0UL, blockhashes[2] );
  fd_txncache_advance_root( tc, s2 );

  fd_txncache_fork_id_t s3 = fd_txncache_attach_child( tc, s2 );
  for( ulong tx=0UL; tx<2UL; tx++ ) {
    ulong idx = 4UL + tx;
    memset( txnhashes[idx], 0, 20UL );
    txnhashes[idx][0] = (uchar)(idx+1U);
    txnhashes[idx][1] = 0xCD;
    fd_txncache_insert( tc, s3, blockhashes[2], txnhashes[idx] );
  }
  fd_txncache_finalize_fork( tc, s3, 0UL, blockhashes[3] );
  fd_txncache_advance_root( tc, s3 );
}

static void
fill_hash32( uchar hash[ 32UL ],
             ulong seed ) {
  memset( hash, 0, 32UL );
  FD_STORE( ulong, hash, seed );
  hash[ 8 ] = 0xAB;
}

static void
fill_hash20( uchar hash[ 20UL ],
             ulong seed ) {
  memset( hash, 0, 20UL );
  FD_STORE( ulong, hash, seed );
  hash[ 8 ] = 0xCD;
}

static void
make_slot_history( uchar out[ FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ ],
                   ulong newest_slot,
                   ulong const * slots,
                   ulong slot_cnt ) {
  ulong const blocks_len = FD_SLOT_HISTORY_MAX_ENTRIES / (8UL*sizeof(ulong));
  memset( out, 0, FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ );
  out[0] = 1;
  FD_STORE( ulong, out+1UL, blocks_len );
  uchar * bits = out+9UL;
  for( ulong i=0UL; i<slot_cnt; i++ ) {
    ulong slot = slots[ i ];
    ulong block_idx = (slot / (8UL*sizeof(ulong))) % blocks_len;
    ulong word = FD_LOAD( ulong, bits + block_idx*sizeof(ulong) );
    word |= 1UL << (slot % (8UL*sizeof(ulong)));
    FD_STORE( ulong, bits + block_idx*sizeof(ulong), word );
  }
  uchar * footer = bits + blocks_len*sizeof(ulong);
  FD_STORE( ulong, footer,      FD_SLOT_HISTORY_MAX_ENTRIES );
  FD_STORE( ulong, footer+8UL,  newest_slot+1UL             );
}

static uchar *
serialize_txncache( fd_txncache_t * tc,
                    ulong           slot,
                    fd_slot_history_view_t const * slot_history,
                    ulong *         sz ) {
  fd_txncache_writer_t * writer = aligned_alloc( alignof(fd_txncache_writer_t), sizeof(fd_txncache_writer_t) );
  FD_TEST( writer );
  fd_txncache_writer_init( writer, tc, slot, slot_history );

  *sz = fd_txncache_writer_serialized_sz( writer );
  FD_TEST( *sz>0UL );

  uchar * buf = malloc( *sz );
  FD_TEST( buf );

  uchar * chunk_buf = malloc( FD_TXNCACHE_WRITER_BUF_MIN );
  FD_TEST( chunk_buf );

  ulong total_written = 0UL;
  for(;;) {
    ulong chunk_sz = fd_txncache_writer_serialize( writer, chunk_buf, FD_TXNCACHE_WRITER_BUF_MIN );
    if( !chunk_sz ) break;
    FD_TEST( total_written + chunk_sz <= *sz );
    memcpy( buf + total_written, chunk_buf, chunk_sz );
    total_written += chunk_sz;
  }
  if( FD_UNLIKELY( total_written!=*sz ) ) {
    FD_LOG_ERR(( "txncache serialized size mismatch: wrote %lu expected %lu", total_written, *sz ));
  }

  free( chunk_buf );
  free( writer );
  return buf;
}

struct parsed_group {
  uchar blockhash[ 32UL ];
  ulong txnhash_offset;
};
typedef struct parsed_group parsed_group_t;

struct expected_entry {
  uchar const * blockhash;
  uchar const * txnhash;
};
typedef struct expected_entry expected_entry_t;

static void
parse_txncache( uchar const *            buf,
                ulong                    sz,
                ulong                    feed_sz,
                ulong                    slot,
                ulong                    expected_slot_cnt,
                parsed_group_t const *   expected_groups,
                ulong                    expected_group_cnt,
                expected_entry_t const * expected_entries,
                ulong                    expected_entry_cnt,
                fd_sstxncache_entry_t *  entries_out,
                parsed_group_t *         groups_out ) {
  void * parser_mem = aligned_alloc( fd_slot_delta_parser_align(), fd_slot_delta_parser_footprint() );
  FD_TEST( parser_mem );
  fd_slot_delta_parser_t * parser = fd_slot_delta_parser_join( fd_slot_delta_parser_new( parser_mem ) );
  FD_TEST( parser );
  fd_slot_delta_parser_init( parser );

  uchar * entry_seen = calloc( expected_entry_cnt ? expected_entry_cnt : 1UL, 1UL );
  FD_TEST( entry_seen );

  ulong entries_parsed = 0UL;
  ulong groups_parsed  = 0UL;
  ulong pos            = 0UL;

  for(;;) {
    fd_slot_delta_parser_advance_result_t result[1];
    ulong chunk_sz = fd_ulong_min( feed_sz, sz-pos );
    int res = fd_slot_delta_parser_consume( parser, buf+pos, chunk_sz, result );
    FD_TEST( res>=0 );
    FD_TEST( result->bytes_consumed<=chunk_sz );
    pos += result->bytes_consumed;

    if( res==FD_SLOT_DELTA_PARSER_ADVANCE_DONE ) {
      FD_TEST( pos==sz );
      break;
    }

    if( res==FD_SLOT_DELTA_PARSER_ADVANCE_AGAIN ) {
      FD_TEST( pos<sz );
      continue;
    }

    if( res==FD_SLOT_DELTA_PARSER_ADVANCE_GROUP ) {
      FD_TEST( groups_parsed<expected_group_cnt );
      FD_TEST( 0==memcmp( result->group.blockhash, expected_groups[ groups_parsed ].blockhash, 32UL ) );
      FD_TEST( result->group.txnhash_offset==expected_groups[ groups_parsed ].txnhash_offset );
      if( groups_out ) {
        memcpy( groups_out[ groups_parsed ].blockhash, result->group.blockhash, 32UL );
        groups_out[ groups_parsed ].txnhash_offset = result->group.txnhash_offset;
      }
      groups_parsed++;
      continue;
    }

    FD_TEST( res==FD_SLOT_DELTA_PARSER_ADVANCE_ENTRY );
    fd_sstxncache_entry_t const * entry = result->entry;
    FD_TEST( entry->slot==slot );
    FD_TEST( entry->result==0U );

    if( expected_entries ) {
      ulong found_idx = ULONG_MAX;
      for( ulong i=0UL; i<expected_entry_cnt; i++ ) {
        if( entry_seen[ i ] ) continue;
        if( (!expected_entries[ i ].blockhash || 0==memcmp( entry->blockhash, expected_entries[ i ].blockhash, 32UL )) &&
            0==memcmp( entry->txnhash,   expected_entries[ i ].txnhash,   20UL ) ) {
          found_idx = i;
          break;
        }
      }
      if( FD_UNLIKELY( found_idx==ULONG_MAX ) ) {
        FD_LOG_ERR(( "unexpected txncache entry blockhash0=%02x txnhash0=%02x txnhash1=%02x",
                     entry->blockhash[0], entry->txnhash[0], entry->txnhash[1] ));
      }
      entry_seen[ found_idx ] = 1U;
    }

    FD_TEST( entries_parsed<expected_entry_cnt );
    if( entries_out ) entries_out[ entries_parsed ] = *entry;
    entries_parsed++;
  }

  FD_TEST( entries_parsed==expected_entry_cnt );
  FD_TEST( groups_parsed ==expected_group_cnt  );

  fd_slot_delta_slot_set_t slot_set = fd_slot_delta_parser_slot_set( parser );
  FD_TEST( slot_set.ele_cnt==expected_slot_cnt );

  free( entry_seen );
  free( fd_slot_delta_parser_delete( fd_slot_delta_parser_leave( parser ) ) );
}

static void
test_manifest_roundtrip( fd_bank_t * bank ) {
  FD_LOG_NOTICE(( "test_manifest_roundtrip" ));

  ulong manifest_sz = fd_snap_manifest_serialized_sz( bank );
  FD_TEST( manifest_sz>0UL );
  FD_LOG_NOTICE(( "manifest serialized size: %lu", manifest_sz ));

  uchar * buf = aligned_alloc( 1UL, manifest_sz );
  FD_TEST( buf );

  uchar * chunk_buf = aligned_alloc( 1UL, FD_SSMANIFEST_BUF_MIN );
  FD_TEST( chunk_buf );

  fd_ssmanifest_writer_t writer[1];
  fd_ssmanifest_writer_init( writer, bank );
  ulong total_written = 0UL;
  for(;;) {
    ulong sz = fd_snap_manifest_serialize( writer, chunk_buf, FD_SSMANIFEST_BUF_MIN );
    if( !sz ) break;
    FD_TEST( total_written + sz <= manifest_sz );
    memcpy( buf + total_written, chunk_buf, sz );
    total_written += sz;
  }
  FD_TEST( total_written==manifest_sz );

  fd_snapshot_manifest_t * manifest = aligned_alloc( alignof(fd_snapshot_manifest_t), sizeof(fd_snapshot_manifest_t) );
  FD_TEST( manifest );
  memset( manifest, 0, sizeof(fd_snapshot_manifest_t) );

  void * parser_mem = aligned_alloc( fd_ssmanifest_parser_align(), fd_ssmanifest_parser_footprint() );
  FD_TEST( parser_mem );
  fd_ssmanifest_parser_t * parser = fd_ssmanifest_parser_join( fd_ssmanifest_parser_new( parser_mem ) );
  FD_TEST( parser );
  fd_ssmanifest_parser_init( parser, manifest );

  int result = fd_ssmanifest_parser_consume( parser, buf, total_written, NULL, NULL );
  FD_TEST( result==FD_SSMANIFEST_PARSER_ADVANCE_DONE );

  FD_TEST( manifest->slot==bank->f.slot );
  FD_TEST( manifest->block_height==bank->f.block_height );
  FD_TEST( manifest->capitalization==bank->f.capitalization );
  FD_TEST( manifest->ticks_per_slot==bank->f.ticks_per_slot );
  FD_TEST( manifest->epoch_schedule_params.slots_per_epoch==bank->f.epoch_schedule.slots_per_epoch );
  FD_TEST( manifest->rent_params.lamports_per_uint8_year==bank->f.rent.lamports_per_uint8_year );
  FD_TEST( manifest->rent_params.burn_percent==bank->f.rent.burn_percent );

  ulong expected_epoch_cnt = (bank->f.epoch > 0UL) ? 3UL : 2UL;
  for( ulong i=0UL; i<expected_epoch_cnt; i++ ) {
    FD_LOG_NOTICE(( "epoch_stakes[%lu]: epoch=%lu total_stake=%lu vote_stakes_len=%lu",
                    i,
                    manifest->epoch_stakes[i].epoch,
                    manifest->epoch_stakes[i].total_stake,
                    manifest->epoch_stakes[i].vote_stakes_len ));
  }

  free( parser_mem );
  free( manifest );
  free( chunk_buf );
  free( buf );
}

static void
test_txncache_roundtrip( void ) {
  FD_LOG_NOTICE(( "test_txncache_roundtrip" ));

  fd_txncache_t * tc = create_txncache();

  uchar blockhashes[4][32];
  uchar txnhashes[6][20];
  populate_txncache( tc, blockhashes, txnhashes );

  ulong tc_sz = 0UL;
  uchar * buf = serialize_txncache( tc, ROOT_SLOT, NULL, &tc_sz );
  FD_LOG_NOTICE(( "txncache serialized size: %lu", tc_sz ));

  fd_sstxncache_entry_t entries[ 6 ];
  parsed_group_t groups[ 4 ];
  parsed_group_t expected_groups[ 4 ];
  for( ulong i=0UL; i<4UL; i++ ) {
    memcpy( expected_groups[ i ].blockhash, blockhashes[ i ], 32UL );
    expected_groups[ i ].txnhash_offset = 0UL;
  }

  parse_txncache( buf, tc_sz, tc_sz, ROOT_SLOT, 1UL, expected_groups, 4UL, NULL, 6UL, entries, groups );
  parse_txncache( buf, tc_sz, 1UL,    ROOT_SLOT, 1UL, expected_groups, 4UL, NULL, 6UL, NULL,    NULL   );
  FD_LOG_NOTICE(( "parsed %lu entries across %lu groups", 6UL, 4UL ));

  fd_txncache_t * restored = create_txncache();
  fd_txncache_fork_id_t parent = NULL_FORK;
  fd_txncache_fork_id_t forks[ 4 ];
  for( ulong i=0UL; i<4UL; i++ ) {
    forks[ i ] = fd_txncache_attach_child( restored, parent );
    if( i<3UL ) {
      fd_txncache_finalize_fork( restored, forks[ i ], groups[ i ].txnhash_offset, groups[ i ].blockhash );
      if( i ) fd_txncache_advance_root( restored, forks[ i ] );
    }
    parent = forks[ i ];
  }
  for( ulong i=0UL; i<6UL; i++ ) fd_txncache_insert( restored, forks[ 3 ], entries[ i ].blockhash, entries[ i ].txnhash );
  fd_txncache_finalize_fork( restored, forks[ 3 ], groups[ 3 ].txnhash_offset, groups[ 3 ].blockhash );
  fd_txncache_advance_root( restored, forks[ 3 ] );

  for( ulong i=0UL; i<6UL; i++ ) FD_TEST( fd_txncache_query( restored, forks[ 3 ], entries[ i ].blockhash, entries[ i ].txnhash ) );

  free( buf );
}

static void
test_txncache_empty_roundtrip( void ) {
  FD_LOG_NOTICE(( "test_txncache_empty_roundtrip" ));

  fd_txncache_t * tc = create_txncache();
  ulong sz = 0UL;
  uchar * buf = serialize_txncache( tc, ROOT_SLOT+1UL, NULL, &sz );

  parse_txncache( buf, sz, sz, ROOT_SLOT+1UL, 1UL, NULL, 0UL, NULL, 0UL, NULL, NULL );
  parse_txncache( buf, sz, 1UL, ROOT_SLOT+1UL, 1UL, NULL, 0UL, NULL, 0UL, NULL, NULL );

  free( buf );
}

static void
test_txncache_empty_groups_roundtrip( void ) {
  FD_LOG_NOTICE(( "test_txncache_empty_groups_roundtrip" ));

  fd_txncache_t * tc = create_txncache();
  uchar blockhashes[ 3 ][ 32 ];
  parsed_group_t expected_groups[ 3 ];

  for( ulong i=0UL; i<3UL; i++ ) fill_hash32( blockhashes[ i ], 0x1000UL+i );

  fd_txncache_fork_id_t root = fd_txncache_attach_child( tc, NULL_FORK );
  fd_txncache_finalize_fork( tc, root, 10UL, blockhashes[ 0 ] );

  fd_txncache_fork_id_t s1 = fd_txncache_attach_child( tc, root );
  fd_txncache_finalize_fork( tc, s1, 11UL, blockhashes[ 1 ] );
  fd_txncache_advance_root( tc, s1 );

  fd_txncache_fork_id_t s2 = fd_txncache_attach_child( tc, s1 );
  fd_txncache_finalize_fork( tc, s2, 12UL, blockhashes[ 2 ] );
  fd_txncache_advance_root( tc, s2 );

  for( ulong i=0UL; i<3UL; i++ ) {
    memcpy( expected_groups[ i ].blockhash, blockhashes[ i ], 32UL );
    expected_groups[ i ].txnhash_offset = 10UL+i;
  }

  ulong sz = 0UL;
  uchar * buf = serialize_txncache( tc, ROOT_SLOT+2UL, NULL, &sz );
  parse_txncache( buf, sz, sz, ROOT_SLOT+2UL, 1UL, expected_groups, 3UL, NULL, 0UL, NULL, NULL );
  parse_txncache( buf, sz, 3UL, ROOT_SLOT+2UL, 1UL, expected_groups, 3UL, NULL, 0UL, NULL, NULL );

  free( buf );
}

static void
test_txncache_sparse_groups_roundtrip( void ) {
  FD_LOG_NOTICE(( "test_txncache_sparse_groups_roundtrip" ));

  fd_txncache_t * tc = create_txncache();
  uchar blockhashes[ 4 ][ 32 ];
  uchar txnhashes[ 4 ][ 20 ];
  parsed_group_t expected_groups[ 4 ];

  for( ulong i=0UL; i<4UL; i++ ) fill_hash32( blockhashes[ i ], 0x2000UL+i );
  for( ulong i=0UL; i<4UL; i++ ) fill_hash20( txnhashes[ i ], 0x3000UL+i );

  fd_txncache_fork_id_t root = fd_txncache_attach_child( tc, NULL_FORK );
  fd_txncache_finalize_fork( tc, root, 20UL, blockhashes[ 0 ] );

  fd_txncache_fork_id_t s1 = fd_txncache_attach_child( tc, root );
  fd_txncache_insert( tc, s1, blockhashes[ 0 ], txnhashes[ 0 ] );
  fd_txncache_insert( tc, s1, blockhashes[ 0 ], txnhashes[ 1 ] );
  fd_txncache_finalize_fork( tc, s1, 21UL, blockhashes[ 1 ] );
  fd_txncache_advance_root( tc, s1 );

  fd_txncache_fork_id_t s2 = fd_txncache_attach_child( tc, s1 );
  fd_txncache_finalize_fork( tc, s2, 22UL, blockhashes[ 2 ] );
  fd_txncache_advance_root( tc, s2 );

  fd_txncache_fork_id_t s3 = fd_txncache_attach_child( tc, s2 );
  fd_txncache_insert( tc, s3, blockhashes[ 2 ], txnhashes[ 2 ] );
  fd_txncache_insert( tc, s3, blockhashes[ 2 ], txnhashes[ 3 ] );
  fd_txncache_finalize_fork( tc, s3, 23UL, blockhashes[ 3 ] );
  fd_txncache_advance_root( tc, s3 );

  for( ulong i=0UL; i<4UL; i++ ) {
    memcpy( expected_groups[ i ].blockhash, blockhashes[ i ], 32UL );
    expected_groups[ i ].txnhash_offset = 20UL+i;
  }

  ulong sz = 0UL;
  uchar * buf = serialize_txncache( tc, ROOT_SLOT+3UL, NULL, &sz );
  parse_txncache( buf, sz, sz, ROOT_SLOT+3UL, 1UL, expected_groups, 4UL, NULL, 4UL, NULL, NULL );
  parse_txncache( buf, sz, 5UL, ROOT_SLOT+3UL, 1UL, expected_groups, 4UL, NULL, 4UL, NULL, NULL );

  free( buf );
}

static void
test_txncache_hot_roundtrip( void ) {
  FD_LOG_NOTICE(( "test_txncache_hot_roundtrip" ));

  enum { group_cnt = 4UL, txns_per_group = 128UL };
  ulong const entry_cnt = group_cnt*txns_per_group;

  fd_txncache_t * tc = create_txncache();
  uchar blockhashes[ group_cnt+1UL ][ 32 ];
  uchar (* txnhashes)[ 20 ] = calloc( entry_cnt, sizeof(*txnhashes) );
  FD_TEST( txnhashes );
  parsed_group_t * expected_groups = calloc( group_cnt+1UL, sizeof(parsed_group_t) );
  FD_TEST( expected_groups );
  expected_entry_t * expected_entries = calloc( entry_cnt, sizeof(expected_entry_t) );
  FD_TEST( expected_entries );

  for( ulong i=0UL; i<=group_cnt; i++ ) fill_hash32( blockhashes[ i ], 0x4000UL+i );
  for( ulong i=0UL; i<entry_cnt; i++ ) fill_hash20( txnhashes[ i ], 0x5000UL+i );

  fd_txncache_fork_id_t parent = fd_txncache_attach_child( tc, NULL_FORK );
  fd_txncache_finalize_fork( tc, parent, 30UL, blockhashes[ 0 ] );

  for( ulong g=0UL; g<group_cnt; g++ ) {
    fd_txncache_fork_id_t fork = fd_txncache_attach_child( tc, parent );
    for( ulong j=0UL; j<txns_per_group; j++ ) {
      ulong idx = g*txns_per_group + j;
      fd_txncache_insert( tc, fork, blockhashes[ g ], txnhashes[ idx ] );
      expected_entries[ idx ] = (expected_entry_t){ .blockhash = NULL, .txnhash = txnhashes[ idx ] };
    }
    fd_txncache_finalize_fork( tc, fork, 31UL+g, blockhashes[ g+1UL ] );
    fd_txncache_advance_root( tc, fork );
    parent = fork;
  }

  for( ulong i=0UL; i<=group_cnt; i++ ) {
    memcpy( expected_groups[ i ].blockhash, blockhashes[ i ], 32UL );
    expected_groups[ i ].txnhash_offset = 30UL+i;
  }

  ulong sz = 0UL;
  uchar * buf = serialize_txncache( tc, ROOT_SLOT+4UL, NULL, &sz );
  FD_LOG_NOTICE(( "hot txncache serialized size: %lu", sz ));
  parse_txncache( buf, sz, sz,   ROOT_SLOT+4UL, 1UL, expected_groups, group_cnt+1UL, NULL, entry_cnt, NULL, NULL );
  parse_txncache( buf, sz, 13UL, ROOT_SLOT+4UL, 1UL, expected_groups, group_cnt+1UL, NULL, entry_cnt, NULL, NULL );

  free( buf );
  free( expected_entries );
  free( expected_groups );
  free( txnhashes );
}

static void
test_txncache_slot_history_roundtrip( void ) {
  FD_LOG_NOTICE(( "test_txncache_slot_history_roundtrip" ));

  fd_txncache_t * tc = create_txncache();
  uchar blockhashes[4][32];
  uchar txnhashes[6][20];
  populate_txncache( tc, blockhashes, txnhashes );

  ulong slots[ 5 ] = { ROOT_SLOT+9UL, ROOT_SLOT+7UL, ROOT_SLOT+4UL, ROOT_SLOT+1UL, ROOT_SLOT };
  uchar slot_history_data[ FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ ];
  make_slot_history( slot_history_data, ROOT_SLOT+9UL, slots, 5UL );

  fd_slot_history_view_t slot_history[1];
  FD_TEST( fd_sysvar_slot_history_view( slot_history, slot_history_data, sizeof(slot_history_data) ) );

  parsed_group_t expected_groups[ 4 ];
  for( ulong i=0UL; i<4UL; i++ ) {
    memcpy( expected_groups[ i ].blockhash, blockhashes[ i ], 32UL );
    expected_groups[ i ].txnhash_offset = 0UL;
  }

  ulong sz = 0UL;
  uchar * buf = serialize_txncache( tc, ROOT_SLOT+9UL, slot_history, &sz );
  parse_txncache( buf, sz, 7UL, ROOT_SLOT+9UL, 5UL, expected_groups, 4UL, NULL, 6UL, NULL, NULL );

  free( buf );
}

int
main( int     argc,
      char ** argv ) {
  fd_svm_mini_limits_t limits[1];
  fd_svm_mini_limits_default( limits );
  fd_svm_mini_t * mini = fd_svm_test_boot( &argc, &argv, limits );
  FD_TEST( mini );

  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  params->mock_validator_cnt = VALIDATOR_CNT;
  params->root_slot          = ROOT_SLOT;
  params->slots_per_epoch    = 432UL;
  ulong bank_idx = fd_svm_mini_reset( mini, params );
  fd_bank_t * bank = fd_svm_mini_bank( mini, bank_idx );
  FD_TEST( bank );

  test_manifest_roundtrip( bank );
  test_txncache_empty_roundtrip();
  test_txncache_empty_groups_roundtrip();
  test_txncache_sparse_groups_roundtrip();
  test_txncache_roundtrip();
  test_txncache_hot_roundtrip();
  test_txncache_slot_history_roundtrip();

  FD_LOG_NOTICE(( "pass" ));
  fd_svm_test_halt( mini );
  return 0;
}
