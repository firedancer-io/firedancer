/* fuzz_dragon_filter.c drives the SubscribeRequest decoder with
   arbitrary bytes: the protobuf framing, the filter name and address
   limits, the memcmp predicates with their base58 and base64 forms,
   and the cuckoo account filters.  A request from a client is the
   least trusted input the tile takes, so the decoder has to answer
   every byte string with either a filter set that is internally
   consistent or a rejection with a reason.

   The first byte picks the limit table, so that the paths an operator
   opens and closes are both reached. */

#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdlib.h>

#include "fd_dragon_session.h"
#include "../../util/fd_util.h"

#define CUCKOO_ENTRY_MAX (8192UL)

static FD_TL ushort g_cuckoo[ CUCKOO_ENTRY_MAX ];

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  (void)atexit( fd_halt );
  fd_log_level_core_set(1); /* crash on info log */
  return 0;
}

/* fuzz_limits builds a limit table out of one byte: bit 0 narrows the
   filter counts, bit 1 the address lists, bit 2 forbids a filter that
   matches everything, bit 3 closes what a block may carry, bit 4
   forbids an address, bit 5 shrinks the cuckoo bound. */

static void
fuzz_limits( fd_dragon_filter_limits_t * limits,
             uchar                       sel ) {
  fd_dragon_filter_limits_default( limits );
  if( sel & 0x01U ) for( ulong i=0UL; i<FD_DRAGON_FILTER_TYPE_CNT; i++ ) limits->filter_max[ i ] = 2UL;
  if( sel & 0x02U ) {
    limits->account_max         = 3UL;
    limits->owner_max           = 1UL;
    limits->data_slice_max      = 2UL;
    limits->txn_include_max     = 3UL;
    limits->txn_exclude_max     = 1UL;
    limits->txn_required_max    = 1UL;
    limits->status_include_max  = 3UL;
    limits->status_exclude_max  = 1UL;
    limits->status_required_max = 1UL;
    limits->blocks_include_max  = 2UL;
  }
  if( sel & 0x04U ) for( ulong i=0UL; i<FD_DRAGON_FILTER_TYPE_CNT; i++ ) limits->any[ i ] = 0;
  if( sel & 0x08U ) {
    limits->include_transactions = 0;
    limits->include_accounts     = 0;
    limits->include_entries      = 0;
  }
  if( sel & 0x10U ) {
    for( ulong i=0UL; i<FD_DRAGON_REJECT_CNT; i++ ) {
      limits->reject_cnt[ i ] = 2UL;
      fd_memset( limits->reject[ i ][ 0 ], 0x00, 32UL );
      fd_memset( limits->reject[ i ][ 1 ], 0x11, 32UL );
    }
  }
  if( sel & 0x20U ) for( ulong i=0UL; i<FD_DRAGON_FILTER_TYPE_CNT; i++ ) limits->cuckoo_max_size[ i ] = 64UL;
}

/* fuzz_check walks a decoded set and asserts that every range a filter
   holds points inside the pool it names. */

static void
fuzz_check( fd_dragon_filter_set_t const * set ) {
  assert( set->name_cnt<=FD_DRAGON_FILTER_MAX );
  assert( set->acct_cnt<=FD_DRAGON_FILTER_ACCT_MAX );
  assert( set->state_cnt<=FD_DRAGON_FILTER_STATE_MAX );
  assert( set->state_byte_cnt<=FD_DRAGON_FILTER_STATE_BYTES );
  assert( set->slice_cnt<=FD_DRAGON_DATA_SLICE_MAX );
  assert( set->cuckoo_entry_cnt<=CUCKOO_ENTRY_MAX );

  ulong type_total = 0UL;
  for( ulong i=0UL; i<FD_DRAGON_FILTER_TYPE_CNT; i++ ) type_total += set->type_cnt[ i ];
  assert( type_total==set->name_cnt );

  for( ulong i=0UL; i<set->name_cnt; i++ ) {
    fd_dragon_filter_name_t const * n = set->name + i;
    assert( n->type>=0 && n->type<FD_DRAGON_FILTER_TYPE_CNT );
    assert( n->len<=FD_DRAGON_FILTER_NAME_MAX );
    assert( n->cstr[ n->len ]=='\0' );
    assert( (ulong)n->acct_off    +(ulong)n->acct_cnt    <=set->acct_cnt );
    assert( (ulong)n->owner_off   +(ulong)n->owner_cnt   <=set->acct_cnt );
    assert( (ulong)n->include_off +(ulong)n->include_cnt <=set->acct_cnt );
    assert( (ulong)n->exclude_off +(ulong)n->exclude_cnt <=set->acct_cnt );
    assert( (ulong)n->required_off+(ulong)n->required_cnt<=set->acct_cnt );
    assert( (ulong)n->state_off   +(ulong)n->state_cnt   <=set->state_cnt );
    assert( (ulong)n->state_cnt<=FD_DRAGON_ACCT_STATE_MAX );
    if( n->cuckoo_bucket_cnt ) {
      ulong entries = (ulong)n->cuckoo_bucket_cnt*FD_DRAGON_CUCKOO_ENTRIES_PER_BUCKET;
      assert( (ulong)n->cuckoo_off+entries<=set->cuckoo_entry_cnt );
    }
  }

  for( ulong i=0UL; i<set->state_cnt; i++ ) {
    fd_dragon_acct_state_t const * st = set->state + i;
    assert( (ulong)st->data_off+(ulong)st->data_sz<=set->state_byte_cnt );
    assert( (ulong)st->data_sz<=FD_DRAGON_MEMCMP_BYTES_MAX );
  }
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  if( size<2UL ) return -1;
  uchar sel  = data[ 0 ];
  uchar keyb = data[ 1 ];
  data += 2UL; size -= 2UL;

  fd_dragon_filter_limits_t limits[1];
  fuzz_limits( limits, sel );

  static FD_TL fd_dragon_filter_set_t set[1];
  char  err[ FD_DRAGON_ERR_MAX ];
  ulong names_seen = ( sel & 0x40U ) ? FD_DRAGON_FILTER_NAMES_MAX-1UL : 0UL;

  int res = fd_dragon_filter_decode( set, limits, g_cuckoo, CUCKOO_ENTRY_MAX,
                                     &names_seen, data, size, err, sizeof(err) );
  assert( res==0 || res==-1 );

  /* The reason a rejected request gives is always a string */
  ulong err_len = strnlen( err, sizeof(err) );
  assert( err_len<sizeof(err) );

  if( res ) {
    /* A rejected request leaves nothing behind */
    assert( !set->name_cnt && !set->acct_cnt && !set->state_cnt && !set->slice_cnt );
    assert( !set->cuckoo_entry_cnt );
    return 0;
  }

  assert( !err[ 0 ] );
  assert( names_seen>=set->name_cnt );
  fuzz_check( set );

  /* Run every predicate of the decoded set against an account, a
     transaction and a block, which is what the filter set exists for.
     Nothing is asserted about the answers; the point is that the
     matchers read only what the decoder wrote. */
  uchar keys[ 4 ][ 32 ];
  for( ulong i=0UL; i<4UL; i++ ) fd_memset( keys[ i ], (int)( keyb+i ), 32UL );
  uchar sig[ 64 ];
  fd_memset( sig, (int)keyb, 64UL );
  uchar acct_data[ 512 ];
  for( ulong i=0UL; i<sizeof(acct_data); i++ ) acct_data[ i ] = (uchar)( keyb+i );

  int sink = 0;
  for( ulong i=0UL; i<set->name_cnt; i++ ) {
    fd_dragon_filter_name_t const * n = set->name + i;
    switch( n->type ) {
    case FD_DRAGON_FILTER_SLOTS:
      for( int st=0; st<7; st++ ) sink ^= fd_dragon_slots_match( n, set->commitment, st );
      break;
    case FD_DRAGON_FILTER_TRANSACTIONS:
    case FD_DRAGON_FILTER_TRANSACTIONS_STATUS:
      sink ^= fd_dragon_txn_match( set, n, sig, (int)( keyb&1U ), (int)( keyb&2U ),
                                   (uchar const (*)[ 32UL ])keys, 4UL );
      break;
    case FD_DRAGON_FILTER_ACCOUNTS:
      sink ^= fd_dragon_acct_match( set, n, keys[ 0 ], keys[ 1 ], (ulong)keyb,
                                    acct_data, sizeof(acct_data), (int)( keyb&4U ) );
      sink ^= fd_dragon_acct_match( set, n, keys[ 2 ], keys[ 3 ], 0UL, NULL, 0UL, 0 );
      break;
    case FD_DRAGON_FILTER_BLOCKS:
      sink ^= fd_dragon_blocks_txn_match( set, n, (uchar const (*)[ 32UL ])keys, 4UL );
      sink ^= fd_dragon_blocks_acct_match( set, n, keys[ 0 ] );
      break;
    default:
      break;
    }
  }
  FD_COMPILER_UNPREDICTABLE( sink );

  /* A set that is decoded again from the same bytes is the same set,
     and adopting it into another arena keeps its answers. */
  static FD_TL ushort g_cuckoo2[ CUCKOO_ENTRY_MAX ];
  static FD_TL fd_dragon_filter_set_t copy[1];
  fd_dragon_filter_set_adopt( copy, set, g_cuckoo2, CUCKOO_ENTRY_MAX );
  assert( copy->name_cnt==set->name_cnt );
  assert( copy->cuckoo_entry_cnt==set->cuckoo_entry_cnt );
  assert( !memcmp( copy->cuckoo, set->cuckoo, copy->cuckoo_entry_cnt*sizeof(ushort) ) );
  for( ulong i=0UL; i<copy->name_cnt; i++ ) {
    if( copy->name[ i ].type!=FD_DRAGON_FILTER_ACCOUNTS ) continue;
    assert( fd_dragon_acct_match( copy, copy->name+i, keys[ 0 ], keys[ 1 ], (ulong)keyb,
                                  acct_data, sizeof(acct_data), (int)( keyb&4U ) )==
            fd_dragon_acct_match( set,  set->name+i,  keys[ 0 ], keys[ 1 ], (ulong)keyb,
                                  acct_data, sizeof(acct_data), (int)( keyb&4U ) ) );
  }
  return 0;
}
