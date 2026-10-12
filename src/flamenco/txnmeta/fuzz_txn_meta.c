/* fuzz_txn_meta.c drives the shared transaction meta module with
   commit records built out of arbitrary bytes: the transaction payload
   is the fuzzer's, and so are the counts, indices, balances, logs and
   the instruction trace, each reduced to the range the commit record
   schema allows.  That is the shape the record arrives in after
   fd_geyser_core_commit_record has checked its counts and indices, so
   the module is fuzzed with the inputs it is contracted to take.

   What is asserted, besides the absence of crashes: every encoder
   writes exactly the number of bytes it reports, writes nothing past
   it, and refuses a buffer one byte short. */

#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdlib.h>

#include "fd_txn_meta.h"
#include "../../util/fd_util.h"

#define KEYS_MAX  (8UL)
#define TRACE_MAX (8UL)
#define LOGS_MAX  (512UL)

struct fuzz_rec {
  fd_event_internal_commit_t       ev[1];
  uchar                            payload[ FD_TXN_MTU ];
  uchar                            keys[ KEYS_MAX ][ 32 ];
  ulong                            pre [ KEYS_MAX ];
  ulong                            post[ KEYS_MAX ];
  uchar                            writable[ KEYS_MAX ];
  uchar                            logs[ LOGS_MAX ];
  fd_event_internal_commit_trace_t trace[ TRACE_MAX ];
  uchar                            trace_accts[ 64 ];
  uchar                            trace_data[ 128 ];
  uchar                            return_data[ 32 ];
  fd_event_internal_commit_parts_t parts[1];
};

typedef struct fuzz_rec fuzz_rec_t;

static FD_TL fuzz_rec_t            g_rec[1];
static FD_TL fd_txn_meta_scratch_t g_scratch[1];
static FD_TL uchar                 g_enc[ FD_TXN_META_UPDATE_SZ_MAX+64UL ];

/* fuzz_cur is a cursor over the fuzz input that never runs out: past
   the end it returns zeros, so that a short input still builds a
   record. */

struct fuzz_cur {
  uchar const * p;
  ulong         rem;
};

typedef struct fuzz_cur fuzz_cur_t;

static uchar
cur_u8( fuzz_cur_t * c ) {
  if( FD_UNLIKELY( !c->rem ) ) return 0;
  c->rem--;
  return *c->p++;
}

static ulong
cur_u64( fuzz_cur_t * c ) {
  ulong v = 0UL;
  for( ulong i=0UL; i<8UL; i++ ) v |= (ulong)cur_u8( c )<<( 8UL*i );
  return v;
}

/* enc_check runs one encoder and asserts that what it reported is what
   it wrote: the bytes past the end are untouched, the exact size is
   accepted, and one byte less is refused. */

static void
enc_check( ulong (* fn)( fd_txn_meta_t const *, uchar *, ulong ),
           fd_txn_meta_t const * meta ) {
  fd_memset( g_enc, 0xCD, sizeof(g_enc) );
  ulong sz = fn( meta, g_enc, sizeof(g_enc)-32UL );
  if( sz==ULONG_MAX ) return; /* the buffer was too small, which is allowed */
  assert( sz<=sizeof(g_enc)-32UL );
  for( ulong i=sz; i<sizeof(g_enc); i++ ) assert( g_enc[ i ]==0xCD );

  static FD_TL uchar exact[ sizeof(g_enc) ];
  ulong sz2 = fn( meta, exact, sz );
  assert( sz2==sz );
  assert( !memcmp( exact, g_enc, sz ) );

  if( sz ) assert( fn( meta, exact, sz-1UL )==ULONG_MAX );
}

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

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  if( size<32UL ) return -1;

  fuzz_cur_t cur[1] = {{ .p = data, .rem = size }};
  fuzz_rec_t * rec  = g_rec;
  fd_memset( rec, 0, sizeof(fuzz_rec_t) );

  fd_event_internal_commit_t * ev = rec->ev;
  ev->bank_seq             = cur_u64( cur );
  ev->slot                 = cur_u64( cur );
  ev->index_in_slot        = cur_u64( cur );
  ev->commit_index_in_slot = ev->index_in_slot;
  ev->is_leader            = cur_u8( cur ) & 1U;
  ev->is_simple_vote       = cur_u8( cur ) & 1U;
  ev->is_fees_only         = cur_u8( cur ) & 1U;
  ev->txn_err              = (long)(schar)cur_u8( cur );
  ev->exec_err             = (long)(schar)cur_u8( cur );
  ev->exec_err_kind        = (long)(schar)cur_u8( cur );
  ev->exec_err_idx         = cur_u8( cur );
  ev->custom_err           = (uint)cur_u64( cur );
  ev->rent_err_account_idx = cur_u8( cur );
  ev->execution_fee        = cur_u64( cur );
  ev->priority_fee         = cur_u64( cur );
  ev->compute_unit_limit   = cur_u64( cur );
  ev->compute_units_consumed = cur_u64( cur );
  ev->cost_units           = cur_u64( cur );
  ev->logs_truncated       = cur_u8( cur ) & 1U;
  for( ulong i=0UL; i<64UL; i++ ) ev->signature[ i ] = cur_u8( cur );
  for( ulong i=0UL; i<32UL; i++ ) ev->return_data_program_id[ i ] = cur_u8( cur );

  /* The transaction payload is what the meta module parses, so the
     rest of the input goes there. */
  ulong payload_sz = fd_ulong_min( (ulong)cur_u8( cur )*8UL + (ulong)cur_u8( cur ), sizeof(rec->payload) );
  payload_sz = fd_ulong_min( payload_sz, cur->rem );
  for( ulong i=0UL; i<payload_sz; i++ ) rec->payload[ i ] = cur_u8( cur );
  ev->payload_cnt = payload_sz;

  ulong key_cnt = (ulong)cur_u8( cur ) % ( KEYS_MAX+1UL );
  for( ulong i=0UL; i<key_cnt; i++ ) {
    fd_memset( rec->keys[ i ], (int)cur_u8( cur ), 32UL );
    rec->pre     [ i ] = cur_u64( cur );
    rec->post    [ i ] = cur_u64( cur );
    rec->writable[ i ] = cur_u8( cur ) & 1U;
  }
  ev->keys_cnt          = key_cnt;
  ev->pre_lamports_cnt  = key_cnt;
  ev->post_lamports_cnt = key_cnt;
  ev->is_writable_cnt   = key_cnt;
  ev->acct_addr_cnt     = (uint)key_cnt;

  /* The log collector serialization, which the module walks entry by
     entry: the bytes are the fuzzer's. */
  ulong logs_sz = fd_ulong_min( (ulong)cur_u8( cur )*4UL, sizeof(rec->logs) );
  logs_sz       = fd_ulong_min( logs_sz, cur->rem );
  for( ulong i=0UL; i<logs_sz; i++ ) rec->logs[ i ] = cur_u8( cur );
  ev->logs_cnt = logs_sz;

  /* The instruction trace, with every index inside its array, which
     is what the core checks before the module sees a record. */
  ulong trace_cnt = (ulong)cur_u8( cur ) % ( TRACE_MAX+1UL );
  if( !key_cnt ) trace_cnt = 0UL;
  ulong accts_off = 0UL;
  ulong data_off  = 0UL;
  for( ulong i=0UL; i<trace_cnt; i++ ) {
    fd_event_internal_commit_trace_t * t = rec->trace + i;
    ulong acct_cnt = (ulong)cur_u8( cur ) % 5UL;
    acct_cnt = fd_ulong_min( acct_cnt, sizeof(rec->trace_accts)-accts_off );
    ulong data_sz = (ulong)cur_u8( cur ) % 9UL;
    data_sz  = fd_ulong_min( data_sz, sizeof(rec->trace_data)-data_off );

    t->program_id_idx = (uint)( (ulong)cur_u8( cur ) % key_cnt );
    t->stack_height   = (uint)( 1UL + (ulong)cur_u8( cur ) % 5UL );
    t->acct_cnt       = (uint)acct_cnt;
    t->acct_off       = (uint)accts_off;
    t->data_sz        = (uint)data_sz;
    t->data_off       = (uint)data_off;
    for( ulong j=0UL; j<acct_cnt; j++ ) rec->trace_accts[ accts_off+j ] = (uchar)( (ulong)cur_u8( cur ) % key_cnt );
    for( ulong j=0UL; j<data_sz;  j++ ) rec->trace_data [ data_off +j ] = cur_u8( cur );
    accts_off += acct_cnt;
    data_off  += fd_ulong_align_up( data_sz, 8UL );
    if( data_off>sizeof(rec->trace_data) ) { data_off -= fd_ulong_align_up( data_sz, 8UL ); t->data_sz = 0U; }
  }
  ev->trace_cnt       = trace_cnt;
  ev->trace_accts_cnt = accts_off;
  ev->trace_data_cnt  = data_off;

  ulong return_sz = (ulong)cur_u8( cur ) % ( sizeof(rec->return_data)+1UL );
  for( ulong i=0UL; i<return_sz; i++ ) rec->return_data[ i ] = cur_u8( cur );
  ev->return_data_cnt = return_sz;

  rec->parts->prefix        = ev;
  rec->parts->payload       = rec->payload;
  rec->parts->keys          = (uchar const (*)[ 32UL ])rec->keys;
  rec->parts->pre_lamports  = rec->pre;
  rec->parts->post_lamports = rec->post;
  rec->parts->is_writable   = rec->writable;
  rec->parts->logs          = rec->logs;
  rec->parts->trace         = rec->trace;
  rec->parts->trace_accts   = rec->trace_accts;
  rec->parts->trace_data    = rec->trace_data;
  rec->parts->return_data   = rec->return_data;
  rec->parts->touched       = NULL;

  assert( fd_event_internal_commit_bounded( ev ) );

  fd_txn_meta_t meta[1];
  if( fd_txn_meta_from_commit( meta, g_scratch, rec->parts ) ) return 0;

  /* The meta describes only what the record holds */
  assert( meta->key_cnt<=key_cnt );
  assert( meta->balance_cnt<=key_cnt );
  assert( meta->inner_cnt<=trace_cnt );

  /* Every log entry the walker returns is inside the buffer */
  ulong off = 0UL;
  for(;;) {
    ulong         msg_sz;
    uchar const * msg = fd_txn_meta_log_next( &meta->logs, &off, &msg_sz );
    if( !msg ) break;
    assert( msg>=rec->logs && msg+msg_sz<=rec->logs+logs_sz );
    assert( off<=logs_sz );
  }

  enc_check( fd_txn_meta_encode_transaction, meta );
  enc_check( fd_txn_meta_encode_meta,        meta );
  enc_check( fd_txn_meta_encode_txn_info,    meta );
  enc_check( fd_txn_meta_encode_txn_update,  meta );
  enc_check( fd_txn_meta_encode_txn_status,  meta );

  /* The update encoder's bound is what the tile reserves for it */
  ulong update_sz = fd_txn_meta_encode_txn_update( meta, g_enc, sizeof(g_enc)-32UL );
  if( update_sz!=ULONG_MAX ) assert( update_sz<=FD_TXN_META_UPDATE_SZ_MAX );

  /* The bincode error encoding is bounded by its own buffer */
  uchar errbuf[ FD_TXN_META_ERR_SZ_MAX+16UL ];
  fd_memset( errbuf, 0xCD, sizeof(errbuf) );
  ulong err_sz = fd_txn_meta_err_encode( &meta->err, errbuf );
  assert( err_sz<=FD_TXN_META_ERR_SZ_MAX );
  for( ulong i=err_sz; i<sizeof(errbuf); i++ ) assert( errbuf[ i ]==0xCD );
  return 0;
}
