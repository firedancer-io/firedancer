/* test_dragon_records drives the internal record path end to end
   without a topology: the thread-local reporter publishes records on a
   real mcache and dcache, the fragments are handed to the ingest module
   exactly as the dragon tile hands them over, and the records come back
   out and are unpacked with the generated helpers.

   What it pins down: the chunked framing (som on the first fragment
   with the type and total size in its signal, eom on the last, one
   fragment per piece of the record), reassembly of one fragment, many
   fragments, a record larger than one fragment and a record of the
   largest size the framing allows, the packing convention the producer
   uses when it splices its own pieces into the record, and that a
   fragment lost in the middle drops the record in progress and reports
   a gap. */

#include "fd_dragon_ingest.h"

#include "../../disco/events/generated/fd_event_internal_gen.h"
#include "../../flamenco/events/fd_event_internal.h"

/* The link the test publishes on.  The depth has to cover the largest
   record in fragments, plus room for the records published before
   it. */

#define TEST_DEPTH (512UL)

static fd_wksp_t *      test_wksp;
static fd_frag_meta_t * test_mcache;
static uchar *          test_dcache;

static fd_event_reporter_t   test_reporter[1];
static fd_dragon_ingest_t *  test_ingest;

/* test_drain hands every fragment the reporter published since the last
   drain to the ingest module, in order, checking the framing as it
   goes.  drop_seq, when not ULONG_MAX, is the index of the fragment to
   lose, which is what an overrun looks like to the tile.  Returns the
   number of records the ingest module completed. */

static ulong
test_drain( ulong   from_seq,
            ulong   to_seq,
            ulong   drop_idx,
            ulong   expect_type,
            ulong   expect_total,
            ulong * opt_frag_cnt ) {
  ulong ready_cnt = 0UL;
  ulong frag_cnt  = 0UL;
  ulong sz_sum    = 0UL;

  for( ulong seq=from_seq; seq<to_seq; seq++ ) {
    fd_frag_meta_t const * line = test_mcache + fd_mcache_line_idx( seq, TEST_DEPTH );
    FD_TEST( line->seq==seq );

    ulong ctl = (ulong)line->ctl;
    ulong sz  = (ulong)line->sz;

    /* The first fragment of the record carries the type and the total
       size, the others carry no signal. */
    if( frag_cnt==0UL ) {
      FD_TEST( fd_frag_meta_ctl_som( ctl ) );
      FD_TEST( FD_EVENT_SIG_TYPE( line->sig )==expect_type  );
      FD_TEST( FD_EVENT_SIG_SZ  ( line->sig )==expect_total );
    } else {
      FD_TEST( !fd_frag_meta_ctl_som( ctl ) );
      FD_TEST( !line->sig );
    }
    FD_TEST( sz && sz<=FD_EVENT_INTERNAL_FRAG_MAX );
    sz_sum += sz;
    FD_TEST( fd_frag_meta_ctl_eom( ctl )==( sz_sum==expect_total ) );

    frag_cnt++;
    if( FD_UNLIKELY( frag_cnt-1UL==drop_idx ) ) continue; /* the fragment the tile never saw */

    ready_cnt += (ulong)!!fd_dragon_ingest_frag( test_ingest, 0UL, seq, line->sig, ctl,
                                                 fd_chunk_to_laddr_const( test_wksp, (ulong)line->chunk ), sz );
  }

  FD_TEST( sz_sum==expect_total );
  if( opt_frag_cnt ) *opt_frag_cnt = frag_cnt;
  return ready_cnt;
}

/* A runtime write record of one account with data_sz bytes of data,
   which fits one fragment for small sizes and many for large ones. */

static void
test_runtime_write( ulong   data_sz,
                    uchar * data,
                    ulong   drop_idx ) {
  fd_event_internal_runtime_write_t ev[1];
  fd_memset( ev, 0, sizeof(fd_event_internal_runtime_write_t) );
  ev->bank_seq          = 7UL;
  ev->slot              = 42UL;
  ev->phase             = 2U;
  ev->accounts_included = 1;
  ev->write_seq         = 3UL;
  ev->keys_cnt          = 1UL;
  ev->touched_cnt       = 1UL;
  ev->account_data_cnt  = data_sz;

  uchar keys[ 1 ][ 32 ];
  fd_memset( keys[ 0 ], 0xA5, 32UL );

  fd_event_internal_runtime_write_touched_t touched[1] = {{
    .key_idx    = 0U,
    .executable = 0U,
    .lamports   = 1000UL,
    .data_off   = 0UL,
    .data_sz    = data_sz
  }};
  fd_memset( touched->owner, 0x11, 32UL );

  fd_event_internal_runtime_write_parts_t parts = {
    .prefix       = ev,
    .keys         = (uchar const (*)[ 32UL ])keys,
    .touched      = touched,
    .account_data = data
  };

  ulong total   = fd_event_internal_runtime_write_footprint( ev );
  ulong seq0    = test_reporter->seq;
  fd_event_report_internal_runtime_write( &parts );

  ulong frag_cnt;
  ulong ready = test_drain( seq0, test_reporter->seq, drop_idx,
                            FD_EVENT_INTERNAL_RUNTIME_WRITE_ID, total, &frag_cnt );
  FD_TEST( frag_cnt==(total+FD_EVENT_INTERNAL_FRAG_MAX-1UL)/FD_EVENT_INTERNAL_FRAG_MAX );

  if( drop_idx!=ULONG_MAX ) {
    /* The record in progress is gone and the gap is reported. */
    FD_TEST( !ready );
    FD_TEST( fd_dragon_ingest_gap_clear( test_ingest ) );
    FD_TEST( !fd_dragon_ingest_gap_clear( test_ingest ) );
    return;
  }

  FD_TEST( ready==1UL );
  FD_TEST( !fd_dragon_ingest_gap_clear( test_ingest ) );

  ulong        type;
  void const * rec;
  ulong        rec_sz;
  fd_dragon_ingest_record( test_ingest, 0UL, &type, &rec, &rec_sz );
  FD_TEST( type==FD_EVENT_INTERNAL_RUNTIME_WRITE_ID );
  FD_TEST( rec_sz==total );

  fd_event_internal_runtime_write_parts_t got[1];
  FD_TEST( !fd_event_internal_runtime_write_unpack( rec, rec_sz, got ) );
  FD_TEST( got->prefix->bank_seq==7UL         );
  FD_TEST( got->prefix->slot==42UL            );
  FD_TEST( got->prefix->phase==2U             );
  FD_TEST( got->prefix->write_seq==3UL        );
  FD_TEST( got->prefix->keys_cnt==1UL         );
  FD_TEST( got->prefix->touched_cnt==1UL      );
  FD_TEST( got->prefix->account_data_cnt==data_sz );
  FD_TEST( !memcmp( got->keys[ 0 ], keys[ 0 ], 32UL ) );
  FD_TEST( got->touched[ 0 ].lamports==1000UL );
  FD_TEST( got->touched[ 0 ].data_sz==data_sz );
  FD_TEST( !memcmp( got->account_data+got->touched[ 0 ].data_off, data, data_sz ) );
}

/* A commit record packed the way the producer packs one: the arrays
   below the account data, then one piece per written account (padded to
   8 bytes so the next piece stays aligned), then the arrays above
   it.  The offsets the record carries have to agree with the pieces. */

static void
test_commit_scatter( void ) {
  static uchar payload[ 1232 ];
  static uchar logs   [ 4000 ];
  for( ulong i=0UL; i<sizeof(payload); i++ ) payload[ i ] = (uchar)i;
  for( ulong i=0UL; i<sizeof(logs);    i++ ) logs   [ i ] = (uchar)(i+1UL);

  uchar keys[ 3 ][ 32 ];
  for( ulong i=0UL; i<3UL; i++ ) fd_memset( keys[ i ], (int)(0x20+i), 32UL );

  ulong pre [ 3 ] = { 1UL, 2UL, 3UL };
  ulong post[ 3 ] = { 4UL, 5UL, 6UL };
  uchar writable[ 3 ] = { 1, 0, 1 };

  /* Two instructions, the second with data of a length that needs
     padding. */
  static uchar instr0[ 100 ];
  static uchar instr1[ 3   ];
  for( ulong i=0UL; i<sizeof(instr0); i++ ) instr0[ i ] = (uchar)(i+2UL);
  for( ulong i=0UL; i<sizeof(instr1); i++ ) instr1[ i ] = (uchar)(i+3UL);

  fd_event_internal_commit_trace_t trace[ 2 ] = {
    { .program_id_idx = 2U, .stack_height = 1U, .acct_cnt = 2U, .acct_off = 0U, .data_off = 0U,   .data_sz = (uint)sizeof(instr0) },
    { .program_id_idx = 1U, .stack_height = 2U, .acct_cnt = 1U, .acct_off = 2U, .data_off = 104U, .data_sz = (uint)sizeof(instr1) }
  };
  uchar trace_accts[ 3 ] = { 0, 1, 2 };

  /* Two written accounts; the record names them and their sizes, the
     data follows in account records of their own. */
  static uchar acct0[ 37   ];
  static uchar acct1[ 8192 ];

  fd_event_internal_commit_touched_t touched[ 2 ] = {
    { .key_idx = 0U, .executable = 0U, .lamports = 10UL, .data_sz = sizeof(acct0) },
    { .key_idx = 2U, .executable = 1U, .lamports = 20UL, .data_sz = sizeof(acct1) }
  };
  fd_memset( touched[ 0 ].owner, 0x31, 32UL );
  fd_memset( touched[ 1 ].owner, 0x32, 32UL );

  fd_event_internal_commit_t ev[1];
  fd_memset( ev, 0, sizeof(fd_event_internal_commit_t) );
  ev->bank_seq             = 9UL;
  ev->slot                 = 11UL;
  ev->index_in_slot        = 5UL;
  ev->commit_index_in_slot = 6UL;
  ev->accounts_included    = 1;
  ev->payload_cnt          = sizeof(payload);
  ev->keys_cnt             = 3UL;
  ev->pre_lamports_cnt     = 3UL;
  ev->post_lamports_cnt    = 3UL;
  ev->is_writable_cnt      = 3UL;
  ev->logs_cnt             = sizeof(logs);
  ev->trace_cnt            = 2UL;
  ev->trace_accts_cnt      = 3UL;
  ev->trace_data_cnt       = 104UL+8UL; /* 100 padded to 104, plus 3 padded to 8 */
  ev->touched_cnt          = 2UL;
  fd_memset( ev->signature, 0x77, 64UL );

  fd_event_internal_commit_parts_t parts = {
    .prefix        = ev,
    .payload       = payload,
    .keys          = (uchar const (*)[ 32UL ])keys,
    .pre_lamports  = pre,
    .post_lamports = post,
    .is_writable   = writable,
    .logs          = logs,
    .trace         = trace,
    .trace_accts   = trace_accts,
    .trace_data    = NULL,
    .return_data   = NULL,
    .touched       = touched
  };

  fd_event_report_iov_t iov[ FD_EVENT_INTERNAL_COMMIT_IOV_MAX+8UL ];
  iov[ 0 ].base = (void const *)ev;
  iov[ 0 ].sz   = FD_EVENT_INTERNAL_COMMIT_PREFIX_SZ;
  ulong iov_cnt = fd_event_internal_commit_iov( &parts, iov, 1UL, 0UL, FD_EVENT_INTERNAL_COMMIT_ARR_TRACE_DATA );

  iov[ iov_cnt   ].base = instr0;              iov[ iov_cnt++ ].sz = sizeof(instr0);
  iov[ iov_cnt   ].base = fd_event_internal_pad(); iov[ iov_cnt++ ].sz = 4UL;
  iov[ iov_cnt   ].base = instr1;              iov[ iov_cnt++ ].sz = sizeof(instr1);
  iov[ iov_cnt   ].base = fd_event_internal_pad(); iov[ iov_cnt++ ].sz = 5UL;

  iov_cnt = fd_event_internal_commit_iov( &parts, iov, iov_cnt,
                                          FD_EVENT_INTERNAL_COMMIT_ARR_TRACE_DATA+1UL,
                                          FD_EVENT_INTERNAL_COMMIT_ARR_CNT );

  ulong total = fd_event_internal_commit_footprint( ev );
  ulong sum   = 0UL;
  for( ulong i=0UL; i<iov_cnt; i++ ) sum += iov[ i ].sz;
  FD_TEST( sum==total );

  ulong seq0 = test_reporter->seq;
  fd_event_report_chunked_( FD_EVENT_INTERNAL_COMMIT_ID, iov, iov_cnt );
  FD_TEST( test_drain( seq0, test_reporter->seq, ULONG_MAX,
                       FD_EVENT_INTERNAL_COMMIT_ID, total, NULL )==1UL );

  ulong        type;
  void const * rec;
  ulong        rec_sz;
  fd_dragon_ingest_record( test_ingest, 0UL, &type, &rec, &rec_sz );
  FD_TEST( type==FD_EVENT_INTERNAL_COMMIT_ID );

  fd_event_internal_commit_parts_t got[1];
  FD_TEST( !fd_event_internal_commit_unpack( rec, rec_sz, got ) );
  FD_TEST( got->prefix->bank_seq==9UL      );
  FD_TEST( got->prefix->index_in_slot==5UL );
  FD_TEST( !memcmp( got->payload, payload, sizeof(payload) ) );
  FD_TEST( !memcmp( got->keys[ 1 ], keys[ 1 ], 32UL ) );
  FD_TEST( got->pre_lamports[ 2 ]==3UL     );
  FD_TEST( got->post_lamports[ 0 ]==4UL    );
  FD_TEST( got->is_writable[ 1 ]==0        );
  FD_TEST( !memcmp( got->logs, logs, sizeof(logs) ) );
  FD_TEST( got->trace[ 1 ].stack_height==2U );
  FD_TEST( got->trace_accts[ 2 ]==2         );
  FD_TEST( !memcmp( got->trace_data+got->trace[ 0 ].data_off, instr0, sizeof(instr0) ) );
  FD_TEST( !memcmp( got->trace_data+got->trace[ 1 ].data_off, instr1, sizeof(instr1) ) );
  FD_TEST( got->touched[ 0 ].data_sz==sizeof(acct0) && got->touched[ 1 ].data_sz==sizeof(acct1) );

  /* Every array of the record starts 8 byte aligned, which is what
     lets the unpack helper hand out typed pointers. */
  FD_TEST( fd_ulong_is_aligned( (ulong)got->pre_lamports, 8UL ) );
  FD_TEST( fd_ulong_is_aligned( (ulong)got->trace,        8UL ) );
  FD_TEST( fd_ulong_is_aligned( (ulong)got->touched,      8UL ) );
}

/* The largest record a producer can send, which is what a rewrite of
   the largest account produces.  It is bounded by the account data
   bound of the schema, and has to stay within the record size limit the
   consumer sizes its buffer by. */

static void
test_max_record( void ) {
  ulong fixed_sz = FD_EVENT_INTERNAL_RUNTIME_WRITE_PREFIX_SZ + 32UL +
                   sizeof(fd_event_internal_runtime_write_touched_t);
  ulong data_sz  = FD_EVENT_INTERNAL_RUNTIME_WRITE_ACCOUNT_DATA_MAX;
  FD_TEST( fixed_sz+data_sz<=FD_EVENT_INTERNAL_SZ_MAX );

  uchar * data = fd_wksp_alloc_laddr( test_wksp, 8UL, data_sz, 1UL );
  FD_TEST( data );
  for( ulong i=0UL; i<data_sz; i+=4093UL ) data[ i ] = (uchar)i;
  data[ data_sz-1UL ] = 0x5AU;

  test_runtime_write( data_sz, data, ULONG_MAX );

  fd_wksp_free_laddr( data );
}

/* A record one byte too large is dropped rather than published: a
   producer on the execution path must not fail, and the consumer must
   not have to hold a buffer for it. */

static void
test_oversized_record( void ) {
  ulong seq0 = test_reporter->seq;

  uchar small[ 8 ] = {0};
  fd_event_report_iov_t iov[ 2 ];
  iov[ 0 ].base = small;
  iov[ 0 ].sz   = 8UL;
  iov[ 1 ].base = small;
  iov[ 1 ].sz   = FD_EVENT_INTERNAL_SZ_MAX-7UL;
  fd_event_report_chunked_( FD_EVENT_INTERNAL_COMMIT_ID, iov, 2UL );

  FD_TEST( test_reporter->seq==seq0 );
}

/* Framing a consumer must refuse: a first fragment claiming a size the
   buffer cannot hold, a continuation with no start, and a run whose
   fragments do not add up to the size the first one claimed. */

static void
test_malformed_framing( void ) {
  fd_dragon_ingest_metrics_t const * m = fd_dragon_ingest_metrics( test_ingest );
  ulong malformed0 = m->malformed_cnt;

  uchar buf[ 64 ] = {0};
  ulong seq = 1000UL;

  /* Claims more than the record size limit. */
  FD_TEST( !fd_dragon_ingest_frag( test_ingest, 0UL, seq++, FD_EVENT_SIG( FD_EVENT_INTERNAL_COMMIT_ID, FD_EVENT_INTERNAL_SZ_MAX+1UL ),
                                   fd_frag_meta_ctl( 0UL, 1, 0, 0 ), buf, 64UL ) );
  FD_TEST( m->malformed_cnt==malformed0+1UL );

  /* Claims zero. */
  FD_TEST( !fd_dragon_ingest_frag( test_ingest, 0UL, seq++, FD_EVENT_SIG( FD_EVENT_INTERNAL_COMMIT_ID, 0UL ),
                                   fd_frag_meta_ctl( 0UL, 1, 1, 0 ), buf, 64UL ) );
  FD_TEST( m->malformed_cnt==malformed0+2UL );

  /* A continuation with no start is skipped, not counted as malformed:
     it is the tail of a record the tile already gave up on. */
  FD_TEST( !fd_dragon_ingest_frag( test_ingest, 0UL, seq++, 0UL, fd_frag_meta_ctl( 0UL, 0, 1, 0 ), buf, 64UL ) );
  FD_TEST( m->malformed_cnt==malformed0+2UL );

  /* More bytes than the first fragment claimed. */
  FD_TEST( !fd_dragon_ingest_frag( test_ingest, 0UL, seq++, FD_EVENT_SIG( FD_EVENT_INTERNAL_COMMIT_ID, 32UL ),
                                   fd_frag_meta_ctl( 0UL, 1, 0, 0 ), buf, 16UL ) );
  FD_TEST( !fd_dragon_ingest_frag( test_ingest, 0UL, seq++, 0UL, fd_frag_meta_ctl( 0UL, 0, 1, 0 ), buf, 64UL ) );
  FD_TEST( m->malformed_cnt==malformed0+3UL );

  /* Fewer bytes than the first fragment claimed. */
  FD_TEST( !fd_dragon_ingest_frag( test_ingest, 0UL, seq++, FD_EVENT_SIG( FD_EVENT_INTERNAL_COMMIT_ID, 32UL ),
                                   fd_frag_meta_ctl( 0UL, 1, 0, 0 ), buf, 16UL ) );
  FD_TEST( !fd_dragon_ingest_frag( test_ingest, 0UL, seq++, 0UL, fd_frag_meta_ctl( 0UL, 0, 1, 0 ), buf, 8UL ) );
  FD_TEST( m->malformed_cnt==malformed0+4UL );

  /* A fragment larger than the framing allows. */
  FD_TEST( !fd_dragon_ingest_frag( test_ingest, 0UL, seq++, FD_EVENT_SIG( FD_EVENT_INTERNAL_COMMIT_ID, 32UL ),
                                   fd_frag_meta_ctl( 0UL, 1, 1, 0 ), buf, FD_EVENT_INTERNAL_FRAG_MAX+1UL ) );

  fd_event_internal_runtime_write_parts_t parts[1];

  /* A prefix whose counts do not describe a record of that size. */
  fd_event_internal_runtime_write_t ev[1];
  fd_memset( ev, 0, sizeof(fd_event_internal_runtime_write_t) );
  ev->keys_cnt = 1UL;
  FD_TEST( fd_event_internal_runtime_write_unpack( ev, FD_EVENT_INTERNAL_RUNTIME_WRITE_PREFIX_SZ, parts )==-1 );

  /* A record shorter than the prefix. */
  FD_TEST( fd_event_internal_runtime_write_unpack( ev, 8UL, parts )==-1 );

  /* Counts out of bounds. */
  fd_memset( ev, 0, sizeof(fd_event_internal_runtime_write_t) );
  ev->keys_cnt = FD_EVENT_INTERNAL_RUNTIME_WRITE_KEYS_MAX+1UL;
  FD_TEST( !fd_event_internal_runtime_write_bounded( ev ) );
  FD_TEST( fd_event_internal_runtime_write_unpack( ev, FD_EVENT_INTERNAL_RUNTIME_WRITE_PREFIX_SZ, parts )==-1 );

  /* An unaligned record is refused rather than dereferenced. */
  static uchar unaligned[ 512 ] __attribute__((aligned(8)));
  FD_TEST( fd_event_internal_runtime_write_unpack( unaligned+1, 511UL, parts )==-1 );
}

/* The post balance a record reports is the balance the account ends the
   transaction with.  A transaction that failed writes back only its
   rollback accounts, so everything else keeps what it started with even
   though the account objects still hold what execution left behind. */

static fd_txn_out_t test_txn_out[1];

static void
test_post_lamports( void ) {
  static fd_acc_t accs[ 4 ];

  ulong const pre [4] = { 1000UL, 2000UL, 3000UL, 4000UL };
  ulong const live[4] = {  900UL, 2500UL, 1500UL, 7000UL };

  fd_memset( test_txn_out, 0, sizeof(fd_txn_out_t) );
  for( ulong i=0UL; i<4UL; i++ ) {
    accs[ i ].lamports                          = live[ i ];
    test_txn_out->accounts.account[ i ]           = &accs[ i ];
    test_txn_out->accounts.starting_lamports[ i ] = pre[ i ];
  }
  test_txn_out->accounts.nonce_idx_in_txn = ULONG_MAX;

  /* A transaction that succeeded reports every account as it stands. */
  test_txn_out->err.txn_err = 0;
  test_txn_out->err.is_noop = 0;
  for( ulong i=0UL; i<4UL; i++ )
    FD_TEST( fd_event_internal_post_lamports( test_txn_out, i )==live[ i ] );

  /* A transaction that failed with no nonce reports the fee payer as it
     stands -- the rollback already wrote its post-fee balance there --
     and everything else as it started. */
  test_txn_out->err.txn_err = FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR;
  FD_TEST( fd_event_internal_post_lamports( test_txn_out, 0UL )==live[ 0 ] );
  for( ulong i=1UL; i<4UL; i++ )
    FD_TEST( fd_event_internal_post_lamports( test_txn_out, i )==pre[ i ] );

  /* A nonce account is rolled back too, so it is reported as it
     stands. */
  test_txn_out->accounts.nonce_idx_in_txn = 2UL;
  FD_TEST( fd_event_internal_post_lamports( test_txn_out, 0UL )==live[ 0 ] );
  FD_TEST( fd_event_internal_post_lamports( test_txn_out, 1UL )==pre [ 1 ] );
  FD_TEST( fd_event_internal_post_lamports( test_txn_out, 2UL )==live[ 2 ] );
  FD_TEST( fd_event_internal_post_lamports( test_txn_out, 3UL )==pre [ 3 ] );

  /* A no-op transaction never executed and is never rolled back. */
  test_txn_out->accounts.nonce_idx_in_txn = ULONG_MAX;
  test_txn_out->err.is_noop = 1;
  for( ulong i=0UL; i<4UL; i++ )
    FD_TEST( fd_event_internal_post_lamports( test_txn_out, i )==live[ i ] );

  /* An account the transaction never loaded reports zero. */
  test_txn_out->err.is_noop          = 0;
  test_txn_out->accounts.account[ 3 ] = NULL;
  FD_TEST( fd_event_internal_post_lamports( test_txn_out, 3UL )==pre[ 3 ] );
  test_txn_out->err.txn_err          = 0;
  FD_TEST( fd_event_internal_post_lamports( test_txn_out, 3UL )==0UL );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "normal" );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 32768UL  );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( cpu_idx ) );

  test_wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt,
                                     fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( test_wksp );

  void * _mcache = fd_wksp_alloc_laddr( test_wksp, fd_mcache_align(), fd_mcache_footprint( TEST_DEPTH, 0UL ), 1UL );
  FD_TEST( _mcache );
  test_mcache = fd_mcache_join( fd_mcache_new( _mcache, TEST_DEPTH, 0UL, 0UL ) );
  FD_TEST( test_mcache );

  ulong dcache_data_sz = fd_dcache_req_data_sz( FD_EVENT_INTERNAL_MTU, TEST_DEPTH, 1UL, 1 );
  FD_TEST( dcache_data_sz );
  void * _dcache = fd_wksp_alloc_laddr( test_wksp, fd_dcache_align(), fd_dcache_footprint( dcache_data_sz, 0UL ), 1UL );
  FD_TEST( _dcache );
  test_dcache = fd_dcache_join( fd_dcache_new( _dcache, dcache_data_sz, 0UL ) );
  FD_TEST( test_dcache );

  test_reporter->mcache    = test_mcache;
  test_reporter->depth     = TEST_DEPTH;
  test_reporter->seq       = 0UL;
  test_reporter->seq_store = fd_mcache_seq_laddr( test_mcache );
  test_reporter->mem       = test_wksp;
  test_reporter->chunk0    = fd_dcache_compact_chunk0( test_wksp, test_dcache );
  test_reporter->wmark     = fd_dcache_compact_wmark ( test_wksp, test_dcache, FD_EVENT_INTERNAL_MTU );
  test_reporter->chunk     = test_reporter->chunk0;
  test_reporter->mtu       = FD_EVENT_INTERNAL_MTU;
  fd_event_internal_tl     = test_reporter;

  void * _ingest = fd_wksp_alloc_laddr( test_wksp, fd_dragon_ingest_align(), fd_dragon_ingest_footprint( 1UL ), 1UL );
  FD_TEST( _ingest );
  test_ingest = fd_dragon_ingest_join( fd_dragon_ingest_new( _ingest, 1UL ) );
  FD_TEST( test_ingest );

  FD_TEST( !fd_dragon_ingest_footprint( 0UL                             ) );
  FD_TEST( !fd_dragon_ingest_footprint( FD_DRAGON_INGEST_LINK_MAX+1UL   ) );

  static uchar small[ 64 ];
  for( ulong i=0UL; i<sizeof(small); i++ ) small[ i ] = (uchar)i;

  /* One fragment. */
  test_runtime_write( sizeof(small), small, ULONG_MAX );
  FD_LOG_NOTICE(( "pass: one_frag" ));

  /* Many fragments: over one fragment, and well over. */
  static uchar medium[ 200000 ];
  for( ulong i=0UL; i<sizeof(medium); i++ ) medium[ i ] = (uchar)(i*7UL);
  test_runtime_write( 70000UL,         medium, ULONG_MAX );
  FD_LOG_NOTICE(( "pass: over_one_frag" ));
  test_runtime_write( sizeof(medium),  medium, ULONG_MAX );
  FD_LOG_NOTICE(( "pass: many_frags" ));

  /* A fragment lost in the middle of a record. */
  test_runtime_write( sizeof(medium), medium, 1UL );
  FD_LOG_NOTICE(( "pass: gap_mid_record" ));

  /* The link recovers with the next record. */
  test_runtime_write( sizeof(small), small, ULONG_MAX );
  FD_LOG_NOTICE(( "pass: recovery_after_gap" ));

  test_commit_scatter();
  FD_LOG_NOTICE(( "pass: commit_scatter" ));

  test_max_record();
  FD_LOG_NOTICE(( "pass: max_record" ));

  test_oversized_record();
  FD_LOG_NOTICE(( "pass: oversized_record" ));

  fd_dragon_ingest_metrics_t const * m = fd_dragon_ingest_metrics( test_ingest );
  FD_LOG_NOTICE(( "records %lu multi frag %lu malformed %lu gap drops %lu overruns %lu",
                  m->record_cnt, m->multi_frag_cnt, m->malformed_cnt, m->gap_drop_cnt, m->overrun_cnt ));
  FD_TEST( m->record_cnt==6UL     );
  FD_TEST( m->multi_frag_cnt==3UL );
  FD_TEST( m->malformed_cnt==0UL  );
  FD_TEST( m->gap_drop_cnt==1UL   );
  FD_TEST( m->overrun_cnt==1UL    );

  /* The malformed cases jump the sequence numbers, so they run after
     the counts above are checked. */
  test_malformed_framing();
  FD_LOG_NOTICE(( "pass: malformed_framing" ));

  test_post_lamports();
  FD_LOG_NOTICE(( "pass: post_lamports" ));

  fd_event_internal_tl = NULL;
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
