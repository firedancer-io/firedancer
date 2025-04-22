#include "fd_txn_account.h"
#include "../../funk/fd_funk.h"

#define NUM_ACCOUNTS (ulong)1000000

fd_pubkey_t random_pubkeys[NUM_ACCOUNTS];

struct fd_create_account_task_info {
  fd_funk_t * funk;
  fd_funk_txn_t * funk_txn;
};
typedef struct fd_create_account_task_info fd_create_account_task_info_t;

static void
create_account( fd_funk_t * funk,
                fd_funk_txn_t * funk_txn,
                ulong           i ) {
  FD_TXN_ACCOUNT_DECL( rec );
  int res = fd_txn_account_init_from_funk_mutable( rec, &random_pubkeys[i], funk, funk_txn, 1, 0 );
  FD_TEST(res == 0);
  fd_txn_account_mutable_fini(rec, funk, funk_txn);
}

static void
benchmark_account_creation_single_threaded( fd_funk_t *     funk,
                                            fd_funk_txn_t * funk_txn ) {
  for( ulong i=0; i < NUM_ACCOUNTS; i++) {
    create_account( funk, funk_txn, i );
  }
}

static void
create_account_task( void * tpool,
    ulong t0, ulong t1,
    void *args FD_PARAM_UNUSED,
    void *reduce FD_PARAM_UNUSED, ulong stride FD_PARAM_UNUSED,
    ulong l0 FD_PARAM_UNUSED, ulong l1 FD_PARAM_UNUSED,
    ulong m0 FD_PARAM_UNUSED, ulong m1 FD_PARAM_UNUSED,
    ulong n0 FD_PARAM_UNUSED, ulong n1 FD_PARAM_UNUSED) {
  fd_create_account_task_info_t * task_info = (fd_create_account_task_info_t *)tpool;
  for( ulong i = t0; i < t1; i++ ) {
     create_account( task_info->funk, task_info->funk_txn, i );
  }
}

static void
benchmark_account_creation( fd_funk_t *     funk,
                            fd_funk_txn_t * funk_txn,
                            uint            num_threads,
                            fd_tpool_t *    tpool ) {
  if( num_threads==1 ) {
    benchmark_account_creation_single_threaded(funk, funk_txn );
  }
  else {
    fd_create_account_task_info_t task_info = {
      .funk = funk,
      .funk_txn = funk_txn
    };

    ulong cnt_per_worker = NUM_ACCOUNTS / (num_threads);
    for( ulong worker_idx=1UL; worker_idx<num_threads+1; worker_idx++ ) {
      ulong start_idx = (worker_idx-1UL) * cnt_per_worker;
      ulong end_idx = worker_idx!=num_threads+1 ? fd_ulong_sat_sub( start_idx + cnt_per_worker, 1UL ) : fd_ulong_sat_sub( NUM_ACCOUNTS, 1UL );
      fd_tpool_exec(tpool, worker_idx, create_account_task, &task_info, start_idx, end_idx, NULL, NULL, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL );
    }

    for( ulong worker_idx=1UL; worker_idx<num_threads+1; worker_idx++ ) {
        fd_tpool_wait( tpool, worker_idx );
    }
  }
}

int main( int argc,
          char ** argv ) {
  fd_boot( &argc, &argv );

  char const * _page_sz    = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--page-sz",         NULL, "gigantic" );
  ulong        page_cnt    = fd_env_strip_cmdline_ulong ( &argc, &argv, "--page-cnt",        NULL, 50UL );
  ulong        near_cpu    = fd_env_strip_cmdline_ulong ( &argc, &argv, "--near-cpu",        NULL, fd_log_cpu_id() );
  uint         num_threads = fd_env_strip_cmdline_uint  ( &argc, &argv, "--num-threads", NULL, 1 );

  FD_LOG_NOTICE(( "Creating workspace (--page-cnt %lu, --page-sz %s)", page_cnt, _page_sz ));
  FD_LOG_WARNING(("near cpu: %lu", near_cpu));
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, near_cpu, "wksp", 0UL );
  FD_TEST( wksp );

  ulong const txn_max =  16UL;
  ulong const rec_max =  2000000UL;

  ulong const funk_seed = 0xeffb398d4552afbcUL;
  ulong const funk_tag  = 42UL;
  fd_funk_t * funk = fd_funk_join( fd_funk_new( fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_footprint( txn_max, rec_max ), funk_tag ), funk_tag, funk_seed, txn_max, rec_max ) );
  FD_TEST( funk );

  fd_funk_txn_xid_t xid = { 0 };
  fd_funk_txn_t * funk_txn = fd_funk_txn_prepare(funk, NULL, &xid, 1);

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  /* setup tpool */
  uchar _tpool[ FD_TPOOL_FOOTPRINT(FD_TILE_MAX) ] __attribute__((aligned(FD_TPOOL_ALIGN)));
  ulong worker_cnt = num_threads+1;
  fd_tpool_t * tpool = fd_tpool_init( _tpool, worker_cnt );
  if( tpool == NULL ) {
    FD_LOG_ERR(( "failed to create thread pool" ));
  }
  FD_LOG_WARNING(("tile count: %lu", fd_tile_cnt()));
  FD_LOG_WARNING(("tpool worker max: %lu", fd_tpool_worker_max(tpool)));

  if( worker_cnt > 2 ) {
    for( ulong i=1UL; i<worker_cnt; i++) {
        if( fd_tpool_worker_push( tpool, i, NULL, 0UL ) == NULL ) {
          FD_LOG_ERR(( "failed to launch worker" ));
        }
      }
  }

  /* set up some random pubkeys */
  for( ulong i=0; i < NUM_ACCOUNTS; i++ ) {
    for( ulong j = 0; j < sizeof(fd_pubkey_t); j++ ) {
      random_pubkeys[i].uc[j] = fd_rng_uchar( rng );
    }
  }

  FD_LOG_WARNING(("starting to benchmark account creation!"));
  /* create accounts */
  long dt = -fd_log_wallclock();
  benchmark_account_creation( funk, funk_txn, num_threads, tpool );
  dt += fd_log_wallclock();

  FD_LOG_NOTICE(( "Inserted %lu accounts in %.2fs (rate=%.2g per_item=%.0fns)",
    NUM_ACCOUNTS, (double)dt/1e9,
                  (double)NUM_ACCOUNTS/( (double)dt/1e9 ),
                  (double)dt/(double)NUM_ACCOUNTS ));

  fd_rng_delete( fd_rng_leave( rng ) );
  fd_halt();
  return 0;
}