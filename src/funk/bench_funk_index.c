#include "fd_funk.h"
#include "fd_funk_base.h"
#include <math.h>

#define FUNK_TAG 1UL

__attribute__((noinline)) static void
run_benchmark( fd_funk_t * funk,
               fd_rng_t *  rng,
               ulong       acc_cnt ) {
  fd_wksp_t * funk_wksp = fd_funk_wksp( funk );
  ulong acc_rem=acc_cnt;
  while( acc_rem-- ) {
    fd_funk_rec_key_t key;
    key.ul[ 0 ] = fd_rng_ulong( rng );
    fd_funk_rec_prepare_t prepare[1];
    fd_funk_rec_t * rec = fd_funk_rec_prepare( funk, NULL, &key, prepare, NULL );
    FD_TEST( rec );
    fd_funk_val_truncate( rec,
                          fd_funk_alloc( funk ),
                          funk_wksp,
                          0UL,
                          104,
                          NULL );
    fd_funk_rec_publish( funk, prepare );
  }
}

static void
stat_chains( fd_funk_t * funk ) {
  fd_funk_rec_map_t * rec_map = fd_funk_rec_map( funk );
  fd_funk_rec_map_shmem_private_chain_t * chain_tbl = fd_funk_rec_map_shmem_private_chain( rec_map->map, 0UL );
  ulong chain_cnt = fd_funk_rec_map_chain_cnt( rec_map );

  double sum = 0.0;
  ulong min = ULONG_MAX;
  ulong max = 0UL;
  for( ulong chain_idx=0UL; chain_idx<chain_cnt; chain_idx++ ) {
    ulong chain_len = fd_funk_rec_map_private_vcnt_cnt( chain_tbl[ chain_idx ].ver_cnt );
    sum += (double)chain_len;
    min = fd_ulong_min( min, chain_len );
    max = fd_ulong_max( max, chain_len );
  }
  double mean = sum / (double)chain_cnt;
  double var = 0.0;
  for( ulong chain_idx=0UL; chain_idx<chain_cnt; chain_idx++ ) {
    double diff = (double)fd_funk_rec_map_private_vcnt_cnt( chain_tbl[ chain_idx ].ver_cnt ) - mean;
    var += diff*diff;
  }
  var /= (double)chain_cnt;
  FD_LOG_NOTICE(( "Chain lengths: min=%lu max=%lu mean=%.2f var=%.2f stddev=%.2f",
                  min, max, (double)mean, (double)var, (double)sqrt(var) ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * name       = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--wksp",       NULL,            NULL );
  char const * _page_sz   = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--page-sz",    NULL,      "gigantic" );
  ulong        page_cnt   = fd_env_strip_cmdline_ulong ( &argc, &argv, "--page-cnt",   NULL,           128UL );
  ulong        near_cpu   = fd_env_strip_cmdline_ulong ( &argc, &argv, "--near-cpu",   NULL, fd_log_cpu_id() );
  double       acc_cnt_d  = fd_env_strip_cmdline_double( &argc, &argv, "--accounts",   NULL,             1e9 );
  double       rec_max_d  = fd_env_strip_cmdline_double( &argc, &argv, "--rec-max",    NULL,             1e9 );
  uint         rng_seed   = fd_env_strip_cmdline_uint  ( &argc, &argv, "--rng-seed",   NULL,          1234UL );
  ulong        funk_seed  = fd_env_strip_cmdline_ulong ( &argc, &argv, "--funk-seed",  NULL,          1234UL );
  int          fast_clean = fd_env_strip_cmdline_int   ( &argc, &argv, "--fast-clean", NULL,               1 );

  ulong const txn_max = 16UL;
  ulong const acc_cnt = (ulong)acc_cnt_d;
  ulong const rec_max = (ulong)rec_max_d;

  fd_rng_t rng_[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( rng_, rng_seed, 0UL ) );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  ulong funk_footprint = fd_funk_footprint( txn_max, rec_max );
  FD_LOG_NOTICE(( "fd_funk_footprint(txn_max=%lu,rec_max=%g) = %.1f MiB", txn_max, (double)rec_max, (double)funk_footprint/(1024.0*1024.0) ));
  ulong chain_cnt = fd_funk_rec_map_chain_cnt_est( rec_max );
  FD_LOG_NOTICE(( "fd_funk_rec_map_chain_cnt_est(rec_max=%g) = %g", (double)rec_max, (double)chain_cnt ));
  if( FD_UNLIKELY( funk_footprint > (page_cnt*page_sz ) ) ) FD_LOG_ERR(( "funk footprint exceeds memory bounds" ));

  fd_wksp_t * wksp;
  if( name ) {
    FD_LOG_NOTICE(( "Attaching to --wksp %s", name ));
    wksp = fd_wksp_attach( name );
  } else {
    FD_LOG_NOTICE(( "--wksp not specified, using an anonymous local workspace, --page-sz %s, --page-cnt %lu, --near-cpu %lu",
                    _page_sz, page_cnt, near_cpu ));
    wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, near_cpu, "wksp", 0UL );
  }

  void * funk_mem = fd_wksp_alloc_laddr( wksp, fd_funk_align(), funk_footprint, FUNK_TAG );
  if( FD_UNLIKELY( !funk_mem ) ) FD_LOG_ERR(( "failed to allocate funk" ));
  fd_funk_t funk_[1];
  fd_funk_t * funk = fd_funk_join( funk_, fd_funk_new( funk_mem, FUNK_TAG, funk_seed, 16UL, rec_max ) );
  FD_TEST( funk );

  fd_funk_rec_map_t * rec_map = fd_funk_rec_map( funk );
  FD_TEST( fd_funk_rec_map_chain_cnt( rec_map ) == chain_cnt );

  FD_LOG_NOTICE(( "Starting insert loop" ));
  long dt = -fd_log_wallclock();
  run_benchmark( funk, rng, acc_cnt );
  dt += fd_log_wallclock();
  FD_LOG_NOTICE(( "Inserted %lu accounts in %.2fs (rate=%.2g per_item=%.0fns)",
                  acc_cnt, (double)dt/1e9,
                  (double)acc_cnt/( (double)dt/1e9 ),
                  (double)dt/(double)acc_cnt ));

  stat_chains( funk );

  dt = -fd_log_wallclock();
  fd_funk_leave( funk, NULL );
  if( fast_clean ) {
    fd_funk_delete_fast( funk_mem );
  } else {
    fd_wksp_free_laddr( fd_funk_delete( funk_mem ) );
  }
  if( name ) fd_wksp_detach( wksp );
  else       fd_wksp_delete_anonymous( wksp );
  fd_rng_delete( fd_rng_leave( rng ) );
  dt += fd_log_wallclock();
  FD_LOG_NOTICE(( "Clean up took %.1fs", (double)dt/1e9 ));

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
