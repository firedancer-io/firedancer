#include "fd_funk.h"
#include "fd_funk_base.h"
#include "../flamenco/runtime/fd_acc_mgr.h"
#include "../util/simd/fd_avx.h"
#include <math.h>

#define FUNK_TAG 1UL
#define BATCH_SZ 16UL

__attribute__((noinline)) static void
run_benchmark1( fd_funk_t * funk,
                fd_rng_t *  rng,
                ulong       acc_cnt,
                int         slow ) {
  fd_wksp_t * funk_wksp = fd_funk_wksp( funk );
  fd_funk_rec_t * rec_pool = fd_funk_rec_pool( funk, funk_wksp ).ele;
  uint rec_idx = 0UL;
  fd_funk_rec_map_t rec_map = fd_funk_rec_map( funk, funk_wksp );
  fd_funk_rec_map_shmem_t * map = rec_map.map;
  fd_funk_rec_map_shmem_private_chain_t * chain_tbl = (fd_funk_rec_map_shmem_private_chain_t *)(map+1);
  ulong acc_rem=acc_cnt;
  //ulong retired_fast = 0UL;
  if( !slow ) {
    while( acc_rem>=BATCH_SZ ) {

      /* Generate keys */
      for( ulong k=0UL; k<BATCH_SZ; k++ ) {
        fd_funk_rec_t * r = rec_pool+k;
        r->pair.key->ui[ 0 ] = fd_rng_uint( rng );
        r->pair.key->ui[ 1 ] = fd_rng_uint( rng );
        r->pair.key->ui[ 2 ] = 0;
        r->pair.key->ui[ 3 ] = 0;
        r->pair.key->ui[ 4 ] = 0;
        r->pair.key->ui[ 5 ] = 0;
        r->pair.key->ui[ 6 ] = 0;
        r->pair.key->ui[ 7 ] = 0;
      }

      /* Hash keys */
      ulong chain_idx[ BATCH_SZ ];
      for( ulong k=0UL; k<BATCH_SZ; k++ ) {
        fd_funk_rec_t * r = rec_pool+k;
        fd_funk_xid_key_pair_t * kp = &r->pair;
        fd_funk_txn_xid_set_root( kp->xid );
        ulong hash = fd_funk_xid_key_pair_hash( kp, funk->seed );
        r->map_hash = hash;
        r->flags = 0;
        chain_idx[ k ] = (hash & (map->chain_cnt-1UL));
      }

      /* Gather old heads */
      for( ulong k=0UL; k<BATCH_SZ; k++ ) {
        _mm_prefetch( (const char *)&chain_tbl[ chain_idx[ k ] ], _MM_HINT_T0 );
      }

      for( uint k=0UL; k<BATCH_SZ; k++ ) {
        ulong ver_cnt = chain_tbl[ chain_idx[ k ] ].ver_cnt;
        ulong version = fd_funk_rec_map_private_vcnt_ver( ver_cnt );
        ulong ele_cnt = fd_funk_rec_map_private_vcnt_cnt( ver_cnt );

        fd_funk_rec_t * rec = rec_pool+k;
        uint old_head = chain_tbl[ chain_idx[ k ] ].head_cidx;
        uint new_head = rec_idx+k;
        rec->map_next = old_head;

        chain_tbl[ chain_idx[ k ] ].head_cidx = new_head;
        chain_tbl[ chain_idx[ k ] ].ver_cnt   = fd_funk_rec_map_private_vcnt( version, ele_cnt+1UL );

        //fd_funk_val_truncate( rec, sizeof(fd_account_meta_t), fd_funk_alloc( funk, funk_wksp ), funk_wksp, NULL );
        //memset( fd_funk_val( rec, funk_wksp ), 0, sizeof(fd_account_meta_t) );
      }

      acc_rem  -= BATCH_SZ;
      rec_pool += BATCH_SZ;
      rec_idx  += BATCH_SZ;
    }
  }
  while( acc_rem-- ) {
    fd_funk_rec_key_t key;
    for( ulong j=0UL; j<8UL; j++ ) key.ui[j] = fd_rng_uint( rng );
    fd_funk_rec_t * rec = rec_pool++;
    fd_funk_txn_xid_set_root( rec->pair.xid );
    rec->txn_cidx = fd_funk_txn_cidx( FD_FUNK_TXN_IDX_NULL );
    fd_funk_rec_key_copy( rec->pair.key, &key );
    fd_funk_val_init( rec );
    rec->tag = 0;
    rec->flags = 0;
    rec->prev_idx = (uint)FD_FUNK_REC_IDX_NULL;
    rec->next_idx = (uint)FD_FUNK_REC_IDX_NULL;
    fd_funk_rec_prepare_t prepare = {
      .rec = rec,
      .rec_head_idx = &funk->rec_head_idx,
      .rec_tail_idx = &funk->rec_tail_idx
    };
    //fd_funk_val_truncate( rec, sizeof(fd_account_meta_t), fd_funk_alloc( funk, funk_wksp ), funk_wksp, NULL );
    //memset( fd_funk_val( rec, funk_wksp ), 0, sizeof(fd_account_meta_t) );
    fd_funk_rec_publish( &prepare, funk, funk_wksp );
  }

  //FD_LOG_NOTICE(( "Retired %lu non-conflicting map accesses", retired_fast*BATCH_SZ ));
}

static void
stat_chains( fd_funk_t * funk ) {
  fd_funk_rec_map_t rec_map = fd_funk_rec_map( funk, fd_funk_wksp( funk ) );
  fd_funk_rec_map_shmem_private_chain_t * chain_tbl = fd_funk_rec_map_shmem_private_chain( rec_map.map, 0UL );
  ulong chain_cnt = fd_funk_rec_map_chain_cnt( &rec_map );

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
  ulong        page_cnt   = fd_env_strip_cmdline_ulong ( &argc, &argv, "--page-cnt",   NULL,             3UL );
  ulong        near_cpu   = fd_env_strip_cmdline_ulong ( &argc, &argv, "--near-cpu",   NULL, fd_log_cpu_id() );
  double       acc_cnt_d  = fd_env_strip_cmdline_double( &argc, &argv, "--accounts",   NULL,             1e9 );
  double       rec_max_d  = fd_env_strip_cmdline_double( &argc, &argv, "--rec-max",    NULL,             1e9 );
  uint         rng_seed   = fd_env_strip_cmdline_uint  ( &argc, &argv, "--rng-seed",   NULL,          1234UL );
  ulong        funk_seed  = fd_env_strip_cmdline_ulong ( &argc, &argv, "--funk-seed",  NULL,          1234UL );
  int          fast_clean = fd_env_strip_cmdline_int   ( &argc, &argv, "--fast-clean", NULL,               1 );
  int          slow       = fd_env_strip_cmdline_int   ( &argc, &argv, "--slow",       NULL,               0 );

  ulong const txn_max = 16UL;
  ulong const acc_cnt = (ulong)acc_cnt_d;
  ulong const rec_max = (ulong)rec_max_d;
  FD_TEST( rec_max<=UINT_MAX );

  fd_rng_t rng_[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( rng_, rng_seed, 0UL ) );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  ulong funk_footprint = fd_funk_footprint( txn_max, (uint)rec_max );
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
  fd_funk_t * funk = fd_funk_join( fd_funk_new( funk_mem, FUNK_TAG, funk_seed, 16UL, (uint)rec_max ) );

  fd_funk_rec_map_t rec_map = fd_funk_rec_map( funk, wksp );
  FD_TEST( fd_funk_rec_map_chain_cnt( &rec_map ) == chain_cnt );

  FD_LOG_NOTICE(( "Starting insert loop" ));
  long dt = -fd_log_wallclock();
  run_benchmark1( funk, rng, acc_cnt, slow );
  dt += fd_log_wallclock();
  FD_LOG_NOTICE(( "Inserted %lu accounts in %.2fs (rate=%.2g per_item=%.0fns)",
                  acc_cnt, (double)dt/1e9,
                  (double)acc_cnt/( (double)dt/1e9 ),
                  (double)dt/(double)acc_cnt ));

  stat_chains( funk );

  dt = -fd_log_wallclock();
  if( fast_clean ) {
    ulong const tags[1] = { FUNK_TAG };
    fd_wksp_tag_free( wksp, tags, 1UL );
  } else {
    fd_wksp_free_laddr( fd_funk_delete( fd_funk_leave( funk ) ) );
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
