#include "fd_cost_tracker.h"
#include "fd_slot_params.h"
#include "../features/fd_features.h"
#include <string.h>

/* SIMD-525: verify fd_cost_tracker_init applies the per-regime
   slot-params limits and the raise_block_limits_to_100m scaling, and
   sets the per-regime data-size limit. */
static void
test_cost_tracker_init_reconciliation( fd_cost_tracker_t * ct ) {
  ulong const   SLOT = 10UL; /* features with activation_slot 0 are active here */
  fd_features_t f;

  /* 400ms baseline, no features: table 60M / 24M / 100M. */
  memset( &f, 0xFF, sizeof(f) );
  fd_cost_tracker_init( ct, &f, &FD_SLOT_PARAMS_400MS, SLOT );
  FD_TEST( ct->block_cost_limit  ==60000000UL  );
  FD_TEST( ct->account_cost_limit==24000000UL  );
  FD_TEST( ct->vote_cost_limit   ==36000000UL  );
  FD_TEST( ct->data_size_limit   ==100000000UL );

  /* 400ms + raise_block_limits_to_100m: table scaled by 100/60 ->
     100M / 40M. */
  memset( &f, 0xFF, sizeof(f) );
  f.raise_block_limits_to_100m = 0UL;
  fd_cost_tracker_init( ct, &f, &FD_SLOT_PARAMS_400MS, SLOT );
  FD_TEST( ct->block_cost_limit  ==100000000UL );
  FD_TEST( ct->account_cost_limit==40000000UL  );
  FD_TEST( ct->data_size_limit   ==100000000UL );

  /* 200ms + 100m: regime table scaled by 100/60 -> 50M / 20M / 50M. */
  memset( &f, 0xFF, sizeof(f) );
  f.raise_block_limits_to_100m = 0UL;
  fd_cost_tracker_init( ct, &f, &FD_SLOT_PARAMS_200MS, SLOT );
  FD_TEST( ct->block_cost_limit  ==50000000UL );
  FD_TEST( ct->account_cost_limit==20000000UL );
  FD_TEST( ct->data_size_limit   ==50000000UL );

  /* 200ms, no 100m: regime table 30M / 12M / 50M (account = table
     40%). */
  memset( &f, 0xFF, sizeof(f) );
  fd_cost_tracker_init( ct, &f, &FD_SLOT_PARAMS_200MS, SLOT );
  FD_TEST( ct->block_cost_limit  ==30000000UL );
  FD_TEST( ct->account_cost_limit==12000000UL );
  FD_TEST( ct->data_size_limit   ==50000000UL );

  /* 350ms + 100m: 52.5M*100/60=87.5M, 21M*100/60=35M, 87.5M. */
  memset( &f, 0xFF, sizeof(f) );
  f.raise_block_limits_to_100m = 0UL;
  fd_cost_tracker_init( ct, &f, &FD_SLOT_PARAMS_350MS, SLOT );
  FD_TEST( ct->block_cost_limit  ==87500000UL );
  FD_TEST( ct->account_cost_limit==35000000UL );
  FD_TEST( ct->data_size_limit   ==87500000UL );
}

int main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  char const * name     = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp",      NULL, NULL            );
  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL, "gigantic"      );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",  NULL, 1UL             );
  ulong        near_cpu = fd_env_strip_cmdline_ulong( &argc, &argv, "--near-cpu",  NULL, fd_log_cpu_id() );
  ulong        wksp_tag = fd_env_strip_cmdline_ulong( &argc, &argv, "--wksp-tag",  NULL, 1234UL          );

  fd_wksp_t * wksp;
  if( name ) {
    FD_LOG_NOTICE(( "Attaching to --wksp %s", name ));
    wksp = fd_wksp_attach( name );
  } else {
    FD_LOG_NOTICE(( "--wksp not specified, using an anonymous local workspace, --page-sz %s, --page-cnt %lu, --near-cpu %lu",
                    _page_sz, page_cnt, near_cpu ));
    wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, near_cpu, "wksp", 0UL );
  }

  void * cost_tracker_mem = fd_wksp_alloc_laddr( wksp, fd_cost_tracker_align(), fd_cost_tracker_footprint(), wksp_tag );
  FD_TEST( cost_tracker_mem );

  FD_TEST( fd_cost_tracker_align()>=alignof(fd_cost_tracker_t) );
  FD_TEST( fd_cost_tracker_align()<=FD_COST_TRACKER_ALIGN );

  FD_TEST( fd_cost_tracker_footprint()<=FD_COST_TRACKER_FOOTPRINT );
  FD_LOG_WARNING(( "fd_cost_tracker_footprint: %lu", fd_cost_tracker_footprint() ));

  FD_TEST( !fd_cost_tracker_new( NULL, 0, 999UL ) );
  void * new_cost_tracker_mem = fd_cost_tracker_new( cost_tracker_mem, 0, 999UL );

  FD_TEST( !fd_cost_tracker_join( NULL ) );
  void * junk_mem = fd_wksp_alloc_laddr( wksp, 1UL, 1UL, 999UL );
  FD_TEST( junk_mem );
  FD_TEST( !fd_cost_tracker_join( junk_mem ) );

  fd_cost_tracker_t * cost_tracker = fd_cost_tracker_join( new_cost_tracker_mem );
  FD_TEST( cost_tracker );

  test_cost_tracker_init_reconciliation( cost_tracker );

  /* TODO: Add more sophisticated tests for the cost tracker. */

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
