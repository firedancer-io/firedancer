#include "test_sysvar_cache.c"
#include "test_sysvar_clock.c"
#include "test_sysvar_epoch_rewards.c"
#include "test_sysvar_epoch_schedule.c"
#include "test_sysvar_last_restart_slot.c"
#include "test_sysvar_recent_hashes.c"
#include "test_sysvar_rent.c"
#include "test_sysvar_slot_hashes.c"
#include "test_sysvar_slot_history.c"
#include "test_sysvar_stake_history.c"
#include "../../../util/fd_util.h"

__attribute__((aligned(FD_SHMEM_NORMAL_PAGE_SZ)))
static uchar wksp_mem[ 2<<20 ]; /* 2 MiB */

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong const wksp_part_max = 16UL;
  ulong const wksp_data_max = fd_wksp_data_max_est( sizeof(wksp_mem), wksp_part_max );
  fd_wksp_t * wksp = fd_wksp_join( fd_wksp_new( wksp_mem, "wksp", 1U, wksp_part_max, wksp_data_max ) );
  FD_TEST( wksp );
  fd_shmem_join_anonymous( "shmem", FD_SHMEM_JOIN_MODE_READ_WRITE, wksp, wksp_mem, FD_SHMEM_NORMAL_PAGE_SZ, sizeof(wksp_mem)/FD_SHMEM_NORMAL_PAGE_SZ );

  test_sysvar_cache();

  test_sysvar_clock();
  test_sysvar_epoch_rewards();
  test_sysvar_epoch_schedule();
  test_sysvar_last_restart_slot();
  test_sysvar_recent_hashes( wksp );
  test_sysvar_rent();
  test_sysvar_slot_hashes();
  test_sysvar_slot_history();
  test_sysvar_stake_history( wksp );

  FD_TEST( fd_shmem_leave_anonymous( wksp_mem, NULL )==0 );
  FD_TEST( fd_wksp_delete( fd_wksp_leave( wksp ) ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
