#include "fd_sysvar_last_restart_slot.h"

static void
test_sysvar_last_restart_slot_bounds( void ) {
  /* Real sysvar account observed on-chain */
  static uchar const data[] = {
    0x28, 0xbe, 0xb0, 0x0e, 0x00, 0x00, 0x00, 0x00
  };
  FD_TEST( sizeof(data)==FD_SYSVAR_LAST_RESTART_SLOT_BINCODE_SZ );
}

static void
test_sysvar_last_restart_slot_derive( void ) {
  fd_bank_t bank[1] = {0};

  bank->f.slot = 120UL;
  bank->f.hard_fork_cnt = 3UL;
  bank->f.hard_forks[0] = (fd_hard_fork_t) { .slot =  25UL };
  bank->f.hard_forks[1] = (fd_hard_fork_t) { .slot = 250UL };
  bank->f.hard_forks[2] = (fd_hard_fork_t) { .slot =  80UL };

  FD_TEST( fd_sysvar_last_restart_slot_derive( bank )==80UL );

  bank->f.slot = 249UL;
  FD_TEST( fd_sysvar_last_restart_slot_derive( bank )==80UL );

  bank->f.slot = 250UL;
  FD_TEST( fd_sysvar_last_restart_slot_derive( bank )==250UL );

  bank->f.slot = 251UL;
  FD_TEST( fd_sysvar_last_restart_slot_derive( bank )==250UL );

  bank->f.hard_fork_cnt = 0UL;
  FD_TEST( fd_sysvar_last_restart_slot_derive( bank )==0UL );
}

static void
test_sysvar_last_restart_slot( void ) {
  test_sysvar_last_restart_slot_bounds();
  test_sysvar_last_restart_slot_derive();
}
