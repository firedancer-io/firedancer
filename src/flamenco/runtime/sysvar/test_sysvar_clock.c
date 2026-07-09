#include "fd_sysvar_clock.h"

FD_STATIC_ASSERT( alignof ( fd_sol_sysvar_clock_t                        )==0x08UL, layout );
FD_STATIC_ASSERT( offsetof( fd_sol_sysvar_clock_t, slot                  )==0x00UL, layout );
FD_STATIC_ASSERT( offsetof( fd_sol_sysvar_clock_t, epoch_start_timestamp )==0x08UL, layout );
FD_STATIC_ASSERT( offsetof( fd_sol_sysvar_clock_t, epoch                 )==0x10UL, layout );
FD_STATIC_ASSERT( offsetof( fd_sol_sysvar_clock_t, leader_schedule_epoch )==0x18UL, layout );
FD_STATIC_ASSERT( offsetof( fd_sol_sysvar_clock_t, unix_timestamp        )==0x20UL, layout );
FD_STATIC_ASSERT( sizeof  ( fd_sol_sysvar_clock_t                        )==0x28UL, layout );
FD_STATIC_ASSERT( sizeof  ( fd_sol_sysvar_clock_t                        )==FD_SYSVAR_CLOCK_BINCODE_SZ, layout );
