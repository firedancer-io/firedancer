/* The watchdog stage disables the kernel lockup detectors, the
   runtime equivalent of booting with "nowatchdog".  The soft lockup
   detector arms a per-CPU hrtimer that interrupts every CPU several
   times a minute (keeping nohz_full CPUs out of full tick silence),
   and the NMI hardlockup detector claims a perf counter that fires
   periodic NMIs.  Both interrupt spinning Firedancer tiles for no
   benefit: tiles run in userspace and cannot cause kernel lockups.

   /proc/sys/kernel/watchdog is the master switch covering both
   detectors.  fini restores it to 1 (the kernel default), which may
   over-restore if the operator had disabled it themselves before
   init; the previous value is not persisted anywhere. */

#include "configure.h"

#include "../../../platform/fd_file_util.h"

#include <errno.h>
#include <unistd.h>
#include <linux/capability.h>

#define NAME "watchdog"

#define WATCHDOG_PATH "/proc/sys/kernel/watchdog"

static int
enabled( config_t const * config ) {
  (void)config;
  /* Absent when the kernel has no lockup detector support
     (CONFIG_LOCKUP_DETECTOR off), in which case there is nothing to
     configure. */
  return 0==access( WATCHDOG_PATH, F_OK );
}

static void
init_perm( fd_cap_chk_t *   chk,
           config_t const * config FD_PARAM_UNUSED ) {
  fd_cap_chk_cap( chk, NAME, CAP_SYS_ADMIN, "modify `" WATCHDOG_PATH "`" );
}

static void
write_watchdog( uint value ) {
  FD_LOG_NOTICE(( "%sRUN: `echo \"%u\" > " WATCHDOG_PATH "`%s", fd_log_style_dim(), value, fd_log_style_normal() ));
  if( FD_UNLIKELY( -1==fd_file_util_write_uint( WATCHDOG_PATH, value ) ) )
    FD_LOG_ERR(( "could not set kernel parameter `" WATCHDOG_PATH "` to %u (%i-%s)", value, errno, fd_io_strerror( errno ) ));
}

static void
init( config_t const * config ) {
  (void)config;
  write_watchdog( 0U );
}

static int
fini( config_t const * config,
      int              pre_init ) {
  (void)config; (void)pre_init;
  write_watchdog( 1U );
  return 1;
}

static configure_result_t
check( config_t const * config,
       int              check_type ) {
  (void)config; (void)check_type;

  uint value;
  if( FD_UNLIKELY( -1==fd_file_util_read_uint( WATCHDOG_PATH, &value ) ) )
    FD_LOG_ERR(( "could not read kernel parameter `" WATCHDOG_PATH "` (%i-%s)", errno, fd_io_strerror( errno ) ));

  if( FD_UNLIKELY( value ) )
    NOT_CONFIGURED( "kernel lockup watchdog is enabled (`" WATCHDOG_PATH "` is %u, expected 0)", value );

  CONFIGURE_OK();
}

configure_stage_t fd_cfg_stage_watchdog = {
  .name            = NAME,
  .always_recreate = 0,
  .enabled         = enabled,
  .init_perm       = init_perm,
  .fini_perm       = init_perm,
  .init            = init,
  .fini            = fini,
  .check           = check,
};

#undef NAME
#undef WATCHDOG_PATH
