/* The console stage quiets periodic kernel console rendering work
   that would otherwise run on isolated tile CPUs.

   Two sources, neither stoppable by cpuset partitions, IRQ steering,
   or the unbound-workqueue cpumask, because both use bound (per-CPU)
   work that runs on the CPU that queued it:

     - The framebuffer console cursor blink (fb_flashcursor) is driven
       by a self-re-arming timer.  Ordinary timers fire on the CPU
       that armed them, so once the blink timer lands on a tile CPU
       (e.g. because a kernel message was printed from that CPU and
       redrew the console) it re-arms there forever, preempting the
       tile at ~5Hz.

     - Any printk at or below the console loglevel renders to the
       framebuffer console via work queued on the printing CPU
       (drm_fb_helper_damage_work).  A kernel warning emitted inside a
       tile's own syscall therefore schedules display work onto that
       tile's core.

   init disables the cursor blink and clamps the console loglevel to
   ERR (4): oopses, panics, and hardware errors still render on the
   console; WARNING-class no longer reaches it.  All messages still
   land in the kernel ring buffer (dmesg/journal) regardless of the
   console loglevel.

   fini restores the kernel defaults (blink on, loglevel 7), which may
   over-restore if the operator had their own settings before init;
   the previous values are not persisted anywhere. */

#include "configure.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#define NAME "console"

#define CURSOR_BLINK_PATH "/sys/class/graphics/fbcon/cursor_blink"
#define PRINTK_PATH       "/proc/sys/kernel/printk"

#define CONSOLE_LOGLEVEL_QUIET   (4UL) /* KERN_ERR and above render */
#define CONSOLE_LOGLEVEL_DEFAULT (7UL)

static ulong
read_ulong_field( char const * path,
                  ulong        idx ) {
  int fd = open( path, O_RDONLY );
  if( FD_UNLIKELY( fd<0 ) ) {
    if( FD_LIKELY( errno==ENOENT ) ) return ULONG_MAX;
    FD_LOG_ERR(( "open(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  }

  char buf[ 256 ];
  long len = read( fd, buf, sizeof(buf)-1UL );
  if( FD_UNLIKELY( len<=0L ) ) FD_LOG_ERR(( "read(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( fd ) ) ) FD_LOG_ERR(( "close(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  buf[ len ] = '\0';

  char * p = buf;
  for( ulong i=0UL; i<idx; i++ ) {
    while( *p && *p!=' ' && *p!='\t' ) p++;
    while( *p==' ' || *p=='\t' ) p++;
  }
  char * end;
  ulong val = strtoul( p, &end, 10 );
  if( FD_UNLIKELY( end==p ) ) FD_LOG_ERR(( "failed to parse `%s`", path ));
  return val;
}

static void
write_cstr( char const * path,
            char const * val ) {
  FD_LOG_NOTICE(( "%sRUN: `echo \"%s\" > %s`%s", fd_log_style_dim(), val, path , fd_log_style_normal() ));

  int fd = open( path, O_WRONLY );
  if( FD_UNLIKELY( fd<0 ) ) FD_LOG_ERR(( "open(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  long len = (long)strlen( val );
  if( FD_UNLIKELY( write( fd, val, (ulong)len )!=len ) )
    FD_LOG_ERR(( "write(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( fd ) ) ) FD_LOG_ERR(( "close(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
}

static int
has_fbcon( void ) {
  return 0==access( CURSOR_BLINK_PATH, F_OK );
}

static int
enabled( config_t const * config ) {
  (void)config;
  /* The printk knob always exists; fbcon only when a framebuffer
     console is bound.  Loglevel clamping is worth doing even without
     fbcon (serial consoles render synchronously in the printk
     caller's context). */
  return 0==access( PRINTK_PATH, F_OK );
}

static void
init_perm( fd_cap_chk_t *   chk,
           config_t const * config FD_PARAM_UNUSED ) {
  fd_cap_chk_root( chk, NAME, "modify `" PRINTK_PATH "` and `" CURSOR_BLINK_PATH "`" );
}

static void
fini_perm( fd_cap_chk_t *   chk,
           config_t const * config FD_PARAM_UNUSED ) {
  fd_cap_chk_root( chk, NAME, "modify `" PRINTK_PATH "` and `" CURSOR_BLINK_PATH "`" );
}

static void
init( config_t const * config ) {
  (void)config;

  if( FD_LIKELY( has_fbcon() ) ) write_cstr( CURSOR_BLINK_PATH, "0" );

  ulong level = read_ulong_field( PRINTK_PATH, 0UL );
  if( FD_LIKELY( level>CONSOLE_LOGLEVEL_QUIET ) ) write_cstr( PRINTK_PATH, "4" );
}

static int
fini( config_t const * config,
      int              pre_init ) {
  (void)config; (void)pre_init;

  if( FD_LIKELY( has_fbcon() ) ) write_cstr( CURSOR_BLINK_PATH, "1" );

  ulong level = read_ulong_field( PRINTK_PATH, 0UL );
  if( FD_LIKELY( level<CONSOLE_LOGLEVEL_DEFAULT ) ) write_cstr( PRINTK_PATH, "7" );
  return 1;
}

static configure_result_t
check( config_t const * config,
       int              check_type ) {
  (void)config; (void)check_type;

  if( FD_LIKELY( has_fbcon() ) ) {
    ulong blink = read_ulong_field( CURSOR_BLINK_PATH, 0UL );
    if( FD_UNLIKELY( blink!=0UL && blink!=ULONG_MAX ) )
      NOT_CONFIGURED( "framebuffer console cursor blink is enabled" );
  }

  ulong level = read_ulong_field( PRINTK_PATH, 0UL );
  if( FD_UNLIKELY( level!=ULONG_MAX && level>CONSOLE_LOGLEVEL_QUIET ) )
    NOT_CONFIGURED( "console loglevel is %lu; kernel warnings render console work on the printing CPU", level );

  CONFIGURE_OK();
}

configure_stage_t fd_cfg_stage_console = {
  .name            = NAME,
  .always_recreate = 0,
  .enabled         = enabled,
  .init_perm       = init_perm,
  .fini_perm       = fini_perm,
  .init            = init,
  .fini            = fini,
  .check           = check,
};

#undef NAME
#undef CURSOR_BLINK_PATH
#undef PRINTK_PATH
