/* The irq-affinity stage attempts to minimize the amount of CPU time
   stolen by device interrupts from Firedancer fixed tiles.

   Configuring interrupt affinity is an annoying problem, and doing so
   blindly using a default policy is very annoying.  This wall of text
   documents why the code was written like it is.

   The problem is that default Linux system configuration dispatches
   IRQs to arbitrary CPUs.  Since socket-based networking heavily relies
   on IRQs, heavy incoming traffic can possibly starve a Firedancer tile
   from running. Tiles cannot evacuate to other CPUs since they are
   pinned to one CPU each.

   The goal is to prevent interrupt requests from being delivered to
   CPUs that Firedancer tiles are spinning on.  The kernel exposes the
   /proc/irq/N/smp_affinity API for this purpose.

   ### isolcpus

   isolcpus is the ideal way to achieve CPU isolation from interrupts
   and lots of other undesired activity.  At the time of writing,
   isolcpus can only be configured at boot as a kernel command line
   parameter, though.

   ### procfs smp_affinity

   On a typical Intel/AMD system (with an x2APIC interrupt controller),
   the kernel binds an IRQ to one CPU core.  That CPU core is picked out
   of the smp_affinity mask (unless the mask is impossible to satisfy).
   This CPU can be found in /proc/irq/N/effective_affinity_list.
   (Technically, IRQ load balancing can be done dynamically at the
   hardware level with x2APIC, but this is rare...)

   The kernel picks the effective CPU index out of smp_affinity using
   roughly these rules:
   - ignore offline CPUs
   - ignore isolated CPUs (isolcpus kernel boot parameter)
   - ignore CPUs on a different NUMA than the device
   - pick the CPU with the fewest IRQs (kernel/irq/matrix.c)

   This load balancing policy is decent but does not take into account
   how busy different IRQs are.  On an unlucky system startup, one CPU
   might have multiple busy IRQs while another CPU barely gets any
   interrupts.

   ### irqbalance

   The irqbalance userland daemon was created to achieve better load
   balancing than the kernel's static mapping.
   It periodically rewrites all /proc/irq/N/smp_affinity files to
   dynamically rebalance IRQs, reacting to high CPU usage, thermal
   events, etc.

   One can ban irqbalance from using certain CPUs either via a config
   file or unix domain sockets.  The latter is ephemeral in nature,
   config written via UDS is auto-reset on restart.

   ### Firedancer smp_affinity interop

   Firedancer also manually updates the smp_affinity list.  Some IRQs
   cannot be removed from a CPU (e.g. hardware timer or NVMe managed
   interrupts), so Firedancer should ignore them.  Unfortunately, the
   kernel provides no method to tell which IRQs can be moved.

   Thus, irq-affinity is implemented as follows:
   - 'check' (which looks for misconfigured IRQs) writes back the
     existing smp_affinity mask, if the mask includes tile CPUs.  If
     this results in a permission error, the interrupt likely cannot be
     reconfigured.
   - 'init' does the actual reconfiguration (any CPUs that are not
     Firedancer tiles are allowed)
   - 'fini' re-admits fixed tile CPUs into the smp_affinity mask
     (attempts to keep CPUs excluded that were already excluded before
     Firedancer)

   Another quirk is that the kernel leaves the effective CPU of an IRQ
   unchanged if the smp_affinity mask is narrowed, but the effective CPU
   stays in the mask.  Due to this, 'check' is truly a no-op (ignoring
   TOCTOU races), and 'fini' fails to restore effective affinity masks.

   ### Firedancer irqbalance interop

   If irqbalance is available, Firedancer uses that unix domain socket
   API to ban tile CPUs.  Since irqbalance forgets UDS config on restart
   we would ideally periodically re-apply the config.  Unfortunately,
   irqbalance creates the UDS socket path on each startup.  Opening
   arbitrary files does not play well with Firedancer's sandbox.

   Thus, Firedancer only configures the irqbalance daemon on startup
   using this configure stage.

   Manual procfs smp_affinity is the lesser evil, so Firedancer logs a
   warning if it finds irqbalance.

   ### Firedancer network stack

   Firedancer code avoids producing interrupts/softirq where possible,
   instead opting for busy polling.  But at the time of writing, XDP
   driver code in the Linux kernel is so botched that preferred busy
   polling cannot be reliably enabled.

   Thus, unfortunately, IRQs for Firedancer RX XDP traffic will be
   handled by remote CPU cores. */

#define _DEFAULT_SOURCE
#include "configure.h"
#include "fd_cpu_isolation.h"
#include "../../../../util/tile/fd_tile_private.h"
#include <fcntl.h>
#include <sys/types.h>
#include <dirent.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

/* FD_IRQ_AFFINITY_CHECK_TIGHT, when non-zero, makes check() also flag
   IRQs whose affinity mask is a strict subset of the allowed CPUs (but
   that do not overlap any tile CPU).  Such IRQs do not steal time from
   tiles, and irqbalance routinely narrows IRQs this way, which would
   make check() never pass while it runs.  Disabled for now. */
#ifndef FD_IRQ_AFFINITY_CHECK_TIGHT
#define FD_IRQ_AFFINITY_CHECK_TIGHT 0
#endif

/* smp_affinity file format is 4a4a4a4a,fcfcfcfc,...
   So, 9 bytes per 32 bits ~ 3.56 bits per byte. */
#define SMP_AFFINITY_STR_LEN (FD_TILE_MAX/3)
#define MISMATCH_SAMPLE_MAX  (16UL)
#define MISMATCH_STR_LEN     (128UL)
#define MISMATCH_TILE_STR_LEN (128UL)

static char *
append_ulong_list_sample( char *        buf,
                          ulong         buf_sz,
                          ulong const * vals,
                          ulong         val_cnt,
                          ulong         total_cnt ) {
  char * p = fd_cstr_init( buf );
  for( ulong i=0UL; i<val_cnt; i++ ) {
    if( FD_LIKELY( i ) ) p = fd_cstr_append_char( p, ',' );
    if( FD_UNLIKELY( (ulong)(p-buf)+32UL >= buf_sz ) ) break;
    p = fd_cstr_append_ulong_as_text( p, 0, 0, vals[ i ], fd_ulong_base10_dig_cnt( vals[ i ] ) );
  }
  if( FD_UNLIKELY( total_cnt>val_cnt && (ulong)(p-buf)+32UL<buf_sz ) ) {
    p = fd_cstr_append_cstr( p, ",+" );
    p = fd_cstr_append_ulong_as_text( p, 0, 0, total_cnt-val_cnt, fd_ulong_base10_dig_cnt( total_cnt-val_cnt ) );
    p = fd_cstr_append_cstr( p, " more" );
  }
  fd_cstr_fini( p );
  return buf;
}

static char *
tile_list_sample( char *            buf,
                  ulong             buf_sz,
                  fd_topo_t const * topo,
                  ulong const *     tile_idxs,
                  ulong             tile_cnt,
                  ulong             total_cnt ) {
  char * p = fd_cstr_init( buf );
  for( ulong i=0UL; i<tile_cnt; i++ ) {
    fd_topo_tile_t const * tile = &topo->tiles[ tile_idxs[ i ] ];
    if( FD_LIKELY( i ) ) p = fd_cstr_append_char( p, ',' );
    if( FD_UNLIKELY( (ulong)(p-buf)+32UL >= buf_sz ) ) break;
    p = fd_cstr_append_cstr( p, tile->name );
    p = fd_cstr_append_char( p, ':' );
    p = fd_cstr_append_ulong_as_text( p, 0, 0, tile->kind_id, fd_ulong_base10_dig_cnt( tile->kind_id ) );
  }
  if( FD_UNLIKELY( total_cnt>tile_cnt && (ulong)(p-buf)+32UL<buf_sz ) ) {
    p = fd_cstr_append_cstr( p, ",+" );
    p = fd_cstr_append_ulong_as_text( p, 0, 0, total_cnt-tile_cnt, fd_ulong_base10_dig_cnt( total_cnt-tile_cnt ) );
    p = fd_cstr_append_cstr( p, " more" );
  }
  fd_cstr_fini( p );
  return buf;
}

static int
irq_dirent_is_irq( char const * name ) {
  if( FD_UNLIKELY( !name[0] ) ) return 0;
  for( char const * p=name; *p; p++ ) {
    if( FD_UNLIKELY( !isdigit( (uchar)*p ) ) ) return 0;
  }
  return 1;
}

static int
read_irq_smp_affinity( char const * irq,
                       fd_cpuset_t * cpuset ) {
  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "/proc/irq/%s/smp_affinity", irq ) );

  int fd = open( path, O_RDONLY );
  if( FD_UNLIKELY( fd<0 ) ) return 0;

  char affinity[ SMP_AFFINITY_STR_LEN+64UL ];
  long affinity_len = read( fd, affinity, sizeof(affinity)-1UL );
  int err = errno;
  if( FD_UNLIKELY( close( fd ) ) ) FD_LOG_ERR(( "close(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( affinity_len<0 ) ) {
    errno = err;
    return 0;
  }

  affinity[ affinity_len ] = '\0';
  return fd_cpu_isolation_parse_mask( cpuset, affinity );
}

static int
write_irq_smp_affinity( char const *        irq,
                        fd_cpuset_t const * cpuset,
                        int                 warn ) {
  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "/proc/irq/%s/smp_affinity", irq ) );

  char affinity[ SMP_AFFINITY_STR_LEN+64UL ];
  fd_cpu_isolation_format_mask( affinity, sizeof(affinity), cpuset );
  ulong affinity_len = strlen( affinity );

  int fd = open( path, O_WRONLY );
  if( FD_UNLIKELY( fd<0 ) ) {
    if( FD_LIKELY( warn ) ) FD_LOG_WARNING(( "open(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    return 0;
  }

  int ok = 1;
  if( FD_UNLIKELY( write( fd, affinity, affinity_len )!=(long)affinity_len ) ) {
    int err = errno;
    if( FD_LIKELY( warn ) ) FD_LOG_WARNING(( "write(%s) failed (%i-%s)", path, err, fd_io_strerror( err ) ));
    errno = err;
    ok = 0;
  }

  if( FD_UNLIKELY( close( fd ) ) ) FD_LOG_ERR(( "close(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  return ok;
}

static void
update_irq_smp_affinities( fd_cpuset_t const * add_cpus,
                           fd_cpuset_t const * remove_cpus ) {
  DIR * dir = opendir( "/proc/irq" );
  if( FD_UNLIKELY( !dir ) ) {
    FD_LOG_WARNING(( "opendir(/proc/irq) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    return;
  }

  FD_CPUSET_DECL( fallback );
  if( FD_LIKELY( remove_cpus ) ) fd_cpuset_subtract( fallback, fd_cpu_isolation_host_cpus( fallback ), remove_cpus );

  struct dirent * entry;
  while( (entry = readdir( dir )) ) {
    if( FD_UNLIKELY( !irq_dirent_is_irq( entry->d_name ) ) ) continue;

    FD_CPUSET_DECL( current );
    if( FD_UNLIKELY( !read_irq_smp_affinity( entry->d_name, current ) ) ) continue;

    FD_CPUSET_DECL( next );
    if( FD_LIKELY( remove_cpus ) ) fd_cpuset_subtract( next, current, remove_cpus );
    else                           fd_cpuset_copy    ( next, current );
    if( FD_UNLIKELY( !fd_cpuset_cnt( next ) && remove_cpus ) ) fd_cpuset_copy( next, fallback );
    if( FD_LIKELY( add_cpus ) ) fd_cpuset_union( next, next, add_cpus );

    if( FD_LIKELY( fd_cpuset_eq( current, next ) ) ) continue;
    if( FD_UNLIKELY( !write_irq_smp_affinity( entry->d_name, next, 0 ) && errno!=EPERM && errno!=EIO ) ) {
      int err = errno;
      FD_LOG_WARNING(( "write(/proc/irq/%s/smp_affinity) failed (%i-%s)", entry->d_name, err, fd_io_strerror( err ) ));
    }
  }

  if( FD_UNLIKELY( closedir( dir ) ) ) FD_LOG_ERR(( "closedir(/proc/irq) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

static void
set_irq_smp_affinities( fd_cpuset_t const * desired ) {
  DIR * dir = opendir( "/proc/irq" );
  if( FD_UNLIKELY( !dir ) ) {
    FD_LOG_WARNING(( "opendir(/proc/irq) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    return;
  }

  struct dirent * entry;
  while( (entry = readdir( dir )) ) {
    if( FD_UNLIKELY( !irq_dirent_is_irq( entry->d_name ) ) ) continue;

    FD_CPUSET_DECL( current );
    if( FD_UNLIKELY( !read_irq_smp_affinity( entry->d_name, current ) ) ) continue;

    if( FD_LIKELY( fd_cpuset_eq( current, desired ) ) ) continue;
    if( FD_UNLIKELY( !write_irq_smp_affinity( entry->d_name, desired, 0 ) && errno!=EPERM && errno!=EIO ) ) {
      int err = errno;
      FD_LOG_WARNING(( "write(/proc/irq/%s/smp_affinity) failed (%i-%s)", entry->d_name, err, fd_io_strerror( err ) ));
    }
  }

  if( FD_UNLIKELY( closedir( dir ) ) ) FD_LOG_ERR(( "closedir(/proc/irq) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

/* topo_banned_cpus returns the set of CPUs that should not handle
   interrupts in *cpuset. */

static fd_cpuset_t *
topo_banned_cpus( fd_cpuset_t cpuset[ static fd_cpuset_word_cnt ],
                  fd_topo_t const * topo ) {
  fd_cpuset_new( cpuset );
  ulong cpu_cnt = fd_shmem_cpu_cnt();
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t const * tile = &topo->tiles[ i ];
    if( tile->cpu_idx < cpu_cnt ) fd_cpuset_insert( cpuset, tile->cpu_idx );
  }
  return cpuset;
}

static void
init_perm( fd_cap_chk_t *   chk,
           config_t const * config FD_PARAM_UNUSED ) {
  fd_cap_chk_root( chk, "irq-affinity", "modify `/proc/irq/*/smp_affinity`" );
}

static void
fini_perm( fd_cap_chk_t *   chk,
           config_t const * config FD_PARAM_UNUSED ) {
  fd_cap_chk_root( chk, "irq-affinity", "modify `/proc/irq/*/smp_affinity`" );
}

static void
init( config_t const * config ) {
  FD_CPUSET_DECL( banned );
  topo_banned_cpus( banned, &config->topo );

  FD_CPUSET_DECL( allowed );
  fd_cpuset_subtract( allowed, fd_cpu_isolation_host_cpus( allowed ), banned );

  if( FD_UNLIKELY( !fd_cpuset_cnt( allowed ) ) ) {
    FD_LOG_ERR(( "all host CPUs are assigned to Firedancer tiles; cannot reserve any CPU for device interrupts" ));
  }

  set_irq_smp_affinities( allowed );
}

static int
fini( config_t const * config,
      int              pre_init ) {
  (void)pre_init;

  FD_CPUSET_DECL( banned );
  topo_banned_cpus( banned, &config->topo );

  update_irq_smp_affinities( banned, NULL );
  return 1;
}

static configure_result_t
check( config_t const * config,
       int              check_type ) {
  FD_CPUSET_DECL( banned );
  topo_banned_cpus( banned, &config->topo );

  FD_CPUSET_DECL( allowed );
  fd_cpuset_subtract( allowed, fd_cpu_isolation_host_cpus( allowed ), banned );

  DIR * dir = opendir( "/proc/irq" );
  if( FD_UNLIKELY( !dir ) ) FD_LOG_ERR(( "opendir(/proc/irq) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  ulong irq_cnt        = 0UL;
  ulong misconfigured  = 0UL;
  ulong unprobeable    = 0UL;
  ulong overlap_irq_sample[ MISMATCH_SAMPLE_MAX ];
  ulong overlap_irq_sample_cnt = 0UL;
  ulong overlap_irq_cnt = 0UL;
#if FD_IRQ_AFFINITY_CHECK_TIGHT
  ulong tight_irq_sample[ MISMATCH_SAMPLE_MAX ];
  ulong tight_irq_sample_cnt = 0UL;
  ulong tight_irq_cnt = 0UL;
#endif
  ulong tile_sample[ MISMATCH_SAMPLE_MAX ];
  ulong tile_sample_cnt = 0UL;
  ulong tile_overlap_cnt = 0UL;
  uchar tile_seen[ FD_TOPO_MAX_TILES ] = {0};
  struct dirent * entry;
  while( (entry = readdir( dir )) ) {
    if( FD_UNLIKELY( !irq_dirent_is_irq( entry->d_name ) ) ) continue;
    irq_cnt++;

    FD_CPUSET_DECL( current );
    if( FD_UNLIKELY( !read_irq_smp_affinity( entry->d_name, current ) ) ) {
      unprobeable++;
      continue;
    }

    if( FD_LIKELY( fd_cpuset_eq( current, allowed ) ) ) continue;

    /* Some IRQs cannot be moved.  Per the stage comment above, writing
       the same mask back lets us distinguish those from configurable IRQs. */
    if( FD_UNLIKELY( !write_irq_smp_affinity( entry->d_name, current, 0 ) ) ) {
      if( FD_LIKELY( errno==EPERM || errno==EIO || errno==ENOENT || errno==ENODEV || errno==ENXIO ) ) continue;
      else if( FD_LIKELY( errno==EACCES ) ) {
        char irq_name[ NAME_MAX+1UL ];
        FD_TEST( fd_cstr_printf_check( irq_name, sizeof(irq_name), NULL, "%s", entry->d_name ) );
        if( FD_UNLIKELY( closedir( dir ) ) ) FD_LOG_ERR(( "closedir(/proc/irq) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
        if( check_type==FD_CONFIGURE_CHECK_TYPE_FINI_PERM ) CONFIGURE_OK();
        NOT_CONFIGURED( "insufficient permissions to write /proc/irq/%s/smp_affinity", irq_name );
      } else {
        FD_LOG_ERR(( "write(/proc/irq/%s/smp_affinity) failed (%i-%s)", entry->d_name, errno, fd_io_strerror( errno ) ));
      }
    }

    FD_CPUSET_DECL( overlap );
    fd_cpuset_intersect( overlap, current, banned );
    ulong irq = strtoul( entry->d_name, NULL, 10 );
    if( FD_UNLIKELY( !fd_cpuset_is_null( overlap ) ) ) {
      misconfigured++;
      if( FD_LIKELY( overlap_irq_sample_cnt<MISMATCH_SAMPLE_MAX ) ) overlap_irq_sample[ overlap_irq_sample_cnt++ ] = irq;
      overlap_irq_cnt++;
      for( ulong i=0UL; i<config->topo.tile_cnt; i++ ) {
        fd_topo_tile_t const * tile = &config->topo.tiles[ i ];
        if( FD_UNLIKELY( tile->cpu_idx>=FD_TILE_MAX || !fd_cpuset_test( overlap, tile->cpu_idx ) || tile_seen[ i ] ) ) continue;
        tile_seen[ i ] = 1;
        if( FD_LIKELY( tile_sample_cnt<MISMATCH_SAMPLE_MAX ) ) tile_sample[ tile_sample_cnt++ ] = i;
        tile_overlap_cnt++;
      }
    }
#if FD_IRQ_AFFINITY_CHECK_TIGHT
    /* An IRQ pinned to a strict subset of the allowed CPUs (but no tile
       CPUs) does not steal time from any tile, so it does not violate the
       stage's goal.  irqbalance routinely narrows IRQs this way, which
       would make check() never pass while it runs, so the tight check is
       disabled for now. */
    else if( FD_UNLIKELY( fd_cpuset_subset( current, allowed ) ) ) {
      misconfigured++;
      if( FD_LIKELY( tight_irq_sample_cnt<MISMATCH_SAMPLE_MAX ) ) tight_irq_sample[ tight_irq_sample_cnt++ ] = irq;
      tight_irq_cnt++;
    }
#endif
  }

  if( FD_UNLIKELY( closedir( dir ) ) ) FD_LOG_ERR(( "closedir(/proc/irq) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  if( FD_UNLIKELY( unprobeable==irq_cnt ) ) PARTIALLY_CONFIGURED( "could not read any IRQ affinity masks from /proc/irq" );
  if( FD_UNLIKELY( misconfigured ) ) {
    if( FD_LIKELY( overlap_irq_cnt ) ) {
      char irq_str[ MISMATCH_STR_LEN ];
      char tile_str[ MISMATCH_TILE_STR_LEN ];
      append_ulong_list_sample( irq_str, sizeof(irq_str), overlap_irq_sample, overlap_irq_sample_cnt, overlap_irq_cnt );
      tile_list_sample( tile_str, sizeof(tile_str), &config->topo, tile_sample, tile_sample_cnt, tile_overlap_cnt );
      NOT_CONFIGURED( "found IRQs overlapping with Firedancer tile CPUs (IRQs: %s; tiles: %s)",
                      irq_str,
                      tile_str );
    }
#if FD_IRQ_AFFINITY_CHECK_TIGHT
    if( FD_UNLIKELY( tight_irq_cnt ) ) {
      char tight_irq_str[ MISMATCH_STR_LEN ];
      append_ulong_list_sample( tight_irq_str, sizeof(tight_irq_str), tight_irq_sample, tight_irq_sample_cnt, tight_irq_cnt );
      NOT_CONFIGURED( "found IRQ affinity masks excluding allowed CPUs (IRQs: %s)", tight_irq_str );
    }
#endif
    NOT_CONFIGURED( "%lu configurable IRQ affinity masks do not match Firedancer CPU policy", misconfigured );
  }
  CONFIGURE_OK();
}

configure_stage_t fd_cfg_stage_irq_affinity = {
  .name            = "irq-affinity",
  .init_perm       = init_perm,
  .fini_perm       = fini_perm,
  .init            = init,
  .fini            = fini,
  .check           = check
};

#undef FD_IRQ_AFFINITY_CHECK_TIGHT
#undef SMP_AFFINITY_STR_LEN
#undef MISMATCH_SAMPLE_MAX
#undef MISMATCH_STR_LEN
#undef MISMATCH_TILE_STR_LEN
