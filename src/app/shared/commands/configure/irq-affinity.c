#include "configure.h"

#include "../../../../disco/topo/fd_cpu_topo.h"
#include "../../../../util/tile/fd_tile_private.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define NAME "irq-affinity"

#define MIN_UNISOLATED_CNT (3)
#define CSV_SZ_MAX         (FD_SHMEM_CPU_MAX * 8UL)
#define MASK_SZ_MAX        (2UL * (((FD_SHMEM_CPU_MAX + 31UL) / 32UL) * 9UL))

static void
init_perm( fd_cap_chk_t *      chk,
           fd_config_t const * config FD_PARAM_UNUSED ) {
  fd_cap_chk_root( chk, NAME, "write /proc/irq/N/smp_affinity files and check irqbalance ban list" );
}

static int
cpuset_init_mask( fd_cpuset_t * set,
                  char const *  mask ) {
  /* The mask is a comma-separated list of 32-bit hex-encoded integers.
     Leading zeros may be omitted.  For example, the mask "1" would mean
     CPU 0 is high and all others low.
     e.g. 000000ff,00000000,00000000,00000000,00000fff
     e.g. fffffe,0,0,3f8,1fff */
  uint groups[ (FD_SHMEM_CPU_MAX + 31UL) / 32UL ];
  ulong const max_groups = sizeof(groups)/sizeof(uint);
  ulong num_groups = 0UL;
  char const *       p = mask;
  char const * const e = mask + strlen( mask );
  while( p < e ) {
    errno = 0;
    char * endptr;
    ulong val = strtoul( p, &endptr, 16 );
    if( FD_UNLIKELY( (errno!=0) | (endptr==p) | (val>UINT_MAX) | (num_groups==max_groups) ) ) return -1;
    groups[ num_groups++ ] = (uint)val;
    p = endptr + 1;
  }

  FD_STATIC_ASSERT( sizeof(set[0]) == sizeof(ulong), size );
  fd_cpuset_null( set );
  for( ulong i=0UL; i<num_groups; i++ ) {
    ulong v = (ulong)groups[ num_groups-i-1 ];
    set[ i/2 ] |= fd_ulong_if( i&1UL, v<<32, v );
  }

  return 0;
}

static ulong
cpuset_write_csv( char *              buf,
                  ulong               buf_sz,
                  fd_cpuset_t const * set ) {
  char * p = buf;
  for( ulong idx = fd_cpuset_const_iter_init( set );
       !fd_cpuset_const_iter_done( idx );
       idx = fd_cpuset_const_iter_next( set, idx ) ) {
    if( FD_UNLIKELY( (buf_sz-(ulong)(p-buf)) < 128UL ) ) FD_LOG_ERR(( "cpuset csv buffer too small" ));
    p = fd_cstr_append_char( fd_cstr_append_ulong_as_text( p, ' ', '\0', idx, fd_ulong_base10_dig_cnt( idx ) ), ',' );
  }
  if( FD_LIKELY( p!=buf ) ) --p;
  fd_cstr_fini( p );
  return (ulong)(p - buf);
}

static ulong
cpuset_write_mask( char *              buf,
                   ulong               buf_sz,
                   fd_cpuset_t const * set ) {
  char * p = buf;
  FD_STATIC_ASSERT( sizeof(set[0]) == sizeof(ulong), size );
  uint const groups_cnt = fd_cpuset_word_cnt * 2;
  for( ulong i=0UL; i<groups_cnt; i++ ) {
    uint v = ((uint const *)set)[ groups_cnt-i-1 ];
    if( (p==buf) & (v==0) & (i!=(groups_cnt-1)) ) continue; /* Skip leading zero groups */
    if( FD_UNLIKELY( (buf_sz-(ulong)(p-buf)) < ((sizeof(uint)*2)+1) ) ) FD_LOG_ERR(( "cpuset mask buffer too small" ));
    if( p!=buf ) p = fd_cstr_append_char( p, ',' );
    p = fd_cstr_append_printf( p, "%x", v );
  }
  return (ulong)(p - buf);
}

static int
find_irqbalance_sock( char * path,
                      ulong  path_sz ) {
  static char const * SOCK_DIRS[] = {
    "/run/irqbalance/",
    "/var/run/irqbalance/"
  };
  for( ulong i=0UL; i<(sizeof(SOCK_DIRS)/sizeof(SOCK_DIRS[0])); i++ ) {
    DIR * dir = opendir( SOCK_DIRS[ i ] );
    if( FD_UNLIKELY( dir==NULL ) ) {
      if( FD_UNLIKELY( errno!=ENOENT ) )
        FD_LOG_WARNING(( "irqbalance opendir(%s) failed (%i-%s)", SOCK_DIRS[ i ], errno, fd_io_strerror( errno ) ));
      continue;
    }
    struct dirent * ent;
    while( NULL!=(ent = readdir( dir )) ) {
      ulong name_len = strlen( ent->d_name );
      if( (name_len > 15UL) &&
          (0==strncmp( ent->d_name, "irqbalance", 10UL )) &&
          (0==strncmp( ent->d_name + name_len - 5UL, ".sock", 5UL ))) {
        char * p = fd_cstr_append_cstr_safe( fd_cstr_init( path ), SOCK_DIRS[ i ], path_sz );
        fd_cstr_fini( fd_cstr_append_cstr_safe( p, ent->d_name, path_sz-(ulong)(p-path) ) );
        return 1;
      }
    }
    closedir( dir );
  }
  return 0;
}

static int
try_mask_irq_affinity( char const *        path,
                       fd_cpuset_t const * isocpus,
                       char const *        defmask,
                       ulong               defmask_sz ) {
  int modified = 0;
  int fd = open( path, O_RDWR );
  if( FD_UNLIKELY( fd<0 ) ) {
    FD_LOG_WARNING(( "open(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    return modified;
  }
  do {
    char buf[ MASK_SZ_MAX ];
    long buf_sz = read( fd, buf, sizeof(buf) );
    if( FD_UNLIKELY( (buf_sz<=0L) | ((ulong)buf_sz>=sizeof(buf)) ) ) {
      FD_LOG_WARNING(( "read(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
      break;
    }
    fd_cstr_fini( buf + buf_sz );

    FD_CPUSET_DECL( cpus );
    if( FD_UNLIKELY( 0!=cpuset_init_mask( cpus, buf ) ) ) {
      FD_LOG_WARNING(( "read(%s) failed, invalid IRQ affinity mask (%s)", path, buf ));
      break;
    }

    FD_CPUSET_DECL( intersection );
    fd_cpuset_intersect( intersection, cpus, isocpus );
    if( fd_cpuset_is_null( intersection ) ) break; /* No change necessary */

    fd_cpuset_subtract( cpus, cpus, isocpus );
    char const * mask;
    if( FD_UNLIKELY( fd_cpuset_is_null( cpus ) ) ) {
      mask = defmask;
      buf_sz = (long)defmask_sz;
    } else {
      mask = buf;
      buf_sz = (long)cpuset_write_mask( buf, sizeof(buf), cpus );
    }
    if( FD_UNLIKELY( ((off_t)-1)==lseek( fd, 0, SEEK_SET ) ) ) {
      FD_LOG_WARNING(( "lseek(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
      break;
    }
    if( buf_sz==write( fd, mask, (ulong)buf_sz ) ) {
      modified = 1;
      FD_LOG_INFO(( "set IRQ affinity mask (%s) to (%.*s)", path, (int)buf_sz, mask ));
    } else if( FD_UNLIKELY( errno != EIO )) {
      /* EIO indicates an IRQ which is not allowed to be changed */
      FD_LOG_WARNING(( "could not set IRQ affinity, write(%s)=(%.*s) failed (%i-%s)",
                       path, (int)buf_sz, mask, errno, fd_io_strerror( errno ) ));
    }
  } while( 0 );
  close( fd );
  return modified;
}

static void
init( fd_config_t const * config ) {
  fd_topo_cpus_t cpu_meta[ 1 ];
  fd_topo_cpus_init( cpu_meta );

  /* First determine the set of CPUs that we want to isolate.  This is
     based on all of the cpus used by the current topology.  We also
     isolate the hyperthreaded siblings of those cpus if applicable. */
  FD_CPUSET_DECL( isocpus );
  fd_cpuset_null( isocpus );
  for( ulong i=0UL; i<config->topo.tile_cnt; i++ ) {
    ulong const cpu_idx = config->topo.tiles[ i ].cpu_idx;
    if( cpu_idx != ULONG_MAX ) {
      fd_cpuset_insert( isocpus, cpu_idx );
      if( cpu_meta->cpu[ cpu_idx ].sibling != ULONG_MAX )
        fd_cpuset_insert( isocpus, cpu_meta->cpu[ cpu_idx ].sibling );
    }
  }

  /* If masking isolated CPUs from an IRQ's current affinity would set
     it to zero, we fall back to using all non-isolated CPUs. */
  FD_CPUSET_DECL( defcpus );
  fd_cpuset_complement( defcpus, isocpus );
  fd_cpuset_remove_range( defcpus, fd_ulong_min( cpu_meta->cpu_cnt, fd_cpuset_max( defcpus ) ), fd_cpuset_max( defcpus ) );
  char defmask[ MASK_SZ_MAX ];
  ulong const defmask_sz = cpuset_write_mask( defmask, sizeof(defmask), defcpus );

  /* We need to leave a reasonable number of CPUs for processing IRQs.
     If this set is too small, log warning and do not change any affinities. */
  if( FD_UNLIKELY( fd_cpuset_cnt( defcpus ) < MIN_UNISOLATED_CNT ) ) {
    FD_LOG_WARNING(( "will not attempt to set IRQ affinities, as the current layout would"
                     " leave too few unisolated CPUs for IRQ handlers.  Consider adjusting"
                     " the layout config settings or running on a higher core count machine."
                     " %lu total, %lu isolated, %lu unisolated.",
                     cpu_meta->cpu_cnt, fd_cpuset_cnt( isocpus ), fd_cpuset_cnt( defcpus ) ));
    return;
  }

  /* Attempt to mask the IRQ affinities for the default affinity and
     then all of the specific IRQ affinities.  It is expected that some
     of these will fail, many do not allow the affinity to be changed. */
  int modified = 0;
  modified |= try_mask_irq_affinity( "/proc/irq/default_smp_affinity", isocpus, defmask, defmask_sz );
  DIR * dir = opendir( "/proc/irq" );
  if( FD_UNLIKELY( NULL==dir ) ) {
    FD_LOG_WARNING(( "open(/proc/irq) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  } else {
    struct dirent * ent;
    while( NULL!=(ent = readdir( dir )) ) {
      if( FD_UNLIKELY( 0==strcmp( ent->d_name, "." ) ||
                       0==strcmp( ent->d_name, ".." ) ||
                       0==strcmp( ent->d_name, "default_smp_affinity" ) ) )
        continue;
      char path[ PATH_MAX ];
      if( FD_UNLIKELY( 1!=fd_cstr_printf_check( path, sizeof(path), NULL, "/proc/irq/%s/smp_affinity", ent->d_name ) ) ) {
        FD_LOG_WARNING(( "open(/proc/irq/%s/smp_affinity) failed", ent->d_name ));
        continue;
      }
      modified |= try_mask_irq_affinity( path, isocpus, defmask, defmask_sz );
    }
    closedir( dir );
  }
  if( modified ) {
    char csv[ CSV_SZ_MAX ];
    ulong csv_sz = cpuset_write_csv( csv, CSV_SZ_MAX, isocpus );
    FD_LOG_NOTICE(( "set IRQ affinities to isolate CPUs (%.*s) with default mask (%.*s)",
                    (int)csv_sz, csv, (int)defmask_sz, defmask ));
  }

  /* If a running irqbalance service is detected, check its current
     CPU ban list.  If any of the isolated CPUs are not in this list,
     log a warning instructing the operator how to resolve this. */
  struct sockaddr_un irqbal_addr = { .sun_family = AF_UNIX };
  if( find_irqbalance_sock( irqbal_addr.sun_path, sizeof(irqbal_addr.sun_path) ) ) {
    int sock = socket( AF_UNIX, SOCK_STREAM, 0 );
    do {
      if( FD_UNLIKELY( sock < 0 ) ) {
        FD_LOG_WARNING(( "irqbalance socket() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
        break;
      }
      if( FD_UNLIKELY( 0!=connect( sock, fd_type_pun_const( &irqbal_addr ), sizeof(irqbal_addr) ) ) ) {
        FD_LOG_WARNING(( "irqbalance connect() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
        break;
      }
      if( FD_UNLIKELY( 5L!=send( sock, "setup", 5UL, 0 ) ) ) {
        FD_LOG_WARNING(( "irqbalance send(setup) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
        break;
      }
      char setup_buf[ 256UL + MASK_SZ_MAX ];
      long setup_sz = recv( sock, setup_buf, sizeof(setup_buf), 0 );
      if( FD_UNLIKELY( (setup_sz<=0L) | ((ulong)setup_sz>=sizeof(setup_buf)) ) ) {
        FD_LOG_WARNING(( "irqbalance recv() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
        break;
      }
      fd_cstr_fini( setup_buf + setup_sz );
      char const * mask = strstr( setup_buf, "BANNED " );
      if( FD_UNLIKELY( mask==NULL ) ) {
        FD_LOG_WARNING(( "irqbalance recv() failed (%s)", setup_buf ));
        break;
      }
      mask += 7;
      FD_CPUSET_DECL( banlist );
      if( FD_UNLIKELY( 0!=cpuset_init_mask( banlist, mask ) ) ) {
        FD_LOG_WARNING(( "irqbalance recv() failed (%s)", setup_buf ));
        break;
      }
      FD_CPUSET_DECL( missing );
      fd_cpuset_subtract( missing, isocpus, banlist );
      if( FD_UNLIKELY( !fd_cpuset_is_null( missing ) ) ) {
        char masks[ 3UL*MASK_SZ_MAX ];
        ulong banlist_mask_sz = cpuset_write_mask( masks + 0UL*MASK_SZ_MAX, MASK_SZ_MAX, banlist );
        ulong isocpus_mask_sz = cpuset_write_mask( masks + 1UL*MASK_SZ_MAX, MASK_SZ_MAX, isocpus );
        ulong missing_mask_sz = cpuset_write_mask( masks + 2UL*MASK_SZ_MAX, MASK_SZ_MAX, missing ) ;
        char csvs[ 3UL*CSV_SZ_MAX ];
        ulong banlist_csv_sz = cpuset_write_csv( csvs + 0UL*CSV_SZ_MAX, CSV_SZ_MAX, banlist );
        ulong isocpus_csv_sz = cpuset_write_csv( csvs + 1UL*CSV_SZ_MAX, CSV_SZ_MAX, isocpus );
        ulong missing_csv_sz = cpuset_write_csv( csvs + 2UL*CSV_SZ_MAX, CSV_SZ_MAX, missing );
        FD_LOG_WARNING(( "detected irqbalance service (%s) but current CPU ban list does not"
                         " fully isolate layout CPUs.  Proceeding but performance may be reduced."
                         "  Consider modifying IRQBALANCE_BANNED_CPUS or equivalent system setup."
                         "  Masks current (%.*s) desired (%.*s) missing (%.*s)."
                         "  Lists current (%.*s) desired (%.*s) missing (%.*s).",
                         irqbal_addr.sun_path,
                         (int)banlist_mask_sz, masks + 0UL*MASK_SZ_MAX,
                         (int)isocpus_mask_sz, masks + 1UL*MASK_SZ_MAX,
                         (int)missing_mask_sz, masks + 2UL*MASK_SZ_MAX,
                         (int)banlist_csv_sz, csvs + 0UL*CSV_SZ_MAX,
                         (int)isocpus_csv_sz, csvs + 1UL*CSV_SZ_MAX,
                         (int)missing_csv_sz, csvs + 2UL*CSV_SZ_MAX ));

      }
    } while( 0 );
    close( sock );
  }
}

static configure_result_t
check( fd_config_t const * config FD_PARAM_UNUSED ) {
  /* Note: There is no practical way to check whether the IRQ affinity
     init stage is completely "done".  In general this is a best-effort
     configuration and it is expected that many of the IRQ affinities
     will fail to be set.  We also can not check whether the irqbalance
     cpu ban setting is correct as this requires root privlidges.  Thus
     we set the always_recreate flag so we just re-run init every time. */
  PARTIALLY_CONFIGURED( "irq-affinity" );
}

configure_stage_t fd_cfg_stage_irq_affinity = {
  .name            = NAME,
  .always_recreate = 1,
  .enabled         = NULL,
  .init_perm       = init_perm,
  .fini_perm       = NULL,
  .init            = init,
  .fini            = NULL,
  .check           = check,
};

#undef NAME
