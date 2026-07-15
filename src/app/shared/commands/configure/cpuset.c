/* The cpuset stage creates a cgroup v2 "isolated" cpuset partition
   over the Firedancer tile CPUs, at /sys/fs/cgroup/<name> where <name>
   is the instance [name] from the configuration (default "fd1"),
   allowing multiple Firedancer instances on one host to own distinct
   partitions.

   An isolated partition removes its CPUs from the scheduler domains of
   the rest of the system: no load balancing onto them, and processes
   outside the cgroup cannot be scheduled (or set affinity) onto them
   at all.  This is the runtime-configurable equivalent of the
   `isolcpus=` boot parameter, and the strongest tool available for
   keeping foreign tasks off tile CPUs.

   IMPORTANT INTERACTION: once the partition exists, ONLY processes
   inside the cgroup may run on tile CPUs.  The tile launcher
   (execve_tile in run.c) joins the cgroup before setting a fixed
   tile's affinity.  Setting affinity to a partitioned CPU from
   outside the cgroup fails with EINVAL; run `configure fini cpuset`
   to remove the partition if that happens with tooling that predates
   this stage.

   Notes:
   - Requires cgroup v2 (unified hierarchy) with the cpuset controller,
     and kernel support for the "isolated" partition type (5.15+ for
     root-adjacent partitions; probed at init by the partition write).
   - The cgroup directory is created directly under the cgroup root.
     systemd tolerates foreign cgroups there, but external cleanup may
     remove it; the check stage detects this and reports unconfigured.
   - Sibling exclusivity: the partition's CPUs must not appear in any
     sibling cgroup's explicit cpuset.cpus.  Typical systemd slices
     leave cpuset.cpus empty (meaning "parent's effective"), which
     does not conflict.  If an operator has explicitly assigned tile
     CPUs to another cgroup, the partition write fails and init
     reports it. */

#include "configure.h"
#include "fd_cpu_isolation.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#define NAME "cpuset"

#define CGROUP_ROOT     "/sys/fs/cgroup"
#define SUBTREE_CONTROL CGROUP_ROOT "/cgroup.subtree_control"

/* cgroup_path formats the per-instance cgroup path or one of its files
   into buf.  file may be NULL for the cgroup directory itself. */

static char const *
cgroup_path( char             buf[ static PATH_MAX ],
             config_t const * config,
             char const *     file ) {
  FD_TEST( fd_cstr_printf_check( buf, PATH_MAX, NULL, CGROUP_ROOT "/%s%s%s",
                                 config->name, file ? "/" : "", file ? file : "" ) );
  return buf;
}

/* write_cstr writes val to the file at path.  Returns 1 on success,
   0 on open/write failure with errno set; callers decide severity
   (typically FD_LOG_ERR with call-site context). */

static int
write_cstr( char const * path,
            char const * val ) {
  int fd = open( path, O_WRONLY );
  if( FD_UNLIKELY( fd<0 ) ) return 0;
  ulong val_len = strlen( val );
  int err = 0;
  if( FD_UNLIKELY( write( fd, val, val_len )!=(long)val_len ) ) err = errno;
  if( FD_UNLIKELY( close( fd ) ) ) FD_LOG_ERR(( "close(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( err ) ) {
    errno = err; /* preserve write() errno across close() */
    return 0;
  }
  return 1;
}

/* read_cstr reads the first line of path into buf.  Returns 1 on
   success, 0 if the file does not exist (ENOENT).  Any other error is
   fatal: these are kernel-provided files, and an unexpected failure
   reading them means something is wrong that we should not paper
   over. */

static int
read_cstr( char const * path,
           char *       buf,
           ulong        buf_sz ) {
  int fd = open( path, O_RDONLY );
  if( FD_UNLIKELY( fd<0 ) ) {
    if( FD_LIKELY( errno==ENOENT ) ) return 0;
    FD_LOG_ERR(( "open(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  }
  long n = read( fd, buf, buf_sz-1UL );
  if( FD_UNLIKELY( n<0L ) ) FD_LOG_ERR(( "read(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( fd ) ) ) FD_LOG_ERR(( "close(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  buf[ n ] = '\0';
  char * nl = strchr( buf, '\n' );
  if( FD_LIKELY( nl ) ) *nl = '\0';
  return 1;
}

static int
enabled( config_t const * config ) {
  (void)config;
  /* cgroup v2 unified hierarchy with the cpuset controller.  On v1 or
     hybrid systems the unified root has no cgroup.controllers file (or
     no cpuset in it) and this stage cannot work.  Only genuine absence
     disables the stage; any other failure reading the file is fatal
     (in read_cstr). */
  char controllers[ 256 ];
  if( FD_UNLIKELY( !read_cstr( CGROUP_ROOT "/cgroup.controllers", controllers, sizeof(controllers) ) ) ) return 0;
  return NULL!=strstr( controllers, "cpuset" );
}

static void
init_perm( fd_cap_chk_t *   chk,
           config_t const * config ) {
  char path[ PATH_MAX ];
  static char reason[ PATH_MAX+64UL ];
  FD_TEST( fd_cstr_printf_check( reason, sizeof(reason), NULL, "create and configure the cgroup `%s`",
                                 cgroup_path( path, config, NULL ) ) );
  fd_cap_chk_root( chk, NAME, reason );
}

static void
init( config_t const * config ) {
  FD_CPUSET_DECL( part_cpus );
  fd_cpu_isolation_partition_cpus( part_cpus, &config->topo );

  char cgroup[ PATH_MAX ]; cgroup_path( cgroup, config, NULL );

  if( FD_UNLIKELY( !fd_cpuset_cnt( part_cpus ) ) ) {
    FD_LOG_WARNING(( "no fixed tile CPUs in topology; not creating `%s`", cgroup ));
    return;
  }

  FD_CPUSET_DECL( host );
  fd_cpu_isolation_host_cpus( host );
  FD_CPUSET_DECL( housekeeping );
  fd_cpuset_subtract( housekeeping, host, part_cpus );
  if( FD_UNLIKELY( !fd_cpuset_cnt( housekeeping ) ) )
    FD_LOG_ERR(( "all host CPUs are assigned to Firedancer tiles; cannot isolate them all (the kernel needs at "
                 "least one housekeeping CPU)" ));

  char list[ FD_CPU_ISOLATION_LIST_MAX ];
  fd_cpu_isolation_format_list( list, sizeof(list), part_cpus );

  /* The parent must delegate the cpuset controller before a child can
     use it.  "+cpuset" is idempotent. */
  FD_LOG_NOTICE(( "%sRUN: `echo \"+cpuset\" > " SUBTREE_CONTROL "`%s", fd_log_style_dim(), fd_log_style_normal() ));
  if( FD_UNLIKELY( !write_cstr( SUBTREE_CONTROL, "+cpuset" ) ) )
    FD_LOG_ERR(( "could not enable the cpuset controller in `" SUBTREE_CONTROL "` (%i-%s)", errno, fd_io_strerror( errno ) ));

  FD_LOG_NOTICE(( "%sRUN: `mkdir %s`%s", fd_log_style_dim(), cgroup , fd_log_style_normal() ));
  if( FD_UNLIKELY( mkdir( cgroup, 0755 ) && errno!=EEXIST ) )
    FD_LOG_ERR(( "mkdir(%s) failed (%i-%s)", cgroup, errno, fd_io_strerror( errno ) ));

  char path[ PATH_MAX ];
  cgroup_path( path, config, "cpuset.cpus" );
  FD_LOG_NOTICE(( "%sRUN: `echo \"%s\" > %s`%s", fd_log_style_dim(), list, path , fd_log_style_normal() ));
  if( FD_UNLIKELY( !write_cstr( path, list ) ) )
    FD_LOG_ERR(( "write(%s,\"%s\") failed (%i-%s)", path, list, errno, fd_io_strerror( errno ) ));

  cgroup_path( path, config, "cpuset.cpus.partition" );
  FD_LOG_NOTICE(( "%sRUN: `echo \"isolated\" > %s`%s", fd_log_style_dim(), path , fd_log_style_normal() ));
  if( FD_UNLIKELY( !write_cstr( path, "isolated" ) ) )
    FD_LOG_ERR(( "write(%s,\"isolated\") failed (%i-%s). The kernel may be too old for isolated cpuset "
                 "partitions, or a sibling cgroup may have explicitly claimed one of the CPUs `%s`",
                 path, errno, fd_io_strerror( errno ), list ));
}

static int
fini( config_t const * config,
      int              pre_init ) {
  (void)pre_init;

  char cgroup[ PATH_MAX ]; cgroup_path( cgroup, config, NULL );
  if( FD_UNLIKELY( access( cgroup, F_OK ) ) ) return 0;

  /* Downgrade to a regular member cgroup first so the CPUs return to
     the system scheduler domains even if rmdir fails (e.g. because
     Firedancer is still running in it).  ENOENT is tolerated here and
     below: the access() check above races with concurrent removal (a
     second `configure fini`, or systemd cleaning up foreign cgroups),
     and someone else deleting the cgroup is this stage's goal state,
     not an error. */
  char path[ PATH_MAX ];
  cgroup_path( path, config, "cpuset.cpus.partition" );
  if( FD_UNLIKELY( !write_cstr( path, "member" ) && errno!=ENOENT ) )
    FD_LOG_ERR(( "write(%s,\"member\") failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));

  FD_LOG_NOTICE(( "%sRUN: `rmdir %s`%s", fd_log_style_dim(), cgroup , fd_log_style_normal() ));
  if( FD_UNLIKELY( rmdir( cgroup ) && errno!=ENOENT ) ) {
    if( FD_LIKELY( errno==EBUSY ) ) {
      FD_LOG_ERR(( "Removal of the CPU isolation cgroup `%s` failed because processes are still inside it, "
                   "likely because Firedancer is still running. The partition was downgraded so its CPUs are "
                   "returned to the system, but the cgroup itself could not be removed. Stop the validator and "
                   "run `%s configure fini cpuset` again, or remove it manually with `rmdir %s`",
                   cgroup, FD_BINARY_NAME, cgroup ));
    } else {
      FD_LOG_ERR(( "rmdir(%s) failed (%i-%s)", cgroup, errno, fd_io_strerror( errno ) ));
    }
  }
  return 1;
}

static configure_result_t
check( config_t const * config,
       int              check_type ) {
  (void)check_type;

  FD_CPUSET_DECL( part_cpus );
  fd_cpu_isolation_partition_cpus( part_cpus, &config->topo );
  if( FD_UNLIKELY( !fd_cpuset_cnt( part_cpus ) ) ) CONFIGURE_OK();

  char cgroup[ PATH_MAX ]; cgroup_path( cgroup, config, NULL );
  if( FD_UNLIKELY( access( cgroup, F_OK ) ) )
    NOT_CONFIGURED( "`%s` does not exist", cgroup );

  char path[ PATH_MAX ];
  cgroup_path( path, config, "cpuset.cpus" );
  char cpus[ FD_CPU_ISOLATION_LIST_MAX ];
  if( FD_UNLIKELY( !read_cstr( path, cpus, sizeof(cpus) ) ) )
    NOT_CONFIGURED( "`%s` does not exist", path ); /* cgroup removed concurrently */

  FD_CPUSET_DECL( current );
  if( FD_UNLIKELY( !fd_cpu_isolation_parse_list( current, cpus ) ) )
    FD_LOG_ERR(( "failed to parse `%s` (\"%s\")", path, cpus ));

  if( FD_UNLIKELY( !fd_cpuset_eq( current, part_cpus ) ) ) {
    char expected[ FD_CPU_ISOLATION_LIST_MAX ];
    fd_cpu_isolation_format_list( expected, sizeof(expected), part_cpus );
    PARTIALLY_CONFIGURED( "`%s` is \"%s\", expected \"%s\"", path, cpus, expected );
  }

  cgroup_path( path, config, "cpuset.cpus.partition" );
  char partition[ 64 ];
  if( FD_UNLIKELY( !read_cstr( path, partition, sizeof(partition) ) ) )
    NOT_CONFIGURED( "`%s` does not exist", path ); /* cgroup removed concurrently */

  /* An invalid partition reads as e.g. "isolated invalid (...)". */
  if( FD_UNLIKELY( strcmp( partition, "isolated" ) ) )
    PARTIALLY_CONFIGURED( "`%s` is \"%s\", expected \"isolated\"", path, partition );

  CONFIGURE_OK();
}

configure_stage_t fd_cfg_stage_cpuset = {
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
#undef CGROUP_ROOT
#undef SUBTREE_CONTROL
