#define _GNU_SOURCE
#include "fd_bootinfo.h"

#include "../../util/fd_version.h"
#include "../../util/pod/fd_pod.h"
#include "../../util/sandbox/fd_sandbox.h"
#include "../../util/shmem/fd_shmem_private.h"
#include "../../tango/tempo/fd_tempo.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#define BOOTINFO_NORMAL "\033[0m"
#define BOOTINFO_BOLD   "\033[1m"
#define BOOTINFO_DIM    "\033[2m"
#define BOOTINFO_GREEN  "\033[32m"
#define BOOTINFO_YELLOW "\033[93m"

/* proc_start_time reads /proc/<pid>/stat field 22 (starttime, in
   clock ticks since boot).  Returns 0 on failure (0 is not a valid
   start time for any process we care about).  The comm field can
   contain spaces and parens, so parse from the last ')'. */

static ulong
proc_start_time( ulong pid ) {
  char path[ 64UL ];
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "/proc/%lu/stat", pid ) );

  char buf[ 4096UL ];
  int fd = open( path, O_RDONLY );
  if( FD_UNLIKELY( -1==fd ) ) return 0UL;
  long sz = read( fd, buf, sizeof(buf)-1UL );
  if( FD_UNLIKELY( close( fd ) ) ) FD_LOG_WARNING(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( sz<=0L ) ) return 0UL;
  buf[ sz ] = '\0';

  char * p = strrchr( buf, ')' );
  if( FD_UNLIKELY( !p ) ) return 0UL;

  /* fields 3 (state) through 21 follow ')', starttime is field 22 */
  ulong start_time = 0UL;
  if( FD_UNLIKELY( 1!=sscanf( p+1UL, " %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %lu", &start_time ) ) ) return 0UL;
  return start_time;
}

static void
bootinfo_path( char const * mount_path,
               char const * name,
               char *       out ) {
  FD_TEST( fd_cstr_printf_check( out, PATH_MAX, NULL, "%s/%s.bootinfo", mount_path, name ) );
}

/* write_file_atomic writes sz bytes at data to path via a same-dir
   .partial rename.  Returns 0 on success, -1 otherwise. */

static int
write_file_atomic( char const * path,
                   void const * data,
                   ulong        sz,
                   mode_t       mode ) {
  char partial_path[ PATH_MAX ];
  if( FD_UNLIKELY( !fd_cstr_printf_check( partial_path, sizeof(partial_path), NULL, "%s.partial", path ) ) ) return -1;

  int fd = open( partial_path, O_WRONLY|O_CREAT|O_TRUNC, mode );
  if( FD_UNLIKELY( -1==fd ) ) return -1;

  uchar const * p         = (uchar const *)data;
  ulong         remaining = sz;
  while( remaining ) {
    long written = write( fd, p, remaining );
    if( FD_UNLIKELY( written<=0L ) ) {
      if( FD_UNLIKELY( written<0L && errno==EINTR ) ) continue;
      if( FD_UNLIKELY( close( fd ) ) ) FD_LOG_WARNING(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      if( FD_UNLIKELY( -1==unlink( partial_path ) && errno!=ENOENT ) ) FD_LOG_WARNING(( "unlink() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      return -1;
    }
    p += written; remaining -= (ulong)written;
  }
  if( FD_UNLIKELY( close( fd ) ) ) FD_LOG_WARNING(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  if( FD_UNLIKELY( -1==rename( partial_path, path ) ) ) return -1;
  return 0;
}

void
fd_bootinfo_write( config_t const * config ) {
  fd_bootinfo_t info = {0};
  info.magic                 = FD_BOOTINFO_MAGIC;
  info.version               = FD_BOOTINFO_VERSION;
  info.pid                   = fd_sandbox_getpid();
  info.pid_start_time        = proc_start_time( info.pid );
  info.boot_wallclock_nanos  = fd_log_wallclock();
  fd_cstr_ncpy( info.commit_ref, fd_commit_ref_cstr, sizeof(info.commit_ref) );
  info.fd_version[ 0 ]       = fd_major_version;
  info.fd_version[ 1 ]       = fd_minor_version;
  info.fd_version[ 2 ]       = fd_patch_version;
  fd_cstr_ncpy( info.name, config->name, sizeof(info.name) );
  info.uid                   = config->uid;
  info.gid                   = config->gid;
  info.topo_layout_hash      = config->topo.layout_hash;

  ulong adminctl_obj_id = fd_pod_query_ulong( config->topo.props, "adminctl", ULONG_MAX );
  if( FD_LIKELY( adminctl_obj_id!=ULONG_MAX ) ) {
    fd_topo_obj_t const *  obj  = &config->topo.objs[ adminctl_obj_id ];
    fd_topo_wksp_t const * wksp = &config->topo.workspaces[ obj->wksp_id ];
    FD_TEST( fd_cstr_printf_check( info.adminctl_wksp_file, sizeof(info.adminctl_wksp_file), NULL, "%s_%s.wksp", config->name, wksp->name ) );
    info.adminctl_page_sz = wksp->page_sz;
    info.adminctl_offset  = obj->offset;
  }

  if( FD_UNLIKELY( !info.pid_start_time ) ) {
    FD_LOG_WARNING(( "could not read own process start time, validator discovery will be unavailable" ));
    return;
  }

  /* Publish the resolved config blob first so a reader that sees the
     descriptor can always recover it.  Contains paths and settings, no
     key material. */
  char blob_path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( blob_path, sizeof(blob_path), NULL, "%s/%s.config", config->hugetlbfs.mount_path, config->name ) );
  if( FD_UNLIKELY( -1==write_file_atomic( blob_path, config, sizeof(config_t), S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH ) ) ) {
    FD_LOG_WARNING(( "write(%s) failed (%i-%s), attaching to this validator will require --config", blob_path, errno, fd_io_strerror( errno ) ));
  } else {
    FD_TEST( fd_cstr_printf_check( info.config_file, sizeof(info.config_file), NULL, "%s.config", config->name ) );
    info.config_sz = sizeof(config_t);
  }

  char path[ PATH_MAX ];
  bootinfo_path( config->hugetlbfs.mount_path, config->name, path );

  if( FD_UNLIKELY( -1==write_file_atomic( path, &info, sizeof(info), S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH ) ) )
    FD_LOG_WARNING(( "write(%s) failed (%i-%s), validator discovery will be unavailable", path, errno, fd_io_strerror( errno ) ));

  char const * c_normal = fd_log_style_normal();
  char const * c_bold   = fd_log_style_bold();
  char const * c_dim    = fd_log_style_dim();

  ulong mem_gib = (fd_topo_mlock( &config->topo )+((1UL<<30UL)-1UL))>>30UL;
  FD_LOG_NOTICE(( "booting validator %s%s%s version %lu.%lu.%lu %s(%.11s)%s pid %lu with %s%lu%s tiles and %s%lu GiB%s memory at %s%s%s",
                  c_bold, info.name, c_normal,
                  info.fd_version[ 0 ], info.fd_version[ 1 ], info.fd_version[ 2 ],
                  c_dim, info.commit_ref, c_normal,
                  info.pid,
                  c_bold, config->topo.tile_cnt, c_normal,
                  c_bold, mem_gib, c_normal,
                  c_dim, config->hugetlbfs.mount_path, c_normal ));
}

void
fd_bootinfo_unlink( config_t const * config ) {
  char const * suffix[ 4 ] = { "bootinfo", "bootinfo.partial", "config", "config.partial" };
  for( ulong i=0UL; i<4UL; i++ ) {
    char path[ PATH_MAX ];
    FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "%s/%s.%s", config->hugetlbfs.mount_path, config->name, suffix[ i ] ) );
    if( FD_UNLIKELY( -1==unlink( path ) && errno!=ENOENT ) )
      FD_LOG_WARNING(( "unlink(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  }
}

int
fd_bootinfo_path_read( char const *    path,
                       fd_bootinfo_t * out ) {
  int fd = open( path, O_RDONLY );
  if( FD_UNLIKELY( -1==fd ) ) return -1;

  struct stat st;
  if( FD_UNLIKELY( -1==fstat( fd, &st )                 ) ) goto fail;
  if( FD_UNLIKELY( !S_ISREG( st.st_mode )               ) ) goto fail;
  if( FD_UNLIKELY( st.st_uid && st.st_uid!=geteuid()    ) ) goto fail; /* only trust root or self */
  if( FD_UNLIKELY( st.st_mode & S_IWOTH                 ) ) goto fail;
  /* Newer builds may append fields, the v1 prefix is frozen so any
     genuine descriptor is at least this large and parses below. */
  if( FD_UNLIKELY( st.st_size<(long)sizeof(*out)        ) ) goto fail;

  if( FD_UNLIKELY( sizeof(*out)!=(ulong)read( fd, out, sizeof(*out) ) ) ) goto fail;
  if( FD_UNLIKELY( close( fd ) ) ) FD_LOG_WARNING(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  if( FD_UNLIKELY( out->magic!=FD_BOOTINFO_MAGIC       ) ) return -1;
  if( FD_UNLIKELY( !out->version                       ) ) return -1;
  if( FD_UNLIKELY( !memchr( out->name, '\0', sizeof(out->name) )                             ) ) return -1;
  if( FD_UNLIKELY( !memchr( out->commit_ref, '\0', sizeof(out->commit_ref) )                 ) ) return -1;
  if( FD_UNLIKELY( !memchr( out->adminctl_wksp_file, '\0', sizeof(out->adminctl_wksp_file) ) ) ) return -1;
  if( FD_UNLIKELY( strchr( out->adminctl_wksp_file, '/' )                                    ) ) return -1;
  if( FD_UNLIKELY( !memchr( out->config_file, '\0', sizeof(out->config_file) )               ) ) return -1;
  if( FD_UNLIKELY( strchr( out->config_file, '/' )                                           ) ) return -1;
  return 0;

fail:
  if( FD_UNLIKELY( close( fd ) ) ) FD_LOG_WARNING(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  return -1;
}

int
fd_bootinfo_live( fd_bootinfo_t const * info ) {
  ulong start_time = proc_start_time( info->pid );
  return start_time && start_time==info->pid_start_time;
}

/* mountinfo_unescape decodes \0NN octal escapes in-place. */

static void
mountinfo_unescape( char * s ) {
  char * w = s;
  while( *s ) {
    if( FD_UNLIKELY( s[0]=='\\' && s[1]>='0' && s[1]<='3' && s[2]>='0' && s[2]<='7' && s[3]>='0' && s[3]<='7' ) ) {
      *w++ = (char)( ((s[1]-'0')<<6) | ((s[2]-'0')<<3) | (s[3]-'0') );
      s += 4;
    } else {
      *w++ = *s++;
    }
  }
  *w = '\0';
}

/* candidate_mounts fills dirs with parent directories of firedancer
   shaped hugetlbfs mounts (mountpoint basename .gigantic/.huge/.normal)
   plus the default mount path.  Returns the count. */

static ulong
candidate_mounts( char  dirs[ FD_BOOTINFO_INSTANCE_MAX ][ PATH_MAX ],
                  ulong max ) {
  ulong cnt = 0UL;

  FILE * fp = fopen( "/proc/self/mountinfo", "r" );
  if( FD_LIKELY( fp ) ) {
    char line[ 4096UL ];
    while( FD_LIKELY( fgets( line, sizeof(line), fp ) ) ) {
      /* fields: id parent maj:min root mountpoint opts [optional]* - fstype src superopts */
      char * sep = strstr( line, " - " );
      if( FD_UNLIKELY( !sep ) ) continue;

      char * fstype = sep+3UL;
      char * fstype_end = strchr( fstype, ' ' );
      if( FD_UNLIKELY( !fstype_end ) ) continue;
      *fstype_end = '\0';
      if( FD_LIKELY( strcmp( fstype, "hugetlbfs" ) ) ) continue;

      *sep = '\0';
      char * mountpoint = NULL;
      char * tok = strtok( line, " " );
      for( ulong i=0UL; tok; i++, tok=strtok( NULL, " " ) ) {
        if( i==4UL ) { mountpoint = tok; break; }
      }
      if( FD_UNLIKELY( !mountpoint ) ) continue;
      mountinfo_unescape( mountpoint );

      char * base = strrchr( mountpoint, '/' );
      if( FD_UNLIKELY( !base || base==mountpoint ) ) continue;
      if( FD_LIKELY( strcmp( base, "/.gigantic" ) && strcmp( base, "/.huge" ) && strcmp( base, "/.normal" ) ) ) continue;
      *base = '\0'; /* mountpoint is now the parent dir */

      int seen = 0;
      for( ulong i=0UL; i<cnt; i++ ) if( !strcmp( dirs[ i ], mountpoint ) ) { seen = 1; break; }
      if( FD_UNLIKELY( seen ) ) continue;
      if( FD_UNLIKELY( cnt>=max ) ) break;
      strncpy( dirs[ cnt ], mountpoint, PATH_MAX-1UL );
      dirs[ cnt ][ PATH_MAX-1UL ] = '\0';
      cnt++;
    }
    if( FD_UNLIKELY( fclose( fp ) ) ) FD_LOG_WARNING(( "fclose() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  /* default path, covers normal page setups with no hugetlbfs mounts */
  int seen = 0;
  for( ulong i=0UL; i<cnt; i++ ) if( !strcmp( dirs[ i ], "/mnt/.fd" ) ) { seen = 1; break; }
  if( FD_LIKELY( !seen && cnt<max ) ) {
    strncpy( dirs[ cnt ], "/mnt/.fd", PATH_MAX-1UL );
    cnt++;
  }

  return cnt;
}

ulong
fd_bootinfo_discover( fd_bootinfo_instance_t * out,
                      ulong                    max ) {
  static char dirs[ FD_BOOTINFO_INSTANCE_MAX ][ PATH_MAX ];
  ulong dir_cnt = candidate_mounts( dirs, FD_BOOTINFO_INSTANCE_MAX );

  ulong cnt = 0UL;
  for( ulong i=0UL; i<dir_cnt && cnt<max; i++ ) {
    DIR * dir = opendir( dirs[ i ] );
    if( FD_UNLIKELY( !dir ) ) continue;

    struct dirent * entry;
    while( FD_LIKELY( cnt<max && (entry=readdir( dir )) ) ) {
      char const * suffix = strstr( entry->d_name, ".bootinfo" );
      if( FD_LIKELY( !suffix || strcmp( suffix, ".bootinfo" ) ) ) continue;

      char path[ PATH_MAX ];
      if( FD_UNLIKELY( !fd_cstr_printf_check( path, sizeof(path), NULL, "%s/%s", dirs[ i ], entry->d_name ) ) ) continue;

      fd_bootinfo_t info;
      if( FD_UNLIKELY( -1==fd_bootinfo_path_read( path, &info ) ) ) continue;

      /* name must match filename */
      if( FD_UNLIKELY( strncmp( entry->d_name, info.name, (ulong)(suffix-entry->d_name) ) || strlen( info.name )!=(ulong)(suffix-entry->d_name) ) ) continue;

      strncpy( out[ cnt ].mount_path, dirs[ i ], PATH_MAX-1UL );
      out[ cnt ].mount_path[ PATH_MAX-1UL ] = '\0';
      out[ cnt ].info = info;
      out[ cnt ].live = fd_bootinfo_live( &info );
      cnt++;
    }
    if( FD_UNLIKELY( -1==closedir( dir ) ) ) FD_LOG_WARNING(( "closedir() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  return cnt;
}

void
fd_bootinfo_print( fd_bootinfo_instance_t const * instances,
                   ulong                          cnt ) {
  /* fd_log colorize already honors NO_COLOR/TERM/--log-colorize, but is
     keyed to stderr, so additionally require stdout to be a tty. */
  int color = fd_log_colorize() && isatty( STDOUT_FILENO );
  char const * c_normal = color ? BOOTINFO_NORMAL : "";
  char const * c_bold   = color ? BOOTINFO_BOLD   : "";
  char const * c_dim    = color ? BOOTINFO_DIM    : "";
  char const * c_live   = color ? BOOTINFO_GREEN  : "";
  char const * c_stale  = color ? BOOTINFO_YELLOW : "";

  if( FD_UNLIKELY( !cnt ) ) {
    FD_LOG_STDOUT(( "%sno validators found%s\n", c_dim, c_normal ));
    return;
  }

  FD_LOG_STDOUT(( "%s%-16s %-8s %-7s %-10s %-12s %-12s %s%s\n", c_dim, "NAME", "PID", "STATE", "UPTIME", "VERSION", "COMMIT", "MOUNT", c_normal ));
  for( ulong i=0UL; i<cnt; i++ ) {
    fd_bootinfo_instance_t const * instance = &instances[ i ];
    fd_bootinfo_t const *          info     = &instance->info;

    char uptime[ 32UL ] = "-";
    if( FD_LIKELY( instance->live ) ) {
      long secs = (fd_log_wallclock()-info->boot_wallclock_nanos)/(long)1e9;
      if( FD_UNLIKELY( secs<0L ) ) secs = 0L;
      long days = secs/86400L, hours = (secs/3600L)%24L, mins = (secs/60L)%60L;
      if(      FD_UNLIKELY( days  ) ) FD_TEST( fd_cstr_printf_check( uptime, sizeof(uptime), NULL, "%ldd%ldh%ldm", days, hours, mins ) );
      else if( FD_UNLIKELY( hours ) ) FD_TEST( fd_cstr_printf_check( uptime, sizeof(uptime), NULL, "%ldh%ldm", hours, mins ) );
      else if( FD_LIKELY(   mins  ) ) FD_TEST( fd_cstr_printf_check( uptime, sizeof(uptime), NULL, "%ldm", mins ) );
      else                            FD_TEST( fd_cstr_printf_check( uptime, sizeof(uptime), NULL, "%lds", secs ) );
    }

    char version[ 32UL ];
    FD_TEST( fd_cstr_printf_check( version, sizeof(version), NULL, "%lu.%lu.%lu", info->fd_version[ 0 ], info->fd_version[ 1 ], info->fd_version[ 2 ] ) );

    char commit[ 12UL ] = {0};
    strncpy( commit, info->commit_ref, sizeof(commit)-1UL );

    FD_LOG_STDOUT(( "%s%-16s%s %-8lu %s%-7s%s %-10s %-12s %-12s %s%s%s\n",
                    c_bold, info->name, c_normal,
                    info->pid,
                    instance->live ? c_live : c_stale,
                    instance->live ? "live" : "stale",
                    c_normal,
                    uptime,
                    version,
                    commit,
                    c_dim, instance->mount_path, c_normal ));
  }
}

void
fd_bootinfo_notice( fd_bootinfo_instance_t const * instance ) {
  fd_bootinfo_t const * info = &instance->info;

  long secs = (fd_log_wallclock()-info->boot_wallclock_nanos)/(long)1e9;
  if( FD_UNLIKELY( secs<0L ) ) secs = 0L;
  long days = secs/86400L, hours = (secs/3600L)%24L, mins = (secs/60L)%60L;
  char uptime[ 32UL ];
  if(      FD_UNLIKELY( days  ) ) FD_TEST( fd_cstr_printf_check( uptime, sizeof(uptime), NULL, "%ldd%ldh%ldm", days, hours, mins ) );
  else if( FD_UNLIKELY( hours ) ) FD_TEST( fd_cstr_printf_check( uptime, sizeof(uptime), NULL, "%ldh%ldm", hours, mins ) );
  else if( FD_LIKELY(   mins  ) ) FD_TEST( fd_cstr_printf_check( uptime, sizeof(uptime), NULL, "%ldm", mins ) );
  else                            FD_TEST( fd_cstr_printf_check( uptime, sizeof(uptime), NULL, "%lds", secs ) );

  char const * c_normal = fd_log_style_normal();
  char const * c_bold   = fd_log_style_bold();
  char const * c_dim    = fd_log_style_dim();
  char const * c_live   = fd_log_colorize() ? BOOTINFO_GREEN : "";

  FD_LOG_NOTICE(( "attached to %slive%s validator %s%s%s version %lu.%lu.%lu %s(%.11s)%s pid %lu up %s at %s%s%s",
                  c_live, c_normal,
                  c_bold, info->name, c_normal,
                  info->fd_version[ 0 ], info->fd_version[ 1 ], info->fd_version[ 2 ],
                  c_dim, info->commit_ref, c_normal,
                  info->pid,
                  uptime,
                  c_dim, instance->mount_path, c_normal ));
}

void
fd_bootinfo_adopt( config_t * config ) {
  if( FD_LIKELY( config->has_user_config ) ) return; /* fd_bootinfo_check_layout verifies before joining */

  fd_bootinfo_instance_t instances[ FD_BOOTINFO_INSTANCE_MAX ];
  ulong cnt = fd_bootinfo_discover( instances, FD_BOOTINFO_INSTANCE_MAX );

  fd_bootinfo_instance_t * match     = NULL;
  ulong                    live_cnt  = 0UL;
  for( ulong i=0UL; i<cnt; i++ ) {
    if( FD_UNLIKELY( !instances[ i ].live ) ) continue;
    match = &instances[ i ];
    live_cnt++;
  }

  if( FD_UNLIKELY( !live_cnt ) ) {
    if( FD_UNLIKELY( cnt ) ) fd_bootinfo_print( instances, cnt );
    FD_LOG_ERR(( "No running validator found. If a validator is running, pass --config with the "
                 "configuration file it was started with." ));
  }

  if( FD_UNLIKELY( live_cnt>1UL ) ) {
    fd_bootinfo_print( instances, cnt );
    FD_LOG_ERR(( "Multiple running validators found. Pass --config to select one." ));
  }

  fd_bootinfo_t const * info = &match->info;

  if( FD_UNLIKELY( strcmp( info->commit_ref, fd_commit_ref_cstr ) ) )
    FD_LOG_ERR(( "The running validator `%s` is running commit %s but this binary is commit %s.  "
                 "This command reads the validator's memory directly and must be run from the "
                 "same binary the validator is running.", info->name, info->commit_ref, fd_commit_ref_cstr ));

  if( FD_UNLIKELY( !info->config_file[ 0 ] || info->config_sz!=sizeof(config_t) ) )
    FD_LOG_ERR(( "The running validator `%s` did not publish a usable configuration.  Pass --config "
                 "with the configuration file it was started with.", info->name ));

  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "%s/%s", match->mount_path, info->config_file ) );

  int fd = open( path, O_RDONLY );
  if( FD_UNLIKELY( -1==fd ) ) FD_LOG_ERR(( "open(%s) failed (%i-%s).  The validator `%s` appears to be running "
                                           "but its configuration could not be read.  Pass --config with the "
                                           "configuration file it was started with.", path, errno, fd_io_strerror( errno ), info->name ));

  struct stat st;
  if( FD_UNLIKELY( -1==fstat( fd, &st )               ) ) FD_LOG_ERR(( "fstat(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( !S_ISREG( st.st_mode )             ) ) FD_LOG_ERR(( "`%s` is not a regular file", path ));
  if( FD_UNLIKELY( st.st_uid && st.st_uid!=geteuid()  ) ) FD_LOG_ERR(( "`%s` is not owned by root", path ));
  if( FD_UNLIKELY( st.st_mode & S_IWOTH               ) ) FD_LOG_ERR(( "`%s` is world writable", path ));
  if( FD_UNLIKELY( st.st_size!=(long)sizeof(config_t) ) ) FD_LOG_ERR(( "validator `%s` config has unexpected size %ld", info->name, st.st_size ));

  uchar * p         = (uchar *)config;
  ulong   remaining = sizeof(config_t);
  while( remaining ) {
    long got = read( fd, p, remaining );
    if( FD_UNLIKELY( got<=0L ) ) {
      if( FD_UNLIKELY( got<0L && errno==EINTR ) ) continue;
      FD_LOG_ERR(( "read(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    }
    p += got; remaining -= (ulong)got;
  }
  if( FD_UNLIKELY( close( fd ) ) ) FD_LOG_WARNING(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  config->has_user_config = 0;

  /* Rebind process state that was derived from the default config
     before adoption. */
  fd_tempo_set_tick_per_ns( config->tick_per_ns_mu, config->tick_per_ns_sigma );

  ulong base_len = strlen( config->hugetlbfs.mount_path );
  if( FD_UNLIKELY( !base_len || base_len>=FD_SHMEM_PRIVATE_BASE_MAX ) ) FD_LOG_ERR(( "adopted invalid mount path" ));
  memcpy( fd_shmem_private_base, config->hugetlbfs.mount_path, base_len+1UL );
  fd_shmem_private_base_len = base_len;

  /* Permissions were checked against the default topology, which may
     mlock less than the adopted one.  Best effort raise. */
  struct rlimit rl = { .rlim_cur = fd_topo_mlock( &config->topo ), .rlim_max = fd_topo_mlock( &config->topo ) };
  if( FD_UNLIKELY( -1==setrlimit( RLIMIT_MEMLOCK, &rl ) ) )
    FD_LOG_INFO(( "setrlimit(RLIMIT_MEMLOCK) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  fd_bootinfo_notice( match );
}

void
fd_bootinfo_check_layout( config_t const * config ) {
  char path[ PATH_MAX ];
  bootinfo_path( config->hugetlbfs.mount_path, config->name, path );

  fd_bootinfo_t info;
  if( FD_UNLIKELY( -1==fd_bootinfo_path_read( path, &info ) ) ) return; /* no or unreadable descriptor, older validator */
  if( FD_UNLIKELY( !fd_bootinfo_live( &info ) ) ) return;
  if( FD_UNLIKELY( !info.topo_layout_hash ) ) return;

  if( FD_UNLIKELY( info.topo_layout_hash!=config->topo.layout_hash ) ) {
    if( FD_UNLIKELY( !strcmp( info.commit_ref, fd_commit_ref_cstr ) ) ) {
      FD_LOG_ERR(( "The configuration file provided to this command is not the one the "
                   "running validator was started with.  Rerun the command with the "
                   "validator's configuration file, or without --config to use the "
                   "running validator's configuration automatically." ));
    }
    FD_LOG_ERR(( "This binary is a different version than the running validator.  The "
                 "validator is running commit %s%.11s%s and this binary is commit "
                 "%s%.11s%s.  Rerun the command with the same binary the validator was "
                 "started with.",
                 fd_log_style_bold(), info.commit_ref, fd_log_style_normal(),
                 fd_log_style_bold(), fd_commit_ref_cstr, fd_log_style_normal() ));
  }
}
