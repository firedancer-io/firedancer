#define _GNU_SOURCE
#include "config.h"
#include "config_parse.h"
#include "fdctl.h"

#include "run/topos/topos.h"

#include "../shared/fd_sys_util.h"
#include "../shared/fd_net_util.h"

#include "../../ballet/toml/fd_toml.h"
#include "../../disco/topo/fd_pod_format.h"
#include "../../flamenco/genesis/fd_genesis_cluster.h"
#include "../../disco/keyguard/fd_keyswitch.h"
#if FD_HAS_NO_AGAVE
#include "../../flamenco/runtime/fd_blockstore.h"
#include "../../flamenco/runtime/fd_txncache.h"
#include "../../flamenco/runtime/fd_runtime.h"
#endif
#include "../../funk/fd_funk.h"
#include "../../waltz/ip/fd_fib4.h"
#include "../../waltz/mib/fd_dbl_buf.h"
#undef FD_MAP_FLAG_BLOCKING
#include "../../waltz/neigh/fd_neigh4_map.h"
#include "../../util/net/fd_eth.h"
#include "../../util/net/fd_ip4.h"

#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <sys/wait.h>

/* FD_TOML_POD_SZ sets the buffer size of the fd_pod that will hold the
   parsed config file content.

   This should be large enough to hold a Firedancer TOML file with all
   config options set. */

#define FD_TOML_POD_SZ (1UL<<20)

void
replace( char *       in,
         const char * pat,
         const char * sub ) {
  char * replace = strstr( in, pat );
  if( FD_LIKELY( replace ) ) {
    ulong pat_len = strlen( pat );
    ulong sub_len = strlen( sub );
    ulong in_len  = strlen( in );
    if( FD_UNLIKELY( pat_len > in_len ) ) return;

    ulong total_len = in_len - pat_len + sub_len;
    if( FD_UNLIKELY( total_len >= PATH_MAX ) )
      FD_LOG_ERR(( "configuration scratch directory path too long: `%s`", in ));

    uchar after[PATH_MAX] = {0};
    fd_memcpy( after, replace + pat_len, strlen( replace + pat_len ) );
    fd_memcpy( replace, sub, sub_len );
    ulong after_len = strlen( ( const char * ) after );
    fd_memcpy( replace + sub_len, after, after_len );
    in[ total_len ] = '\0';
  }
}

static void
fdctl_cfg_load_buf( config_t *   out,
                    char const * buf,
                    ulong        sz,
                    char const * path ) {

  static uchar pod_mem[ 1UL<<30 ];
  uchar * pod = fd_pod_join( fd_pod_new( pod_mem, sizeof(pod_mem) ) );

  fd_toml_err_info_t toml_err[1];
  uchar scratch[ 4096 ];
  int toml_errc = fd_toml_parse( buf, sz, pod, scratch, sizeof(scratch), toml_err );
  if( FD_UNLIKELY( toml_errc!=FD_TOML_SUCCESS ) ) {
    /* Override the default error messages of fd_toml for a better user
       experience */
    switch( toml_errc ) {
    case FD_TOML_ERR_POD:
      FD_LOG_ERR(( "Failed to parse config file (%s): ran out of buffer space while parsing (Increase FD_TOML_POD_SZ?)", path ));
      break;
    case FD_TOML_ERR_SCRATCH:
      FD_LOG_ERR(( "Failed to parse config file (%s) at line %lu: ran out of scratch space while parsing", path, toml_err->line ));
      break;
    case FD_TOML_ERR_KEY:
      FD_LOG_ERR(( "Failed to parse config file (%s) at line %lu: oversize key", path, toml_err->line ));
      break;
    case FD_TOML_ERR_DUP:
      FD_LOG_ERR(( "Failed to parse config file (%s) at line %lu: duplicate key", path, toml_err->line ));
      break;
    case FD_TOML_ERR_RANGE:
      FD_LOG_ERR(( "Failed to parse config file (%s) at line %lu: invalid value for key", path, toml_err->line ));
      break;
    case FD_TOML_ERR_PARSE:
      FD_LOG_ERR(( "Failed to parse config file (%s) at line %lu", path, toml_err->line ));
      break;
    default:
      FD_LOG_ERR(( "Failed to parse config file (%s): %s", path, fd_toml_strerror( toml_errc ) ));
      break;
    }
  }

  if( FD_UNLIKELY( !fdctl_pod_to_cfg( out, pod ) ) ) {
    FD_LOG_ERR(( "Invalid config (%s)", path ));
  }

  fd_pod_delete( fd_pod_leave( pod ) );
}

static void
fdctl_cfg_load_file( config_t *   out,
                     char const * path ) {

  int fd = open( path, O_RDONLY );
  if( FD_UNLIKELY( fd<0 ) ) {
    FD_LOG_ERR(( "open(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  }

  struct stat st;
  if( FD_UNLIKELY( fstat( fd, &st ) ) ) {
    FD_LOG_ERR(( "fstat(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  }
  ulong toml_sz = (ulong)st.st_size;

  if( FD_UNLIKELY( toml_sz==0UL ) ) {
    if( FD_UNLIKELY( 0!=close( fd ) ) ) {
      FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    return;
  }

  void * mem = mmap( NULL, toml_sz, PROT_READ, MAP_PRIVATE, fd, 0 );
  if( FD_UNLIKELY( mem==MAP_FAILED ) ) {
    FD_LOG_ERR(( "mmap(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  }

  if( FD_UNLIKELY( 0!=close( fd ) ) ) {
    FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  fdctl_cfg_load_buf( out, mem, toml_sz, path );

  if( FD_UNLIKELY( 0!=munmap( mem, toml_sz ) ) ) {
    FD_LOG_ERR(( "munmap(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  }
}

static uint
listen_address( const char * interface ) {
  int fd = socket( AF_INET, SOCK_DGRAM, 0 );
  struct ifreq ifr = {0};
  ifr.ifr_addr.sa_family = AF_INET;
  strncpy( ifr.ifr_name, interface, IFNAMSIZ );
  ifr.ifr_name[ IFNAMSIZ-1 ] = '\0';
  if( FD_UNLIKELY( ioctl( fd, SIOCGIFADDR, &ifr ) ) )
    FD_LOG_ERR(( "could not get IP address of interface `%s` (%i-%s)", interface, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close(fd) ) )
    FD_LOG_ERR(( "could not close socket (%i-%s)", errno, fd_io_strerror( errno ) ));
  return ((struct sockaddr_in *)fd_type_pun( &ifr.ifr_addr ))->sin_addr.s_addr;
}

static void
username_to_id( config_t * config ) {
  uint * results = mmap( NULL, 4096, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0 );
  if( FD_UNLIKELY( results==MAP_FAILED ) ) FD_LOG_ERR(( "mmap() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  results[ 0 ] = UINT_MAX;
  results[ 1 ] = UINT_MAX;

  /* This is extremely unfortunate.  We just want to call getpwnam but
     on various glibc it can open `/var/lib/sss/mc/passwd` and then not
     close it.  We could go and find this file descriptor and close it
     for the library, but that is a bit of a hack.  Instead we fork a
     new process to call getpwnam and then exit.

     We could try just reading /etc/passwd here instead, but the glibc
     getpwnam implementation does a lot of things we need, including
     potentially reading from NCSD or SSSD. */

  pid_t pid = fork();
  if( FD_UNLIKELY( pid == -1 ) ) FD_LOG_ERR(( "fork() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  if( FD_LIKELY( !pid ) ) {
    char buf[ 16384 ];
    struct passwd pwd;
    struct passwd * result;
    int error = getpwnam_r( config->user, &pwd, buf, sizeof(buf), &result );
    if( FD_UNLIKELY( error ) ) {
      if( FD_LIKELY( error==ENOENT || error==ESRCH ) ) FD_LOG_ERR(( "configuration file wants firedancer to run as user `%s` but it does not exist", config->user ));
      else FD_LOG_ERR(( "could not get user id for `%s` (%i-%s)", config->user, errno, fd_io_strerror( errno ) ));
    }
    if( FD_UNLIKELY( !result ) ) FD_LOG_ERR(( "configuration file wants firedancer to run as user `%s` but it does not exist", config->user ));
    results[ 0 ] = pwd.pw_uid;
    results[ 1 ] = pwd.pw_gid;
    fd_sys_util_exit_group( 0 );
  } else {
    int wstatus;
    if( FD_UNLIKELY( waitpid( pid, &wstatus, 0 )==-1 ) ) FD_LOG_ERR(( "waitpid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( WIFSIGNALED( wstatus ) ) )
      FD_LOG_ERR(( "uid fetch process terminated by signal %i-%s", WTERMSIG( wstatus ), fd_io_strsignal( WTERMSIG( wstatus ) ) ));
    if( FD_UNLIKELY( WEXITSTATUS( wstatus ) ) )
      FD_LOG_ERR(( "uid fetch process exited with status %i", WEXITSTATUS( wstatus ) ));
  }

  if( FD_UNLIKELY( results[ 0 ]==UINT_MAX || results[ 1 ]==UINT_MAX ) ) FD_LOG_ERR(( "could not get user id for `%s`", config->user ));
  config->uid = results[ 0 ];
  config->gid = results[ 1 ];

  if( FD_UNLIKELY( munmap( results, 4096 ) ) ) FD_LOG_ERR(( "munmap() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

fd_topo_run_tile_t *
fd_topo_tile_to_config( fd_topo_tile_t const * tile ) {
  fd_topo_run_tile_t ** run = TILES;
  while( *run ) {
    if( FD_LIKELY( !strcmp( (*run)->name, tile->name ) ) ) return *run;
    run++;
  }
  FD_LOG_ERR(( "unknown tile name `%s`", tile->name ));
}

ulong
fdctl_obj_align( fd_topo_t const *     topo,
                 fd_topo_obj_t const * obj ) {
  if( FD_UNLIKELY( !strcmp( obj->name, "tile" ) ) ) {
    fd_topo_tile_t const * tile = NULL;
    for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
      if( FD_LIKELY( topo->tiles[ i ].tile_obj_id==obj->id ) ) {
        tile = &topo->tiles[ i ];
        break;
      }
    }
    fd_topo_run_tile_t * config = fd_topo_tile_to_config( tile );
    if( FD_LIKELY( config->scratch_align ) ) return config->scratch_align();
    return 1UL;
  } else if( FD_UNLIKELY( !strcmp( obj->name, "mcache" ) ) ) {
    return fd_mcache_align();
  } else if( FD_UNLIKELY( !strcmp( obj->name, "dcache" ) ) ) {
    return fd_dcache_align();
  } else if( FD_UNLIKELY( !strcmp( obj->name, "cnc" ) ) ) {
    return fd_cnc_align();
  } else if( FD_UNLIKELY( !strcmp( obj->name, "fseq" ) ) ) {
    return fd_fseq_align();
  } else if( FD_UNLIKELY( !strcmp( obj->name, "metrics" ) ) ) {
    return FD_METRICS_ALIGN;
  } else if( FD_UNLIKELY( !strcmp( obj->name, "opaque" ) ) ) {
    ulong align = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.align", obj->id );
    if( FD_UNLIKELY( align==ULONG_MAX ) ) FD_LOG_ERR(( "obj.%lu.align was not set", obj->id ));
    return align;
  } else if( FD_UNLIKELY( !strcmp( obj->name, "dbl_buf" ) ) ) {
    return fd_dbl_buf_align();
  } else if( FD_UNLIKELY( !strcmp( obj->name, "funk" ) ) ) {
    return fd_funk_align();
  } else if( FD_UNLIKELY( !strcmp( obj->name, "neigh4_hmap" ) ) ) {
    return fd_neigh4_hmap_align();
  } else if( FD_UNLIKELY( !strcmp( obj->name, "fib4" ) ) ) {
    return fd_fib4_align();
  } else if( FD_UNLIKELY( !strcmp( obj->name, "keyswitch" ) ) ) {
    return fd_keyswitch_align();
#if FD_HAS_NO_AGAVE
  } else if( FD_UNLIKELY( !strcmp( obj->name, "replay_pub" ) ) ) {
    return fd_runtime_public_align();
  } else if( FD_UNLIKELY( !strcmp( obj->name, "blockstore" ) ) ) {
    return fd_blockstore_align();
  } else if( FD_UNLIKELY( !strcmp( obj->name, "txncache" ) ) ) {
    return fd_txncache_align();
#endif /* FD_HAS_NO_AGAVE */
  } else {
    FD_LOG_ERR(( "unknown object `%s`", obj->name ));
    return 0UL;
  }
}

ulong
fdctl_obj_footprint( fd_topo_t const *     topo,
                     fd_topo_obj_t const * obj ) {
  #define VAL(name) (__extension__({                                                               \
      ulong __x = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.%s", obj->id, name );      \
      if( FD_UNLIKELY( __x==ULONG_MAX ) ) FD_LOG_ERR(( "obj.%lu.%s was not set", obj->id, name )); \
      __x; }))

  if( FD_UNLIKELY( !strcmp( obj->name, "tile" ) ) ) {
    fd_topo_tile_t const * tile = NULL;
    for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
      if( FD_LIKELY( topo->tiles[ i ].tile_obj_id==obj->id ) ) {
        tile = &topo->tiles[ i ];
        break;
      }
    }
    fd_topo_run_tile_t * config = fd_topo_tile_to_config( tile );
    if( FD_LIKELY( config->scratch_footprint ) ) return config->scratch_footprint( tile );
    return 0UL;
  } else if( FD_UNLIKELY( !strcmp( obj->name, "mcache" ) ) ) {
    return fd_mcache_footprint( VAL("depth"), 0UL );
  } else if( FD_UNLIKELY( !strcmp( obj->name, "dcache" ) ) ) {
    return fd_dcache_footprint( fd_dcache_req_data_sz( VAL("mtu"), VAL("depth"), VAL("burst"), 1), 0UL );
  } else if( FD_UNLIKELY( !strcmp( obj->name, "cnc" ) ) ) {
    return fd_cnc_footprint( 0UL );
  } else if( FD_UNLIKELY( !strcmp( obj->name, "fseq" ) ) ) {
    return fd_fseq_footprint();
  } else if( FD_UNLIKELY( !strcmp( obj->name, "metrics" ) ) ) {
    return FD_METRICS_FOOTPRINT( VAL("in_cnt"), VAL("cons_cnt") );
  } else if( FD_UNLIKELY( !strcmp( obj->name, "opaque" ) ) ) {
    return VAL("footprint");
  } else if( FD_UNLIKELY( !strcmp( obj->name, "dbl_buf" ) ) ) {
    return fd_dbl_buf_footprint( VAL("mtu") );
  } else if( FD_UNLIKELY( !strcmp( obj->name, "funk" ) ) ) {
    return fd_funk_footprint();
  } else if( FD_UNLIKELY( !strcmp( obj->name, "neigh4_hmap" ) ) ) {
    return fd_neigh4_hmap_footprint( VAL("ele_max"), VAL("lock_cnt"), VAL("probe_max") );
  } else if( FD_UNLIKELY( !strcmp( obj->name, "fib4" ) ) ) {
    return fd_fib4_footprint( VAL("route_max") );
  } else if( FD_UNLIKELY( !strcmp( obj->name, "keyswitch" ) ) ) {
    return fd_keyswitch_footprint();
#if FD_HAS_NO_AGAVE
  } else if( FD_UNLIKELY( !strcmp( obj->name, "replay_pub" ) ) ) {
    return fd_runtime_public_footprint();
  } else if( FD_UNLIKELY( !strcmp( obj->name, "blockstore" ) ) ) {
    return fd_blockstore_footprint( VAL("shred_max"), VAL("block_max"), VAL("idx_max"), VAL("txn_max") ) + VAL("alloc_max");
  } else if( FD_UNLIKELY( !strcmp( obj->name, "txncache" ) ) ) {
    return fd_txncache_footprint( VAL("max_rooted_slots"), VAL("max_live_slots"), VAL("max_txn_per_slot"), FD_TXNCACHE_DEFAULT_MAX_CONSTIPATED_SLOTS );
#endif /* FD_HAS_NO_AGAVE */
  } else {
    FD_LOG_ERR(( "unknown object `%s`", obj->name ));
    return 0UL;
  }
#undef VAL
}

ulong
fdctl_obj_loose( fd_topo_t const *     topo,
                 fd_topo_obj_t const * obj ) {
  ulong loose = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.%s", obj->id, "loose" );
  if( loose!=ULONG_MAX ) {
    return loose;
  }

  if( FD_UNLIKELY( !strcmp( obj->name, "tile" ) ) ) {
    fd_topo_tile_t const * tile = NULL;
    for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
      if( FD_LIKELY( topo->tiles[ i ].tile_obj_id==obj->id ) ) {
        tile = &topo->tiles[ i ];
        break;
      }
    }
    fd_topo_run_tile_t * config = fd_topo_tile_to_config( tile );
    if( FD_LIKELY( config->loose_footprint ) ) return config->loose_footprint( tile );
  }
  return 0UL;
}

fd_topo_run_tile_t
fdctl_tile_run( fd_topo_tile_t * tile ) {
  return *fd_topo_tile_to_config( tile );
}


static void
validate_ports( config_t * result ) {
  char dynamic_port_range[ 32 ];
  fd_memcpy( dynamic_port_range, result->dynamic_port_range, sizeof(dynamic_port_range) );

  char * dash = strstr( dynamic_port_range, "-" );
  if( FD_UNLIKELY( !dash ) )
    FD_LOG_ERR(( "configuration specifies invalid [dynamic_port_range] `%s`. "
                 "This must be formatted like `<min>-<max>`",
                 result->dynamic_port_range ));

  *dash = '\0';
  char * endptr;
  ulong agave_port_min = strtoul( dynamic_port_range, &endptr, 10 );
  if( FD_UNLIKELY( *endptr != '\0' || agave_port_min > USHORT_MAX ) )
    FD_LOG_ERR(( "configuration specifies invalid [dynamic_port_range] `%s`. "
                 "This must be formatted like `<min>-<max>`",
                 result->dynamic_port_range ));
  ulong agave_port_max = strtoul( dash + 1, &endptr, 10 );
  if( FD_UNLIKELY( *endptr != '\0' || agave_port_max > USHORT_MAX ) )
    FD_LOG_ERR(( "configuration specifies invalid [dynamic_port_range] `%s`. "
                 "This must be formatted like `<min>-<max>`",
                 result->dynamic_port_range ));
  if( FD_UNLIKELY( agave_port_min > agave_port_max ) )
    FD_LOG_ERR(( "configuration specifies invalid [dynamic_port_range] `%s`. "
                 "The minimum port must be less than or equal to the maximum port",
                 result->dynamic_port_range ));

  if( FD_UNLIKELY( result->tiles.quic.regular_transaction_listen_port >= agave_port_min &&
                   result->tiles.quic.regular_transaction_listen_port < agave_port_max ) )
    FD_LOG_ERR(( "configuration specifies invalid [tiles.quic.transaction_listen_port] `%hu`. "
                 "This must be outside the dynamic port range `%s`",
                 result->tiles.quic.regular_transaction_listen_port,
                 result->dynamic_port_range ));

  if( FD_UNLIKELY( result->tiles.quic.quic_transaction_listen_port >= agave_port_min &&
                   result->tiles.quic.quic_transaction_listen_port < agave_port_max ) )
    FD_LOG_ERR(( "configuration specifies invalid [tiles.quic.quic_transaction_listen_port] `%hu`. "
                 "This must be outside the dynamic port range `%s`",
                 result->tiles.quic.quic_transaction_listen_port,
                 result->dynamic_port_range ));

  if( FD_UNLIKELY( result->tiles.shred.shred_listen_port >= agave_port_min &&
                   result->tiles.shred.shred_listen_port < agave_port_max ) )
    FD_LOG_ERR(( "configuration specifies invalid [tiles.shred.shred_listen_port] `%hu`. "
                 "This must be outside the dynamic port range `%s`",
                 result->tiles.shred.shred_listen_port,
                 result->dynamic_port_range ));
}

FD_FN_CONST static int
parse_log_level( char const * level ) {
  if( FD_UNLIKELY( !strcmp( level, "DEBUG" ) ) )    return 0;
  if( FD_UNLIKELY( !strcmp( level, "INFO"  ) ) )    return 1;
  if( FD_UNLIKELY( !strcmp( level, "NOTICE"  ) ) )  return 2;
  if( FD_UNLIKELY( !strcmp( level, "WARNING"  ) ) ) return 3;
  if( FD_UNLIKELY( !strcmp( level, "ERR" ) ) )      return 4;
  if( FD_UNLIKELY( !strcmp( level, "CRIT" ) ) )     return 5;
  if( FD_UNLIKELY( !strcmp( level, "ALERT" ) ) )    return 6;
  if( FD_UNLIKELY( !strcmp( level, "EMERG" ) ) )    return 7;
  return -1;
}

static char *
default_user( void ) {
  char * name = getenv( "SUDO_USER" );
  if( FD_UNLIKELY( name ) ) return name;

  name = getenv( "LOGNAME" );
  if( FD_LIKELY( name ) ) return name;

  name = getenv( "USER" );
  if( FD_LIKELY( name ) ) return name;

  name = getenv( "LNAME" );
  if( FD_LIKELY( name ) ) return name;

  name = getenv( "USERNAME" );
  if( FD_LIKELY( name ) ) return name;

  name = getlogin();
  if( FD_UNLIKELY( !name && (errno==ENXIO || errno==ENOTTY) ) ) return NULL;
  else if( FD_UNLIKELY( !name ) ) FD_LOG_ERR(( "getlogin failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  return name;
}

void
fdctl_cfg_from_env( int *      pargc,
                    char ***   pargv,
                    config_t * config ) {

  memset( config, 0, sizeof(config_t) );
#if FD_HAS_NO_AGAVE
  static uchar pod_mem1[ FD_TOML_POD_SZ ];
  static uchar pod_mem2[ FD_TOML_POD_SZ ];
  uchar * pod1 = fd_pod_join( fd_pod_new( pod_mem1, sizeof(pod_mem1) ) );
  uchar * pod2 = fd_pod_join( fd_pod_new( pod_mem2, sizeof(pod_mem2) ) );

  uchar scratch[ 4096 ];
  int toml_err = fd_toml_parse( fdctl_default_config, fdctl_default_config_sz, pod1, scratch, sizeof(scratch), NULL );
  if( FD_UNLIKELY( toml_err!=FD_TOML_SUCCESS ) ) FD_LOG_ERR(( "Invalid config (%s)", "default.toml" ));
  toml_err = fd_toml_parse( fdctl_default_firedancer_config, fdctl_default_firedancer_config_sz, pod2, scratch, sizeof(scratch), NULL );
  if( FD_UNLIKELY( toml_err!=FD_TOML_SUCCESS ) ) FD_LOG_ERR(( "Invalid config (%s)", "default-firedancer.toml" ));

  if( FD_UNLIKELY( !fdctl_pod_to_cfg( config, pod1 ) ) ) FD_LOG_ERR(( "Invalid config (%s)", "default.toml" ));
  if( FD_UNLIKELY( !fdctl_pod_to_cfg( config, pod2 ) ) ) FD_LOG_ERR(( "Invalid config (%s)", "default-firedancer.toml" ));
  fd_pod_delete( fd_pod_leave( pod1 ) );
  fd_pod_delete( fd_pod_leave( pod2 ) );
#else
  fdctl_cfg_load_buf( config, (char const *)fdctl_default_config, fdctl_default_config_sz, "default" );
#endif

  const char * user_config = fd_env_strip_cmdline_cstr(
      pargc,
      pargv,
      "--config",
      "FIREDANCER_CONFIG_TOML",
      NULL );

  if( FD_LIKELY( user_config ) ) {
    fdctl_cfg_load_file( config, user_config );
  }

  int netns = fd_env_strip_cmdline_contains( pargc, pargv, "--netns" );
  if( FD_UNLIKELY( netns ) ) {
    config->development.netns.enabled = 1;
    strncpy( config->tiles.net.interface,
             config->development.netns.interface0,
             sizeof(config->tiles.net.interface) );
    config->tiles.net.interface[ sizeof(config->tiles.net.interface) - 1 ] = '\0';
  }

  if( FD_UNLIKELY( !strcmp( config->user, "" ) ) ) {
    const char * user = default_user();
    if( FD_UNLIKELY( !user ) ) FD_LOG_ERR(( "could not automatically determine a user to run Firedancer as. You must specify a [user] in your configuration TOML file." ));
    if( FD_UNLIKELY( strlen( user ) >= sizeof( config->user ) ) )
                              FD_LOG_ERR(( "user name `%s` is too long", user ));
    strncpy( config->user, user, 256 );
  }

  struct utsname utsname;
  if( FD_UNLIKELY( -1==uname( &utsname ) ) )
    FD_LOG_ERR(( "could not get uname (%i-%s)", errno, fd_io_strerror( errno ) ));
  strncpy( config->hostname, utsname.nodename, sizeof(config->hostname) );
  config->hostname[ sizeof(config->hostname)-1UL ] = '\0'; /* Just truncate the name if it's too long to fit */

  if( FD_UNLIKELY( !strcmp( config->tiles.net.interface, "" ) && !config->development.netns.enabled ) ) {
    uint ifindex;
    int result = fd_net_util_internet_ifindex( &ifindex );
    if( FD_UNLIKELY( -1==result && errno!=ENODEV ) ) FD_LOG_ERR(( "could not get network device index (%i-%s)", errno, fd_io_strerror( errno ) ));
    else if( FD_UNLIKELY( -1==result ) )
      FD_LOG_ERR(( "no network device found which routes to 8.8.8.8. If no network "
                   "interface is specified in the configuration file, Firedancer "
                   "tries to use the first network interface found which routes to "
                   "8.8.8.8. You can see what this is by running `ip route get 8.8.8.8` "
                   "You can fix this error by specifying a network interface to bind to in "
                   "your configuration file under [net.interface]" ));

    if( FD_UNLIKELY( !if_indextoname( ifindex, config->tiles.net.interface ) ) )
      FD_LOG_ERR(( "could not get name of interface with index %u", ifindex ));
  }

  ulong cluster = fd_genesis_cluster_identify( config->consensus.expected_genesis_hash );
  config->is_live_cluster = cluster != FD_CLUSTER_UNKNOWN;

  if( FD_UNLIKELY( config->development.netns.enabled ) ) {
    if( !strcmp( config->tiles.net.interface, "" ) ) {
      memcpy( config->tiles.net.interface, config->development.netns.interface0, sizeof(config->tiles.net.interface) );
    }

    if( !strcmp( config->development.pktgen.fake_dst_ip, "" ) ) {
      memcpy( config->development.pktgen.fake_dst_ip, config->development.netns.interface1_addr, sizeof(config->development.netns.interface1_addr) );
    }

    if( FD_UNLIKELY( strcmp( config->development.netns.interface0, config->tiles.net.interface ) ) ) {
      FD_LOG_ERR(( "netns interface and firedancer interface are different. If you are using the "
                   "[development.netns] functionality to run Firedancer in a network namespace "
                   "for development, the configuration file must specify that "
                   "[development.netns.interface0] is the same as [tiles.net.interface]" ));
    }

    if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( config->development.netns.interface0_addr, &config->tiles.net.ip_addr ) ) )
      FD_LOG_ERR(( "configuration specifies invalid netns IP address `%s`", config->development.netns.interface0_addr ));
  } else {
    if( FD_UNLIKELY( !if_nametoindex( config->tiles.net.interface ) ) )
      FD_LOG_ERR(( "configuration specifies network interface `%s` which does not exist", config->tiles.net.interface ));
    uint iface_ip = listen_address( config->tiles.net.interface );
    if( FD_UNLIKELY( strcmp( config->gossip.host, "" ) ) ) {
      uint gossip_ip_addr = iface_ip;
      int  has_gossip_ip4 = 0;
      if( FD_UNLIKELY( strlen( config->gossip.host )<=15UL ) ) {
        /* Only sets gossip_ip_addr if it's a valid IPv4 address, otherwise assume it's a DNS name */
        has_gossip_ip4 = fd_cstr_to_ip4_addr( config->gossip.host, &gossip_ip_addr );
      }
      if ( FD_UNLIKELY( !fd_ip4_addr_is_public( gossip_ip_addr ) && config->is_live_cluster && has_gossip_ip4 ) )
        FD_LOG_ERR(( "Trying to use [gossip.host] " FD_IP4_ADDR_FMT " for listening to incoming "
                     "transactions, but it is part of a private network and will not be routable "
                     "for other Solana network nodes.",
                     FD_IP4_ADDR_FMT_ARGS( iface_ip ) ));
    } else if ( FD_UNLIKELY( !fd_ip4_addr_is_public( iface_ip ) && config->is_live_cluster ) ) {
      FD_LOG_ERR(( "Trying to use network interface `%s` for listening to incoming transactions, "
                   "but it has IPv4 address " FD_IP4_ADDR_FMT " which is part of a private network "
                   "and will not be routable for other Solana network nodes. If you are running "
                   "behind a NAT and this interface is publicly reachable, you can continue by "
                   "manually specifying the IP address to advertise in your configuration under "
                   "[gossip.host].",
                   config->tiles.net.interface, FD_IP4_ADDR_FMT_ARGS( iface_ip ) ));
    }

    config->tiles.net.ip_addr = iface_ip;

  }

  username_to_id( config );

  if( config->uid == 0 || config->gid == 0 )
    FD_LOG_ERR(( "firedancer cannot run as root. please specify a non-root user in the configuration file" ));

  if( FD_UNLIKELY( getuid() != 0 && config->uid != getuid() ) )
    FD_LOG_ERR(( "running as uid %u, but config specifies uid %u", getuid(), config->uid ));
  if( FD_UNLIKELY( getgid() != 0 && config->gid != getgid() ) )
    FD_LOG_ERR(( "running as gid %u, but config specifies gid %u", getgid(), config->gid ));

  ulong len = strlen( config->hugetlbfs.mount_path );
  if( FD_UNLIKELY( !len ) ) FD_LOG_ERR(( "[hugetlbfs.mount_path] must be non-empty in your configuration file" ));
  FD_TEST( fd_cstr_printf_check( config->hugetlbfs.gigantic_page_mount_path,
                                 sizeof(config->hugetlbfs.gigantic_page_mount_path),
                                 NULL,
                                 "%s/.gigantic",
                                 config->hugetlbfs.mount_path ) );
  FD_TEST( fd_cstr_printf_check( config->hugetlbfs.huge_page_mount_path,
                                 sizeof(config->hugetlbfs.huge_page_mount_path),
                                 NULL,
                                 "%s/.huge",
                                 config->hugetlbfs.mount_path ) );

  ulong max_page_sz = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );
  if( FD_UNLIKELY( max_page_sz!=FD_SHMEM_HUGE_PAGE_SZ && max_page_sz!=FD_SHMEM_GIGANTIC_PAGE_SZ ) ) {
    FD_LOG_ERR(( "[hugetlbfs.max_page_size] must be \"huge\" or \"gigantic\"" ));
  }

  replace( config->log.path, "{user}", config->user );
  replace( config->log.path, "{name}", config->name );
  if( FD_LIKELY( !strcmp( "auto", config->log.colorize ) ) )       config->log.colorize1 = 2;
  else if( FD_LIKELY( !strcmp( "true", config->log.colorize ) ) )  config->log.colorize1 = 1;
  else if( FD_LIKELY( !strcmp( "false", config->log.colorize ) ) ) config->log.colorize1 = 0;
  else FD_LOG_ERR(( "[log.colorize] must be one of \"auto\", \"true\", or \"false\"" ));

  if( FD_LIKELY( 2==config->log.colorize1 ) ) {
    char const * cstr = fd_env_strip_cmdline_cstr( NULL, NULL, NULL, "COLORTERM", NULL );
    int truecolor = cstr && !strcmp( cstr, "truecolor" );

    cstr = fd_env_strip_cmdline_cstr( NULL, NULL, NULL, "TERM", NULL );
    int xterm256color = cstr && !strcmp( cstr, "xterm-256color" );

    config->log.colorize1 = truecolor || xterm256color;
  }

  config->log.level_logfile1 = parse_log_level( config->log.level_logfile );
  config->log.level_stderr1  = parse_log_level( config->log.level_stderr );
  config->log.level_flush1   = parse_log_level( config->log.level_flush );
  if( FD_UNLIKELY( -1==config->log.level_logfile1 ) ) FD_LOG_ERR(( "unrecognized [log.level_logfile] `%s`", config->log.level_logfile ));
  if( FD_UNLIKELY( -1==config->log.level_stderr1 ) )  FD_LOG_ERR(( "unrecognized [log.level_stderr] `%s`", config->log.level_logfile ));
  if( FD_UNLIKELY( -1==config->log.level_flush1 ) )   FD_LOG_ERR(( "unrecognized [log.level_flush] `%s`", config->log.level_logfile ));

  replace( config->scratch_directory, "{user}", config->user );
  replace( config->scratch_directory, "{name}", config->name );

  if( FD_UNLIKELY( strcmp( config->ledger.path, "" ) ) ) {
    replace( config->ledger.path, "{user}", config->user );
    replace( config->ledger.path, "{name}", config->name );
  } else {
    FD_TEST( fd_cstr_printf_check( config->ledger.path, sizeof(config->ledger.path), NULL, "%s/ledger", config->scratch_directory ) );
  }

  if( FD_UNLIKELY( strcmp( config->snapshots.path, "" ) ) ) {
    replace( config->snapshots.path, "{user}", config->user );
    replace( config->snapshots.path, "{name}", config->name );
  } else {
    strncpy( config->snapshots.path, config->ledger.path, sizeof(config->snapshots.path) );
  }

  if( FD_UNLIKELY( !strcmp( config->consensus.identity_path, "" ) ) ) {
    FD_TEST( fd_cstr_printf_check( config->consensus.identity_path,
                                   sizeof(config->consensus.identity_path),
                                   NULL,
                                   "%s/identity.json",
                                   config->scratch_directory ) );
  } else {
    replace( config->consensus.identity_path, "{user}", config->user );
    replace( config->consensus.identity_path, "{name}", config->name );
  }

#if FD_HAS_NO_AGAVE
  if( FD_UNLIKELY( !strcmp( config->consensus.vote_account_path, "" ) ) ) {
    FD_TEST( fd_cstr_printf_check( config->consensus.vote_account_path,
                                   sizeof(config->consensus.vote_account_path),
                                   NULL,
                                   "%s/vote-account.json",
                                   config->scratch_directory ) );
  }
#endif
  replace( config->consensus.vote_account_path, "{user}", config->user );
  replace( config->consensus.vote_account_path, "{name}", config->name );

  for( ulong i=0UL; i<config->consensus.authorized_voter_paths_cnt; i++ ) {
    replace( config->consensus.authorized_voter_paths[ i ], "{user}", config->user );
    replace( config->consensus.authorized_voter_paths[ i ], "{name}", config->name );
  }

  strcpy( config->cluster, fd_genesis_cluster_name( cluster ) );

#if FD_HAS_NO_AGAVE
  if( FD_UNLIKELY( config->is_live_cluster && cluster!=FD_CLUSTER_TESTNET ) )
    FD_LOG_ERR(( "Attempted to start against live cluster `%s`. Firedancer is not "
                 "ready for production deployment, has not been tested, and is "
                 "missing consensus critical functionality. Joining a live Solana "
                 "cluster may destabilize the network. Please do not attempt. You "
                 "can start against the testnet cluster by specifying the testnet "
                 "entrypoints from https://docs.solana.com/clusters under "
                 "[gossip.entrypoints] in your configuration file.", fd_genesis_cluster_name( cluster ) ));
#endif /* FD_HAS_NO_AGAVE */

  if( FD_LIKELY( config->is_live_cluster) ) {
    if( FD_UNLIKELY( !config->development.sandbox ) )
      FD_LOG_ERR(( "trying to join a live cluster, but configuration disables the sandbox which is a a development only feature" ));
    if( FD_UNLIKELY( config->development.no_clone ) )
      FD_LOG_ERR(( "trying to join a live cluster, but configuration disables multiprocess which is a development only feature" ));
    if( FD_UNLIKELY( config->development.netns.enabled ) )
      FD_LOG_ERR(( "trying to join a live cluster, but configuration enables [development.netns] which is a development only feature" ));
    if( FD_UNLIKELY( config->development.bench.larger_max_cost_per_block ) )
      FD_LOG_ERR(( "trying to join a live cluster, but configuration enables [development.bench.larger_max_cost_per_block] which is a development only feature" ));
    if( FD_UNLIKELY( config->development.bench.larger_shred_limits_per_block ) )
      FD_LOG_ERR(( "trying to join a live cluster, but configuration enables [development.bench.larger_shred_limits_per_block] which is a development only feature" ));
    if( FD_UNLIKELY( config->development.bench.disable_blockstore_from_slot ) )
      FD_LOG_ERR(( "trying to join a live cluster, but configuration has a non-zero value for [development.bench.disable_blockstore_from_slot] which is a development only feature" ));
    if( FD_UNLIKELY( config->development.bench.disable_status_cache ) )
      FD_LOG_ERR(( "trying to join a live cluster, but configuration enables [development.bench.disable_status_cache] which is a development only feature" ));
  }

  if( FD_UNLIKELY( config->tiles.quic.quic_transaction_listen_port != config->tiles.quic.regular_transaction_listen_port + 6 ) )
    FD_LOG_ERR(( "configuration specifies invalid [tiles.quic.quic_transaction_listen_port] `%hu`. "
                 "This must be 6 more than [tiles.quic.regular_transaction_listen_port] `%hu`",
                 config->tiles.quic.quic_transaction_listen_port,
                 config->tiles.quic.regular_transaction_listen_port ));

  if( FD_LIKELY( !strcmp( config->consensus.identity_path, "" ) ) ) {
    if( FD_UNLIKELY( config->is_live_cluster ) )
      FD_LOG_ERR(( "configuration file must specify [consensus.identity_path] when joining a live cluster" ));

    FD_TEST( fd_cstr_printf_check( config->consensus.identity_path,
                                   sizeof(config->consensus.identity_path),
                                   NULL,
                                   "%s/identity.json",
                                   config->scratch_directory ) );
  }

  fdctl_cfg_validate( config );
  validate_ports( config );
  fd_topo_initialize( config );
}

int
fdctl_cfg_to_memfd( config_t * config ) {
  int config_memfd = memfd_create( "fd_config", 0 );
  if( FD_UNLIKELY( -1==config_memfd ) ) FD_LOG_ERR(( "memfd_create() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( -1==ftruncate( config_memfd, sizeof( config_t ) ) ) ) FD_LOG_ERR(( "ftruncate() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  uchar * bytes = mmap( NULL, sizeof( config_t ), PROT_READ | PROT_WRITE, MAP_SHARED, config_memfd, 0 );
  if( FD_UNLIKELY( bytes == MAP_FAILED ) ) FD_LOG_ERR(( "mmap() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  fd_memcpy( bytes, config, sizeof( config_t ) );
  if( FD_UNLIKELY( munmap( bytes, sizeof( config_t ) ) ) ) FD_LOG_ERR(( "munmap() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  return config_memfd;
}
