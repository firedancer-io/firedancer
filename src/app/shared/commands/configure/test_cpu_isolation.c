/* Exercise real configure paths against requested/effective mask semantics.
   No host sysfs/cgroup writes. */
#include "configure.h"
#include "fd_cpu_isolation.h"
#include "../../../../disco/topo/fd_cpu_topo.h"
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

static config_t config[1];
static args_t args[1];
static jmp_buf failure;
static int expect_failure;
static char error_message[8192];
static uint effective, requested, partition_cpus;
static int present, isolated, populated, requested_missing, fail_write;
static int root_partition;
static int writes, migrations, removals;
char const * FD_BINARY_NAME = "test_cpu_isolation";
char const * FD_APP_NAME = "test_cpu_isolation";
action_t * ACTIONS[] = { NULL };
fd_topo_run_tile_t * TILES[] = { NULL };

static void __attribute__((noreturn))
test_error( char const * fmt, ... ) {
  va_list ap;
  va_start( ap, fmt );
  vsnprintf( error_message, sizeof(error_message), fmt, ap );
  va_end( ap );
  if( expect_failure ) longjmp( failure, 1 );
  FD_LOG_EMERG(( "unexpected error: %s", error_message ));
}

enum { MASK=100, REQUESTED, ISOLATED, CONTROLLERS, CPUS, PARTITION, SUBTREE };
static int
test_open( char const * path, int flags, ... ) {
  (void)flags;
  if( !strcmp( path, FD_CPU_ISOLATION_WQ_MASK_PATH ) ) return MASK;
  if( !strcmp( path, FD_CPU_ISOLATION_WQ_MASK_PATH "_requested" ) ) {
    if( requested_missing ) { errno=ENOENT; return -1; }
    return REQUESTED;
  }
  if( !strcmp( path, FD_CPU_ISOLATION_WQ_MASK_PATH "_isolated" ) ) return ISOLATED;
  if( !strcmp( path, "/sys/fs/cgroup/cgroup.controllers" ) ) return CONTROLLERS;
  if( !strcmp( path, "/sys/fs/cgroup/cgroup.subtree_control" ) ) return SUBTREE;
  if( !present ) { errno=ENOENT; return -1; }
  if( !strcmp( path, "/sys/fs/cgroup/test/cpuset.cpus" ) ) return CPUS;
  if( !strcmp( path, "/sys/fs/cgroup/test/cpuset.cpus.partition" ) ) return PARTITION;
  FD_LOG_EMERG(( "unexpected open: %s", path ));
}
static int
test_access( char const * path, int mode ) {
  (void)mode;
  if( !strcmp( path, FD_CPU_ISOLATION_WQ_MASK_PATH ) ) return 0;
  FD_TEST( !strcmp( path, "/sys/fs/cgroup/test" ) );
  if( present ) return 0;
  errno=ENOENT; return -1;
}
static long
test_read( int fd, void * buf, ulong size ) {
  char text[256];
  switch( fd ) {
    case MASK:        snprintf( text, sizeof(text), "%08x\n", effective ); break;
    case REQUESTED:   snprintf( text, sizeof(text), "%08x\n", requested ); break;
    case ISOLATED:    snprintf( text, sizeof(text), "%08x\n", isolated ? partition_cpus : 0U ); break;
    case CONTROLLERS: strcpy( text, "cpuset memory\n" ); break;
    case PARTITION:   strcpy( text, isolated ? "isolated\n" : root_partition ? "root\n" : "member\n" ); break;
    case CPUS: {
      FD_CPUSET_DECL( cpus ); fd_cpuset_new( cpus );
      for( ulong i=0; i<8UL; i++ ) if( partition_cpus & (1U<<i) ) fd_cpuset_insert( cpus, i );
      fd_cpu_isolation_format_list( text, sizeof(text), cpus );
      break;
    }
    default: FD_LOG_EMERG(( "unexpected read fd %d", fd ));
  }
  ulong n=strlen( text ); FD_TEST( n<size );
  memcpy( buf, text, n ); return (long)n;
}
static void
set_effective( uint mask ) {
  if( mask!=effective ) migrations++;
  effective=mask;
}
static void
apply_partition( void ) {
  uint mask = requested & ~(isolated ? partition_cpus : 0U);
  set_effective( mask ? mask : requested );
}
static long
test_write( int fd, void const * buf, ulong size ) {
  char text[4096]; FD_TEST( size<sizeof(text) );
  memcpy( text, buf, size ); text[size]='\0';
  writes++;
  if( fail_write ) { errno=EIO; return -1; }
  switch( fd ) {
    case MASK:
      /* Equal effective mask skips migration but still updates requested. */
      requested=(uint)strtoul( text, NULL, 16 ); set_effective( requested ); break;
    case CPUS: {
      FD_CPUSET_DECL( cpus ); FD_TEST( fd_cpu_isolation_parse_list( cpus, text ) );
      partition_cpus=0U;
      for( ulong i=0; i<8UL; i++ ) if( fd_cpuset_test( cpus, i ) ) partition_cpus |= 1U<<i;
      apply_partition(); break;
    }
    case PARTITION:
      isolated=!strcmp( text, "isolated" ); root_partition=!strcmp( text, "root" );
      apply_partition(); break;
    case SUBTREE: break;
    default: FD_LOG_EMERG(( "unexpected write fd %d", fd ));
  }
  return (long)size;
}
static int
test_close( int fd ) { (void)fd; return 0; }
static int
test_mkdir( char const * path, mode_t mode ) {
  FD_TEST( !strcmp( path, "/sys/fs/cgroup/test" ) && mode==0755 ); present=1; return 0;
}
static int
test_rmdir( char const * path ) {
  FD_TEST( !strcmp( path, "/sys/fs/cgroup/test" ) );
  if( populated ) { errno=EBUSY; return -1; }
  present=isolated=root_partition=0; removals++; apply_partition(); return 0;
}
static ulong
test_cpu_cnt( void ) { return 8UL; }
static void
test_cpu_topo( fd_topo_cpus_t * cpus ) {
  memset( cpus, 0, sizeof(*cpus) ); cpus->cpu_cnt=8UL;
  for( ulong i=0; i<8UL; i++ ) { cpus->cpu[i].online=1; cpus->cpu[i].sibling=i^4UL; }
}

#undef FD_LOG_ERR
#define FD_LOG_ERR(args) test_error args
#define open test_open
#define access test_access
#define read test_read
#define write test_write
#define close test_close
#define mkdir test_mkdir
#define rmdir test_rmdir
#define fd_shmem_cpu_cnt test_cpu_cnt
#define fd_topo_cpus_init test_cpu_topo
#include "fd_cpu_isolation.c"
#include "kworkers.c"
#include "cpuset.c"
#include "configure.c"

configure_stage_t * STAGES[] = { &fd_cfg_stage_kworkers, &fd_cfg_stage_cpuset, NULL };
static void
reset( void ) {
  memset( config, 0, sizeof(*config) ); memset( args, 0, sizeof(*args) );
  strcpy( config->name, "test" ); config->topo.tile_cnt=1;
  strcpy( config->topo.tiles[0].name, "net" ); config->topo.tiles[0].cpu_idx=1;
  effective=0xfdU; requested=0xffU; partition_cpus=2U;
  present=isolated=1; populated=requested_missing=fail_write=0;
  root_partition=0;
  writes=migrations=removals=0;
  args->configure.stages[0]=&fd_cfg_stage_kworkers;
  args->configure.stages[1]=&fd_cfg_stage_cpuset;
}
static void
command( int cmd ) {
  args->configure.command=cmd; configure_cmd_fn( args, config );
  FD_TEST( !migrations );
}
static void
refused( int cmd, char const * message ) {
  expect_failure=1;
  if( !setjmp( failure ) ) { command( cmd ); FD_LOG_EMERG(( "command should have failed" )); }
  expect_failure=0;
  FD_TEST( strstr( error_message, message ) ); FD_TEST( !migrations );
}
int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  /* fini all runs cpuset before kworkers: preserve BEFORE downgrade. */
  reset(); command( CONFIGURE_CMD_FINI );
  FD_TEST( !present && removals==1 && requested==0xfdU && effective==0xfdU );
  command( CONFIGURE_CMD_INIT ); FD_TEST( present && isolated && effective==0xfdU );
  int saved_writes=writes; command( CONFIGURE_CMD_INIT ); FD_TEST( writes==saved_writes );

  /* Standalone teardown and reverse stage ordering also leave E fixed. */
  reset(); args->configure.stages[0]=&fd_cfg_stage_cpuset; args->configure.stages[1]=NULL;
  command( CONFIGURE_CMD_FINI ); FD_TEST( !present && requested==0xfdU );
  reset(); args->configure.stages[0]=&fd_cfg_stage_kworkers; args->configure.stages[1]=NULL;
  command( CONFIGURE_CMD_FINI ); FD_TEST( !writes && present && effective==0xfdU );
  reset(); args->configure.stages[0]=&fd_cfg_stage_cpuset; args->configure.stages[1]=&fd_cfg_stage_kworkers;
  command( CONFIGURE_CMD_FINI ); FD_TEST( !present && effective==0xfdU && requested==0xfdU );

  /* Compatible stale partition: implicit fini then init does not migrate. */
  reset(); effective=0xf9U; partition_cpus=6U; command( CONFIGURE_CMD_INIT );
  FD_TEST( removals==1 && partition_cpus==2U && requested==0xf9U && effective==0xf9U );

  /* New tile CPUs are refused by kworkers before its mask write. */
  reset(); config->topo.tiles[0].cpu_idx=2; refused( CONFIGURE_CMD_INIT, "would move" );
  FD_TEST( !writes && !removals );
  /* New SMT siblings are refused locally by cpuset, after normal cleanup. */
  reset(); strcpy( config->topo.tiles[0].name, "pack" ); refused( CONFIGURE_CMD_INIT, "would move" );
  FD_TEST( removals==1 && !present && effective==0xfdU );

  /* First setup cannot narrow the mask live either, including cpuset alone. */
  reset(); present=isolated=0; effective=requested=0xffU;
  refused( CONFIGURE_CMD_INIT, "workqueue.unbound_cpus" ); FD_TEST( !writes );
  args->configure.stages[0]=&fd_cfg_stage_cpuset; args->configure.stages[1]=NULL;
  refused( CONFIGURE_CMD_INIT, "workqueue.unbound_cpus" ); FD_TEST( !writes );

  /* Existing busy-cgroup behavior is unchanged, but E cannot expand. */
  reset(); populated=1; refused( CONFIGURE_CMD_FINI, "Stop the validator" );
  FD_TEST( present && !isolated && !removals && requested==effective );
  reset(); requested_missing=1; refused( CONFIGURE_CMD_FINI, "cpumask_requested" );
  FD_TEST( !writes && present && isolated );
  reset(); fail_write=1; refused( CONFIGURE_CMD_FINI, "write(" );
  FD_TEST( present && isolated && !removals );
  reset(); effective=requested=0xffU;
  refused( CONFIGURE_CMD_FINI, "overlaps existing isolated" ); FD_TEST( !writes && !removals );

  /* Switching to root mode also preserves the old workqueue exclusion. */
  reset(); config->topo.tiles[0].floats=1; command( CONFIGURE_CMD_INIT );
  FD_TEST( present && root_partition && !isolated && effective==0xfdU );
  command( CONFIGURE_CMD_FINI ); FD_TEST( !present && effective==0xfdU );
  reset(); populated=1; command( CONFIGURE_CMD_INIT ); FD_TEST( !writes && !removals );
  reset(); present=isolated=0; requested=effective=0xfdU;
  command( CONFIGURE_CMD_INIT ); FD_TEST( present && isolated && !removals );

  /* Read-only checks and no pinned tiles accept a narrower mask. */
  reset(); args->configure.stages[0]=&fd_cfg_stage_kworkers; args->configure.stages[1]=NULL;
  command( CONFIGURE_CMD_CHECK ); FD_TEST( !writes );
  config->topo.tile_cnt=0; command( CONFIGURE_CMD_CHECK ); command( CONFIGURE_CMD_FINI );
  FD_TEST( !writes && effective==0xfdU );
  FD_LOG_NOTICE(( "pass" )); fd_halt(); return 0;
}
