#ifndef _GNU_SOURCE /* GCC seems to do this this is on the command line somehow when using g++ */
#define _GNU_SOURCE
#endif

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <sched.h>
#include <syscall.h>
#include <sys/resource.h>
#include <sys/mman.h>

#include "../sanitize/fd_sanitize.h"
#include "fd_tile_private.h"

/* Operating system shims ********************************************/

struct fd_tile_private_cpu_config {
  int prio;
};

typedef struct fd_tile_private_cpu_config fd_tile_private_cpu_config_t;

/* Configure the CPU optimally */

static inline void
fd_tile_private_cpu_config( fd_tile_private_cpu_config_t * save,
                            ulong                          cpu_idx ) {

  /* If a floating tile, leave scheduler priority unchanged from however
     the thread group launcher configured it. */

  if( cpu_idx==65535UL ) {
    save->prio = INT_MIN;
    return;
  }

  /* Otherwise, configure high scheduler priority */

  errno = 0;
  int prio = getpriority( PRIO_PROCESS, (id_t)0 );
  if( prio==-1 && errno ) {
    FD_LOG_WARNING(( "fd_tile: getpriority failed (%i-%s)\n\t"
                     "Unable to determine initial tile priority so not configuring the tile\n\t"
                     "for high scheduler priority.  Attempting to continue but this thread\n\t"
                     "group's performance and stability might be compromised.  Probably should\n\t"
                     "configure 'ulimit -e 39' (or 40 and this might require adjusting\n\t"
                     "/etc/security/limits.conf as superuser to nice -19 or -20 for this user)\n\t"
                     "to eliminate this warning.  Also consider starting this thread group\n\t"
                     "with 'nice --19'.",
                     errno, fd_io_strerror( errno ) ));
    save->prio = INT_MIN;
  }

  if( FD_UNLIKELY( prio!=-19 ) && FD_UNLIKELY( setpriority( PRIO_PROCESS, (id_t)0, -19 ) ) ) {
    FD_LOG_WARNING(( "fd_tile: setpriority failed (%i-%s)\n\t"
                     "Unable to configure this tile for high scheduler priority.  Attempting\n\t"
                     "to continue but this thread group's performance and stability might be\n\t"
                     "compromised.  Probably should configure 'ulimit -e 39' (or 40 and this\n\t"
                     "might require adjusting /etc/security/limits.conf to nice -19 or -20\n\t"
                     "for this user) to eliminate this warning.  Also consider starting this\n\t"
                     "thread group with 'nice --19'.",
                     errno, fd_io_strerror( errno ) ));
    save->prio = INT_MIN;
    return;
  }

  save->prio = prio;
}

/* Restore the CPU to the given state */

static inline void
fd_tile_private_cpu_restore( fd_tile_private_cpu_config_t * save ) {
  int prio = save->prio;
  if( FD_LIKELY( prio!=INT_MIN ) && FD_UNLIKELY( prio!=-19 ) && FD_UNLIKELY( setpriority( PRIO_PROCESS, (id_t)0, prio ) ) )
    FD_LOG_WARNING(( "fd_tile: setpriority failed (%i-%s); attempting to continue", errno, fd_io_strerror( errno ) ));
}

void *
fd_tile_private_stack_new( int   optimize,
                           ulong cpu_idx ) { /* Ignored if optimize is not requested */

  uchar * stack = NULL;

  if( optimize ) { /* Create a NUMA and TLB optimized stack for a tile running on cpu cpu_idx */

    stack = (uchar *)
      fd_shmem_acquire( FD_SHMEM_HUGE_PAGE_SZ, (FD_TILE_PRIVATE_STACK_SZ/FD_SHMEM_HUGE_PAGE_SZ)+2UL, cpu_idx ); /* logs details */

    if( FD_LIKELY( stack ) ) { /* Make space for guard lo and guard hi */

      fd_shmem_release( stack, FD_SHMEM_HUGE_PAGE_SZ, 1UL );

      stack += FD_SHMEM_HUGE_PAGE_SZ;

      fd_shmem_release( stack + FD_TILE_PRIVATE_STACK_SZ, FD_SHMEM_HUGE_PAGE_SZ, 1UL );

    } else {

      ulong numa_idx = fd_shmem_numa_idx( cpu_idx );
      static ulong warn = 0UL;
      if( FD_LIKELY( !(warn & (1UL<<numa_idx) ) ) ) {
        FD_LOG_WARNING(( "fd_tile: fd_shmem_acquire failed\n\t"
                         "There are probably not enough huge pages allocated by the OS on numa\n\t"
                         "node %lu.  Falling back on normal page backed stack for tile on cpu %lu\n\t"
                         "and attempting to continue.  Run:\n\t"
                         "\techo [CNT] > /sys/devices/system/node/node%lu/hugepages/hugepages-2048kB/nr_hugepages\n\t"
                         "(probably as superuser) or equivalent where [CNT] is a sufficient number\n\t"
                         "huge pages to reserve on this numa node system wide and/or adjust\n\t"
                         "/etc/security/limits.conf to permit this user to lock a sufficient\n\t"
                         "amount of memory to eliminate this warning.",
                         numa_idx, cpu_idx, numa_idx ));
        warn |= 1UL<<numa_idx;
      }

    }

  }

  if( !stack ) { /* Request for a non-optimized stack (or optimized stack creation failed above and we are falling back) */

    ulong mmap_sz = FD_TILE_PRIVATE_STACK_SZ + 2UL*FD_SHMEM_NORMAL_PAGE_SZ;
    stack = (uchar *)mmap( NULL, mmap_sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, (off_t)0 );

    if( FD_LIKELY( ((void *)stack)!=MAP_FAILED ) ) { /* Make space for guard lo and guard hi */

      if( FD_UNLIKELY( munmap( stack, FD_SHMEM_NORMAL_PAGE_SZ ) ) )
        FD_LOG_WARNING(( "fd_tile: munmap failed (%i-%s); attempting to continue", errno, fd_io_strerror( errno ) ));

      stack += FD_SHMEM_NORMAL_PAGE_SZ;

      if( FD_UNLIKELY( munmap( stack + FD_TILE_PRIVATE_STACK_SZ, FD_SHMEM_NORMAL_PAGE_SZ ) ) )
        FD_LOG_WARNING(( "fd_tile: munmap failed (%i-%s); attempting to continue", errno, fd_io_strerror( errno ) ));

    } else {

      FD_LOG_WARNING(( "fd_tile: mmap(NULL,%lu KiB,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0) failed (%i-%s)\n\t"
                       "Falling back on pthreads created stack and attempting to continue.",
                       mmap_sz >> 10, errno, fd_io_strerror( errno ) ));
      return NULL;

    }

  }

  /* Create the guard regions in the extra space */

  void * guard_lo = (void *)(stack - FD_SHMEM_NORMAL_PAGE_SZ );
  if( FD_UNLIKELY( mmap( guard_lo, FD_SHMEM_NORMAL_PAGE_SZ, PROT_NONE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, (off_t)0 )!=guard_lo ) )
    FD_LOG_WARNING(( "fd_tile: mmap failed (%i-%s)\n\tAttempting to continue without stack guard lo.",
                     errno, fd_io_strerror( errno ) ));

  void * guard_hi = (void *)(stack + FD_TILE_PRIVATE_STACK_SZ);
  if( FD_UNLIKELY( mmap( guard_hi, FD_SHMEM_NORMAL_PAGE_SZ, PROT_NONE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, (off_t)0 )!=guard_hi ) )
    FD_LOG_WARNING(( "fd_tile: mmap failed (%i-%s)\n\tAttempting to continue without stack guard hi.",
                     errno, fd_io_strerror( errno ) ));

  return stack;
}

static void
fd_tile_private_stack_delete( void * _stack ) {
  if( FD_UNLIKELY( !_stack ) ) return;

  uchar * stack    = (uchar *)_stack;
  uchar * guard_lo = stack - FD_SHMEM_NORMAL_PAGE_SZ;
  uchar * guard_hi = stack + FD_TILE_PRIVATE_STACK_SZ;

  if( FD_UNLIKELY( munmap( guard_hi, FD_SHMEM_NORMAL_PAGE_SZ ) ) )
    FD_LOG_WARNING(( "fd_tile: munmap failed (%i-%s); attempting to continue", errno, fd_io_strerror( errno ) ));

  if( FD_UNLIKELY( munmap( guard_lo, FD_SHMEM_NORMAL_PAGE_SZ ) ) )
    FD_LOG_WARNING(( "fd_tile: munmap failed (%i-%s); attempting to continue", errno, fd_io_strerror( errno ) ));

  /* Note that fd_shmem_release is just a wrapper around munmap such
     that this covers both the optimized and non-optimized cases */

  if( FD_UNLIKELY( munmap( stack, FD_TILE_PRIVATE_STACK_SZ ) ) )
    FD_LOG_WARNING(( "fd_tile: munmap failed (%i-%s); attempting to continue", errno, fd_io_strerror( errno ) ));
}

/* Tile side APIs ****************************************************/

static ulong fd_tile_private_id0; /* Zeroed at app start, initialized by the boot manager */
static ulong fd_tile_private_id1; /* " */
static ulong fd_tile_private_cnt; /* " */

ulong fd_tile_id0( void ) { return fd_tile_private_id0; }
ulong fd_tile_id1( void ) { return fd_tile_private_id1; }
ulong fd_tile_cnt( void ) { return fd_tile_private_cnt; }

static FD_TL ulong fd_tile_private_id;     /* Zeroed at app/thread start, initialized by the boot / tile manager */
static FD_TL ulong fd_tile_private_idx;    /* " */
/**/   FD_TL ulong fd_tile_private_stack0; /* " */
/**/   FD_TL ulong fd_tile_private_stack1; /* " */

ulong fd_tile_id ( void ) { return fd_tile_private_id;  }
ulong fd_tile_idx( void ) { return fd_tile_private_idx; }

static ushort fd_tile_private_cpu_id[ FD_TILE_MAX ]; /* Zeroed at app start, initialized by boot */

ulong
fd_tile_cpu_id( ulong tile_idx ) {
  if( FD_UNLIKELY( tile_idx>=fd_tile_private_cnt ) ) return ULONG_MAX;
  ulong cpu_idx = (ulong)fd_tile_private_cpu_id[ tile_idx ];
  return fd_ulong_if( cpu_idx<65535UL, cpu_idx, ULONG_MAX-1UL );
}

/* This is used for the OS services to communicate information with the
   tile managers */

#define FD_TILE_PRIVATE_STATE_BOOT (0) /* Tile is booting */
#define FD_TILE_PRIVATE_STATE_IDLE (1) /* Tile is idle */
#define FD_TILE_PRIVATE_STATE_EXEC (2) /* Tile is executing a task */
#define FD_TILE_PRIVATE_STATE_HALT (3) /* Tile is halting */

struct __attribute__((aligned(128))) fd_tile_private { /* Double cache line aligned to avoid aclpf false sharing */
  ulong          id;
  ulong          idx;
  int            state;  /* FD_TILE_PRIVATE_STATE_* */
  int            argc;
  char **        argv;
  fd_tile_task_t task;
  char const *   fail;
  int            ret;
};

typedef struct fd_tile_private fd_tile_private_t;

struct fd_tile_private_manager_args {
  ulong               id;
  ulong               idx;
  ulong               cpu_idx;
  void *              stack;    /* NULL if pthread created, non-NULL if user created */
  ulong               stack_sz;
  fd_tile_private_t * tile;
};

typedef struct fd_tile_private_manager_args fd_tile_private_manager_args_t;

static void *
fd_tile_private_manager( void * _args ) {
  fd_tile_private_manager_args_t * args = (fd_tile_private_manager_args_t *)_args;

# if !__GLIBC__
  if( args->cpu_idx<65535UL ) {
    FD_CPUSET_DECL( cpu_set );
    fd_cpuset_insert( cpu_set, args->cpu_idx );
    int err = fd_cpuset_setaffinity( (pid_t)0, cpu_set );
    if( FD_UNLIKELY( err ) )
      FD_LOG_WARNING(( "fd_tile: fd_cpuset_setaffinity_failed (%i-%s)\n\t"
                       "Unable to set the thread affinity for tile %lu to cpu %lu.  Attempting to\n\t"
                       "continue without explicitly specifying this tile's cpu affinity but it\n\t"
                       "is likely this thread group's performance and stability are compromised\n\t"
                       "(possibly catastrophically so).  Update --tile-cpus to specify a set of\n\t"
                       "allowed cpus that have been reserved for this thread group on this host\n\t"
                       "to eliminate this warning.", err, fd_io_strerror( err ), args->idx, args->cpu_idx ));
  }
# endif /* !__GLIBC__ */

  ulong  id       = args->id;
  ulong  idx      = args->idx;
  void * stack    = args->stack;
  ulong  stack_sz = args->stack_sz;

  if( FD_UNLIKELY( !( (id ==fd_log_thread_id()                                       ) &
                      (idx==(id-fd_tile_private_id0)                                 ) &
                      ((fd_tile_private_id0<id) & (id<fd_tile_private_id1)           ) &
                      (fd_tile_private_cnt==(fd_tile_private_id1-fd_tile_private_id0)) ) ) )
    FD_LOG_ERR(( "fd_tile: internal error (unexpected thread identifiers)" ));

  fd_tile_private_t tile[1];
  FD_VOLATILE( tile->id    ) = id;
  FD_VOLATILE( tile->idx   ) = idx;
  FD_VOLATILE( tile->state ) = FD_TILE_PRIVATE_STATE_BOOT;
  FD_VOLATILE( tile->argc  ) = 0;
  FD_VOLATILE( tile->argv  ) = NULL;
  FD_VOLATILE( tile->task  ) = NULL;
  FD_VOLATILE( tile->fail  ) = NULL;
  FD_VOLATILE( tile->ret   ) = 0;

  /* state is BOOT ... configure the tile, transition to IDLE and then
     start polling for tasks */

  fd_tile_private_id  = id;
  fd_tile_private_idx = idx;

  if( FD_LIKELY( stack ) ) { /* User provided stack */
    fd_tile_private_stack0 = (ulong)stack;
    fd_tile_private_stack1 = (ulong)stack + stack_sz;
  } else { /* Pthread provided stack */
    fd_log_private_stack_discover( stack_sz, &fd_tile_private_stack0, &fd_tile_private_stack1 ); /* logs details */
    if( FD_UNLIKELY( !fd_tile_private_stack0 ) )
      FD_LOG_WARNING(( "stack diagnostics not available on this tile; attempting to continue" ));
  }

  fd_tile_private_cpu_config_t dummy[1];
  fd_tile_private_cpu_config( dummy, args->cpu_idx );

  ulong app_id = fd_log_app_id();
  FD_LOG_INFO(( "fd_tile: boot tile %lu success (thread %lu:%lu in thread group %lu:%lu/%lu)",
                idx, app_id, id, app_id, fd_tile_private_id0, fd_tile_private_cnt ));

  FD_COMPILER_MFENCE();
  FD_VOLATILE( tile->state ) = FD_TILE_PRIVATE_STATE_IDLE;
  FD_VOLATILE( args->tile  ) = tile;

  for(;;) {

    /* We are awake ... see what we should do next */

    int state = FD_VOLATILE_CONST( tile->state );
    if( FD_UNLIKELY( state!=FD_TILE_PRIVATE_STATE_EXEC ) ) {
      if( FD_UNLIKELY( state!=FD_TILE_PRIVATE_STATE_IDLE ) ) break;
      /* state is IDLE ... try again */
      FD_SPIN_PAUSE();
      continue;
    }

    /* state is EXEC ... the run assigned task and then
       transition to IDLE when done */
    /* FIXME: MORE SOPHISTICATED HANDLING OF EXCEPTIONS */

    int            argc = FD_VOLATILE_CONST( tile->argc );
    char **        argv = FD_VOLATILE_CONST( tile->argv );
    fd_tile_task_t task = FD_VOLATILE_CONST( tile->task );
    try {
      FD_VOLATILE( tile->ret  ) = task( argc, argv );
      FD_VOLATILE( tile->fail ) = NULL;
    } catch( ... ) {
      FD_VOLATILE( tile->fail ) = "uncaught exception";
    }

    FD_COMPILER_MFENCE();
    FD_VOLATILE( tile->state ) = FD_TILE_PRIVATE_STATE_IDLE;
  }

  /* state is HALT, clean up and then reset back to BOOT */

  FD_LOG_INFO(( "fd_tile: halting tile %lu", idx ));

  FD_COMPILER_MFENCE();
  FD_VOLATILE( tile->state ) = FD_TILE_PRIVATE_STATE_BOOT;
  return stack;
}

/* Dispatch side APIs ************************************************/

static struct __attribute__((aligned(128))) { /* Each on its own cache line pair to limit false sharing in parallel dispatch */
  fd_tile_private_t * lock; /* Non-NULL if tile idx is available for dispatch, ==tile otherwise */
  fd_tile_private_t * tile;
  pthread_t           pthread;
} fd_tile_private[ FD_TILE_MAX ];

/* FIXME: ATOMIC_XCHG BASED INSTEAD? */
static inline fd_tile_private_t *
fd_tile_private_trylock( ulong tile_idx ) {
  fd_tile_private_t * volatile * vtile = (fd_tile_private_t * volatile *)&fd_tile_private[ tile_idx ].lock;
  fd_tile_private_t * tile = *vtile;
  if( FD_LIKELY( tile ) && FD_LIKELY( FD_ATOMIC_CAS( vtile, tile, NULL )==tile ) ) return tile;
  return NULL;
}

static inline fd_tile_private_t *
fd_tile_private_lock( ulong tile_idx ) {
  fd_tile_private_t * volatile * vtile = (fd_tile_private_t * volatile *)&fd_tile_private[ tile_idx ].lock;
  fd_tile_private_t * tile;
  for(;;) {
    tile = *vtile;
    if( FD_LIKELY( tile ) && FD_LIKELY( FD_ATOMIC_CAS( vtile, tile, NULL )==tile ) ) break;
    FD_SPIN_PAUSE();
  }
  return tile;
}

static inline void
fd_tile_private_unlock( ulong               tile_idx,
                        fd_tile_private_t * tile ) {
  FD_VOLATILE( fd_tile_private[ tile_idx ].lock ) = tile;
}

fd_tile_exec_t *
fd_tile_exec_new( ulong          idx,
                  fd_tile_task_t task,
                  int            argc,
                  char **        argv ) {
  if( FD_UNLIKELY( (idx==fd_tile_private_idx) | (!idx) ) ) return NULL; /* Can't dispatch to self or to tile 0 */

  fd_tile_private_t * tile = fd_tile_private_trylock( idx );
  if( FD_UNLIKELY( !tile ) ) return NULL;

  /* Exec holds the lock and tile state is idle here */
  FD_VOLATILE( tile->argc ) = argc;
  FD_VOLATILE( tile->argv ) = argv;
  FD_VOLATILE( tile->task ) = task;
  FD_COMPILER_MFENCE();
  FD_VOLATILE( tile->state ) = FD_TILE_PRIVATE_STATE_EXEC;
  return (fd_tile_exec_t *)tile;
}

char const *
fd_tile_exec_delete( fd_tile_exec_t * exec,
                     int *            opt_ret ) {
  fd_tile_private_t * tile     = (fd_tile_private_t *)exec;
  ulong               tile_idx = tile->idx;

  int state;
  for(;;) {
    state = FD_VOLATILE_CONST( tile->state );
    if( FD_LIKELY( state==FD_TILE_PRIVATE_STATE_IDLE ) ) break;
    FD_SPIN_PAUSE();
  }
  /* state is IDLE at this point */
  char const * fail = FD_VOLATILE_CONST( tile->fail );
  if( FD_LIKELY( (!fail) & (!!opt_ret) ) ) *opt_ret = FD_VOLATILE_CONST( tile->ret );
  fd_tile_private_unlock( tile_idx, tile );
  return fail;
}

fd_tile_exec_t * fd_tile_exec( ulong tile_idx ) { return (fd_tile_exec_t *)fd_tile_private[ tile_idx ].tile; }

ulong          fd_tile_exec_id  ( fd_tile_exec_t const * exec ) { return ((fd_tile_private_t const *)exec)->id;   }
ulong          fd_tile_exec_idx ( fd_tile_exec_t const * exec ) { return ((fd_tile_private_t const *)exec)->idx;  }
fd_tile_task_t fd_tile_exec_task( fd_tile_exec_t const * exec ) { return ((fd_tile_private_t const *)exec)->task; }
int            fd_tile_exec_argc( fd_tile_exec_t const * exec ) { return ((fd_tile_private_t const *)exec)->argc; }
char **        fd_tile_exec_argv( fd_tile_exec_t const * exec ) { return ((fd_tile_private_t const *)exec)->argv; }

int
fd_tile_exec_done( fd_tile_exec_t const * exec ) {
  fd_tile_private_t const * tile = (fd_tile_private_t const *)exec;
  return FD_VOLATILE_CONST( tile->state )==FD_TILE_PRIVATE_STATE_IDLE;
}

/* Boot/halt APIs ****************************************************/

/* Parse a list of cpu tiles */

FD_STATIC_ASSERT( FD_TILE_MAX<65535, update_tile_to_cpu_type );

ulong
fd_tile_private_cpus_parse( char const * cstr,
                            ushort *     tile_to_cpu ) {
  if( !cstr ) return 0UL;
  ulong cnt = 0UL;

  FD_CPUSET_DECL( assigned_set );

  char const * p = cstr;
  for(;;) {

    while( isspace( (int)p[0] ) ) p++; /* Munch whitespace */

    if( p[0]=='f' ) { /* These tiles have been requested to float on the original core set */
      p++;

      ulong float_cnt;

      while( isspace( (int)p[0] ) ) p++; /* Munch whitespace */
      if     ( p[0]==','             ) float_cnt = 1UL, p++;
      else if( p[0]=='\0'            ) float_cnt = 1UL;
      else if( !isdigit( (int)p[0] ) ) FD_LOG_ERR(( "fd_tile: malformed --tile-cpus (malformed count)" ));
      else {
        float_cnt = fd_cstr_to_ulong( p );
        if( FD_UNLIKELY( !float_cnt ) ) FD_LOG_ERR(( "fd_tile: malformed --tile-cpus (bad count)" ));
        p++; while( isdigit( (int)p[0] ) ) p++; /* FIXME: USE STRTOUL ENDPTR FOR CORRECT HANDLING OF NON-BASE-10 */
        while( isspace( (int)p[0] ) ) p++; /* Munch whitespace */
        if( FD_UNLIKELY( !( p[0]==',' || p[0]=='\0' ) ) ) FD_LOG_ERR(( "fd_tile: malformed --tile-cpus (bad count delimiter)" ));
        if( p[0]==',' ) p++;
      }

      /* float_cnt is at least 1 at this point */
      do {
        if( FD_UNLIKELY( cnt>=FD_TILE_MAX ) ) FD_LOG_ERR(( "fd_tile: too many --tile-cpus" ));
        tile_to_cpu[ cnt++ ] = (ushort)65535;
      } while( --float_cnt );

      continue;
    }

    if( !isdigit( (int)p[0] ) ) {
      if( FD_UNLIKELY( p[0]!='\0' ) ) FD_LOG_ERR(( "fd_tile: malformed --tile-cpus (range lo not a cpu)" ));
      break;
    }
    ulong cpu0   = fd_cstr_to_ulong( p );
    ulong cpu1   = cpu0;
    ulong stride = 1UL;
    p++; while( isdigit( (int)p[0] ) ) p++; /* FIXME: USE STRTOUL ENDPTR FOR CORRECT HANDLING OF NON-BASE-10 */
    while( isspace( (int)p[0] ) ) p++;
    if( p[0]=='-' ) {
      p++;
      while( isspace( (int)p[0] ) ) p++;
      if( FD_UNLIKELY( !isdigit( (int)p[0] ) ) ) FD_LOG_ERR(( "fd_tile: malformed --tile-cpus (range hi not a cpu)" ));
      cpu1 = fd_cstr_to_ulong( p );
      p++; while( isdigit( (int)p[0] ) ) p++; /* FIXME: USE STRTOUL ENDPTR FOR CORRECT HANDLING OF NON-BASE-10 */
      while( isspace( (int)p[0] ) ) p++;
      if( p[0]=='/' || p[0]==':' ) {
        p++;
        while( isspace( (int)p[0] ) ) p++;
        if( FD_UNLIKELY( !isdigit( (int)p[0] ) ) ) FD_LOG_ERR(( "fd_tile: malformed --tile-cpus (stride not an int)" ));
        stride = fd_cstr_to_ulong( p );
        p++; while( isdigit( (int)p[0] ) ) p++; /* FIXME: USE STRTOUL ENDPTR FOR CORRECT HANDLING OF NON-BASE-10 */
      }
    }
    while( isspace( (int)p[0] ) ) p++;
    if( FD_UNLIKELY( !( p[0]==',' || p[0]=='\0' ) ) ) FD_LOG_ERR(( "fd_tile: malformed --tile-cpus (bad range delimiter)" ));
    if( p[0]==',' ) p++;
    cpu1++;
    if( FD_UNLIKELY( cpu1<=cpu0 ) ) FD_LOG_ERR(( "fd_tile: malformed --tile-cpus (invalid range)"  ));
    if( FD_UNLIKELY( !stride    ) ) FD_LOG_ERR(( "fd_tile: malformed --tile-cpus (invalid stride)" ));

    for( ulong cpu=cpu0; cpu<cpu1; cpu+=stride ) {
      if( FD_UNLIKELY( cnt>=FD_TILE_MAX                    ) ) FD_LOG_ERR(( "fd_tile: too many --tile-cpus" ));
      if( FD_UNLIKELY( fd_cpuset_test( assigned_set, cpu ) ) ) FD_LOG_ERR(( "fd_tile: malformed --tile-cpus (repeated cpu)" ));
      tile_to_cpu[ cnt++ ] = (ushort)cpu;
      fd_cpuset_insert( assigned_set, cpu );
    }
  }

  return cnt;
}

static fd_tile_private_cpu_config_t fd_tile_private_cpu_config_save[1];

void
fd_tile_private_boot( int *    pargc,
                      char *** pargv ) {
  FD_LOG_INFO(( "fd_tile: boot" ));

  /* Extract the tile configuration from the command line */

  char const * cpus = fd_env_strip_cmdline_cstr( pargc, pargv, "--tile-cpus", "FD_TILE_CPUS", NULL );
  if( !cpus ) FD_LOG_INFO(( "fd_tile: --tile-cpus not specified" ));
  else        FD_LOG_INFO(( "fd_tile: --tile-cpus \"%s\"", cpus ));
  ushort tile_to_cpu[ FD_TILE_MAX ];
  ulong  tile_cnt = fd_tile_private_cpus_parse( cpus, tile_to_cpu );

  if( FD_UNLIKELY( !tile_cnt ) ) {
    FD_LOG_INFO(( "fd_tile: no cpus specified; treating thread group as single tile running on O/S assigned cpu(s)" ));
    tile_to_cpu[0] = (ushort)65535;
    tile_cnt       = 1UL;
  }

  fd_tile_private_id0 = fd_log_thread_id();
  fd_tile_private_id1 = fd_tile_private_id0 + tile_cnt;
  fd_tile_private_cnt = tile_cnt;

  ulong app_id  = fd_log_app_id();
  ulong host_id = fd_log_host_id();
  FD_LOG_INFO(( "fd_tile: booting thread group %lu:%lu/%lu", app_id, fd_tile_private_id0, fd_tile_private_cnt ));

  /* We create the tiles [1,tile_cnt) first so that any floating tiles
     in this inherit the appropriate scheduler priorities and affinities
     from the thread group launcher. */

  for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ ) {

    ulong cpu_idx = (ulong)tile_to_cpu[ tile_idx ];
    int   fixed   = (cpu_idx<65535UL);

    if( fixed ) FD_LOG_INFO(( "fd tile: booting tile %lu on cpu %lu:%lu",   tile_idx, host_id, cpu_idx ));
    else        FD_LOG_INFO(( "fd tile: booting tile %lu on cpu %lu:float", tile_idx, host_id ));

    pthread_attr_t attr[1];
    int err = pthread_attr_init( attr );
    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_tile: pthread_attr_init failed (%i-%s) for tile %lu.\n\t",
                                          err, fd_io_strerror( err ), tile_idx ));

    /* Set affinity ahead of time.  This is a GNU-specific extension
       that is not available on musl.  On musl, we just skip this
       step as we call sched_setaffinity(2) later on regardless. */

#   if __GLIBC__
    if( fixed ) {
      FD_CPUSET_DECL( cpu_set );
      fd_cpuset_insert( cpu_set, cpu_idx );
      err = pthread_attr_setaffinity_np( attr, fd_cpuset_footprint(), (cpu_set_t const *)fd_type_pun_const( cpu_set ) );
      if( FD_UNLIKELY( err ) ) FD_LOG_WARNING(( "fd_tile: pthread_attr_setaffinity_failed (%i-%s)\n\t"
                                                "Unable to set the thread affinity for tile %lu on cpu %lu.  Attempting to\n\t"
                                                "continue without explicitly specifying this cpu's thread affinity but it\n\t"
                                                "is likely this thread group's performance and stability are compromised\n\t"
                                                "(possibly catastrophically so).  Update --tile-cpus to specify a set of\n\t"
                                                "allowed cpus that have been reserved for this thread group on this host\n\t"
                                                "to eliminate this warning.",
                                                err, fd_io_strerror( err ), tile_idx, cpu_idx ));
    }
#   endif /* __GLIBC__ */

    /* Create an optimized stack with guard regions if the build target
       is x86 (e.g. supports huge pages necessary to optimize TLB usage)
       and the tile is assigned to a particular CPU (e.g. bind the stack
       memory to the NUMA node closest to the cpu).

       Otherwise (or if an optimized stack could not be created), create
       vanilla pthread-style stack with guard regions.  We DIY here
       because pthreads seems to be missing an API to determine the
       extents of the stacks it creates and we need to know the stack
       extents for run-time stack diagnostics.  Though we can use
       fd_log_private_stack_discover to determine stack extents after
       the thread is started, it is faster, more flexible, more reliable
       and more portable to use a user specified stack when possible.

       If neither can be done, we will let pthreads create the tile's
       stack and try to discover the stack extents after the thread is
       started. */

    int optimize = FD_HAS_X86 & fixed;

    void * stack = fd_tile_private_stack_new( optimize, cpu_idx );
    if( FD_LIKELY( stack ) ) {
      err = pthread_attr_setstack( attr, stack, FD_TILE_PRIVATE_STACK_SZ );
      if( FD_UNLIKELY( err ) ) {
        FD_LOG_WARNING(( "fd_tile: pthread_attr_setstack failed (%i-%s)\n\t", err, fd_io_strerror( err ) ));
        fd_tile_private_stack_delete( stack );
        stack = NULL;
      }
    }

    if( FD_UNLIKELY( !stack ) ) FD_LOG_WARNING(( "fd_tile: Unable to create a stack for tile %lu.\n\t"
                                                 "Attempting to continue with the default stack but it is likely this\n\t"
                                                 "thread group's performance and stability is compromised (possibly\n\t"
                                                 "catastrophically so).",
                                                 tile_idx ));

    ulong stack_sz;
    err = pthread_attr_getstacksize( attr, &stack_sz );
    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_tile: pthread_attr_getstacksize failed (%i-%s) for tile %lu.\n\t",
                                          err, fd_io_strerror( err ), tile_idx ));

    FD_VOLATILE( fd_tile_private[ tile_idx ].lock ) = NULL;

    fd_tile_private_manager_args_t args[1];

    FD_VOLATILE( args->id       ) = fd_tile_private_id0 + tile_idx;
    FD_VOLATILE( args->idx      ) = tile_idx;
    FD_VOLATILE( args->cpu_idx  ) = cpu_idx;
    FD_VOLATILE( args->stack    ) = stack;
    FD_VOLATILE( args->stack_sz ) = stack_sz;
    FD_VOLATILE( args->tile     ) = NULL;

    FD_COMPILER_MFENCE();

    err = pthread_create( &fd_tile_private[tile_idx].pthread, attr, fd_tile_private_manager, args );
    if( FD_UNLIKELY( err ) ) {
      if( fixed ) FD_LOG_ERR(( "fd_tile: pthread_create failed (%i-%s)\n\t"
                               "Unable to start up the tile %lu on cpu %lu.  Likely causes for this include\n\t"
                               "this cpu is restricted from the user or does not exist on this host.\n\t"
                               "Update --tile-cpus to specify a set of allowed cpus that have been reserved\n\t"
                               "for this thread group on this host.",
                               err, fd_io_strerror( err ), tile_idx, cpu_idx ));
      FD_LOG_ERR(( "fd_tile: pthread_create failed (%i-%s)\n\tUnable to start up the tile %lu (floating).",
                   err, fd_io_strerror( err ), tile_idx ));
    }

    /* Wait for the tile to be ready to exec */

    fd_tile_private_t * tile;
    for(;;) {
      tile = FD_VOLATILE_CONST( args->tile );
      if( FD_LIKELY( tile ) ) break;
      FD_YIELD();
    }
    FD_VOLATILE( fd_tile_private[ tile_idx ].tile ) = tile;
    FD_VOLATILE( fd_tile_private[ tile_idx ].lock ) = tile;

    /* Tile is running, args is safe to reuse */

    err = pthread_attr_destroy( attr );
    if( FD_UNLIKELY( err ) )
      FD_LOG_WARNING(( "fd_tile: pthread_attr_destroy failed (%i-%s) for tile %lu; attempting to continue",
                       err, fd_io_strerror( err ), tile_idx ));
  }

  /* And now we "boot" tile 0 */

  ulong cpu_idx = (ulong)tile_to_cpu[ 0UL ];
  int   fixed   = (cpu_idx<65535UL);
  if( fixed ) FD_LOG_INFO(( "fd tile: booting tile %lu on cpu %lu:%lu",   0UL, host_id, cpu_idx ));
  else        FD_LOG_INFO(( "fd tile: booting tile %lu on cpu %lu:float", 0UL, host_id ));

  if( fixed ) {

    int good_taskset;
    FD_CPUSET_DECL( cpu_set );
    if( FD_UNLIKELY( fd_cpuset_getaffinity( (pid_t)0, cpu_set ) ) ) {
      FD_LOG_WARNING(( "fd_tile: fd_cpuset_getaffinity failed (%i-%s) for tile 0 on cpu %lu",
                       errno, fd_io_strerror( errno ), cpu_idx ));
      good_taskset = 0;
    } else {
      ulong cnt = fd_cpuset_cnt( cpu_set );
      ulong idx = fd_cpuset_first( cpu_set );
      good_taskset = (cnt==1UL) & (idx==cpu_idx);
    }

    if( FD_UNLIKELY( !good_taskset ) ) {
      FD_LOG_WARNING(( "fd_tile: --tile-cpus for tile 0 may not match initial kernel affinity\n\t"
                       "Tile 0 might not be fully optimized because of kernel first touch.\n\t"
                       "Overriding fd_log_cpu_id(), fd_log_cpu(), fd_log_thread() on tile 0 to\n\t"
                       "match --tile-cpus and attempting to continue.  Launch this thread\n\t"
                       "group via 'taskset -c %lu' or equivalent to eliminate this warning.", cpu_idx ));
      fd_cpuset_null( cpu_set );
      fd_cpuset_insert( cpu_set, cpu_idx );
      if( FD_UNLIKELY( fd_cpuset_setaffinity( (pid_t)0, cpu_set ) ) )
        FD_LOG_WARNING(( "fd_tile: fd_cpuset_setaffinity_failed (%i-%s)\n\t"
                         "Unable to set the thread affinity for tile 0 on cpu %lu.  Attempting to\n\t"
                         "continue without explicitly specifying this cpu's thread affinity but it\n\t"
                         "is likely this thread group's performance and stability are compromised\n\t"
                         "(possibly catastrophically so).  Update --tile-cpus to specify a set of\n\t"
                         "allowed cpus that have been reserved for this thread group on this host\n\t"
                         "to eliminate this warning.",
                         errno, fd_io_strerror( errno ), cpu_idx ));
      fd_log_private_cpu_id_set( cpu_idx );
      fd_log_cpu_set   ( NULL );
      fd_log_thread_set( NULL );
    }
  }

  /* Tile 0 "pthread_create" */
  fd_tile_private[0].pthread = pthread_self();
  /* FIXME: ON X86, DETECT IF TILE 0 STACK ISN'T HUGE PAGE AND WARN AS NECESSARY? */

  /* Tile 0 "thread manager init" */
  fd_tile_private_id  = fd_tile_private_id0;
  fd_tile_private_idx = 0UL;

# if !FD_HAS_ASAN
  fd_log_private_stack_discover( fd_log_private_main_stack_sz(),
                                 &fd_tile_private_stack0, &fd_tile_private_stack1 ); /* logs details */
  if( FD_UNLIKELY( !fd_tile_private_stack0 ) )
    FD_LOG_WARNING(( "stack diagnostics not available on this tile; attempting to continue" ));
# endif /* FD_HAS_ASAN */

  fd_tile_private_cpu_config( fd_tile_private_cpu_config_save, cpu_idx );
  fd_tile_private[0].lock = NULL; /* Can't dispatch to tile 0 */
  fd_tile_private[0].tile = NULL; /* " */

  FD_LOG_INFO(( "fd_tile: boot tile %lu success (thread %lu:%lu in thread group %lu:%lu/%lu)",
                fd_tile_private_idx, app_id, fd_tile_private_id, app_id, fd_tile_private_id0, fd_tile_private_cnt ));

  fd_memcpy( fd_tile_private_cpu_id, tile_to_cpu, fd_tile_private_cnt*sizeof(ushort) );

  FD_LOG_INFO(( "fd_tile: boot success" ));
}

void
fd_tile_private_halt( void ) {
  FD_LOG_INFO(( "fd_tile: halt" ));

  fd_memset( fd_tile_private_cpu_id, 0, fd_tile_private_cnt*sizeof(ushort) );

  ulong tile_cnt = fd_tile_private_cnt;

  fd_tile_private_t * tile[ FD_TILE_MAX ]; /* FIXME: ALLOCA TO TILE_CNT? */

  FD_LOG_INFO(( "fd_tile: disabling dispatch" ));
  for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ ) tile[ tile_idx ] = fd_tile_private_lock( tile_idx );
  /* All tile to tile dispatches will fail at this point */

  FD_LOG_INFO(( "fd_tile: waiting for all tasks to complete" ));
  for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ )
    while( FD_VOLATILE_CONST( tile[ tile_idx ]->state )!=FD_TILE_PRIVATE_STATE_IDLE ) FD_YIELD();
  /* All halt transitions will be valid at this point */

  FD_LOG_INFO(( "fd_tile: signaling all tiles to halt" ));
  for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ ) FD_VOLATILE( tile[ tile_idx ]->state ) = FD_TILE_PRIVATE_STATE_HALT;
  /* All tiles are halting at this point.  tile[*] is no longer safe */

  FD_LOG_INFO(( "fd_tile: waiting for all tiles to halt" ));
  for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ ) {
    void * stack;
    int err = pthread_join( fd_tile_private[ tile_idx ].pthread, &stack );
    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_tile: pthread_join failed (%i-%s)", err, fd_io_strerror( err ) ));
    fd_tile_private_stack_delete( stack );
    FD_LOG_INFO(( "fd_tile: halt tile %lu success", tile_idx ));
  }

  /* All tiles but this one are halted at this point */

  fd_tile_private_cpu_restore( fd_tile_private_cpu_config_save );

  FD_LOG_INFO(( "fd_tile: halt tile 0 success" ));

  FD_LOG_INFO(( "fd_tile: cleaning up" ));

  for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ ) fd_tile_private_unlock( tile_idx, NULL );

  fd_memset( fd_tile_private_cpu_config_save, 0, sizeof(fd_tile_private_cpu_config_t) );

  fd_tile_private_stack1 = 0UL;
  fd_tile_private_stack0 = 0UL;
  fd_tile_private_idx    = 0UL;
  fd_tile_private_id     = 0UL;

  fd_tile_private_cnt = 0UL;
  fd_tile_private_id1 = 0UL;
  fd_tile_private_id0 = 0UL;

  FD_LOG_INFO(( "fd_tile: halt success" ));
}
