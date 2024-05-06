#ifndef HEADER_fd_src_util_tile_fd_tile_h
#define HEADER_fd_src_util_tile_fd_tile_h

/* Note: fd must be booted to use the APIs in this module */

/* fd_tile is used for fast dispatching of task within a thread group. */

#include "../shmem/fd_shmem.h"

/* FD_TILE_MAX gives a compile tile constant that is the upper bound
   of the number of tiles that could exist within a thread group. */

#define FD_TILE_MAX (1024UL)

/* A fd_tile_task_t is a function pointer with the function signature
   for tasks that can be dispatched to a tile. */

typedef int (*fd_tile_task_t)( int argc, char ** argv );

/* A fd_tile_exec_t is an opaque handle of a tile execution */

struct fd_tile_exec_private;
typedef struct fd_tile_exec_private fd_tile_exec_t;

/* TODO: Allow this to be run-time configured (e.g. match ulimit -s)? */
#define FD_TILE_PRIVATE_STACK_SZ (8UL<<20) /* Should be a multiple of HUGE (and NORMAL) page sizes */

FD_PROTOTYPES_BEGIN

/* fd_tile_{id0,id1,id,idx,cnt} return various information about the
   calling tile.  Will be constant while tile services are booted. */

FD_FN_PURE ulong fd_tile_id0( void ); /* Application threads [fd_tile_id0(),fd_tile_id1()) are the caller's thread group */
FD_FN_PURE ulong fd_tile_id1( void );
FD_FN_PURE ulong fd_tile_id ( void ); /* == fd_log_thread_id(), in [fd_tile_id0(),fd_tile_id1()) */
FD_FN_PURE ulong fd_tile_idx( void ); /* == fd_tile_id ()-fd_tile_id0(), in [0,fd_tile_cnt()) */
FD_FN_PURE ulong fd_tile_cnt( void ); /* == fd_tile_id1()-fd_tile_id0() > 0 */

/* fd_tile_cpu_id returns the physical cpu_idx used by tile_idx.  This
   matches the --tile-cpus / FD_TILE_CPUS configuration extracted from
   the command line / environment when tile services were booted.  Will
   be constant while tile services are booted.  Returns ULONG_MAX if
   tile_idx is not in [0,td_tile_cnt()) and ULONG_MAX-1 if tile_idx was
   configured to float. */

FD_FN_PURE ulong fd_tile_cpu_id( ulong tile_idx );

/* Tile stack diagnostics.  These are meant to help with instrumenting
   and debugging stack issues but usually should not be used in final
   production code.  For reference, tile 0's stack size is usually set
   at thread group start with the size in KiB given by "ulimit -s".
   This is typically 8 MiB and dynamically backed by normal 4 KiB pages.
   Other tiles usually have a size of a not-so-coincidentally 8 MiB but
   are backed by preallocated NUMA and TLB optimized huge 2 MiB pages.
   Additionally, tile stacks are usually bookended by guard regions that
   are 4 KiB in size to protect against common stack overflow /
   underflow risks.  The below assumes the stack grows from higher
   addresses (i.e. stack1) toward lower addresses (i.e. stack0).

   [fd_tile_stack0(),fd_tile_stack1()) gives the location in caller's
   local address space the caller's stack.  The size of this region is
   fd_tile_stack_sz().  fd_tile_stack_est_used() and
   fd_tile_stack_est_free() are estimates of the number of bytes in the
   stack currently used and currently free.

   If the tile stack parameters could not be determined at tile startup,
   details will be logged and stack0/stack1/stack_sz/est_used/est_free
   will be NULL/NULL/0/0/0. */

extern FD_TL ulong fd_tile_private_stack0;
extern FD_TL ulong fd_tile_private_stack1;

static inline void const * fd_tile_stack0  ( void ) { return (void const *)fd_tile_private_stack0; }
static inline void const * fd_tile_stack1  ( void ) { return (void const *)fd_tile_private_stack1; }
static inline ulong        fd_tile_stack_sz( void ) { return fd_tile_private_stack1 - fd_tile_private_stack0; }

static inline ulong
fd_tile_stack_est_used( void ) {
  uchar stack_mem[1];
  FD_VOLATILE( stack_mem[0] ) = (uchar)1; /* Paranoia to guarantee stack_mem is on the stack and backed by memory */
  return fd_ulong_if( !fd_tile_private_stack1, 0UL, fd_tile_private_stack1 - (ulong)stack_mem );
}

static inline ulong
fd_tile_stack_est_free( void ) {
  uchar stack_mem[1];
  FD_VOLATILE( stack_mem[0] ) = (uchar)1; /* Paranoia to guarantee stack_mem is on the stack and backed by memory */
  return fd_ulong_if( !fd_tile_private_stack0, 0UL, (ulong)stack_mem - fd_tile_private_stack0 );
}

/* fd_tile_exec_new starts parallel execution of task( argc, argv ) on
   tile idx (in [0,fd_tile_cnt()).  Returns a handle for this exec on
   success (tile idx was signaled to start execution of task) or NULL on
   failure (e.g.  tried to dispatch to self or tried dispatch to tile 0,
   another exec is currently running on that tile id, tried to dispatch
   to a thread in a different thread group, etc).

   task, argc, argv and argv[0:argc] are intended to be in this thread
   group's address space and argc and argv are intended (but not
   required) to be POSIX-like command line interface such that argc>0,
   argv[0] is the task name, argv[argc]==NULL and argv[0:argc-1] are all
   non-NULL cstrs.  On success, the returned exec has ownership of argv
   and all cstrs pointed to by it.  On failure, ownership is unchanged.

   Typically, a tile can't dispatch to itself or to tile 0. */

fd_tile_exec_t *
fd_tile_exec_new( ulong          idx,  /* In [0,fd_tile_cnt()) */
                  fd_tile_task_t task, /* Non-NULL */
                  int            argc,
                  char **        argv );

/* fd_tile_exec_by_id_new same as the above but tile to run is specified
   by the application thread index. */

static inline fd_tile_exec_t *
fd_tile_exec_by_id_new( ulong          id,   /* In [fd_tile_id0(),fd_tile_id1()) */
                        fd_tile_task_t task, /* Non-NULL */
                        int            argc,
                        char **        argv ) {
  return fd_tile_exec_new( id-fd_tile_id0(), task, argc, argv );
}

/* fd_tile_exec_delete deletes the given exec, blocking the caller if
   necessary (will be non-blocking if the exec is done).  Returns NULL
   if the exec terminated normally (if opt_ret is non-NULL and *opt_ret
   will be the value returned by the tile task) or an infinite lifetime
   cstr if the exec terminated abnormally (e.g. had an uncaught
   exception, called exit ... yes, currently tile tasks must return for
   normal termination, called abort, etc ... opt_ret will be
   non-touched). */

char const *
fd_tile_exec_delete( fd_tile_exec_t * exec,
                     int *            opt_ret );

/* fd_tile_exec returns the fd_tile_exec_t * running on tile tile_idx.
   fd_tile_exec_by_id_new same but tile to specified by the application
   thread index.  Undefined if tile_idx is not in [0,fd_tile_cnt()) (or
   tile_id is not in [fd_tile_id0(),fd_tile_id1()) or called outside a
   fd_tile_exec*_new / fd_tile_exec_delete pair. */

FD_FN_PURE fd_tile_exec_t * fd_tile_exec( ulong tile_idx );

static inline fd_tile_exec_t * fd_tile_exec_by_id( ulong tile_id ) { return fd_tile_exec( tile_id-fd_tile_id0() ); }

/* fd_tile_exec_{id,idx,task,argc,argv} access details exec pointed to
   by exec.  These assume exec points to a current exec. */

FD_FN_PURE ulong          fd_tile_exec_id  ( fd_tile_exec_t const * exec );
FD_FN_PURE ulong          fd_tile_exec_idx ( fd_tile_exec_t const * exec );
FD_FN_PURE fd_tile_task_t fd_tile_exec_task( fd_tile_exec_t const * exec );
FD_FN_PURE int            fd_tile_exec_argc( fd_tile_exec_t const * exec );
FD_FN_PURE char **        fd_tile_exec_argv( fd_tile_exec_t const * exec );

/* fd_tile_exec_done returns 0 if the given exec is still running or 1
   if it has stopped.  Assumes exec points to a current exec. */

int fd_tile_exec_done( fd_tile_exec_t const * exec );

/* These functions are for fd_util internal use only. */

void
fd_tile_private_boot( int *    pargc,
                      char *** pargv );

void
fd_tile_private_map_boot( ushort * tile_to_cpu,
                          ulong    tile_cnt );

void
fd_tile_private_halt( void );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_tile_fd_tile_h */
