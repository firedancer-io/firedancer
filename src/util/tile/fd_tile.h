#ifndef HEADER_fd_src_util_tile_fd_tile_h
#define HEADER_fd_src_util_tile_fd_tile_h

/* Note: fd must be booted to use the APIs in this module */

/* fd_tile is used for fast dispatching of task within a thread group. */

#include "../shmem/fd_shmem.h"

/* FD_TILE_MAX gives a compile tile constant that is the upper bound
   of the number of tiles that could exist within a thread group. */

#define FD_TILE_MAX (1024UL)

/* A fd_tile_task_t is a function point with the function signature for
   of a tasks that can be dispatched to a tile. */

typedef int (*fd_tile_task_t)( int argc, char ** argv );

/* A fd_tile_exec_t is an opaque handle of a tile execution */

struct fd_tile_exec_private;
typedef struct fd_tile_exec_private fd_tile_exec_t;

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
   tile_idx is is not in [0,td_tile_cnt()). */

FD_FN_PURE ulong fd_tile_cpu_id( ulong tile_idx );

/* fd_tile_exec_new start parallel execution of task( argc, argv ) on
   tile idx (in [0,fd_tile_cnt()).  Returns a handle for this exec on
   success (tile idx was signaled to start execution of task) or NULL on
   failure (e.g.  tried to dispatch to self or tried dispatch to tile 0,
   another exec is currently running on that tile id, tried to dispath
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

/* These functions for for fd_tile internal use only. */

void
fd_tile_private_boot( int *    pargc,
                      char *** pargv );

void
fd_tile_private_halt( void );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_tile_fd_tile_h */
