#ifndef HEADER_fd_src_util_tile_fd_cpuset_h
#define HEADER_fd_src_util_tile_fd_cpuset_h

#include "../fd_util_base.h"
#include <sys/types.h>

#if FD_HAS_THREADS

/* fd_cpuset_t is a replacement for libc cpu_set_t.  It exists to work
   around stability issues working with the cpu_set_t API which is
   opaque, and in the case of musl libc, broken due to strict aliasing
   violations:

     error: dereferencing type-punned pointer might break strict-aliasing rules [-Werror=strict-aliasing]
     CPU_SET( args->cpu_idx, cpu_set );

   Firedancer code should instead use the fd_cpuset API, which is
   predictable and transparent.  Example usage:

     FD_CPUSET_DECL( cpuset );
     fd_cpuset_zero( cpuset );
     fd_cpuset_insert( cpuset, 2UL );

   See util/tmpl/fd_set.c for available methods.

   Safety notes:
   - DO NOT declare by fd_cpuset_t x; Instead use FD_CPUSET_DECL(x).
   - DO NOT use sizeof(fd_cpuset_t).  Instead use fd_cpuset_footprint(). */

/* FD_CPUSET_MAX is the max supported number of host CPUs.  Replaces
   CPU_SETSIZE. */

#define FD_CPUSET_MAX (4096UL)

#define SET_NAME fd_cpuset
#define SET_MAX FD_CPUSET_MAX
#include "../tmpl/fd_set.c"

/* FD_CPUSET_DECL declares an uninitialized fd_cpuset_t with given name
   in the current scope that is able to hold FD_CPUSET_MAX bits. */

#define FD_CPUSET_DECL(name) fd_cpuset_t name [ fd_cpuset_word_cnt ]

FD_PROTOTYPES_BEGIN

/* fd_cpuset_zero sets all bits in an fd_cpuset_t to zero.  Replaces the
   CPU_ZERO macro.  Returns cpuset. */

static inline fd_cpuset_t *
fd_cpuset_zero( fd_cpuset_t cpuset[ fd_cpuset_word_cnt ] ) {
  fd_memset( cpuset, 0, fd_cpuset_footprint() );
  return cpuset;
}

/* fd_sched_{get,set}affinity wrap sched_{get,set}affinity for fd_tile
   internal use.  Serves to fix type-punning issues.

   Note that sched_getaffinity will silently truncate CPUs if the number
   of host CPUs exceeds FD_CPUSET_MAX.

   To set tile affinity, use the public fd_tile.h API.
   fd_sched_set_affinity can result in sub-optimal core/memory affinity,
   silent failures, and various other performance and stability issues. */

int
fd_sched_getaffinity( pid_t       pid,
                      fd_cpuset_t mask[ fd_cpuset_word_cnt ] );

int
fd_sched_setaffinity( pid_t             pid,
                      fd_cpuset_t const mask[ fd_cpuset_word_cnt ] );

FD_PROTOTYPES_END

#endif /* FD_HAS_THREADS */

#endif /* HEADER_fd_src_util_tile_fd_cpuset_h */
