#ifndef HEADER_fd_src_util_tile_fd_tile_private_h
#define HEADER_fd_src_util_tile_fd_tile_private_h

#include "fd_tile.h"

/* fd_cpuset_t is an internal replacement for libc cpu_set_t.  It exists
   to work around stability issues working with the cpu_set_t API which
   is opaque, and in the case of musl libc, broken due to strict
   aliasing violations:

     error: dereferencing type-punned pointer might break strict-aliasing rules [-Werror=strict-aliasing]
     CPU_SET( args->cpu_idx, cpu_set );

   This API is intended for internal use within fd_tile.  Example usage:

     FD_CPUSET_DECL( cpuset );
     fd_cpuset_insert( cpuset, 2UL );

   See util/tmpl/fd_set.c for available methods.

   Safety notes:
   - DO NOT declare by fd_cpuset_t x; Instead use FD_CPUSET_DECL(x).
   - DO NOT use sizeof(fd_cpuset_t).  Instead use fd_cpuset_footprint(). */

#define SET_NAME fd_cpuset
#define SET_MAX FD_TILE_MAX
#include "../tmpl/fd_set.c"

/* FD_CPUSET_DECL declares an empty fd_cpuset_t with the given name in
   the current scope that is able to hold FD_TILE_MAX bits. */

#define FD_CPUSET_DECL(name) fd_cpuset_t name [ fd_cpuset_word_cnt ] = {0}

FD_PROTOTYPES_BEGIN

/* fd_cpuset_{get,set}affinity wrap sched_{get,set}affinity for fd_tile
   internal use.  Serves to fix type-punning issues.  tid is the thread
   ID (pid_t).  tid==0 implies current thread.

   Note that fd_cpuset_getaffinity will silently truncate CPUs if the number
   of host CPUs exceeds FD_TILE_MAX.

   To set tile affinity, use the public fd_tile.h API.
   fd_sched_set_affinity can result in sub-optimal core/memory affinity,
   silent failures, and various other performance and stability issues. */

int
fd_cpuset_getaffinity( ulong         tid,
                       fd_cpuset_t * mask );

int
fd_cpuset_setaffinity( ulong               tid,
                       fd_cpuset_t const * mask );

/* These functions are for fd_tile internal use only. */

void *
fd_tile_private_stack_new( int   optimize,
                           ulong cpu_idx );

ulong
fd_tile_private_cpus_parse( char const * cstr,
                            ushort *     tile_to_cpu );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_tile_fd_tile_private_h */
