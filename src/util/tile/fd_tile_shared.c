#define _GNU_SOURCE
#include "fd_tile.h"

#include <ctype.h>
#include <errno.h>
#include <sched.h>
#include <sys/mman.h>

ulong
fd_tile_cpus_parse( char const * cstr,
                    ushort *     tile_to_cpu ) {
  if( !cstr ) return 0UL;
  ulong cnt = 0UL;

  cpu_set_t assigned_set[1];
  CPU_ZERO( assigned_set );

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
      if( FD_UNLIKELY( cpu>=(ulong)CPU_SETSIZE        ) ) FD_LOG_ERR(( "fd_tile: malformed --tile-cpus (invalid cpu index)" ));
      if( FD_UNLIKELY( CPU_ISSET( cpu, assigned_set ) ) ) FD_LOG_ERR(( "fd_tile: malformed --tile-cpus (repeated cpu)" ));
      if( FD_UNLIKELY( cnt>=FD_TILE_MAX               ) ) FD_LOG_ERR(( "fd_tile: too many --tile-cpus" ));
      tile_to_cpu[ cnt++ ] = (ushort)cpu;
      CPU_SET( cpu, assigned_set );
    }
  }

  return cnt;
}

void *
fd_tile_stack_new( int   optimize,
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
        FD_LOG_WARNING(( "fd_tile: munmap failed (%i-%s); attempting to continue", errno, strerror( errno ) ));

      stack += FD_SHMEM_NORMAL_PAGE_SZ;

      if( FD_UNLIKELY( munmap( stack + FD_TILE_PRIVATE_STACK_SZ, FD_SHMEM_NORMAL_PAGE_SZ ) ) )
        FD_LOG_WARNING(( "fd_tile: munmap failed (%i-%s); attempting to continue", errno, strerror( errno ) ));

    } else {

      FD_LOG_WARNING(( "fd_tile: mmap(NULL,%lu KiB,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0) failed (%i-%s)\n\t"
                       "Falling back on pthreads created stack and attempting to continue.",
                       mmap_sz >> 10, errno, strerror( errno ) ));
      return NULL;

    }

  }

  /* Create the guard regions in the extra space */

  void * guard_lo = (void *)(stack - FD_SHMEM_NORMAL_PAGE_SZ );
  if( FD_UNLIKELY( mmap( guard_lo, FD_SHMEM_NORMAL_PAGE_SZ, PROT_NONE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, (off_t)0 )!=guard_lo ) )
    FD_LOG_WARNING(( "fd_tile: mmap failed (%i-%s)\n\tAttempting to continue without stack guard lo.", errno, strerror( errno ) ));

  void * guard_hi = (void *)(stack + FD_TILE_PRIVATE_STACK_SZ);
  if( FD_UNLIKELY( mmap( guard_hi, FD_SHMEM_NORMAL_PAGE_SZ, PROT_NONE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, (off_t)0 )!=guard_hi ) )
    FD_LOG_WARNING(( "fd_tile: mmap failed (%i-%s)\n\tAttempting to continue without stack guard hi.", errno, strerror( errno ) ));

  return stack;
}

void
fd_tile_stack_delete( void * _stack ) {
  if( FD_UNLIKELY( !_stack ) ) return;

  uchar * stack    = (uchar *)_stack;
  uchar * guard_lo = stack - FD_SHMEM_NORMAL_PAGE_SZ;
  uchar * guard_hi = stack + FD_TILE_PRIVATE_STACK_SZ;

  if( FD_UNLIKELY( munmap( guard_hi, FD_SHMEM_NORMAL_PAGE_SZ ) ) )
    FD_LOG_WARNING(( "fd_tile: munmap failed (%i-%s); attempting to continue", errno, strerror( errno ) ));

  if( FD_UNLIKELY( munmap( guard_lo, FD_SHMEM_NORMAL_PAGE_SZ ) ) )
    FD_LOG_WARNING(( "fd_tile: munmap failed (%i-%s); attempting to continue", errno, strerror( errno ) ));

  /* Note that fd_shmem_release is just a wrapper around munmap such
     that this covers both the optimized and non-optimized cases */

  if( FD_UNLIKELY( munmap( stack, FD_TILE_PRIVATE_STACK_SZ ) ) )
    FD_LOG_WARNING(( "fd_tile: munmap failed (%i-%s); attempting to continue", errno, strerror( errno ) ));
}
