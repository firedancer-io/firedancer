#if FD_HAS_THREADS && FD_HAS_X86 /* THREADS implies HOSTED */
#define _GNU_SOURCE
#endif

#include "fd_shmem_private.h"

#if FD_HAS_HOSTED && FD_HAS_X86

#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

char  fd_shmem_private_base[ FD_SHMEM_PRIVATE_BASE_MAX ]; /* ""  at thread group start, initialized at boot */
ulong fd_shmem_private_base_len;                          /* 0UL at ",                  initialized at boot */

/* NUMA TOPOLOGY APIS *************************************************/

static ulong  fd_shmem_private_numa_cnt;                      /* 0UL at thread group start, initialized at boot */
static ulong  fd_shmem_private_cpu_cnt;                       /* " */
static ushort fd_shmem_private_numa_idx[ FD_SHMEM_CPU_MAX  ]; /* " */
static ushort fd_shmem_private_cpu_idx [ FD_SHMEM_NUMA_MAX ]; /* " */

ulong fd_shmem_numa_cnt( void ) { return fd_shmem_private_numa_cnt; }
ulong fd_shmem_cpu_cnt ( void ) { return fd_shmem_private_cpu_cnt;  }

ulong
fd_shmem_numa_idx( ulong cpu_idx ) {
  if( FD_UNLIKELY( cpu_idx>=fd_shmem_private_cpu_cnt ) ) return ULONG_MAX;
  return (ulong)fd_shmem_private_numa_idx[ cpu_idx ];
}

ulong
fd_shmem_cpu_idx( ulong numa_idx ) {
  if( FD_UNLIKELY( numa_idx>=fd_shmem_private_numa_cnt ) ) return ULONG_MAX;
  return (ulong)fd_shmem_private_cpu_idx[ numa_idx ];
}

/* SHMEM REGION CREATION AND DESTRUCTION ******************************/

int
fd_shmem_unlink( char const * name,
                 ulong        page_sz ) {
  char path[ FD_SHMEM_PRIVATE_PATH_BUF_MAX ];

  /* Check input args */

  if( FD_UNLIKELY( !fd_shmem_name_len( name ) ) ) { FD_LOG_WARNING(( "bad name (%s)", name ? name : "NULL" )); return EINVAL; }

  if( FD_UNLIKELY( !fd_shmem_is_page_sz( page_sz ) ) ) { FD_LOG_WARNING(( "bad page_sz (%lu)", page_sz )); return EINVAL; }

  /* Unlink the name */

  if( FD_UNLIKELY( unlink( fd_shmem_private_path( name, page_sz, path ) ) ) ) {
    FD_LOG_WARNING(( "unlink(\"%s\") failed (%i-%s)", path, errno, strerror( errno ) ));
    return errno;
  }

  return 0;
}

int
fd_shmem_info( char const *      name,
               ulong             page_sz,
               fd_shmem_info_t * opt_info ) {

  if( FD_UNLIKELY( !fd_shmem_name_len( name ) ) ) { FD_LOG_WARNING(( "bad name (%s)", name ? name : "NULL" )); return EINVAL; }

  if( !page_sz ) {
    if( !fd_shmem_info( name, FD_SHMEM_GIGANTIC_PAGE_SZ, opt_info ) ) return 0;
    if( !fd_shmem_info( name, FD_SHMEM_HUGE_PAGE_SZ,     opt_info ) ) return 0;
    if( !fd_shmem_info( name, FD_SHMEM_NORMAL_PAGE_SZ,   opt_info ) ) return 0;
    return ENOENT;
  }

  if( FD_UNLIKELY( !fd_shmem_is_page_sz( page_sz ) ) ) { FD_LOG_WARNING(( "bad page_sz (%lu)", page_sz )); return EINVAL; }

  char path[ FD_SHMEM_PRIVATE_PATH_BUF_MAX ];
  int  fd = open( fd_shmem_private_path( name, page_sz, path ), O_RDONLY, (mode_t)0 );
  if( FD_UNLIKELY( fd==-1 ) ) return errno; /* no logging here as this might be an existence check */

  struct stat stat[1];
  if( FD_UNLIKELY( fstat( fd, stat ) ) ) {
    FD_LOG_WARNING(( "fstat failed (%i-%s)", errno, strerror( errno ) ));
    int err = errno;
    if( FD_UNLIKELY( close( fd ) ) )
      FD_LOG_WARNING(( "close(\"%s\") failed (%i-%s); attempting to continue", path, errno, strerror( errno ) ));
    return err;
  }

  ulong sz = (ulong)stat->st_size;
  if( FD_UNLIKELY( !fd_ulong_is_aligned( sz, page_sz ) ) ) {
    FD_LOG_WARNING(( "\"%s\" size (%lu) not a page size (%lu) multiple\n\t"
                     "This thread group's hugetlbfs mount path (--shmem-path / FD_SHMEM_PATH):\n\t"
                     "\t%s\n\t"
                     "has probably been corrupted and needs to be redone.\n\t"
                     "See 'bin/fd_shmem_cfg help' for more information.",
                     path, sz, page_sz, fd_shmem_private_base ));
    if( FD_UNLIKELY( close( fd ) ) )
      FD_LOG_WARNING(( "close(\"%s\") failed (%i-%s); attempting to continue", path, errno, strerror( errno ) ));
    return EFAULT;
  }
  ulong page_cnt = sz / page_sz;

  if( FD_UNLIKELY( close( fd ) ) )
    FD_LOG_WARNING(( "close(\"%s\") failed (%i-%s); attempting to continue", path, errno, strerror( errno ) ));

  if( opt_info ) {
    opt_info->page_sz  = page_sz;
    opt_info->page_cnt = page_cnt;
  }
  return 0;
}

/* RAW PAGE ALLOCATION APIS *******************************************/

void
fd_shmem_release( void * mem,
                  ulong  page_sz,
                  ulong  page_cnt ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return;
  }

  if( FD_UNLIKELY( !fd_shmem_is_page_sz( page_sz ) ) ) {
    FD_LOG_WARNING(( "bad page_sz (%lu)", page_sz ));
    return;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, page_sz ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return;
  }

  if( FD_UNLIKELY( !((1UL<=page_cnt) & (page_cnt<=(((ulong)LONG_MAX)/page_sz))) ) ) {
    FD_LOG_WARNING(( "bad page_cnt (%lu)", page_cnt ));
    return;
  }

  ulong sz = page_sz*page_cnt;

  if( FD_UNLIKELY( munmap( mem, sz ) ) )
    FD_LOG_WARNING(( "munmap(anon,%lu KiB) failed (%i-%s); attempting to continue", sz>>10, errno, strerror( errno ) ));
}

/* SHMEM PARSING APIS *************************************************/

ulong
fd_shmem_name_len( char const * name ) {
  if( FD_UNLIKELY( !name ) ) return 0UL; /* NULL name */

  ulong len = 0UL;
  while( FD_LIKELY( len<FD_SHMEM_NAME_MAX ) ) {
    char c = name[len];
    if( FD_UNLIKELY( !c ) ) break;
    if( FD_UNLIKELY( !( (!!isalnum( c )) | ((len>0UL) & ((c=='_') | (c=='-') | (c=='.'))) ) ) ) return 0UL; /* Bad character */
    len++;
  }

  if( FD_UNLIKELY( !len                   ) ) return 0UL; /* Name too short (empty string) */
  if( FD_UNLIKELY( len>=FD_SHMEM_NAME_MAX ) ) return 0UL; /* Name too long */
  return len;
}

int
fd_cstr_to_shmem_lg_page_sz( char const * cstr ) {
  if( !cstr ) return FD_SHMEM_UNKNOWN_LG_PAGE_SZ;

  if( !fd_cstr_casecmp( cstr, "normal"   ) ) return FD_SHMEM_NORMAL_LG_PAGE_SZ;
  if( !fd_cstr_casecmp( cstr, "huge"     ) ) return FD_SHMEM_HUGE_LG_PAGE_SZ;
  if( !fd_cstr_casecmp( cstr, "gigantic" ) ) return FD_SHMEM_GIGANTIC_LG_PAGE_SZ;

  int i = fd_cstr_to_int( cstr );
  if( i==FD_SHMEM_NORMAL_LG_PAGE_SZ   ) return FD_SHMEM_NORMAL_LG_PAGE_SZ;
  if( i==FD_SHMEM_HUGE_LG_PAGE_SZ     ) return FD_SHMEM_HUGE_LG_PAGE_SZ;
  if( i==FD_SHMEM_GIGANTIC_LG_PAGE_SZ ) return FD_SHMEM_GIGANTIC_LG_PAGE_SZ;

  return FD_SHMEM_UNKNOWN_LG_PAGE_SZ;
}

char const *
fd_shmem_lg_page_sz_to_cstr( int lg_page_sz ) {
  switch( lg_page_sz ) {
  case FD_SHMEM_NORMAL_LG_PAGE_SZ:   return "normal";
  case FD_SHMEM_HUGE_LG_PAGE_SZ:     return "huge";
  case FD_SHMEM_GIGANTIC_LG_PAGE_SZ: return "gigantic";
  default:                           break;
  }
  return "unknown";
}

ulong
fd_cstr_to_shmem_page_sz( char const * cstr ) {
  if( !cstr ) return FD_SHMEM_UNKNOWN_PAGE_SZ;

  if( !fd_cstr_casecmp( cstr, "normal"   ) ) return FD_SHMEM_NORMAL_PAGE_SZ;
  if( !fd_cstr_casecmp( cstr, "huge"     ) ) return FD_SHMEM_HUGE_PAGE_SZ;
  if( !fd_cstr_casecmp( cstr, "gigantic" ) ) return FD_SHMEM_GIGANTIC_PAGE_SZ;

  ulong u = fd_cstr_to_ulong( cstr );
  if( u==FD_SHMEM_NORMAL_PAGE_SZ   ) return FD_SHMEM_NORMAL_PAGE_SZ;
  if( u==FD_SHMEM_HUGE_PAGE_SZ     ) return FD_SHMEM_HUGE_PAGE_SZ;
  if( u==FD_SHMEM_GIGANTIC_PAGE_SZ ) return FD_SHMEM_GIGANTIC_PAGE_SZ;

  return FD_SHMEM_UNKNOWN_PAGE_SZ;
}

char const *
fd_shmem_page_sz_to_cstr( ulong page_sz ) {
  switch( page_sz ) {
  case FD_SHMEM_NORMAL_PAGE_SZ:   return "normal";
  case FD_SHMEM_HUGE_PAGE_SZ:     return "huge";
  case FD_SHMEM_GIGANTIC_PAGE_SZ: return "gigantic";
  default:                        break;
  }
  return "unknown";
}

/* BOOT/HALT APIs *****************************************************/

void
fd_shmem_private_boot( int *    pargc,
                       char *** pargv ) {
  FD_LOG_INFO(( "fd_shmem: booting" ));

  /* Cache the numa topology for this thread group's host for
     subsequent fast use by the application. */

  ulong numa_cnt = fd_numa_node_cnt();
  if( FD_UNLIKELY( !((1UL<=numa_cnt) & (numa_cnt<=FD_SHMEM_NUMA_MAX)) ) )
    FD_LOG_ERR(( "fd_shmem: unexpected numa_cnt %lu (expected in [1,%lu])", numa_cnt, FD_SHMEM_NUMA_MAX ));
  fd_shmem_private_numa_cnt = numa_cnt;

  ulong cpu_cnt = fd_numa_cpu_cnt();
  if( FD_UNLIKELY( !((1UL<=cpu_cnt) & (cpu_cnt<=FD_SHMEM_CPU_MAX)) ) )
    FD_LOG_ERR(( "fd_shmem: unexpected cpu_cnt %lu (expected in [1,%lu])", cpu_cnt, FD_SHMEM_CPU_MAX ));
  fd_shmem_private_cpu_cnt = cpu_cnt;

  for( ulong cpu_rem=cpu_cnt; cpu_rem; cpu_rem-- ) {
    ulong cpu_idx  = cpu_rem-1UL;
    ulong numa_idx = fd_numa_node_idx( cpu_idx );
    if( FD_UNLIKELY( numa_idx>=FD_SHMEM_NUMA_MAX) )
      FD_LOG_ERR(( "fd_shmem: unexpected numa idx (%lu) for cpu idx %lu", numa_idx, cpu_idx ));
    fd_shmem_private_numa_idx[ cpu_idx  ] = (ushort)numa_idx;
    fd_shmem_private_cpu_idx [ numa_idx ] = (ushort)cpu_idx;
  }

  /* Determine the shared memory domain for this thread group */

  char const * shmem_base = fd_env_strip_cmdline_cstr( pargc, pargv, "--shmem-path", "FD_SHMEM_PATH", "/mnt/.fd" );

  ulong len = strlen( shmem_base );
  while( (len>1UL) && (shmem_base[len-1UL]=='/') ) len--; /* lop off any trailing slashes */
  if( FD_UNLIKELY( !len ) ) FD_LOG_ERR(( "Too short --shmem-base" ));
  if( FD_UNLIKELY( len>=FD_SHMEM_PRIVATE_BASE_MAX ) ) FD_LOG_ERR(( "Too long --shmem-base" ));
  fd_memcpy( fd_shmem_private_base, shmem_base, len );
  fd_shmem_private_base[len] = '\0';
  fd_shmem_private_base_len = (ulong)len;

  /* At this point, shared memory is online */

  FD_LOG_INFO(( "fd_shmem: --shmem-path %s", fd_shmem_private_base ));
  FD_LOG_INFO(( "fd_shmem: boot success" ));
}

void
fd_shmem_private_halt( void ) {
  FD_LOG_INFO(( "fd_shmem: halting" ));

  /* At this point, shared memory is offline */

  fd_shmem_private_numa_cnt = 0;
  fd_shmem_private_cpu_cnt  = 0;
  fd_memset( fd_shmem_private_numa_idx, 0, FD_SHMEM_CPU_MAX );

  fd_shmem_private_base[0] = '\0';
  fd_shmem_private_base_len = 0UL;

  FD_LOG_INFO(( "fd_shmem: halt success" ));
}

#else /* unhosted or not x86 */

void
fd_shmem_private_boot( int *    pargc,
                       char *** pargv ) {
  FD_LOG_INFO(( "fd_shmem: booting" ));

  /* Strip the command line even though ignored to make environemnt
     parsing identical to downstream regardless of platform. */

  (void)fd_env_strip_cmdline_cstr( pargc, pargv, "--shmem-path", "FD_SHMEM_PATH", "/mnt/.fd" );

  FD_LOG_INFO(( "fd_shmem: --shmem-path (ignored)" ));
  FD_LOG_INFO(( "fd_shmem: boot success" ));
}

void
fd_shmem_private_halt( void ) {
  FD_LOG_INFO(( "fd_shmem: halting" ));
  FD_LOG_INFO(( "fd_shmem: halt success" ));
}

#endif

