#include "fd_shmem.h"

#if FD_HAS_HOSTED && FD_HAS_X86

/* NUMA TOPOLOGY APIS *************************************************/

#include <errno.h>   /* For errno */
#include <numa.h>    /* For numa_* */

static ulong fd_shmem_private_numa_cnt;                     /* 0UL at thread group start, initialized at boot */
static ulong fd_shmem_private_cpu_cnt;                      /* " */
static uchar fd_shmem_private_numa_idx[ FD_SHMEM_CPU_MAX ]; /* " */

ulong fd_shmem_numa_cnt( void ) { return fd_shmem_private_numa_cnt; }
ulong fd_shmem_cpu_cnt ( void ) { return fd_shmem_private_cpu_cnt;  }

ulong fd_shmem_numa_idx( ulong cpu_idx ) {
  if( FD_UNLIKELY( cpu_idx>=fd_shmem_private_cpu_cnt ) ) return ULONG_MAX;
  return fd_shmem_private_numa_idx[ cpu_idx ];
}

/* SHMEM REGION CREATION AND DESTRUCTION ******************************/

/* Want strlen(base)+strlen("/.")+strlen(page)+strlen("/")+strlen(name)+1 <= BUF_MAX
     -> BASE_MAX-1  +2           +PAGE_MAX-1  +1          +NAME_MAX-1  +1 == BUF_MAX
     -> BASE_MAX == BUF_MAX - NAME_MAX - PAGE_MAX - 1 */

#define FD_SHMEM_PRIVATE_PATH_BUF_MAX  (256UL)
#define FD_SHMEM_PRIVATE_BASE_MAX (FD_SHMEM_PRIVATE_PATH_BUF_MAX-FD_SHMEM_NAME_MAX-FD_SHMEM_PAGE_SZ_CSTR_MAX-1UL)

static char  fd_shmem_private_base[ FD_SHMEM_PRIVATE_BASE_MAX ]; /* ""  at thread group start, initialized at boot */
static ulong fd_shmem_private_base_len;                          /* 0UL at ",                  initialized at boot */

/* SHMEM PARSING APIS *************************************************/

#include <ctype.h>   /* For isalnum */
#include <strings.h> /* For strcasecmp */

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

  if( !strcasecmp( cstr, "normal"   ) ) return FD_SHMEM_NORMAL_LG_PAGE_SZ;
  if( !strcasecmp( cstr, "huge"     ) ) return FD_SHMEM_HUGE_LG_PAGE_SZ;
  if( !strcasecmp( cstr, "gigantic" ) ) return FD_SHMEM_GIGANTIC_LG_PAGE_SZ;

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

  if( !strcasecmp( cstr, "normal"   ) ) return FD_SHMEM_NORMAL_PAGE_SZ;
  if( !strcasecmp( cstr, "huge"     ) ) return FD_SHMEM_HUGE_PAGE_SZ;
  if( !strcasecmp( cstr, "gigantic" ) ) return FD_SHMEM_GIGANTIC_PAGE_SZ;

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

  if( FD_UNLIKELY( numa_available()==-1 ) ) FD_LOG_ERR(( "fd_shmem: numa available failed" ));

  int numa_cnt = numa_num_configured_nodes();
  if( FD_UNLIKELY( !(1<=numa_cnt && numa_cnt<=(int)FD_SHMEM_NUMA_MAX) ) )
    FD_LOG_ERR(( "fd_shmem: unexpected numa_cnt %i (expected in [1,%lu])", numa_cnt, FD_SHMEM_NUMA_MAX ));
  fd_shmem_private_numa_cnt = (ulong)numa_cnt;

  int cpu_cnt = numa_num_configured_cpus();
  if( FD_UNLIKELY( !(1<=cpu_cnt && cpu_cnt<=(int)FD_SHMEM_CPU_MAX) ) )
    FD_LOG_ERR(( "fd_shmem: unexpected cpu_cnt %i (expected in [1,%lu])", cpu_cnt, FD_SHMEM_CPU_MAX ));
  fd_shmem_private_cpu_cnt = (ulong)cpu_cnt;

  for( int cpu_idx=0; cpu_idx<cpu_cnt; cpu_idx++ ) {
    int numa_idx = numa_node_of_cpu( cpu_idx );
    if( FD_UNLIKELY( !((0<=numa_idx) & (numa_idx<(int)FD_SHMEM_NUMA_MAX)) ) )
      FD_LOG_ERR(( "fd_shmem: unexpected numa idx (%i) for cpu idx %i (%i-%s)", numa_idx, cpu_idx, errno, strerror( errno ) ));
    fd_shmem_private_numa_idx[ cpu_idx ] = (uchar)numa_idx;
  }

  /* Determine the shared memory domain for this thread group */

  char const * shmem_base = fd_env_strip_cmdline_cstr( pargc, pargv, "--shmem-path", "FD_SHMEM_PATH", "/mnt/.fd" );

  ulong len = strlen( shmem_base );
  while( (len>1UL) && (shmem_base[len-1UL]=='/') ) len--; /* lop off any trailing slashes */
  if( FD_UNLIKELY( !len ) ) FD_LOG_ERR(( "Too short --shmem-base" ));
  if( FD_UNLIKELY( len>=FD_SHMEM_PRIVATE_BASE_MAX ) ) FD_LOG_ERR(( "Too long --shmem-base" ));
  memcpy( fd_shmem_private_base, shmem_base, len );
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
  memset( fd_shmem_private_numa_idx, 0, FD_SHMEM_CPU_MAX );

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

