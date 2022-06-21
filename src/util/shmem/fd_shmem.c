#include "fd_shmem.h"

#if FD_HAS_HOSTED && FD_HAS_X86

#include <ctype.h>   /* For isalnum */
#include <strings.h> /* For strcasecmp */

/* Want strlen(path)+strlen("/")+strlen(name)+1 <= FD_SHMEM_PRIVATE_BUF_MAX
     -> PATH_MAX-1  +1          +NAME_MAX-1  +1 == FD_SHMEM_PRIVATE_BUF_MAX
     -> PATH_MAX = FD_SHMEM_PRIVATE_BUF_MAX - FD_SHMEM_NAME_MAX */

#define FD_SHMEM_PRIVATE_BUF_MAX  (256UL)
#define FD_SHMEM_PRIVATE_PATH_MAX (FD_SHMEM_PRIVATE_BUF_MAX-FD_SHMEM_NAME_MAX)
static char fd_shmem_private_path[ FD_SHMEM_PRIVATE_PATH_MAX ]; /* "" at thread group start */

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

void
fd_shmem_private_boot( int *    pargc,
                       char *** pargv ) {
  FD_LOG_INFO(( "fd_shmem: booting" ));

  /* Determine the shared memory domain for this thread group */

  char const * shmem_path = fd_env_strip_cmdline_cstr( pargc, pargv, "--shmem-path", "FD_SHMEM_PATH", "/mnt/.fd" );

  ulong len = strlen( shmem_path );
  while( (len>1UL) && (shmem_path[len-1UL]=='/') ) len--; /* lop off any trailing slashes */
  if( FD_UNLIKELY( !len ) ) FD_LOG_ERR(( "Too short --shmem-path" ));
  if( FD_UNLIKELY( len>=FD_SHMEM_PRIVATE_PATH_MAX ) ) FD_LOG_ERR(( "Too long --shmem-path" ));
  memcpy( fd_shmem_private_path, shmem_path, len );
  fd_shmem_private_path[len] = '\0';

  /* At this point, shared memory is online */

  FD_LOG_INFO(( "fd_shmem: --shmem-path %s", fd_shmem_private_path ));
  FD_LOG_INFO(( "fd_shmem: boot success" ));
}

void
fd_shmem_private_halt( void ) {
  FD_LOG_INFO(( "fd_shmem: halting" ));

  /* At this point, shared memory is offline */

  fd_shmem_private_path[0] = '\0';
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

