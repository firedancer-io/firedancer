#include "fd_shmem.h" /* Avoid empty translation unit */

#if FD_HAS_HOSTED && FD_HAS_X86

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

#endif

