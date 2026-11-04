#include "fd_ip4.h"
#include "../fd_util.h"

#include <stdlib.h>


/* FIXME add bounds checks to fd_util version */
static int
__fd_cstr_to_uchar( char const * cstr ) {
  char const * endptr = NULL;
  ulong value = strtoul( cstr, (char **)&endptr, 10 );
  if( FD_UNLIKELY( cstr==endptr || endptr[0] || value>UCHAR_MAX ) ) return -1;
  return (int)value;
}

int
fd_cstr_to_ip4_addr( char const * s,
                     uint *       out ) {

  char _s[ 16 ];
  ulong len = strnlen( s, sizeof(_s) );
  if( FD_UNLIKELY( len==sizeof(_s) ) ) return 0;

  /* The tokenizer ignores a trailing delimiter. */
  ulong dot_cnt = 0UL;
  for( ulong i=0UL; i<len; i++ ) dot_cnt += (ulong)( s[i]=='.' );
  if( FD_UNLIKELY( dot_cnt!=3UL ) ) return 0;
  memcpy( _s, s, len+1UL );

  char *tok[ 5 ];
  if( FD_UNLIKELY( fd_cstr_tokenize( tok, 5UL, _s, '.' )!=4UL ) )
    return 0;

  int v0 = __fd_cstr_to_uchar( tok[ 0 ] );
  int v1 = __fd_cstr_to_uchar( tok[ 1 ] );
  int v2 = __fd_cstr_to_uchar( tok[ 2 ] );
  int v3 = __fd_cstr_to_uchar( tok[ 3 ] );
  if( FD_UNLIKELY( (v0<0)|(v1<0)|(v2<0)|(v3<0) ) ) return 0;
  *out = FD_IP4_ADDR( v0, v1, v2, v3 );
  return 1;
}
