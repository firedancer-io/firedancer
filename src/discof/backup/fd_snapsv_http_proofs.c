#include <stdlib.h>
#include <string.h>
#include "../../util/fd_util.h"
#include "../../util/cstr/fd_cstr.c" /* fd_cstr_ncpy is extern, needed by
                                        fd_ssarchive_parse_filename */

#undef  PATH_MAX
#define PATH_MAX (144)

#define FD_TILE_TEST 1
#include "fd_snapsv_tile.c"

#if !defined(CBMC)
#error "Intended to only be used from CBMC"
#endif

void
fd_log_private_1( int          level,
                  long         now,
                  char const * file,
                  int          line,
                  char const * func,
                  char const * msg ) {}


void
fd_log_private_2( int          level,
                  long         now,
                  char const * file,
                  int          line,
                  char const * func,
                  char const * msg ) __attribute__((noreturn)) {
  __CPROVER_assert( 0, "Error log used" );
}

long
fd_log_wallclock( void ) {
  long t;
  return t;
}

char const *
fd_log_private_0( char const * fmt, ... ) {
  (void)fmt;
  return "";
}

uchar nondet_uchar( void );
int   nondet_int  ( void );

/* CBMC does not have a builtin strtoul */

unsigned long
strtoul( char const * restrict nptr,
         char ** restrict     endptr,
         int                  base ) {
  __CPROVER_assert( base==10, "strtoul model supports base 10 only" );
  char const * p = nptr;
  while( (*p==' ') | (*p=='\t') | (*p=='\n') | (*p=='\v') | (*p=='\f') | (*p=='\r') ) p++;
  int neg = 0;
  if( (*p=='+') | (*p=='-') ) { neg = (*p=='-'); p++; }
  ulong v = 0UL;
  int any = 0;
  int overflow = 0;
  while( (*p>='0') & (*p<='9') ) {
    ulong d = (ulong)(*p-'0');
    if( v>(ULONG_MAX-d)/10UL ) overflow = 1;
    v = v*10UL + d;
    any = 1;
    p++;
  }
  if( endptr ) *endptr = (char *)( any ? p : nptr );
  if( overflow ) return ULONG_MAX; /* real impl also sets errno=ERANGE */
  return neg ? 0UL-v : v;
}

uchar *
fd_base58_decode_32( char const * encoded,
                     uchar        out[ static 32 ] ) {
  ulong n = strlen( encoded );
  __CPROVER_assert( n<=FD_BASE58_ENCODED_32_LEN, "base58 decode input oversized" );
  if( nondet_int() ) return NULL;
  for( ulong i=0UL; i<32UL; i++ ) out[ i ] = nondet_uchar();
  return out;
}

static void
proof_parse_range_header( void ) {
  char  value[ 64UL ];
  ulong value_len;
  __CPROVER_assume( value_len<=64UL );
  ulong object_sz;
  ulong range0, range1;

  int res = parse_range_header( value, value_len, object_sz, &range0, &range1 );
  if( res==0 ) {
    __CPROVER_assert( range0<range1,     "range0 < range1" );
    __CPROVER_assert( range1<=object_sz, "range1 <= object_sz" );
  } else {
    __CPROVER_assert( res==-1 || res==-2, "error code domain" );
  }
}

static void
proof_match_snapshot_path( void ) {
  char  path[ FD_SNAP_NAME_MAX+2UL ];
  ulong path_len;
  __CPROVER_assume( path_len<=FD_SNAP_NAME_MAX+2UL );
  snap_key_t key;
  uchar      hash[ 32 ];
  int        is_zstd;

  snap_key_t * res = match_snapshot_path( path, path_len, &key, hash, &is_zstd );
  if( res ) {
    __CPROVER_assert( res==&key, "returns out pointer" );
    __CPROVER_assert( !( (key.slot==ULONG_MAX) & (key.base_slot==ULONG_MAX) ),
                      "parsed key is never the map free sentinel" );
  }
}

void
cbmc_main( void ) {
  proof_parse_range_header();
  proof_match_snapshot_path();
}
