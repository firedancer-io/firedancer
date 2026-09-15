#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdlib.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "fd_jtok.h"

/* fuzz_jtok verifies that the tokenizer is safe against untrusted
   input: never reads past the end of the buffer, always terminates,
   and the explicit walk and the pure skip path agree on validity. */

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_core_set(3);
  return 0;
}

static void
walk( fd_jtok_t * j,
      ulong       depth ) {
  assert( j->cur<=j->end );
  if( depth>=FD_JTOK_SKIP_DEPTH_MAX ) { fd_jtok_skip( j ); return; }
  switch( fd_jtok_peek( j ) ) {
  case FD_JTOK_OBJ: {
    fd_jtok_str_t k;
    fd_jtok_obj_enter( j );
    while( fd_jtok_obj_next( j, &k ) ) {
      assert( k.ptr>=j->beg && k.ptr+k.sz<=j->end );
      fd_jtok_str_eq( &k, "key" );
      walk( j, depth+1UL );
    }
    break;
  }
  case FD_JTOK_ARR:
    fd_jtok_arr_enter( j );
    while( fd_jtok_arr_next( j ) ) walk( j, depth+1UL );
    break;
  case FD_JTOK_STR: {
    char buf[ 64 ];
    fd_jtok_t save = *j;
    fd_jtok_cstr( j, buf, sizeof(buf) );
    if( j->err==FD_JTOK_ERR_RANGE ) {
      /* too long for buf: consume as a raw view instead */
      fd_jtok_str_t s;
      *j = save;
      fd_jtok_str( j, &s );
      assert( !j->err );
      assert( s.ptr>=j->beg && s.ptr+s.sz<=j->end );
    } else if( !j->err ) {
      assert( strlen( buf )<sizeof(buf) );
    }
    break;
  }
  case FD_JTOK_INT: {
    fd_jtok_t save = *j;
    ulong u; long l;
    if( *j->cur=='-' ) fd_jtok_long( j, &l ); else fd_jtok_ulong( j, &u );
    if( j->err==FD_JTOK_ERR_RANGE ) { *j = save; fd_jtok_skip( j ); assert( !j->err ); }
    break;
  }
  case FD_JTOK_NUM: {
    fd_jtok_t save = *j;
    double d;
    fd_jtok_double( j, &d );
    if( j->err==FD_JTOK_ERR_RANGE ) { *j = save; fd_jtok_skip( j ); assert( !j->err ); }
    break;
  }
  case FD_JTOK_BOOL: { int b; fd_jtok_bool( j, &b ); break; }
  case FD_JTOK_NULL: fd_jtok_null( j ); break;
  default:
    assert( j->err );
    break;
  }
  assert( j->cur<=j->end );
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         data_sz ) {
  fd_jtok_t j[1];

  fd_jtok_init( j, data, data_sz );
  walk( j, 0UL );
  int walk_err = fd_jtok_fini( j );
  assert( j->cur<=j->end );
  assert( walk_err!=FD_JTOK_ERR_TYPE && walk_err!=FD_JTOK_ERR_RANGE && walk_err!=FD_JTOK_ERR_USAGE );

  fd_jtok_init( j, data, data_sz );
  char const * raw; ulong raw_sz = 0UL;
  fd_jtok_raw( j, &raw, &raw_sz );
  int skip_err = fd_jtok_fini( j );
  assert( j->cur<=j->end );
  /* Explicit nesting is unbounded, pure skipping is not: the only
     allowed disagreement is a valid document deeper than the skip
     limit. */
  if( walk_err ) assert( skip_err );
  else           assert( !skip_err || skip_err==FD_JTOK_ERR_DEPTH );
  if( !skip_err ) {
    assert( raw>=(char const *)data && raw+raw_sz<=(char const *)data+data_sz );
    FD_FUZZ_MUST_BE_COVERED;
  } else {
    assert( fd_jtok_err_off( j )<=data_sz );
    FD_FUZZ_MUST_BE_COVERED;
  }
  return 0;
}
