#include "fd_jtok.h"
#include "../fd_ballet.h"

#include <float.h>
#include <math.h>

/* Struct mapping example, exercised across key orders and noise */

struct cfg {
  char  commitment[ 16 ];
  char  encoding[ 16 ];
  int   has_slice;
  ulong off;
  ulong len;
  ulong min_ctx_slot;
  int   flag;
  long  delta;
  double ratio;
};

typedef struct cfg cfg_t;

static void
parse_cfg( fd_jtok_t * j,
           cfg_t *     c ) {
  fd_jtok_str_t k;
  fd_jtok_obj_enter( j );
  while( fd_jtok_obj_next( j, &k ) ) {
    if(      fd_jtok_str_eq( &k, "commitment"     ) ) fd_jtok_cstr  ( j, c->commitment, sizeof(c->commitment) );
    else if( fd_jtok_str_eq( &k, "encoding"       ) ) fd_jtok_cstr  ( j, c->encoding,   sizeof(c->encoding)   );
    else if( fd_jtok_str_eq( &k, "minContextSlot" ) ) fd_jtok_ulong ( j, &c->min_ctx_slot );
    else if( fd_jtok_str_eq( &k, "flag"           ) ) fd_jtok_bool  ( j, &c->flag );
    else if( fd_jtok_str_eq( &k, "delta"          ) ) fd_jtok_long  ( j, &c->delta );
    else if( fd_jtok_str_eq( &k, "ratio"          ) ) fd_jtok_double( j, &c->ratio );
    else if( fd_jtok_str_eq( &k, "dataSlice"      ) ) {
      c->has_slice = 1;
      fd_jtok_str_t k2;
      fd_jtok_obj_enter( j );
      while( fd_jtok_obj_next( j, &k2 ) ) {
        if(      fd_jtok_str_eq( &k2, "offset" ) ) fd_jtok_ulong( j, &c->off );
        else if( fd_jtok_str_eq( &k2, "length" ) ) fd_jtok_ulong( j, &c->len );
      }
    }
  }
}

static int
parse_cfg_cstr( char const * s,
                cfg_t *      c ) {
  fd_jtok_t j[1];
  fd_jtok_init( j, s, strlen( s ) );
  memset( c, 0, sizeof(*c) );
  parse_cfg( j, c );
  return fd_jtok_fini( j );
}

/* err_of tokenizes s with a generic walker and returns the error */

static void
walk( fd_jtok_t * j ) {
  switch( fd_jtok_peek( j ) ) {
  case FD_JTOK_OBJ: {
    fd_jtok_str_t k;
    fd_jtok_obj_enter( j );
    while( fd_jtok_obj_next( j, &k ) ) walk( j );
    break;
  }
  case FD_JTOK_ARR:
    fd_jtok_arr_enter( j );
    while( fd_jtok_arr_next( j ) ) walk( j );
    break;
  case FD_JTOK_STR:  { fd_jtok_str_t s; fd_jtok_str( j, &s ); break; }
  case FD_JTOK_INT:
  case FD_JTOK_NUM:  { double d; fd_jtok_double( j, &d ); break; }
  case FD_JTOK_BOOL: { int b; fd_jtok_bool( j, &b ); break; }
  case FD_JTOK_NULL: fd_jtok_null( j ); break;
  default: break;
  }
}

static int
err_of( char const * s ) {
  fd_jtok_t j[1];
  fd_jtok_init( j, s, strlen( s ) );
  walk( j );
  int e1 = fd_jtok_fini( j );
  fd_jtok_init( j, s, strlen( s ) );
  int e2 = fd_jtok_fini( j ); /* pure skip path */
  FD_TEST( (!e1)==(!e2) );
  return e1;
}

static int
cstr_of( char const * s,
         char *       out,
         ulong        out_sz ) {
  fd_jtok_t j[1];
  fd_jtok_init( j, s, strlen( s ) );
  fd_jtok_cstr( j, out, out_sz );
  return fd_jtok_fini( j );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* struct mapping */

  cfg_t c;
  FD_TEST( !parse_cfg_cstr( "{\"commitment\":\"finalized\",\"encoding\":\"base64\",\"dataSlice\":{\"offset\":1,\"length\":2},\"minContextSlot\":99}", &c ) );
  FD_TEST( !strcmp( c.commitment, "finalized" ) );
  FD_TEST( !strcmp( c.encoding, "base64" ) );
  FD_TEST( c.has_slice && c.off==1UL && c.len==2UL && c.min_ctx_slot==99UL );

  /* reordered, unknown keys of every kind auto-skipped, escapes in key */
  FD_TEST( !parse_cfg_cstr( " { \"junk\" : [ 1 , {\"x\":[[],{}]} , \"s\" , null , true ] ,\n"
                            "\"minContextSlot\" : 7 , \"nope\":{\"a\":{\"b\":{}}}, \"enc\\u006fding\" : \"base58\" ,"
                            "\"dataSlice\":{\"length\":5,\"zzz\":-1.5e3,\"offset\":4}, \"flag\":true, \"delta\":-42, \"ratio\":2.5 } ", &c ) );
  FD_TEST( !strcmp( c.encoding, "base58" ) );
  FD_TEST( c.commitment[0]=='\0' );
  FD_TEST( c.has_slice && c.off==4UL && c.len==5UL && c.min_ctx_slot==7UL );
  FD_TEST( c.flag==1 && c.delta==-42L && c.ratio==2.5 );

  /* empty object */
  FD_TEST( !parse_cfg_cstr( "{}", &c ) );

  /* type errors are sticky and reported once */
  FD_TEST( parse_cfg_cstr( "{\"minContextSlot\":\"7\"}",   &c )==FD_JTOK_ERR_TYPE  );
  FD_TEST( parse_cfg_cstr( "{\"minContextSlot\":7.0}",     &c )==FD_JTOK_ERR_TYPE  );
  FD_TEST( parse_cfg_cstr( "{\"minContextSlot\":-7}",      &c )==FD_JTOK_ERR_RANGE );
  FD_TEST( parse_cfg_cstr( "{\"encoding\":\"0123456789abcdef\"}", &c )==FD_JTOK_ERR_RANGE );
  FD_TEST( parse_cfg_cstr( "{\"encoding\":\"0123456789abcde\"}",  &c )==0 );
  FD_TEST( parse_cfg_cstr( "{\"encoding\":\"a\\u0000b\"}", &c )==FD_JTOK_ERR_RANGE );
  FD_TEST( parse_cfg_cstr( "{\"dataSlice\":[1,2]}",        &c )==FD_JTOK_ERR_TYPE  );
  FD_TEST( parse_cfg_cstr( "[]",                           &c )==FD_JTOK_ERR_TYPE  );
  FD_TEST( parse_cfg_cstr( "{\"flag\":null}",              &c )==FD_JTOK_ERR_TYPE  );
  FD_TEST( parse_cfg_cstr( "{} x",                         &c )==FD_JTOK_ERR_TRAIL );
  FD_TEST( parse_cfg_cstr( "{\"a\":1,}",                   &c )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( parse_cfg_cstr( "{\"a\" 1}",                    &c )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( parse_cfg_cstr( "{\"a\":1 \"b\":2}",            &c )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( parse_cfg_cstr( "{a:1}",                        &c )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( parse_cfg_cstr( "{\"a\":1",                     &c )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( parse_cfg_cstr( "",                             &c )==FD_JTOK_ERR_SYNTAX );

  /* error offset points at the fault */
  {
    fd_jtok_t j[1];
    fd_jtok_init( j, "{\"a\":1,\"b\":x}", 13UL );
    memset( &c, 0, sizeof(c) );
    parse_cfg( j, &c );
    FD_TEST( fd_jtok_fini( j )==FD_JTOK_ERR_SYNTAX );
    FD_TEST( fd_jtok_err_off( j )==11UL );
    FD_TEST( fd_jtok_err( j )==FD_JTOK_ERR_SYNTAX );
  }

  /* grammar: valid */
  FD_TEST( !err_of( "0" ) );
  FD_TEST( !err_of( "-0" ) );
  FD_TEST( !err_of( "  \t\r\n123  " ) );
  FD_TEST( !err_of( "1.5e+10" ) );
  FD_TEST( !err_of( "1E-2" ) );
  FD_TEST( !err_of( "\"\"" ) );
  FD_TEST( !err_of( "\"\\\"\\\\\\/\\b\\f\\n\\r\\t\\u00e9\\ud83d\\ude00\"" ) );
  FD_TEST( !err_of( "\"\xc3\xa9 \xe2\x82\xac \xf0\x9f\x98\x80\"" ) );
  FD_TEST( !err_of( "true" ) );
  FD_TEST( !err_of( "false" ) );
  FD_TEST( !err_of( "null" ) );
  FD_TEST( !err_of( "[]" ) );
  FD_TEST( !err_of( "[ ]" ) );
  FD_TEST( !err_of( "{ }" ) );
  FD_TEST( !err_of( "[[[[[[]]]]]]" ) );
  FD_TEST( !err_of( "[1,[2,[3,{\"a\":[4,{}]}]],\"x\"]" ) );
  FD_TEST( !err_of( "{\"a\":{\"b\":{\"c\":null}},\"d\":[]}" ) );

  /* grammar: invalid */
  FD_TEST( err_of( "" )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( err_of( " " )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( err_of( "01" )==FD_JTOK_ERR_TRAIL );
  FD_TEST( err_of( "1." )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( err_of( ".5" )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( err_of( "+1" )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( err_of( "-" )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( err_of( "1e" )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( err_of( "1e+" )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( err_of( "0x10" )==FD_JTOK_ERR_TRAIL );
  FD_TEST( err_of( "1 2" )==FD_JTOK_ERR_TRAIL );
  FD_TEST( err_of( "tru" )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( err_of( "True" )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( err_of( "nul" )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( err_of( "\"" )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( err_of( "\"abc" )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( err_of( "\"\\x\"" )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( err_of( "\"\\u12\"" )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( err_of( "\"\\u12g4\"" )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( err_of( "\"\\ud83d\"" )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( err_of( "\"\\ud83dx\"" )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( err_of( "\"\\ud83d\\u0041\"" )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( err_of( "\"\\ude00\"" )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( err_of( "\"a\nb\"" )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( err_of( "\"a\x01" "b\"" )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( err_of( "\"\x80\"" )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( err_of( "\"\xc0\xaf\"" )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( err_of( "\"\xed\xa0\x80\"" )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( err_of( "\"\xf4\x90\x80\x80\"" )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( err_of( "\"\xe2\x82\"" )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( err_of( "[" )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( err_of( "]" )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( err_of( "[1,]" )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( err_of( "[,1]" )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( err_of( "[1 2]" )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( err_of( "[1}" )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( err_of( "{1:2}" )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( err_of( "{\"a\"}" )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( err_of( "{\"a\":}" )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( err_of( "{\"a\":1]" )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( err_of( "{,}" )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( err_of( "[1]]" )==FD_JTOK_ERR_TRAIL );
  FD_TEST( err_of( "{}{}" )==FD_JTOK_ERR_TRAIL );
  FD_TEST( err_of( "/* c */ 1" )==FD_JTOK_ERR_SYNTAX );
  FD_TEST( err_of( "\f1" )==FD_JTOK_ERR_SYNTAX );

  /* skip depth limit */
  {
    char deep[ 2UL*FD_JTOK_SKIP_DEPTH_MAX+3UL ];
    ulong n = FD_JTOK_SKIP_DEPTH_MAX;
    for( ulong i=0UL; i<n; i++ ) { deep[i] = '['; deep[2UL*n-1UL-i] = ']'; }
    deep[ 2UL*n ] = '\0';
    fd_jtok_t j[1];
    fd_jtok_init( j, deep, 2UL*n );
    FD_TEST( !fd_jtok_fini( j ) );
    for( ulong i=0UL; i<n+1UL; i++ ) { deep[i] = '['; deep[2UL*n+1UL-i] = ']'; }
    deep[ 2UL*n+2UL ] = '\0';
    fd_jtok_init( j, deep, 2UL*n+2UL );
    FD_TEST( fd_jtok_fini( j )==FD_JTOK_ERR_DEPTH );
    /* explicit nesting is not subject to the limit */
    fd_jtok_init( j, deep, 2UL*n+2UL );
    for( ulong i=0UL; i<n+1UL; i++ ) { fd_jtok_arr_enter( j ); FD_TEST( fd_jtok_arr_next( j )==(i<n) ); }
    for( ulong i=0UL; i<n; i++ ) FD_TEST( !fd_jtok_arr_next( j ) );
    FD_TEST( !fd_jtok_fini( j ) );
  }

  /* numbers */
  {
    fd_jtok_t j[1]; ulong u; long l; double d;
    fd_jtok_init( j, "18446744073709551615", 20UL ); fd_jtok_ulong( j, &u ); FD_TEST( !fd_jtok_fini( j ) && u==ULONG_MAX );
    fd_jtok_init( j, "18446744073709551616", 20UL ); fd_jtok_ulong( j, &u ); FD_TEST( fd_jtok_fini( j )==FD_JTOK_ERR_RANGE );
    fd_jtok_init( j, "9223372036854775807",  19UL ); fd_jtok_long ( j, &l ); FD_TEST( !fd_jtok_fini( j ) && l==LONG_MAX );
    fd_jtok_init( j, "9223372036854775808",  19UL ); fd_jtok_long ( j, &l ); FD_TEST( fd_jtok_fini( j )==FD_JTOK_ERR_RANGE );
    fd_jtok_init( j, "-9223372036854775808", 20UL ); fd_jtok_long ( j, &l ); FD_TEST( !fd_jtok_fini( j ) && l==LONG_MIN );
    fd_jtok_init( j, "-9223372036854775809", 20UL ); fd_jtok_long ( j, &l ); FD_TEST( fd_jtok_fini( j )==FD_JTOK_ERR_RANGE );
    fd_jtok_init( j, "-0", 2UL ); fd_jtok_long( j, &l ); FD_TEST( !fd_jtok_fini( j ) && l==0L );
    fd_jtok_init( j, "0874", 4UL ); fd_jtok_ulong( j, &u ); FD_TEST( fd_jtok_fini( j )==FD_JTOK_ERR_TRAIL );
    fd_jtok_init( j, "[0874]", 6UL ); fd_jtok_arr_enter( j ); FD_TEST( fd_jtok_arr_next( j ) ); fd_jtok_ulong( j, &u ); FD_TEST( !fd_jtok_arr_next( j ) && fd_jtok_err( j )==FD_JTOK_ERR_SYNTAX );
    fd_jtok_init( j, "-0874", 5UL ); fd_jtok_long( j, &l ); FD_TEST( fd_jtok_fini( j )==FD_JTOK_ERR_TRAIL );
    fd_jtok_init( j, "0", 1UL ); u = 5UL; fd_jtok_ulong( j, &u ); FD_TEST( !fd_jtok_fini( j ) && u==0UL );
    fd_jtok_init( j, "1.5", 3UL ); fd_jtok_double( j, &d ); FD_TEST( !fd_jtok_fini( j ) && d==1.5 );
    fd_jtok_init( j, "-2e2", 4UL ); fd_jtok_double( j, &d ); FD_TEST( !fd_jtok_fini( j ) && d==-200.0 );
    fd_jtok_init( j, "7", 1UL ); fd_jtok_double( j, &d ); FD_TEST( !fd_jtok_fini( j ) && d==7.0 );
    fd_jtok_init( j, "\"7\"", 3UL ); fd_jtok_double( j, &d ); FD_TEST( fd_jtok_fini( j )==FD_JTOK_ERR_TYPE );
    fd_jtok_init( j, "1e999", 5UL ); fd_jtok_double( j, &d ); FD_TEST( fd_jtok_fini( j )==FD_JTOK_ERR_RANGE && fd_jtok_err_off( j )==0UL );
    fd_jtok_init( j, "-1e999", 6UL ); fd_jtok_double( j, &d ); FD_TEST( fd_jtok_fini( j )==FD_JTOK_ERR_RANGE );
    fd_jtok_init( j, "1e-999", 6UL ); fd_jtok_double( j, &d ); FD_TEST( fd_jtok_fini( j )==FD_JTOK_ERR_RANGE );
    fd_jtok_init( j, "1.7976931348623157e308", 22UL ); fd_jtok_double( j, &d ); FD_TEST( !fd_jtok_fini( j ) && d==DBL_MAX );
    char big[ FD_JTOK_NUM_SZ_MAX+2UL ]; memset( big, '1', sizeof(big) ); big[ sizeof(big)-1UL ] = '\0';
    fd_jtok_init( j, big, FD_JTOK_NUM_SZ_MAX+1UL ); fd_jtok_double( j, &d ); FD_TEST( fd_jtok_fini( j )==FD_JTOK_ERR_RANGE );
    /* out params untouched on failure */
    u = 123UL; fd_jtok_init( j, "\"x\"", 3UL ); fd_jtok_ulong( j, &u ); FD_TEST( fd_jtok_err( j )==FD_JTOK_ERR_TYPE && u==123UL );
    /* peek kinds */
    fd_jtok_init( j, " -1 ", 4UL );  FD_TEST( fd_jtok_peek( j )==FD_JTOK_INT  );
    fd_jtok_init( j, "1.0", 3UL );   FD_TEST( fd_jtok_peek( j )==FD_JTOK_NUM  );
    fd_jtok_init( j, "1e1", 3UL );   FD_TEST( fd_jtok_peek( j )==FD_JTOK_NUM  );
    fd_jtok_init( j, "{", 1UL );     FD_TEST( fd_jtok_peek( j )==FD_JTOK_OBJ  );
    fd_jtok_init( j, "[", 1UL );     FD_TEST( fd_jtok_peek( j )==FD_JTOK_ARR  );
    fd_jtok_init( j, "\"", 1UL );    FD_TEST( fd_jtok_peek( j )==FD_JTOK_STR  );
    fd_jtok_init( j, "t", 1UL );     FD_TEST( fd_jtok_peek( j )==FD_JTOK_BOOL );
    fd_jtok_init( j, "f", 1UL );     FD_TEST( fd_jtok_peek( j )==FD_JTOK_BOOL );
    fd_jtok_init( j, "n", 1UL );     FD_TEST( fd_jtok_peek( j )==FD_JTOK_NULL );
    fd_jtok_init( j, "x", 1UL );     FD_TEST( fd_jtok_peek( j )==0 && fd_jtok_err( j )==FD_JTOK_ERR_SYNTAX );
    fd_jtok_init( j, "", 0UL );      FD_TEST( fd_jtok_peek( j )==0 && fd_jtok_err( j )==FD_JTOK_ERR_SYNTAX );
    fd_jtok_init( j, NULL, 0UL );    FD_TEST( fd_jtok_err( j )==FD_JTOK_ERR_SYNTAX && fd_jtok_err_off( j )==0UL && fd_jtok_fini( j )==FD_JTOK_ERR_SYNTAX );
  }

  /* strings */
  {
    char out[ 16 ];
    FD_TEST( !cstr_of( "\"\"", out, sizeof(out) ) && !strcmp( out, "" ) );
    FD_TEST( !cstr_of( "\"abc\"", out, sizeof(out) ) && !strcmp( out, "abc" ) );
    FD_TEST( !cstr_of( "\"\\\"\\\\\\/\\b\\f\\n\\r\\t\"", out, sizeof(out) ) && !strcmp( out, "\"\\/\b\f\n\r\t" ) );
    FD_TEST( !cstr_of( "\"\\u0041\\u00e9\\u20ac\\ud83d\\ude00\"", out, sizeof(out) ) && !strcmp( out, "A\xc3\xa9\xe2\x82\xac\xf0\x9f\x98\x80" ) );
    FD_TEST( !cstr_of( "\"\\uD83D\\uDE00\"", out, sizeof(out) ) && !strcmp( out, "\xf0\x9f\x98\x80" ) );
    FD_TEST( !cstr_of( "\"\xf0\x9f\x98\x80\"", out, sizeof(out) ) && !strcmp( out, "\xf0\x9f\x98\x80" ) );
    FD_TEST( !cstr_of( "\"123456789012345\"", out, sizeof(out) ) && !strcmp( out, "123456789012345" ) );
    FD_TEST(  cstr_of( "\"1234567890123456\"", out, sizeof(out) )==FD_JTOK_ERR_RANGE && out[0]=='\0' );
    FD_TEST(  cstr_of( "\"\\u0000\"", out, sizeof(out) )==FD_JTOK_ERR_RANGE && out[0]=='\0' );
    FD_TEST(  cstr_of( "\"\"", out, 0UL )==FD_JTOK_ERR_RANGE );
    FD_TEST( !cstr_of( "\"\"", out, 1UL ) && out[0]=='\0' );
    FD_TEST(  cstr_of( "5", out, sizeof(out) )==FD_JTOK_ERR_TYPE && out[0]=='\0' );

    fd_jtok_t j[1]; fd_jtok_str_t s;
    fd_jtok_init( j, " \"a\\nb\" ", 8UL ); fd_jtok_str( j, &s ); FD_TEST( !fd_jtok_fini( j ) );
    FD_TEST( s.sz==4UL && !memcmp( s.ptr, "a\\nb", 4UL ) );
    FD_TEST(  fd_jtok_str_eq( &s, "a\nb" ) );
    FD_TEST( !fd_jtok_str_eq( &s, "a\\nb" ) );
    FD_TEST( !fd_jtok_str_eq( &s, "a\nbc" ) );
    FD_TEST( !fd_jtok_str_eq( &s, "a\n" ) );
    FD_TEST( !fd_jtok_str_eq( &s, "" ) );
    FD_TEST( fd_jtok_str_decode( &s, out, sizeof(out) )==3L && !strcmp( out, "a\nb" ) );
    FD_TEST( fd_jtok_str_decode( &s, out, 4UL )==3L && !strcmp( out, "a\nb" ) );
    FD_TEST( fd_jtok_str_decode( &s, out, 3UL )==-1L && out[0]=='\0' );
    FD_TEST( fd_jtok_str_decode( &s, out, 0UL )==-1L );
    fd_jtok_str_t e = { "", 0UL };
    FD_TEST( fd_jtok_str_decode( &e, out, sizeof(out) )==0L && out[0]=='\0' );
    FD_TEST(  fd_jtok_str_eq( &e, "" ) );
    FD_TEST( !fd_jtok_str_eq( &e, "a" ) );
    fd_jtok_str_t u = { "\\ud83d\\ude00x", 13UL };
    FD_TEST(  fd_jtok_str_eq( &u, "\xf0\x9f\x98\x80x" ) );
    FD_TEST( !fd_jtok_str_eq( &u, "\xf0\x9f\x98\x80" ) );
    fd_jtok_str_t z = { "\\u0000", 6UL };
    FD_TEST( !fd_jtok_str_eq( &z, "" ) );
    FD_TEST( fd_jtok_str_decode( &z, out, sizeof(out) )==-1L && out[0]=='\0' );
  }

  /* raw, arrays, pending semantics */
  {
    fd_jtok_t j[1]; char const * p; ulong sz; ulong u;
    char const * doc = "{\"id\": {\"a\":[1, 2]} ,\"params\":[10,20,30],\"z\":null}";
    fd_jtok_init( j, doc, strlen( doc ) );
    fd_jtok_str_t k;
    ulong sum = 0UL; ulong cnt = 0UL; int saw_null = 0;
    fd_jtok_obj_enter( j );
    while( fd_jtok_obj_next( j, &k ) ) {
      if( fd_jtok_str_eq( &k, "id" ) ) {
        fd_jtok_raw( j, &p, &sz );
        FD_TEST( sz==12UL && !memcmp( p, "{\"a\":[1, 2]}", 12UL ) );
      } else if( fd_jtok_str_eq( &k, "params" ) ) {
        fd_jtok_arr_enter( j );
        while( fd_jtok_arr_next( j ) ) {
          cnt++;
          if( cnt==2UL ) continue; /* auto-skipped */
          fd_jtok_ulong( j, &u );
          sum += u;
        }
      } else if( fd_jtok_str_eq( &k, "z" ) ) {
        saw_null = (fd_jtok_peek( j )==FD_JTOK_NULL);
        fd_jtok_null( j );
      }
    }
    FD_TEST( !fd_jtok_fini( j ) );
    FD_TEST( cnt==3UL && sum==40UL && saw_null );

    /* top-level pending value skipped by fini */
    fd_jtok_init( j, doc, strlen( doc ) );
    FD_TEST( !fd_jtok_fini( j ) );

    /* usage errors */
    fd_jtok_init( j, "1", 1UL ); fd_jtok_ulong( j, &u ); fd_jtok_ulong( j, &u ); FD_TEST( fd_jtok_err( j )==FD_JTOK_ERR_USAGE );
    fd_jtok_init( j, "1", 1UL ); FD_TEST( !fd_jtok_arr_next( j ) && fd_jtok_err( j )==FD_JTOK_ERR_USAGE );
    fd_jtok_init( j, "{}", 2UL ); fd_jtok_obj_enter( j ); FD_TEST( fd_jtok_fini( j )==FD_JTOK_ERR_USAGE );
    fd_jtok_init( j, "[1]", 3UL ); fd_jtok_obj_enter( j ); FD_TEST( fd_jtok_err( j )==FD_JTOK_ERR_TYPE );
    fd_jtok_init( j, "{}", 2UL ); fd_jtok_arr_enter( j ); FD_TEST( fd_jtok_err( j )==FD_JTOK_ERR_TYPE );

    /* everything after an error is a no-op */
    fd_jtok_init( j, "[x]", 3UL );
    fd_jtok_arr_enter( j );
    FD_TEST( fd_jtok_arr_next( j ) );
    FD_TEST( !fd_jtok_peek( j ) && fd_jtok_err( j )==FD_JTOK_ERR_SYNTAX );
    ulong off = fd_jtok_err_off( j );
    u = 9UL; fd_jtok_ulong( j, &u ); FD_TEST( u==9UL );
    FD_TEST( !fd_jtok_obj_next( j, &k ) && !fd_jtok_arr_next( j ) && !fd_jtok_peek( j ) );
    fd_jtok_skip( j ); fd_jtok_raw( j, &p, &sz );
    FD_TEST( fd_jtok_fini( j )==FD_JTOK_ERR_SYNTAX && fd_jtok_err_off( j )==off );
  }

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
