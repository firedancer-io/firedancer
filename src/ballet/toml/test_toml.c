#include "fd_toml.h"
#include "../../util/fd_util.h"

#include <math.h>

static char           buf[ 4096 ];
static fd_toml_node_t nodes[ 64 ];
static fd_toml_doc_t  doc[1];

/* parse copies toml into a mutable buffer and parses it into doc with
   node_max nodes.  Returns the fd_toml_parse error code. */

static int
parse_n( char const * toml,
         ulong        node_max ) {
  ulong sz = strlen( toml );
  FD_TEST( sz<sizeof(buf) );
  fd_memcpy( buf, toml, sz );
  return fd_toml_parse( doc, buf, sz, nodes, node_max, NULL );
}

static int
parse( char const * toml ) {
  return parse_n( toml, sizeof(nodes)/sizeof(nodes[0]) );
}

static fd_toml_node_t *
get( char const * path ) {
  fd_toml_node_t * n = fd_toml_get( doc, NULL, path );
  FD_TEST( n );
  return n;
}

static char const *
get_str( char const * path ) {
  fd_toml_node_t * n = get( path );
  FD_TEST( n->type==FD_TOML_NODE_STRING );
  char const * s = fd_toml_node_str( doc, n );
  FD_TEST( strlen( s )==n->str.len );
  return s;
}

static void
expect_str( char const * toml,
            char const * path,
            char const * expected ) {
  FD_TEST( parse( toml )==FD_TOML_SUCCESS );
  char const * got = get_str( path );
  if( FD_UNLIKELY( strcmp( got, expected ) ) ) {
    FD_LOG_ERR(( "toml %s: got \"%s\" expected \"%s\"", toml, got, expected ));
  }
}

static void
test_float_frac( void ) {
  static struct { char const * toml; double expected; } const cases[] = {
    { "x = 0.25",      0.25      },
    { "x = 1.25",      1.25      },
    { "x = 3.14",      3.14      },
    { "x = 0.5",       0.5       },
    { "x = 0.025",     0.025     },
    { "x = 12.5",      12.5      },
    { "x = 0.2_5",     0.25      },
    { "x = 0.2_5_0",   0.250     },
    { "x = 1.0",       1.0       },
    { "x = 100.001",   100.001   },
    { "x = 0.125e1",   1.25      },
    { "x = -3.14",     -3.14     },
    { "x = -0.25",     -0.25     },
    { "x = -12.5",     -12.5     },
    { NULL, 0.0 }
  };

  for( ulong i=0UL; cases[i].toml; i++ ) {
    FD_TEST( parse( cases[i].toml )==FD_TOML_SUCCESS );
    fd_toml_node_t * n = get( "x" );
    FD_TEST( n->type==FD_TOML_NODE_FLOAT );
    double got = n->f;
    double exp = cases[i].expected;
    double tol = fabs( exp ) * 1e-9 + 1e-12;
    if( FD_UNLIKELY( !isfinite( got ) || fabs( got - exp ) > tol ) ) {
      FD_LOG_ERR(( "toml %s: got %.17g expected %.17g", cases[i].toml, got, exp ));
    }
  }
}

static void
test_int_and_exp( void ) {
  FD_TEST( parse( "x = 250" )==FD_TOML_SUCCESS );
  FD_TEST( get( "x" )->type==FD_TOML_NODE_INT && get( "x" )->i==250L );

  FD_TEST( parse( "x = 2_500" )==FD_TOML_SUCCESS );
  FD_TEST( get( "x" )->i==2500L );

  FD_TEST( parse( "x = -7" )==FD_TOML_SUCCESS );
  FD_TEST( get( "x" )->i==-7L );

  FD_TEST( parse( "x = 0xff" )==FD_TOML_SUCCESS );
  FD_TEST( get( "x" )->i==255L );

  FD_TEST( parse( "x = 0o17" )==FD_TOML_SUCCESS );
  FD_TEST( get( "x" )->i==15L );

  FD_TEST( parse( "x = 0b101" )==FD_TOML_SUCCESS );
  FD_TEST( get( "x" )->i==5L );

  FD_TEST( parse( "x = 2e3" )==FD_TOML_SUCCESS );
  FD_TEST( fabs( get( "x" )->f - 2000.0 ) < 1e-9 );

  FD_TEST( parse( "x = 1.5e-2" )==FD_TOML_SUCCESS );
  FD_TEST( fabs( get( "x" )->f - 0.015 ) < 1e-12 );

  FD_TEST( parse( "x = 99999999999999999999" )==FD_TOML_ERR_RANGE );
  FD_TEST( parse( "x = inf" )==FD_TOML_ERR_RANGE );
}

static void
test_bool( void ) {
  FD_TEST( parse( "a = true\nb = false" )==FD_TOML_SUCCESS );
  FD_TEST( get( "a" )->type==FD_TOML_NODE_BOOL && get( "a" )->b==1 );
  FD_TEST( get( "b" )->type==FD_TOML_NODE_BOOL && get( "b" )->b==0 );
}

static void
test_strings( void ) {
  expect_str( "x = \"hello\"",                 "x", "hello" );
  expect_str( "x = \"\"",                      "x", "" );
  expect_str( "x = ''",                        "x", "" );
  expect_str( "x = 'C:\\path\\n'",             "x", "C:\\path\\n" );
  expect_str( "x = \"a\\tb\\\"c\\\\d\\n\"",    "x", "a\tb\"c\\d\n" );
  expect_str( "x = \"\\u00e9\"",               "x", "\xc3\xa9" );
  expect_str( "x = \"\\U0001F600\"",           "x", "\xf0\x9f\x98\x80" );
  expect_str( "x = \"\\u0041\\u0042\"",        "x", "AB" );

  /* escapes shrink in place, the following key still parses */
  FD_TEST( parse( "x = \"\\n\\n\\n\"\ny = 1" )==FD_TOML_SUCCESS );
  FD_TEST( !strcmp( get_str( "x" ), "\n\n\n" ) );
  FD_TEST( get( "y" )->i==1L );

  /* multi-line basic */
  expect_str( "x = \"\"\"\nabc\"\"\"",         "x", "abc" );
  expect_str( "x = \"\"\"a\nb\"\"\"",          "x", "a\nb" );
  expect_str( "x = \"\"\"a\"\"b\"\"\"",        "x", "a\"\"b" );
  expect_str( "x = \"\"\"\"abc\"\"\"\"",       "x", "\"abc\"" );
  expect_str( "x = \"\"\"abc\"\"\"\"\"",       "x", "abc\"\"" );
  expect_str( "x = \"\"\"a\\\n   b\"\"\"",     "x", "ab" );
  expect_str( "x = \"\"\"a\\\n\n  \n b\"\"\"", "x", "ab" );
  expect_str( "x = \"\"\"a\\tb\"\"\"",         "x", "a\tb" );

  /* multi-line literal */
  expect_str( "x = '''\nabc'''",               "x", "abc" );
  expect_str( "x = '''a''b'''",                "x", "a''b" );
  expect_str( "x = ''''abc''''",               "x", "'abc'" );
  expect_str( "x = '''a\\nb'''",               "x", "a\\nb" );

  /* unterminated */
  FD_TEST( parse( "x = \"abc" )==FD_TOML_ERR_PARSE );
  FD_TEST( parse( "x = \"\"\"abc" )==FD_TOML_ERR_PARSE );
  FD_TEST( parse( "x = \"a\\qb\"" )==FD_TOML_ERR_PARSE );
}

static void
test_keys( void ) {
  FD_TEST( parse( "a.b.c = 1" )==FD_TOML_SUCCESS );
  FD_TEST( get( "a.b.c" )->i==1L );
  FD_TEST( get( "a" )->type==FD_TOML_NODE_TABLE );

  FD_TEST( parse( "[a.b]\nc = 1\n[a]\nd = 2" )==FD_TOML_SUCCESS );
  FD_TEST( get( "a.b.c" )->i==1L );
  FD_TEST( get( "a.d" )->i==2L );

  /* quoted keys keep their dots */
  FD_TEST( parse( "[\"a.b\"]\nc = 1" )==FD_TOML_SUCCESS );
  FD_TEST( !fd_toml_get( doc, NULL, "a" ) );
  fd_toml_node_t * ab = fd_toml_child( doc, fd_toml_root( doc ), "a.b", 3UL );
  FD_TEST( ab && ab->type==FD_TOML_NODE_TABLE );
  FD_TEST( fd_toml_get( doc, ab, "c" )->i==1L );

  FD_TEST( parse( "\"k\\u0020x\" = 1" )==FD_TOML_SUCCESS );
  FD_TEST( fd_toml_child( doc, fd_toml_root( doc ), "k x", 3UL ) );

  FD_TEST( parse( "'lit' = 1" )==FD_TOML_SUCCESS );
  FD_TEST( get( "lit" )->i==1L );

  FD_TEST( parse( "a = 1\na = 2" )==FD_TOML_ERR_DUP );
  FD_TEST( parse( "a = 1\na.b = 2" )==FD_TOML_ERR_DUP );
  FD_TEST( parse( "a = 1\n[a]\nb = 2" )==FD_TOML_ERR_DUP );
  FD_TEST( parse( "[a]\nb = 1\n[a]\nb = 2" )==FD_TOML_ERR_DUP );

  FD_TEST( parse( "x = { a = 1, b = { c = 2 } }\ny = 3" )==FD_TOML_SUCCESS );
  FD_TEST( get( "x.a" )->i==1L );
  FD_TEST( get( "x.b.c" )->i==2L );
  FD_TEST( get( "y" )->i==3L );

  ulong key_len;
  char const * key = fd_toml_node_key( doc, get( "x.b" ), &key_len );
  FD_TEST( key_len==1UL && key[0]=='b' );
}

static void
test_arrays( void ) {
  FD_TEST( parse( "x = [1, \"s\", [2, 3], { a = 4 }]\ny = []" )==FD_TOML_SUCCESS );
  fd_toml_node_t * x = get( "x" );
  FD_TEST( x->type==FD_TOML_NODE_ARRAY );
  fd_toml_node_t * e = fd_toml_child_first( doc, x );
  FD_TEST( e && e->type==FD_TOML_NODE_INT && e->i==1L && e->key_len==0U );
  e = fd_toml_child_next( doc, e );
  FD_TEST( e && e->type==FD_TOML_NODE_STRING && !strcmp( fd_toml_node_str( doc, e ), "s" ) );
  e = fd_toml_child_next( doc, e );
  FD_TEST( e && e->type==FD_TOML_NODE_ARRAY );
  FD_TEST( fd_toml_child_first( doc, e )->i==2L );
  FD_TEST( fd_toml_child_next( doc, fd_toml_child_first( doc, e ) )->i==3L );
  e = fd_toml_child_next( doc, e );
  FD_TEST( e && e->type==FD_TOML_NODE_TABLE );
  FD_TEST( fd_toml_get( doc, e, "a" )->i==4L );
  FD_TEST( !fd_toml_child_next( doc, e ) );
  FD_TEST( get( "y" )->type==FD_TOML_NODE_ARRAY && !fd_toml_child_first( doc, get( "y" ) ) );

  FD_TEST( parse( "x = [\n  1, # c\n  2,\n]" )==FD_TOML_SUCCESS );
  FD_TEST( fd_toml_child_next( doc, fd_toml_child_first( doc, get( "x" ) ) )->i==2L );

  /* array tables */
  FD_TEST( parse( "[[t]]\nk = 1\n[[t]]\nk = 2\n[t.sub]\nv = 3" )==FD_TOML_SUCCESS );
  fd_toml_node_t * t = get( "t" );
  FD_TEST( t->type==FD_TOML_NODE_ARRAY );
  fd_toml_node_t * t0 = fd_toml_child_first( doc, t );
  fd_toml_node_t * t1 = fd_toml_child_next( doc, t0 );
  FD_TEST( t0 && t1 && !fd_toml_child_next( doc, t1 ) );
  FD_TEST( fd_toml_get( doc, t0, "k" )->i==1L );
  FD_TEST( fd_toml_get( doc, t1, "k" )->i==2L );
  FD_TEST( fd_toml_get( doc, t1, "sub.v" )->i==3L );
  FD_TEST( !fd_toml_get( doc, t0, "sub" ) );
}

static void
test_nodes( void ) {
  FD_TEST( parse_n( "a = 1\nb = 2", 0UL )==FD_TOML_ERR_NODE );
  FD_TEST( parse_n( "a = 1\nb = 2", 2UL )==FD_TOML_ERR_NODE );
  FD_TEST( parse_n( "a = 1\nb = 2", 3UL )==FD_TOML_SUCCESS );
  FD_TEST( doc->node_cnt==3UL );

  FD_TEST( parse( "" )==FD_TOML_SUCCESS );
  FD_TEST( doc->node_cnt==1UL );
  FD_TEST( !fd_toml_child_first( doc, fd_toml_root( doc ) ) );

  fd_toml_err_info_t err[1];
  char toml[] = "a = 1\nb = 2\nc = ?\n";
  FD_TEST( fd_toml_parse( doc, toml, sizeof(toml)-1UL, nodes, 64UL, err )==FD_TOML_ERR_PARSE );
  FD_TEST( err->line==3UL );
}

static void
test_leftover( void ) {
  char path[ 64 ];
  FD_TEST( parse( "a = 1\n[t]\nb = 2\nc = [3, 4]\n[[arr]]\nd = 5\ne = []" )==FD_TOML_SUCCESS );

  fd_toml_node_t * left = fd_toml_find_leftover( doc, fd_toml_root( doc ) );
  FD_TEST( left==get( "a" ) );
  FD_TEST( fd_toml_node_path( doc, left, path, sizeof(path) )==1UL && !strcmp( path, "a" ) );
  fd_toml_node_consume( left );

  left = fd_toml_find_leftover( doc, fd_toml_root( doc ) );
  FD_TEST( left==get( "t.b" ) );
  fd_toml_node_path( doc, left, path, sizeof(path) );
  FD_TEST( !strcmp( path, "t.b" ) );
  fd_toml_node_consume( left );

  left = fd_toml_find_leftover( doc, fd_toml_root( doc ) );
  FD_TEST( left==fd_toml_child_first( doc, get( "t.c" ) ) );
  fd_toml_node_path( doc, left, path, sizeof(path) );
  FD_TEST( !strcmp( path, "t.c[0]" ) );
  fd_toml_node_consume( get( "t.c" ) );

  left = fd_toml_find_leftover( doc, fd_toml_root( doc ) );
  fd_toml_node_path( doc, left, path, sizeof(path) );
  FD_TEST( !strcmp( path, "arr[0].d" ) );
  fd_toml_node_consume( left );

  left = fd_toml_find_leftover( doc, fd_toml_root( doc ) );
  fd_toml_node_path( doc, left, path, sizeof(path) );
  FD_TEST( !strcmp( path, "arr[0].e" ) );
  FD_TEST( left->type==FD_TOML_NODE_ARRAY );
  fd_toml_node_consume( left );

  FD_TEST( !fd_toml_find_leftover( doc, fd_toml_root( doc ) ) );

  FD_TEST( fd_toml_node_path( doc, get( "t.b" ), path, 3UL )==2UL && !strcmp( path, "t." ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_float_frac();
  test_int_and_exp();
  test_bool();
  test_strings();
  test_keys();
  test_arrays();
  test_nodes();
  test_leftover();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
