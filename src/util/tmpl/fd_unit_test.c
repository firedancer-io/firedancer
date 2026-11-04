/* fd_unit_test.c helps with writing unit tests.

   Usage:

     FD_UNIT_TEST( foo ) { ... }
     FD_UNIT_TEST( bar ) { ... }

     #include "fd_unit_test.c"

     void main() { fd_unit_tests( argc, argv ); }

   Then run: ./my_test bar
   (Only runs tests matching the string 'bar') */

#include "../log/fd_log.h"
#include <string.h>

struct fd_unit_test {
  char const * name;
  void (* fn)( void );
  struct fd_unit_test * next;
};

typedef struct fd_unit_test fd_unit_test_t;

/* Linked list of known unit tests */
static fd_unit_test_t * fd_unit_test_head = NULL;
static fd_unit_test_t * fd_unit_test_tail = NULL;

static inline void
register_unit_test( fd_unit_test_t * test ) {
  if( fd_unit_test_tail ) fd_unit_test_tail->next = test;
  else                    fd_unit_test_head = test;
  fd_unit_test_tail = test;
}

static inline int
match_test_name( char const * test_name,
                 int          argc,
                 char **      argv ) {
  if( argc<=1 ) return 1;
  for( int i=1; i<argc; i++ ) {
    if( argv[ i ][ strspn( argv[ i ], " \t\n\r" ) ]=='\0' ) continue;
    if( strstr( test_name, argv[ i ] ) ) return 1;
  }
  return 0;
}

#define FD_UNIT_TEST( name )                                           \
  static void name( void );                                            \
  static fd_unit_test_t name##_test = { #name, name, NULL };           \
  __attribute__((constructor)) static void register_##name( void ) { register_unit_test( &name##_test ); } \
  static void name( void )

static inline void
fd_unit_tests( int     argc,
               char ** argv ) {
  /* The unit test runner passes workspace options to every test.  Strip
     unused options so their values do not become test name filters. */
  int filter_argc = argc>0;
  for( int i=1; i<argc; i++ ) {
    char * arg = argv[ i ];
    if( !strcmp( arg, "--numa-idx" ) || !strcmp( arg, "--page-cnt" ) || !strcmp( arg, "--page-sz" ) ) {
      if( FD_UNLIKELY( i+1>=argc || !strncmp( argv[ i+1 ], "--", 2UL ) ) ) {
        FD_LOG_ERR(( "missing value for %s", arg ));
      }
      i++;
    } else {
      if( FD_UNLIKELY( !strncmp( arg, "--", 2UL ) ) ) FD_LOG_ERR(( "unrecognized argument %s", arg ));
      argv[ filter_argc++ ] = arg;
    }
  }
  argv[ filter_argc ] = NULL;

  for( fd_unit_test_t * tc = fd_unit_test_head; tc; tc = tc->next ) {
    if( match_test_name( tc->name, filter_argc, argv ) ) {
      FD_LOG_NOTICE(( "Running %s", tc->name ));
      tc->fn();
    }
  }
}
