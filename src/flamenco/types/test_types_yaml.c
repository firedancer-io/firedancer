#include "fd_bincode.h"
#include "fd_types_meta.h"
#include "fd_types_yaml.h"
#include "../fd_flamenco.h"
#include "fd_types.h"

#include <stdio.h>

/* This test program ensures that the fd_flamenco_yaml serializer works
   correctly, given various type tree walk inputs. */

/* Unit tests:  Test that a bincode AST walk results in the correct
   YAML stream.

   fd_flamenco_type_step_t is a step of a mocked type walk.
   fd_flamenco_yaml_test_t is a YAML unit test. */

struct fd_flamenco_type_step {
  uint         level;
  int          type;
  char const * name;  /* If part of a map, this is the map key */
  union {
    uchar   uc;
    schar   sc;
    ushort  us;
    short   ss;
    uint    ui;
    int     si;
    ulong   ul;
    long    sl;
    uchar   hash[ 32 ];
  };
};

typedef struct fd_flamenco_type_step fd_flamenco_type_step_t;

struct fd_flamenco_yaml_test {
  fd_flamenco_type_step_t const * walk;
  char const *                    expected;
};

typedef struct fd_flamenco_yaml_test fd_flamenco_yaml_test_t;

/* Unit test 0: Primitive type at root */

static const fd_flamenco_type_step_t test0_walk[] = {
  { .level = 0, .type = FD_FLAMENCO_TYPE_UINT, .ui = 3 },
  {0}
};

static const char test0_expected[] = "3\n";

/* Unit test 1: Simple object */

static const fd_flamenco_type_step_t test1_walk[] = {
  { .level = 0, .type = FD_FLAMENCO_TYPE_MAP },
  { .level = 1, .type = FD_FLAMENCO_TYPE_UINT, .name = "a", .ui = 3 },
  { .level = 1, .type = FD_FLAMENCO_TYPE_UINT, .name = "b", .ui = 4 },
  { .level = 1, .type = FD_FLAMENCO_TYPE_UINT, .name = "c", .ui = 5 },
  { .level = 1, .type = FD_FLAMENCO_TYPE_MAP_END },
  {0}
};

static const char test1_expected[] =
  "a: 3\n"
  "b: 4\n"
  "c: 5\n";

/* Unit test 2: Simple array */

static const fd_flamenco_type_step_t test2_walk[] = {
  { .level = 0, .type = FD_FLAMENCO_TYPE_ARR },
  { .level = 1, .type = FD_FLAMENCO_TYPE_UINT, .ui = 3 },
  { .level = 1, .type = FD_FLAMENCO_TYPE_UINT, .ui = 4 },
  { .level = 1, .type = FD_FLAMENCO_TYPE_UINT, .ui = 5 },
  { .level = 1, .type = FD_FLAMENCO_TYPE_ARR_END },
  {0}
};

static const char test2_expected[] =
  "- 3\n"
  "- 4\n"
  "- 5\n";

/* Unit test 3: Array with maps */

static const fd_flamenco_type_step_t test3_walk[] = {
  { .level = 0, .type = FD_FLAMENCO_TYPE_ARR },
  { .level = 1, .type = FD_FLAMENCO_TYPE_MAP },
  { .level = 2, .type = FD_FLAMENCO_TYPE_UINT, .name = "a", .ui = 3 },
  { .level = 2, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level = 1, .type = FD_FLAMENCO_TYPE_MAP },
  { .level = 2, .type = FD_FLAMENCO_TYPE_UINT, .name = "b", .ui = 3 },
  { .level = 2, .type = FD_FLAMENCO_TYPE_UINT, .name = "c", .ui = 4 },
  { .level = 2, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level = 1, .type = FD_FLAMENCO_TYPE_ARR_END },
  {0}
};

static const char test3_expected[] =
  "- a: 3\n"
  "- b: 3\n"
  "  c: 4\n";

/* Unit test 4: Nested maps */

static const fd_flamenco_type_step_t test4_walk[] = {
  { .level = 0, .type = FD_FLAMENCO_TYPE_MAP },
  { .level = 1, .type = FD_FLAMENCO_TYPE_MAP, .name = "a" },
  { .level = 2, .type = FD_FLAMENCO_TYPE_MAP, .name = "b" },
  { .level = 3, .type = FD_FLAMENCO_TYPE_ARR, .name = "c" },
  { .level = 4, .type = FD_FLAMENCO_TYPE_ARR_END },
  { .level = 3, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level = 2, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level = 1, .type = FD_FLAMENCO_TYPE_MAP_END },
  {0}
};

static const char test4_expected[] =
  "a: \n"
  "  b: \n"
  "    c: []\n";

/* Unit test 5: Nested arrays */

static const fd_flamenco_type_step_t test5_walk[] = {
  { .level = 0, .type = FD_FLAMENCO_TYPE_ARR },
  { .level = 1, .type = FD_FLAMENCO_TYPE_ARR },
  { .level = 2, .type = FD_FLAMENCO_TYPE_ARR },
  { .level = 3, .type = FD_FLAMENCO_TYPE_ARR },
  { .level = 4, .type = FD_FLAMENCO_TYPE_ARR },
  { .level = 5, .type = FD_FLAMENCO_TYPE_UINT, .ui = 3 },
  { .level = 5, .type = FD_FLAMENCO_TYPE_ARR },
  { .level = 6, .type = FD_FLAMENCO_TYPE_ARR_END },
  { .level = 5, .type = FD_FLAMENCO_TYPE_ARR_END },
  { .level = 4, .type = FD_FLAMENCO_TYPE_ARR_END },
  { .level = 3, .type = FD_FLAMENCO_TYPE_ARR_END },
  { .level = 2, .type = FD_FLAMENCO_TYPE_ARR_END },
  { .level = 1, .type = FD_FLAMENCO_TYPE_ARR_END },
  {0}
};

static const char test5_expected[] =
  "- \n"
  "  - \n"
  "    - \n"
  "      - \n"
  "        - 3\n"
  "        - []\n";

/* Unit test 6: Mix objects/arrays */

static const fd_flamenco_type_step_t test6_walk[] = {
  { .level = 0, .type = FD_FLAMENCO_TYPE_MAP },

  { .level = 1, .type = FD_FLAMENCO_TYPE_ARR, .name = "authorized_voters" },
  { .level = 2, .type = FD_FLAMENCO_TYPE_MAP },
  { .level = 3, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch",  .ul =   0 },
  { .level = 3, .type = FD_FLAMENCO_TYPE_ULONG, .name = "pubkey", .ul = 123 },
  { .level = 3, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level = 2, .type = FD_FLAMENCO_TYPE_ARR_END },

  { .level = 1, .type = FD_FLAMENCO_TYPE_MAP, .name = "prior_voters" },
  { .level = 2, .type = FD_FLAMENCO_TYPE_ARR, .name = "buf" },

  { .level = 3, .type = FD_FLAMENCO_TYPE_MAP,   .name = "prior_voter" },
  { .level = 4, .type = FD_FLAMENCO_TYPE_ULONG, .name = "start", .ul = 0UL },
  { .level = 4, .type = FD_FLAMENCO_TYPE_ULONG, .name = "end",   .ul = 0UL },
  { .level = 4, .type = FD_FLAMENCO_TYPE_MAP_END },

  { .level = 3, .type = FD_FLAMENCO_TYPE_MAP,   .name = "prior_voter" },
  { .level = 4, .type = FD_FLAMENCO_TYPE_ULONG, .name = "start", .ul = 0UL },
  { .level = 4, .type = FD_FLAMENCO_TYPE_ULONG, .name = "end",   .ul = 0UL },
  { .level = 4, .type = FD_FLAMENCO_TYPE_MAP_END },

  { .level = 3, .type = FD_FLAMENCO_TYPE_ARR_END },
  { .level = 2, .type = FD_FLAMENCO_TYPE_MAP_END },

  { .level = 1, .type = FD_FLAMENCO_TYPE_MAP_END },
  {0}
};

static const char test6_expected[] =
  "authorized_voters: \n"
  "  - epoch: 0\n"
  "    pubkey: 123\n"
  "prior_voters: \n"
  "  buf: \n"
  "    - start: 0\n"
  "      end: 0\n"
  "    - start: 0\n"
  "      end: 0\n";

/* Unit test 7: Option in map (null) */

static const fd_flamenco_type_step_t test7_walk[] = {
  { .level = 0, .type = FD_FLAMENCO_TYPE_MAP },
  { .level = 1, .type = FD_FLAMENCO_TYPE_NULL, .name = "option" },
  { .level = 1, .type = FD_FLAMENCO_TYPE_MAP_END },
  {0}
};

static const char test7_expected[] =
  "option: null\n";

/* List of unit tests */

static const fd_flamenco_yaml_test_t fd_flamenco_yaml_tests[] = {
  { .walk = test0_walk, .expected = test0_expected },
  { .walk = test1_walk, .expected = test1_expected },
  { .walk = test2_walk, .expected = test2_expected },
  { .walk = test3_walk, .expected = test3_expected },
  { .walk = test4_walk, .expected = test4_expected },
  { .walk = test5_walk, .expected = test5_expected },
  { .walk = test6_walk, .expected = test6_expected },
  { .walk = test7_walk, .expected = test7_expected },
  {0}
};

void
fd_flamenco_yaml_unit_test( fd_flamenco_yaml_test_t const * test ) {

  static char yaml_buf[ 1<<20 ];
  FILE * file = fmemopen( yaml_buf, sizeof(yaml_buf), "w" );

  void * yaml_mem = fd_scratch_alloc( fd_flamenco_yaml_align(), fd_flamenco_yaml_footprint() );
  fd_flamenco_yaml_t * yaml = fd_flamenco_yaml_init( fd_flamenco_yaml_new( yaml_mem ), file );

  for( fd_flamenco_type_step_t const * walk = test->walk;
                                       (!!walk->type) | (!!walk->level);
                                       walk++ ) {
    fd_flamenco_yaml_walk( yaml, &walk->ul, walk->name, walk->type, NULL, walk->level );
  }
  FD_TEST( 0==fputc( '\0', file ) );
  long cnt = ftell( file );
  FD_TEST( cnt>0L );
  FD_TEST( 0==fclose( file ) );

  if( FD_UNLIKELY( 0!=strcmp( yaml_buf, test->expected ) ) ) {
    FD_LOG_WARNING(( "Expected:\n%s", test->expected ));
    FD_LOG_HEXDUMP_WARNING(( "Expected", test->expected, strlen( test->expected ) ));
    FD_LOG_WARNING(( "Actual:\n%s", yaml_buf ));
    FD_LOG_HEXDUMP_WARNING(( "Actual",   yaml_buf,       (ulong)cnt               ));
    FD_LOG_ERR(( "Unit test %ld failed", test - fd_flamenco_yaml_tests ));
  }

  fd_flamenco_yaml_delete( yaml );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  static uchar scratch_mem [ 1<<25 ];  /* 32 MiB */
  static ulong scratch_fmem[ 4UL ] __attribute((aligned(FD_SCRATCH_FMEM_ALIGN)));
  fd_scratch_attach( scratch_mem, scratch_fmem, 1UL<<25, 4UL );

  /* Run tests */

  for( fd_flamenco_yaml_test_t const * test = fd_flamenco_yaml_tests;
       test->walk;
       ++test ) {
    FD_SCRATCH_SCOPE_BEGIN {
      fd_flamenco_yaml_unit_test( test );
    }
    FD_SCRATCH_SCOPE_END;
  }

  /* Cleanup */

  FD_LOG_NOTICE(( "pass" ));
  FD_TEST( fd_scratch_frame_used()==0UL );
  fd_scratch_detach( NULL );
  fd_halt();
  return 0;
}
