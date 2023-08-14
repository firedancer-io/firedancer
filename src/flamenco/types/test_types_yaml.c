#include "fd_bincode.h"
#include "fd_types_meta.h"
#include "fd_types_yaml.h"
#include "../fd_flamenco.h"
#include "fd_types.h"

#include <stdio.h>

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

/* List of unit tests */

static const fd_flamenco_yaml_test_t fd_flamenco_yaml_tests[] = {
  { .walk = test0_walk, .expected = test0_expected },
  { .walk = test1_walk, .expected = test1_expected },
  { .walk = test2_walk, .expected = test2_expected },
  { .walk = test3_walk, .expected = test3_expected },
  { .walk = test4_walk, .expected = test4_expected },
  { .walk = test5_walk, .expected = test5_expected },
  {0}
};

void
fd_flamenco_yaml_unit_test( fd_flamenco_yaml_test_t const * test ) {

  FD_SCRATCH_SCOPED_FRAME;

  static char yaml_buf[ 1<<20 ];
  FILE * file = fmemopen( yaml_buf, sizeof(yaml_buf), "w" );

  void * yaml_mem = fd_scratch_alloc( fd_flamenco_yaml_align(), fd_flamenco_yaml_footprint() );
  fd_flamenco_yaml_t * yaml = fd_flamenco_yaml_init( fd_flamenco_yaml_new( yaml_mem ), file );

  for( fd_flamenco_type_step_t const * walk = test->walk;
                                       walk->type;
                                       walk++ ) {
    fd_flamenco_yaml_walk( yaml, &walk->ul, walk->name, walk->type, walk->level );
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
}

static void
fd_flamenco_yaml_run_unit_tests( void ) {
  for( fd_flamenco_yaml_test_t const * test = fd_flamenco_yaml_tests;
       test->walk;
       ++test ) {
    fd_flamenco_yaml_unit_test( test );
  }
}


/* Integration test: Test deserializer, type walk, and YAML serialize on
   a Solana protocol data structure. */

FD_IMPORT_BINARY( vote_account_bin,  "src/flamenco/types/fixtures/vote_account.bin" );
FD_IMPORT_BINARY( vote_account_yaml, "src/flamenco/types/fixtures/vote_account.yml" );

//static void
//fd_flamenco_integration_test( void ) {
//
//  /* Decode bincode blob */
//
//  fd_scratch_push();
//  fd_bincode_decode_ctx_t decode[1] = {{
//    .data    = vote_account_bin,
//    .dataend = vote_account_bin + vote_account_bin_sz,
//    .valloc  = fd_scratch_virtual()
//  }};
//  fd_vote_state_versioned_t state[1];
//  int err = fd_vote_state_versioned_decode( state, decode );
//  fd_scratch_pop();
//  FD_TEST( err==FD_BINCODE_SUCCESS );
//
//  /* Create memory-backed file */
//
//  static uchar yaml_buf[ 1<<20 ];
//  FILE * file = fmemopen( yaml_buf, sizeof(yaml_buf), "w" );
//
//  /* Encode YAML */
//
//  fd_flamenco_yaml_t  _yaml[1];
//  fd_flamenco_yaml_t * yaml = fd_flamenco_yaml_init( _yaml, file );
//  FD_TEST( yaml==_yaml );
//
//  fd_vote_state_versioned_walk( yaml, state, fd_flamenco_yaml_walk, NULL, 0 );
//  FD_TEST( 0==ferror( file )      );
//  FD_TEST( 0==fputc( '\0', file ) );
//  long sz = ftell(  file );
//  FD_TEST( sz>0 );
//  FD_TEST( 0==fclose( file ) );
//
//  fwrite( yaml_buf, 1, (ulong)sz, stdout );
//}
//

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_flamenco_boot( &argc, &argv );

  char const * _page_sz   = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",    NULL, "gigantic" );
  ulong        page_cnt   = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",   NULL, 2UL        );
  ulong        scratch_mb = fd_env_strip_cmdline_ulong( &argc, &argv, "--scratch-mb", NULL, 1024UL     );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  FD_TEST( page_sz );

  /* Acquire workspace */

  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_log_cpu_id(), "wksp", 0UL );
  FD_TEST( wksp );

  /* Create scratch allocator */

  ulong  smax = scratch_mb << 20;
  void * smem = fd_wksp_alloc_laddr( wksp, fd_scratch_smem_align(), smax, 1UL );
  if( FD_UNLIKELY( !smem ) ) FD_LOG_ERR(( "Failed to alloc scratch mem" ));

# define SCRATCH_DEPTH (4UL)
  ulong fmem[ SCRATCH_DEPTH ] __attribute((aligned(FD_SCRATCH_FMEM_ALIGN)));

  fd_scratch_attach( smem, fmem, smax, SCRATCH_DEPTH );

  /* Run tests */

  fd_flamenco_yaml_run_unit_tests();

  /* Cleanup */

  FD_TEST( fd_scratch_frame_used()==0UL );
  fd_wksp_free_laddr( fd_scratch_detach( NULL ) );
  fd_flamenco_halt();
  fd_halt();
  return 0;
}
