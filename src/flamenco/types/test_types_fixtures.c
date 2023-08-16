#include "fd_types.h"
#include "../fd_flamenco.h"
#include "fd_types_yaml.h"

#include <stdio.h>

/* test_types_fixtures verifies types decoding/encoding against a set of
   fixtures containing captured bincode data.

   This test does not require mmap() or heap allocations. */


/* TEST VECTOR ********************************************************/

/* Define list of test fixtures.

   Each entry is loaded from the following two files:
     - src/flamenco/types/fixtures/<name>.bin
       (containing some input bincode blob)
     - src/flamenco/types/fixtures/<name>.yml
       (containing the expected pretty printed decoding in YAML format)

   Add new fixtures to the end. */

#define TEST_VECTOR( X )\
  X(vote_account)\
  X(gossip_pull_req)\
  X(gossip_pull_resp_contact_info)\
  X(gossip_pull_resp_node_instance)\
  X(gossip_pull_resp_snapshot_hashes)\
  X(gossip_pull_resp_version)\
  X(gossip_push_vote)


/* TEST BOILERPLATE ***************************************************/

/* Embed test vectors into compile unit */

#define X(id) \
  FD_IMPORT_BINARY( test_##id##_bin, "src/flamenco/types/fixtures/" #id ".bin" ); \
  FD_IMPORT_BINARY( test_##id##_yml, "src/flamenco/types/fixtures/" #id ".yml" );
TEST_VECTOR( X )
#undef X

/* Define test vector */

struct test_fixture {
  char const  * name;
  char const  * dump_path;
  uchar const * bin;
  ulong const * bin_sz;  /* extern symbol, thus need pointer */
  char  const * yml;
  ulong const * yml_sz;
};

typedef struct test_fixture test_fixture_t;

static const test_fixture_t test_vector[] = {
# define X(id) \
  { .name      = #id,                                              \
    .dump_path = "src/flamenco/types/fixtures/" #id ".actual.yml", \
    .bin       = test_##id##_bin,                                  \
    .bin_sz    = &test_##id##_bin_sz,                              \
    .yml       = (char const *)test_##id##_yml,                    \
    .yml_sz    = &test_##id##_yml_sz },
TEST_VECTOR( X )
# undef X
  {0}
};


/* TEST DEFINITIONS ***************************************************/

/* test_yaml deserializes t->bin and asserts the YAML representation of
   the result matches t->yaml. */

static void
test_yaml( test_fixture_t const * t ) {

  FD_SCRATCH_SCOPED_FRAME;

  /* Decode bincode blob */

  ulong bin_sz = *t->bin_sz;
  fd_bincode_decode_ctx_t decode[1] = {{
    .data    = t->bin,
    .dataend = t->bin + bin_sz,
    .valloc  = fd_scratch_virtual()
  }};
  fd_vote_state_versioned_t state[1];
  int err = fd_vote_state_versioned_decode( state, decode );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) )
    FD_LOG_ERR(( "Test '%s' failed: Bincode decode err (%d)", t->name, err ));

  /* Encode YAML */

  static char yaml_buf[ 1<<20 ];
  FILE * file = fmemopen( yaml_buf, sizeof(yaml_buf), "w" );

  void * yaml_mem = fd_scratch_alloc( fd_flamenco_yaml_align(), fd_flamenco_yaml_footprint() );
  fd_flamenco_yaml_t * yaml = fd_flamenco_yaml_init( fd_flamenco_yaml_new( yaml_mem ), file );

  fd_vote_state_versioned_walk( yaml, state, fd_flamenco_yaml_walk, NULL, 0 );
  FD_TEST( 0==ferror( file ) );
  long sz = ftell(  file );
  FD_TEST( sz>0 );
  FD_TEST( 0==fclose( file ) );

  /* Compare */

  ulong yml_sz = *t->yml_sz;
  if( FD_UNLIKELY( (ulong)sz!=yml_sz )
                || (0!=memcmp( yaml_buf, t->yml, yml_sz ) ) ) {
    FD_LOG_WARNING(( "Test '%s' failed", t->name ));

    FILE * dump = fopen( t->dump_path, "w" );
    fwrite( yaml_buf, 1, (ulong)sz, dump );
    fclose( dump );

    FD_LOG_WARNING(( "Dumped actual YAML to: %s", t->dump_path ));
    FD_LOG_ERR(( "fail" ));
  }
}

/* test_idempotent first deserializes t->bin, then re-serializes the
   result.  Asserts that the serialized representation is byte-by-byte
   identical. */

static void
test_idempotent( test_fixture_t const * t ) {
  (void)t;  /* TODO */
}

/* Loop through tests */

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_flamenco_boot( &argc, &argv );

  static uchar scratch_mem [ 1<<25 ];  /* 32 MiB */
  static ulong scratch_fmem[ 4UL ] __attribute((aligned(FD_SCRATCH_FMEM_ALIGN)));
  fd_scratch_attach( scratch_mem, scratch_fmem, 1UL<<25, 4UL );

  for( test_fixture_t const * t = test_vector; t->name; t++ ) {

    test_yaml      ( t );
    test_idempotent( t );
    /* Add more here ... */

  }

  FD_LOG_NOTICE(( "pass" ));
  FD_TEST( fd_scratch_frame_used()==0UL );
  fd_scratch_detach( NULL );
  fd_flamenco_halt();
  fd_halt();
  return 0;
}
