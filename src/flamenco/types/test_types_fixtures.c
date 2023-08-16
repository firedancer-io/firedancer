#include "fd_types.h"
#include "../fd_flamenco.h"

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
  uchar const * bin;
  ulong const * bin_sz;  /* extern symbol, thus need pointer */
  char  const * yml;
  ulong const * yml_sz;
};

typedef struct test_fixture test_fixture_t;

static const test_fixture_t test_vector[] = {
# define X(id) \
  { .name   = #id,                           \
    .bin    = test_##id##_bin,               \
    .bin_sz = &test_##id##_bin_sz,           \
    .yml    = (char const *)test_##id##_yml, \
    .yml_sz = &test_##id##_yml_sz },
TEST_VECTOR( X )
# undef X
  {0}
};


/* TEST DEFINITIONS ***************************************************/

/* test_yaml deserializes t->bin and asserts the YAML representation of
   the result matches t->yaml. */

static void
test_yaml( test_fixture_t const * t ) {
  (void)t;  /* TODO */
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

  for( test_fixture_t const * t = test_vector; t->name; t++ ) {

    test_yaml      ( t );
    test_idempotent( t );
    /* Add more here ... */

  }

  FD_LOG_NOTICE(( "pass" ));
  fd_flamenco_halt();
  fd_halt();
  return 0;
}
