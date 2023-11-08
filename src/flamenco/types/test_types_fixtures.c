#include "fd_types.h"
#include "../fd_flamenco.h"
#include "fd_types_yaml.h"

#include <stdio.h>

/* test_types_fixtures verifies types decoding/encoding against a set of
   fixtures containing captured bincode data.

   This test does not require mmap() or heap allocations. */


/* TEST VECTOR ********************************************************/

/* Define list of test fixtures.

   Each entry is X( name, type ).

   Test fixtures are sourced from the following two files:
     - src/flamenco/types/fixtures/<name>.bin
       (containing some input bincode blob)
     - src/flamenco/types/fixtures/<name>.yml
       (containing the expected pretty printed decoding in YAML format)

   type should be set such that fd_<type>_t is defined in fd_types.h. */

#define TEST_VECTOR( X )                                               \
  X( txn_vote,                         flamenco_txn         )          \
  X( vote_account,                     vote_state_versioned )          \
  X( gossip_pull_req,                  gossip_msg           )          \
  X( gossip_pull_resp_contact_info,    gossip_msg           )          \
  X( gossip_pull_resp_node_instance,   gossip_msg           )          \
  X( gossip_pull_resp_snapshot_hashes, gossip_msg           )          \
  X( gossip_pull_resp_version,         gossip_msg           )          \
  X( gossip_push_vote,                 gossip_msg           )          \
  /* Add more fixtures to the end ... */


/* TEST BOILERPLATE ***************************************************/

/* Embed test vectors into compile unit */

#define X(id, _) \
  FD_IMPORT_BINARY( test_##id##_bin, "src/flamenco/types/fixtures/" #id ".bin" ); \
  FD_IMPORT_BINARY( test_##id##_yml, "src/flamenco/types/fixtures/" #id ".yml" );
TEST_VECTOR( X )
#undef X

/* Declare types of abstract class functions.

   Casting self function param from (qualified_t *) to (void *) is
   technically U.B. !!!  The compiler checks for actual ABI violations. */

typedef int
(* fd_types_decode_vfn_t)( void *                    self,
                           fd_bincode_decode_ctx_t * d );

typedef void
(* fd_types_walk_vfn_t)( void *             walker,
                         void const *       self,
                         fd_types_walk_fn_t fun,
                         char const *       name,
                         uint               level );

/* Define test vector */

struct test_fixture {
  char const  * name;
  char const  * dump_path;
  uchar const * bin;
  ulong const * bin_sz;  /* extern symbol, thus need pointer */
  char  const * yml;
  ulong const * yml_sz;
  ulong         struct_sz;  /* size of outer struct */

  fd_types_decode_vfn_t decode;
  fd_types_walk_vfn_t   walk;
};

typedef struct test_fixture test_fixture_t;

static const test_fixture_t test_vector[] = {
# define X( id, type )                                                 \
  { .name      = #id,                                                  \
    .dump_path = "src/flamenco/types/fixtures/" #id ".actual.yml",     \
    .bin       = test_##id##_bin,                                      \
    .bin_sz    = &test_##id##_bin_sz,                                  \
    .yml       = (char const *)test_##id##_yml,                        \
    .yml_sz    = &test_##id##_yml_sz,                                  \
    .struct_sz = sizeof( fd_##type##_t ),                              \
    .decode    = ( fd_types_decode_vfn_t )fd_##type##_decode,          \
    .walk      = ( fd_types_walk_vfn_t   )fd_##type##_walk },
TEST_VECTOR( X )
# undef X
  {0}
};


/* TEST DEFINITIONS ***************************************************/

/* test_yaml deserializes t->bin and asserts the YAML representation of
   the result matches t->yaml. */

static void
test_yaml( test_fixture_t const * t ) {
  FD_SCRATCH_SCOPE_BEGIN {

    /* Decode bincode blob */

    ulong bin_sz = *t->bin_sz;
    fd_bincode_decode_ctx_t decode[1] = {{
        .data    = t->bin,
        .dataend = t->bin + bin_sz,
        .valloc  = fd_scratch_virtual()
      }};

    void * decoded = fd_scratch_alloc( 64UL, t->struct_sz );
    int err = t->decode( decoded, decode );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) )
      FD_LOG_ERR(( "Test '%s' failed: Bincode decode err (%d)", t->name, err ));

    /* Encode YAML */

    static char yaml_buf[ 1<<20 ];
    FILE * file = fmemopen( yaml_buf, sizeof(yaml_buf), "w" );

    void * yaml_mem = fd_scratch_alloc( fd_flamenco_yaml_align(), fd_flamenco_yaml_footprint() );
    fd_flamenco_yaml_t * yaml = fd_flamenco_yaml_init( fd_flamenco_yaml_new( yaml_mem ), file );

    t->walk( yaml, decoded, fd_flamenco_yaml_walk, NULL, 0 );
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
  } FD_SCRATCH_SCOPE_END;
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
