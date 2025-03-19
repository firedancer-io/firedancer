#include "fd_types.h"
#include "fd_types_yaml.h"

#include <stdio.h>

/* test_types_fixtures verifies types decoding/encoding against a set of
   fixtures containing captured bincode data.

   This test does not require mmap() or heap allocations. */


/* TEST VECTOR ********************************************************/

/* Define list of test fixtures.

   Each entry is X( name, type, check_idempotent ).

   Test fixtures are sourced from the following two files:
     - src/flamenco/types/fixtures/<name>.bin
       (containing some input bincode blob)
     - src/flamenco/types/fixtures/<name>.yml
       (containing the expected pretty printed decoding in YAML format)

   type should be set such that fd_<type>_t is defined in fd_types.h. */

#define TEST_VECTOR( X )                                           \
  X( txn_vote,                         flamenco_txn, 0         )   \
  X( vote_account,                     vote_state_versioned, 1 )   \
  X( vote_account_two,                 vote_state_versioned, 1 )   \
  X( slot_bank,                        slot_bank, 1            )   \
  X( rent_fresh_accounts,              rent_fresh_accounts, 1  )   \
  X( gossip_pull_req,                  gossip_msg, 0           )   \
  X( gossip_pull_resp_contact_info,    gossip_msg, 0           )   \
  X( gossip_pull_resp_contact_info_v2, gossip_msg, 0           )   \
  X( gossip_pull_resp_node_instance,   gossip_msg, 0           )   \
  X( gossip_pull_resp_snapshot_hashes, gossip_msg, 0           )   \
  X( gossip_pull_resp_version,         gossip_msg, 0           )   \
  X( gossip_push_vote,                 gossip_msg, 0           )   \
  /* Add more fixtures to the end ... */


/* TEST BOILERPLATE ***************************************************/

/* Embed test vectors into compile unit */

#define X( id, type, check_idempotent ) \
  FD_IMPORT_BINARY( test_##id##_bin, "src/flamenco/types/fixtures/" #id ".bin" ); \
  FD_IMPORT_BINARY( test_##id##_yml, "src/flamenco/types/fixtures/" #id ".yml" );
TEST_VECTOR( X )
#undef X

/* Declare types of abstract class functions.

   Casting self function param from (qualified_t *) to (void *) is
   technically U.B. !!!  The compiler checks for actual ABI violations. */

typedef int
(* fd_types_decode_footprint_vfn_t)( fd_bincode_decode_ctx_t * d,
                                     ulong *                   total_sz );

typedef void *
(* fd_types_decode_vfn_t)( void *                    self,
                           fd_bincode_decode_ctx_t * d );

typedef void *
(* fd_types_decode_global_vfn_t)( void *                    self,
                                  fd_bincode_decode_ctx_t * d );

typedef int
(* fd_types_encode_vfn_t)( void const *              self,
                           fd_bincode_encode_ctx_t * e );
typedef void
(* fd_types_walk_vfn_t)( void *             walker,
                         void const *       self,
                         fd_types_walk_fn_t fun,
                         char const *       name,
                         uint               level );

typedef ulong
(* fd_types_align_vfn_t)( void );

typedef ulong
(* fd_types_footprint_vfn_t)( void );

typedef int
(* fd_types_convert_vfn_t)( void const *              global_self,
                            void *                    self,
                            fd_bincode_decode_ctx_t * d );

/* Define test vector */

struct test_fixture {
  char const  * name;
  char const  * dump_path;
  uchar const * bin;
  ulong const * bin_sz;  /* extern symbol, thus need pointer */
  char  const * yml;
  ulong const * yml_sz;
  ulong         struct_sz;  /* size of outer struct */
  uchar         check_idem;

  fd_types_decode_footprint_vfn_t decode_footprint;
  fd_types_decode_vfn_t           decode;
  fd_types_decode_global_vfn_t    decode_global;
  fd_types_encode_vfn_t           encode;
  fd_types_walk_vfn_t             walk;
  fd_types_align_vfn_t            align;
  fd_types_footprint_vfn_t        footprint;
  fd_types_convert_vfn_t          convert;
};

typedef struct test_fixture test_fixture_t;

static const test_fixture_t test_vector[] = {
# define X( id, type, check_idempotent )                                                 \
  { .name             = #id,                                                             \
    .dump_path        = "src/flamenco/types/fixtures/" #id ".actual.yml",                \
    .bin              = test_##id##_bin,                                                 \
    .bin_sz           = &test_##id##_bin_sz,                                             \
    .yml              = (char const *)test_##id##_yml,                                   \
    .yml_sz           = &test_##id##_yml_sz,                                             \
    .struct_sz        = sizeof( fd_##type##_t ),                                         \
    .check_idem       = check_idempotent,                                                \
    .decode_footprint = ( fd_types_decode_footprint_vfn_t )fd_##type##_decode_footprint, \
    .decode           = ( fd_types_decode_vfn_t )fd_##type##_decode,                     \
    .decode_global    = ( fd_types_decode_global_vfn_t )fd_##type##_decode_global,       \
    .encode           = ( fd_types_encode_vfn_t )fd_##type##_encode,                     \
    .align            = ( fd_types_align_vfn_t )fd_##type##_align,                       \
    .footprint        = ( fd_types_footprint_vfn_t )fd_##type##_footprint,               \
    .walk             = ( fd_types_walk_vfn_t )fd_##type##_walk,                         \
    .convert          = ( fd_types_convert_vfn_t )fd_##type##_convert_global_to_local },
TEST_VECTOR( X )
# undef X
  {0}
};


/* TEST DEFINITIONS ***************************************************/

/* test_yaml deserializes t->bin and asserts the YAML representation of
   the result matches t->yaml. */

static void
test_yaml( test_fixture_t const * t, fd_spad_t * spad ) {
  FD_SPAD_FRAME_BEGIN( spad ) {

    /* Decode bincode blob */

    ulong bin_sz = *t->bin_sz;
    fd_bincode_decode_ctx_t decode[1] = {{
        .data    = t->bin,
        .dataend = t->bin + bin_sz
    }};

    ulong total_sz = 0UL;
    int   err      = t->decode_footprint( decode, &total_sz );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) )
      FD_LOG_ERR(( "Test '%s' failed: Bincode decode err (%d)", t->name, err ));

    void * decoded = fd_spad_alloc( spad, t->align(), total_sz );

    t->decode( decoded, decode );

    /* Encode YAML */

    static char yaml_buf[ 1<<25 ];
    FILE * file = fmemopen( yaml_buf, sizeof(yaml_buf), "w" );

    void * yaml_mem = fd_spad_alloc( spad, fd_flamenco_yaml_align(), fd_flamenco_yaml_footprint() );
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
  } FD_SPAD_FRAME_END;
}

/* test_idempotent first deserializes t->bin, then re-serializes the
   result.  Asserts that the serialized representation is byte-by-byte
   identical. */

static void
test_idempotent( test_fixture_t const * t, fd_spad_t * spad, fd_wksp_t * wksp ) {
  if( !t->check_idem ) return;

  FD_SPAD_FRAME_BEGIN( spad ) {
  /* We first need to decode the contents of the fixture. This decoding
     needs to be done using the local decoder. */
  ulong bin_sz = *t->bin_sz;
  fd_bincode_decode_ctx_t decode[1] = {{
      .data    = t->bin,
      .dataend = t->bin + bin_sz,
      .wksp    = wksp
  }};

  ulong  total_sz = 0UL;
  int err = t->decode_footprint( decode, &total_sz );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
    FD_LOG_ERR(( "Test '%s' failed: Bincode decode err (%d)", t->name, err ));
  }

  void * decoded = fd_spad_alloc( spad, t->align(), total_sz );

  t->decode( decoded, decode );

  uchar * encoded_buf = fd_spad_alloc( spad, t->align(), bin_sz );

  fd_bincode_encode_ctx_t encode[1] = {{
      .data    = encoded_buf,
      .dataend = encoded_buf + bin_sz,
  }};

  err = t->encode( decoded, encode );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
    FD_LOG_ERR(( "Test '%s' failed: Bincode encode err (%d)", t->name, err ));
  }

  /* We want to compare that the re-encoded data is equivalent to the
     original encoded bin. */
  FD_TEST_CUSTOM( !memcmp( encoded_buf, t->bin, bin_sz ), "Decoded type doesn't encode correctly" );

  /* Now we want to make sure that a struct that is decoded globally
     can be converted back to a local struct, re-encoded and compared
     to the original encoded bin. */

  void * decoded_global = fd_spad_alloc( spad, t->align(), total_sz );

  decode->data    = t->bin;
  decode->dataend = t->bin + bin_sz;

  t->decode_global( decoded_global, decode );

  void * converted_struct = fd_spad_alloc( spad, t->align(), t->footprint() );

  err = t->convert( decoded_global, converted_struct, decode );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "Test '%s' failed: Convert err (%d)", t->name, err ));
  }

  fd_bincode_encode_ctx_t converted_encode[1] = {{
    .data    = encoded_buf,
    .dataend = encoded_buf + bin_sz,
  }};

  err = t->encode( converted_struct, converted_encode );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
    FD_LOG_ERR(( "Test '%s' failed: Bincode encode err (%d)", t->name, err ));
  }
  FD_TEST_CUSTOM( !memcmp( encoded_buf, t->bin, bin_sz ), "Global converted type doesn't encode correctly" );

} FD_SPAD_FRAME_END;
}

/* Loop through tests */

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_wksp_t * wksp = fd_wksp_new_anonymous( FD_SHMEM_GIGANTIC_PAGE_SZ,
                                            13UL,
                                            0UL,
                                            "wksp",
                                            0UL );

  uchar *     spad_mem = fd_wksp_alloc_laddr( wksp, FD_SPAD_ALIGN, FD_SHMEM_GIGANTIC_PAGE_SZ * 12, 999UL );
  fd_spad_t * spad     = fd_spad_join( fd_spad_new( spad_mem, FD_SHMEM_GIGANTIC_PAGE_SZ * 12 ) );

  for( test_fixture_t const * t = test_vector; t->name; t++ ) {

    test_yaml      ( t, spad );
    test_idempotent( t, spad, wksp );
    /* Add more here ... */
  }

  FD_LOG_NOTICE(( "pass" ));
  FD_TEST( fd_spad_frame_used( spad )==0UL );
  fd_halt();
  return 0;
}
