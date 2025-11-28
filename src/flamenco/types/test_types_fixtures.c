#include "fd_types.h"
#include "fd_types_yaml.h"

#include <stdio.h>

/* test_types_fixtures verifies types decoding/encoding against a set of
   fixtures containing captured bincode data. */


/* TEST VECTOR ********************************************************/

/* Define list of test fixtures.

   Each entry is X( name, type, check_idempotent ).

   Test fixtures are sourced from the following two files:
     - src/flamenco/types/fixtures/<name>.bin
       (containing some input bincode blob)
     - src/flamenco/types/fixtures/<name>.yml
       (containing the expected pretty printed decoding in YAML format)

   type should be set such that fd_<type>_t is defined in fd_types.h. */

#define TEST_VECTOR( X )                                            \
  X( vote_account,                     vote_state_versioned, 1, 0 ) \
  X( vote_account_two,                 vote_state_versioned, 1, 0 )
  /* Add more fixtures to the end ... */


/* TEST BOILERPLATE ***************************************************/

/* Embed test vectors into compile unit */

#define X( id, type, check_idempotent, global ) \
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
(* fd_types_encode_global_vfn_t)( void *                    self,
                                  fd_bincode_encode_ctx_t * d );

typedef int
(* fd_types_encode_vfn_t)( void const *              self,
                           fd_bincode_encode_ctx_t * e );
typedef void
(* fd_types_walk_vfn_t)( void *             walker,
                         void const *       self,
                         fd_types_walk_fn_t fun,
                         char const *       name,
                         uint               level,
                         uint               varint );

typedef ulong
(* fd_types_align_vfn_t)( void );

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
  fd_types_encode_global_vfn_t    encode_global;
  fd_types_walk_vfn_t             walk;
  fd_types_align_vfn_t            align;
};

typedef struct test_fixture test_fixture_t;

#define SELECT_0( x, y ) y
#define SELECT_1( x, y ) x
#define SELECT( num, x, y ) SELECT_##num( x, y )

static const test_fixture_t test_vector[] = {
# define X( id, type, check_idempotent, global )                                         \
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
    .decode_global    = SELECT( global, (fd_types_decode_global_vfn_t )fd_##type##_decode_global, NULL ), \
    .encode           = ( fd_types_encode_vfn_t )fd_##type##_encode,                     \
    .encode_global    = SELECT( global, (fd_types_encode_global_vfn_t )fd_##type##_encode_global, NULL ), \
    .align            = ( fd_types_align_vfn_t )fd_##type##_align,                       \
    .walk             = ( fd_types_walk_vfn_t )fd_##type##_walk },
TEST_VECTOR( X )
# undef X
  {0}
};


/* TEST DEFINITIONS ***************************************************/

/* test_yaml deserializes t->bin and asserts the YAML representation of
   the result matches t->yaml. */

static void
test_yaml( test_fixture_t const * t ) {
  /* Decode bincode blob */

  ulong bin_sz = *t->bin_sz;
  fd_bincode_decode_ctx_t decode[1] = {{
      .data    = t->bin,
      .dataend = t->bin + bin_sz
  }};

  FD_TEST( fd_scratch_prepare_is_safe( t->align() ) );
  uchar * decoded = fd_scratch_prepare( t->align() );

  ulong total_sz = 0UL;
  int   err      = t->decode_footprint( decode, &total_sz );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
    FD_LOG_ERR(( "Test '%s' failed: Bincode decode err (%d)", t->name, err ));
  }

  FD_TEST( fd_scratch_publish_is_safe( decoded+total_sz ) );
  t->decode( decoded, decode );
  fd_scratch_publish( decoded+total_sz );

  /* Encode YAML */

  static char yaml_buf[ 1<<25 ];
  FILE * file = fmemopen( yaml_buf, sizeof(yaml_buf), "w" );

  static fd_flamenco_yaml_t yaml_mem[1];
  fd_flamenco_yaml_t * yaml = fd_flamenco_yaml_init( fd_flamenco_yaml_new( yaml_mem ), file );

  t->walk( yaml, decoded, fd_flamenco_yaml_walk, NULL, 0, 0 );
  FD_TEST( 0==ferror( file ) );
  long sz = ftell(  file );
  FD_TEST( sz>0 );
  FD_TEST( 0==fclose( file ) );

  /* Compare */

  ulong yml_sz = *t->yml_sz;
  if( FD_UNLIKELY( (ulong)sz!=yml_sz ) || (0!=memcmp( yaml_buf, t->yml, yml_sz ) ) ) {
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
  if( !t->check_idem ) return;

  /* We first need to decode the contents of the fixture. This decoding
     needs to be done using the local decoder. */
  ulong bin_sz = *t->bin_sz;
  fd_bincode_decode_ctx_t decode[1] = {{
    .data    = t->bin,
    .dataend = t->bin + bin_sz
  }};

  FD_TEST( fd_scratch_prepare_is_safe( t->align() ) );
  uchar * decoded = fd_scratch_prepare( t->align() );

  ulong total_sz = 0UL;
  int   err      = t->decode_footprint( decode, &total_sz );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
    FD_LOG_ERR(( "Test '%s' failed: Bincode decode err (%d)", t->name, err ));
  }

  FD_TEST( fd_scratch_publish_is_safe( decoded+total_sz ) );
  t->decode( decoded, decode );
  fd_scratch_publish( decoded+total_sz );

  FD_TEST( fd_scratch_alloc_is_safe( 1UL, bin_sz ) );
  uchar * encoded_buf = fd_scratch_alloc( t->align(), bin_sz );

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

  fd_memset( decoded, 0x41, total_sz );

  if( t->decode_global ) {

    decode->data    = t->bin;
    decode->dataend = t->bin + bin_sz;

    t->decode_global( decoded, decode );

    fd_bincode_encode_ctx_t global_encode[1] = {{
      .data    = encoded_buf,
      .dataend = encoded_buf + bin_sz
    }};

    err = t->encode_global( decoded, global_encode );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
      FD_LOG_ERR(( "Test '%s' failed: Bincode encode err (%d)", t->name, err ));
    }
    FD_TEST_CUSTOM( !memcmp( encoded_buf, t->bin, bin_sz ), "Global type doesn't encode correctly" );

  }
}

/* Loop through tests */

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  static uchar scratch_mem [ 1<<25 ];  /* 32 MiB */
  static ulong scratch_fmem[ 4UL ] __attribute((aligned(FD_SCRATCH_FMEM_ALIGN)));
  fd_scratch_attach( scratch_mem, scratch_fmem, 1UL<<25, 4UL );

  for( test_fixture_t const * t = test_vector; t->name; t++ ) {
    fd_scratch_push();
    test_yaml( t );
    fd_scratch_pop();

    fd_scratch_push();
    test_idempotent( t );
    fd_scratch_pop();
  }

  FD_TEST( fd_scratch_frame_used()==0UL );
  fd_scratch_detach( NULL );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
