#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "../fd_ballet.h"
#include "fd_ed25519_private.h"
#include "../../ballet/json/cJSON.h"
#include "../../ballet/hex/fd_hex.h"

#define EDDSA_TEST_FILE "./contrib/wycheproof/testvectors/eddsa_test.json"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_sha512_t _sha[1]; fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( _sha ) );

  int cases_file = open( EDDSA_TEST_FILE, O_RDONLY, 0 );
  if ( FD_UNLIKELY( !cases_file ) ) {
    FD_LOG_ERR(( "open: %s: " EDDSA_TEST_FILE, strerror( errno ) ));
  }

  struct stat cases_file_stat;
  if ( FD_UNLIKELY( 0 > fstat( cases_file, &cases_file_stat ) ) ) {
    perror("fstat:");
    FD_LOG_ERR(( "fstat: %s: " EDDSA_TEST_FILE, strerror( errno ) ));
  }

  char * mem = mmap(
    NULL,
    (ulong)cases_file_stat.st_size,
    PROT_READ|PROT_WRITE,MAP_PRIVATE,
    cases_file,
    0
  );

  if ( FD_UNLIKELY( mem == MAP_FAILED )) {
    FD_LOG_ERR(( "mmap: %s: " EDDSA_TEST_FILE, strerror( errno ) ));
  }

  cJSON * root = cJSON_Parse( mem );
  if ( FD_UNLIKELY( !root ) ) {
    const char * error_ptr = cJSON_GetErrorPtr();
    if ( FD_UNLIKELY(( error_ptr )) ) {
      FD_LOG_ERR(( "cJSON_Parse: could not parse json: error before: %s", error_ptr));
    }
  }

  /* expect algorithm to be EDDSA */
  cJSON * algnode = cJSON_GetObjectItem( root, "algorithm" );
  if ( FD_UNLIKELY( !algnode || !cJSON_IsString( algnode ) || strcmp( "EDDSA", cJSON_GetStringValue( algnode ) ) ) ) {
    FD_LOG_ERR(( "expected 'algorithm' field to be 'EDDSA' but was '%s'", cJSON_GetStringValue( algnode ) ));
  }

  cJSON * tgroups_node = cJSON_GetObjectItem( root, "testGroups" );

  int test_groups_cnt = cJSON_GetArraySize( tgroups_node );

  FD_LOG_INFO(( "will look at %d test groups", test_groups_cnt ));

  for ( int i = 0; i < test_groups_cnt; i++ ) {
    cJSON * tgroup_node = cJSON_GetArrayItem( tgroups_node, i );
    cJSON * key_node   = cJSON_GetObjectItem( tgroup_node, "key" );

    cJSON * curve_node = cJSON_GetObjectItem( key_node, "curve" );
    cJSON * type_node =  cJSON_GetObjectItem( tgroup_node, "type" );

    /* tests should be EddsaVerify on edwards25519 */
    if ( FD_UNLIKELY( strcmp("edwards25519", cJSON_GetStringValue( curve_node ) ) ) ) {
      FD_LOG_ERR(( "unexpected curve in test: %s", cJSON_GetStringValue( curve_node ) ));
    }

    if ( FD_UNLIKELY( strcmp("EddsaVerify", cJSON_GetStringValue( type_node ) ) ) ) {
      FD_LOG_ERR(( "unexpected curve in test: %s", cJSON_GetStringValue( type_node ) ));
    }

      /* decode the pk field which is hex encoded */
      cJSON * pk_node = cJSON_GetObjectItem( key_node, "pk" );
      char * pk_hex = cJSON_GetStringValue( pk_node );
      ulong pk_hex_sz = strlen( pk_hex );
      if ( FD_UNLIKELY( pk_hex_sz % 2 == 1 ))  {
        FD_LOG_ERR(( "test at i=%d has odd pk len %lu", i, pk_hex_sz ));
      }
      ulong pk_sz = (ulong)pk_hex_sz / 2;
      char * pk = malloc( pk_sz );
      ulong decode_len = fd_hex_decode( pk, pk_hex, pk_sz );
      if ( FD_UNLIKELY( pk_sz != decode_len ) ) {
        FD_LOG_ERR(( "test at i=%d failed hex decoding at %lu", i, decode_len ));
      }

    /* execute every test in group */
    cJSON * tests_node =    cJSON_GetObjectItem( tgroup_node, "tests" );
    int tests_cnt = cJSON_GetArraySize( tests_node );
    FD_LOG_INFO(( "will look at %d tests in group %d", tests_cnt, i+1 ));

    for ( int j = 0; j < tests_cnt; j++ ) {
      cJSON * test_node = cJSON_GetArrayItem( tests_node, j );

      cJSON * result_node = cJSON_GetObjectItem( test_node, "result" );
      char * expected_result = cJSON_GetStringValue( result_node );
      int expect_failure = strcmp("valid", expected_result ) ;

      /* decode the msg field which is hex encoded */
      cJSON * msg_node = cJSON_GetObjectItem( test_node, "msg" );
      char * msg_hex = cJSON_GetStringValue( msg_node );
      ulong msg_hex_sz = strlen( msg_hex );
      if ( FD_UNLIKELY( msg_hex_sz % 2 == 1 ))  {
        FD_LOG_ERR(( "test at i=%d j=%d has odd msg len %lu", i, j, msg_hex_sz ));
      }
      ulong msg_sz = (ulong)msg_hex_sz / 2;
      char * msg = malloc( msg_sz );
      decode_len = fd_hex_decode( msg, msg_hex, msg_sz );
      if ( FD_UNLIKELY( msg_sz != decode_len ) ) {
        FD_LOG_ERR(( "test at i=%d j=%d failed hex decoding at %lu", i, j, decode_len ));
      }

      /* decode the sig field which is hex encoded */
      cJSON * sig_node = cJSON_GetObjectItem( test_node, "sig" );
      char * sig_hex = cJSON_GetStringValue( sig_node );
      ulong sig_hex_sz = strlen( sig_hex );
      if ( FD_UNLIKELY( sig_hex_sz % 2 == 1 ))  {
        FD_LOG_ERR(( "test at i=%d j=%d has odd sig len %lu", i, j, sig_hex_sz ));
      }
      ulong sig_sz = (ulong)sig_hex_sz / 2;
      char * sig = malloc( sig_sz );
      decode_len = fd_hex_decode( sig, sig_hex, sig_sz );
      if ( FD_UNLIKELY( sig_sz != decode_len ) ) {
        FD_LOG_ERR(( "test at i=%d j=%d failed hex decoding at %lu", i, j, decode_len ));
      }

      if ( FD_UNLIKELY( decode_len != FD_ED25519_SIG_SZ )) {
        /* skipping test with improperly sized sigs */
        goto test_cleanup;
      }

      cJSON * comment_node = cJSON_GetObjectItem( test_node, "comment" );
      char * comment = cJSON_GetStringValue( comment_node );
      
      int failure = fd_ed25519_verify( msg, msg_sz, sig, pk, sha );

      if ( failure && !expect_failure ) {
        FD_LOG_WARNING(( "comment: %s", comment ));
        FD_LOG_ERR(( "test at i=%d j=%d expected failure", i, j ));
      }

      if ( !failure && expect_failure ) {
        FD_LOG_WARNING(( "comment: %s", comment ));
        FD_LOG_ERR(( "test at i=%d j=%d expected success got %d", i, j, failure ));
      }

      test_cleanup:
      free( sig );
      free( msg );
    }
    free( pk );
  }

  /* cleanup */
  cJSON_Delete( root );
  munmap( mem, (ulong)cases_file_stat.st_size );
  close( cases_file );
  fd_sha512_delete( fd_sha512_leave( sha ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
