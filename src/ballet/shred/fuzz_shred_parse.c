#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "../../util/sanitize/fd_fuzz.h"
#include "../../util/fd_util.h"
#include "fd_shred.h"

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {

  fd_shred_t const * shred = fd_shred_parse( data, size );
  if( shred==NULL ) return 0;

# define BOUNDS_CHECK( ptr, sz )          \
    do {                                  \
      ulong b0 = (ulong)(ptr);            \
      ulong b1 = b0 + (ulong)(sz);        \
      if( b0!=b1 ) {                      \
        assert( b0<b1 );                  \
        assert( b0>=(ulong)data );        \
        assert( b1<=(ulong)(data+size) ); \
      }                                   \
    } while(0);
# define BOUNDS_CHECK_OFF( off, sz ) BOUNDS_CHECK( (ulong)shred + (off), (sz) )

  uchar variant = (uchar)shred->variant;
  uchar type    = (uchar)fd_shred_type( variant );

  assert( fd_shred_sz        ( shred   ) <= size );
  assert( fd_shred_header_sz ( variant ) <= size );
  assert( fd_shred_payload_sz( shred   ) <= size );
  assert( fd_shred_merkle_sz ( variant ) <= size );

  switch( type ) {

  case FD_SHRED_TYPE_LEGACY_CODE:
    FD_FUZZ_MUST_BE_COVERED;
    assert(  fd_shred_is_code    ( type    ) );
    assert( !fd_shred_is_data    ( type    ) );
    assert( !fd_shred_merkle_cnt ( variant ) );
    assert( !fd_shred_is_chained ( type    ) );
    assert( !fd_shred_is_resigned( type    ) );
    BOUNDS_CHECK( fd_shred_code_payload( shred ), fd_shred_payload_sz( shred ) );
    break;

  case FD_SHRED_TYPE_LEGACY_DATA:
    FD_FUZZ_MUST_BE_COVERED;
    assert( !fd_shred_is_code    ( type    ) );
    assert(  fd_shred_is_data    ( type    ) );
    assert( !fd_shred_merkle_cnt ( variant ) );
    assert( !fd_shred_is_chained ( type    ) );
    assert( !fd_shred_is_resigned( type    ) );
    BOUNDS_CHECK( fd_shred_data_payload( shred ), fd_shred_payload_sz( shred ) );
    break;

  case FD_SHRED_TYPE_MERKLE_CODE:
    FD_FUZZ_MUST_BE_COVERED;
    assert(  fd_shred_is_code    ( type    ) );
    assert( !fd_shred_is_data    ( type    ) );
    //assert(  fd_shred_merkle_cnt ( variant ) );
    assert( !fd_shred_is_chained ( type    ) );
    assert( !fd_shred_is_resigned( type    ) );
    BOUNDS_CHECK( fd_shred_code_payload( shred ), fd_shred_payload_sz( shred ) );
    BOUNDS_CHECK( fd_shred_merkle_nodes( shred ), fd_shred_merkle_sz( variant ) );
    break;

  case FD_SHRED_TYPE_MERKLE_DATA:
    FD_FUZZ_MUST_BE_COVERED;
    assert( !fd_shred_is_code    ( type    ) );
    assert(  fd_shred_is_data    ( type    ) );
    //assert(  fd_shred_merkle_cnt ( variant ) );
    assert( !fd_shred_is_chained ( type    ) );
    assert( !fd_shred_is_resigned( type    ) );
    BOUNDS_CHECK( fd_shred_data_payload( shred ), fd_shred_payload_sz( shred ) );
    BOUNDS_CHECK( fd_shred_merkle_nodes( shred ), fd_shred_merkle_sz( variant ) );
    break;

  case FD_SHRED_TYPE_MERKLE_CODE_CHAINED:
    FD_FUZZ_MUST_BE_COVERED;
    assert(  fd_shred_is_code    ( type    ) );
    assert( !fd_shred_is_data    ( type    ) );
    //assert(  fd_shred_merkle_cnt ( variant ) );
    assert(  fd_shred_is_chained ( type    ) );
    assert( !fd_shred_is_resigned( type    ) );
    BOUNDS_CHECK    ( fd_shred_code_payload( shred   ), fd_shred_payload_sz( shred ) );
    BOUNDS_CHECK    ( fd_shred_merkle_nodes( shred   ), fd_shred_merkle_sz( variant ) );
    BOUNDS_CHECK_OFF( fd_shred_chain_offset( variant ), FD_SHRED_MERKLE_ROOT_SZ );
    break;

  case FD_SHRED_TYPE_MERKLE_DATA_CHAINED:
    FD_FUZZ_MUST_BE_COVERED;
    assert( !fd_shred_is_code    ( type    ) );
    assert(  fd_shred_is_data    ( type    ) );
    //assert(  fd_shred_merkle_cnt ( variant ) );
    assert(  fd_shred_is_chained ( type    ) );
    assert( !fd_shred_is_resigned( type    ) );
    BOUNDS_CHECK    ( fd_shred_data_payload( shred ), fd_shred_payload_sz( shred ) );
    BOUNDS_CHECK    ( fd_shred_merkle_nodes( shred ), fd_shred_merkle_sz( variant ) );
    BOUNDS_CHECK_OFF( fd_shred_chain_offset( variant ), FD_SHRED_MERKLE_ROOT_SZ );
    break;

  case FD_SHRED_TYPE_MERKLE_CODE_CHAINED_RESIGNED:
    FD_FUZZ_MUST_BE_COVERED;
    assert(  fd_shred_is_code    ( type    ) );
    assert( !fd_shred_is_data    ( type    ) );
    //assert(  fd_shred_merkle_cnt ( variant ) );
    assert(  fd_shred_is_chained ( type    ) );
    assert(  fd_shred_is_resigned( type    ) );
    BOUNDS_CHECK    ( fd_shred_code_payload( shred   ), fd_shred_payload_sz( shred ) );
    BOUNDS_CHECK    ( fd_shred_merkle_nodes( shred   ), fd_shred_merkle_sz( variant ) );
    BOUNDS_CHECK_OFF( fd_shred_chain_offset( variant ), FD_SHRED_MERKLE_ROOT_SZ );
    BOUNDS_CHECK_OFF( fd_shred_retransmitter_sig_off( shred ), FD_SHRED_SIGNATURE_SZ );
    break;

  case FD_SHRED_TYPE_MERKLE_DATA_CHAINED_RESIGNED:
    FD_FUZZ_MUST_BE_COVERED;
    assert( !fd_shred_is_code    ( type    ) );
    assert(  fd_shred_is_data    ( type    ) );
    //assert(  fd_shred_merkle_cnt ( variant ) );
    assert(  fd_shred_is_chained ( type    ) );
    assert(  fd_shred_is_resigned( type    ) );
    BOUNDS_CHECK    ( fd_shred_data_payload( shred   ), fd_shred_payload_sz( shred ) );
    BOUNDS_CHECK    ( fd_shred_merkle_nodes( shred   ), fd_shred_merkle_sz( variant ) );
    BOUNDS_CHECK_OFF( fd_shred_chain_offset( variant ), FD_SHRED_MERKLE_ROOT_SZ );
    BOUNDS_CHECK_OFF( fd_shred_retransmitter_sig_off( shred ), FD_SHRED_SIGNATURE_SZ );
    break;

  default:
    /* unknown variant */
    abort();
  }

# undef BOUNDS_CHECK
# undef BOUNDS_CHECK_OFF

  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}
