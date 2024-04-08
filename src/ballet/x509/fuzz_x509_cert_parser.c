#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include "fd_x509_cert_parser.h"
#include "../fd_ballet_base.h"

#include <stdlib.h>

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  return 0;
}

FD_FN_CONST static inline int
bounds_check( ulong size,
              uint  start,
              uint  len ) {
  return ( ( start     <= start+len )
         & ( start+len <= size      ) );
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {

  if( FD_UNLIKELY( size>UINT_MAX ) ) return -1;

  cert_parsing_ctx parsed = {0};
  int err = parse_x509_cert( &parsed, data, (uint)size );
  if( FD_UNLIKELY( err ) ) return 0;

  FD_TEST( bounds_check( size, parsed.tbs_start,                    parsed.tbs_len                    ) );
  FD_TEST( bounds_check( size, parsed.serial_start,                 parsed.serial_len                 ) );
  FD_TEST( bounds_check( size, parsed.tbs_sig_alg_start,            parsed.tbs_sig_alg_len            ) );
  FD_TEST( bounds_check( size, parsed.tbs_sig_alg_oid_start,        parsed.tbs_sig_alg_oid_len        ) );
  FD_TEST( bounds_check( size, parsed.tbs_sig_alg_oid_params_start, parsed.tbs_sig_alg_oid_params_len ) );
  FD_TEST( bounds_check( size, parsed.issuer_start,                 parsed.issuer_len                 ) );
  FD_TEST( bounds_check( size, parsed.subject_start,                parsed.subject_len                ) );
  FD_TEST( bounds_check( size, parsed.spki_start,                   parsed.spki_len                   ) );
  FD_TEST( bounds_check( size, parsed.spki_alg_oid_start,           parsed.spki_alg_oid_start         ) );
  FD_TEST( bounds_check( size, parsed.spki_alg_oid_params_start,    parsed.spki_alg_oid_params_len    ) );
  FD_TEST( bounds_check( size, parsed.spki_pub_key_start,           parsed.spki_pub_key_len           ) );
  FD_TEST( bounds_check( size, parsed.aki_keyIdentifier_start,      parsed.aki_keyIdentifier_len      ) );
  FD_TEST( bounds_check( size, parsed.aki_generalNames_start,       parsed.aki_generalNames_len       ) );
  FD_TEST( bounds_check( size, parsed.aki_serial_start,             parsed.aki_serial_len             ) );
  FD_TEST( bounds_check( size, parsed.sig_alg_start,                parsed.sig_alg_len                ) );
  FD_TEST( bounds_check( size, parsed.sig_start,                    parsed.sig_len                    ) );

  return 0;
}

