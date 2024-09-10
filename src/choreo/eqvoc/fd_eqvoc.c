#include "fd_eqvoc.h"

#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"

int
fd_eqvoc_test( fd_shred_t const * shred1, fd_shred_t const * shred2 ) {
  int c = memcmp( shred1->signature, shred2->signature, FD_SHRED_SIGNATURE_SZ );

#if FD_EQVOC_USE_HANDHOLDING
  if( FD_UNLIKELY( shred1->version != shred2->version ) ) {
    FD_LOG_ERR(( "Received shreds with different (slot, idx) when the same (slot, idx) is "
                 "expected. Indicates programming error or bad config. shred1: (%lu, %u). shred2: "
                 "(%lu, %u).",
                 shred1->slot,
                 shred1->idx,
                 shred2->slot,
                 shred2->idx ));
  }

  if( FD_UNLIKELY( shred1->version != shred2->version ) ) {
    FD_LOG_ERR(( "Received shreds with different versions when the same version is expected. "
                 "Indicates programming error or bad config. shred1: %lu. shred2: %lu.",
                 shred1->version,
                 shred2->version ));
  }

  if( FD_UNLIKELY( fd_shred_type( shred1->variant ) != fd_shred_type( shred2->variant ) ) ) {
    FD_LOG_WARNING(( "[%s] shred1 %lu %u not both resigned", __func__, shred1->slot, shred1->idx ));
    FD_LOG_HEXDUMP_WARNING(( "shred1", shred1, fd_shred_sz( shred1 ) ));
    FD_LOG_HEXDUMP_WARNING(( "shred2", shred2, fd_shred_sz( shred2 ) ));
  }

  if( FD_UNLIKELY( fd_shred_type( shred1->variant ) != fd_shred_type( shred2->variant ) ) ) {
    FD_LOG_WARNING(( "[%s] shred1 %lu %u not both resigned", __func__, shred1->slot, shred1->idx ));
    FD_LOG_HEXDUMP_WARNING(( "shred1", shred1, fd_shred_sz( shred1 ) ));
    FD_LOG_HEXDUMP_WARNING(( "shred2", shred2, fd_shred_sz( shred2 ) ));
  }

  if( FD_UNLIKELY( fd_shred_payload_sz( shred1 ) != fd_shred_payload_sz( shred2 ) ) ) {
    FD_LOG_WARNING(( "[%s] shred1 %lu %u payload_sz not eq", __func__, shred1->slot, shred1->idx ));
    FD_LOG_HEXDUMP_WARNING(( "shred1", shred1, fd_shred_sz( shred1 ) ));
    FD_LOG_HEXDUMP_WARNING(( "shred2", shred2, fd_shred_sz( shred2 ) ));
  }

  ulong memcmp_sz = fd_ulong_if( fd_shred_payload_sz( shred1 ) > FD_SHRED_SIGNATURE_SZ &&
                                     fd_shred_is_resigned( fd_shred_type( shred1->variant ) ),
                                 fd_shred_payload_sz( shred1 ) - FD_SHRED_SIGNATURE_SZ,
                                 fd_shred_payload_sz( shred1 ) );
  if( FD_UNLIKELY( 0 != memcmp( fd_shred_data_payload( shred1 ),
                                fd_shred_data_payload( shred2 ),
                                memcmp_sz ) ) ) {
    FD_LOG_WARNING(( "[%s] shred1 %lu %u payload not eq", __func__, shred1->slot, shred1->idx ));
    FD_LOG_HEXDUMP_WARNING(( "shred1", shred1, fd_shred_sz( shred1 ) ));
    FD_LOG_HEXDUMP_WARNING(( "shred2", shred2, fd_shred_sz( shred2 ) ));
  }
#endif

  return c;
}
