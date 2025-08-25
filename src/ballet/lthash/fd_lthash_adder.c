#include "fd_lthash_adder.h"

#if FD_HAS_AVX512
#define FD_LTHASH_ADDER_PARA_CNT 16
#elif FD_HAS_AVX
#define FD_LTHASH_ADDER_PARA_CNT  8
#else
#define FD_LTHASH_ADDER_PARA_CNT  0
#endif

fd_lthash_adder_t *
fd_lthash_adder_new( fd_lthash_adder_t * adder ) {
  if( FD_UNLIKELY( !adder ) ) {
    FD_LOG_WARNING(( "NULL lthash_adder" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)adder, FD_LTHASH_ADDER_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned lthash_adder" ));
    return NULL;
  }
  fd_memset( adder, 0, sizeof(fd_lthash_adder_t) );
#if FD_LTHASH_ADDER_PARA_CNT>1
  for( ulong i=0UL; i<FD_LTHASH_ADDER_PARA_CNT; i++ ) {
    adder->batch_ptrs[ i ] = (ulong)( adder->batch_data + i*FD_BLAKE3_CHUNK_SZ );
  }
#endif
  return adder;
}

void *
fd_lthash_adder_delete( fd_lthash_adder_t * adder ) {
  (void)adder;
  return NULL;
}
