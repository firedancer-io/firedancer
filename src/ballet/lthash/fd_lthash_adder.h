#ifndef HEADER_fd_src_ballet_lthash_fd_lthash_adder_h
#define HEADER_fd_src_ballet_lthash_fd_lthash_adder_h

/* fd_lthash_adder.h is an optimized streaming LtHash adder.

   Uses two forms of SIMD parallelism internally to accelerate LtHash
   update throughput (multi-block and multi-message BLAKE3 hashing).
   A rate of 5 million LtHash updates per second was previously achieved
   on a 3.7 GHz AMD EPYC 9B45 (Zen 5 / Turin).

   Usage is as follows:

     fd_lthash_value_t sum[1];
     fd_lthash_zero( sum );
     fd_lthash_adder_t adder[1];
     fd_lthash_adder_new( adder );
     for( ... each value ... ) fd_lthash_adder_push( adder, sum, ... );
     fd_lthash_adder_flush( adder, sum );
     fd_lthash_adder_delete( adder ); */

#include "../blake3/fd_blake3.h"
#include "../lthash/fd_lthash.h"

#define FD_LTHASH_ADDER_ALIGN 64

#define FD_LTHASH_ADDER_PARA_MAX 16

struct __attribute__((aligned(FD_LTHASH_ADDER_ALIGN))) fd_lthash_adder {

  uint  batch_cnt;

#if FD_LTHASH_ADDER_PARA_MAX>1

  uchar batch_data[ FD_LTHASH_ADDER_PARA_MAX*FD_BLAKE3_CHUNK_SZ ]
  __attribute__((aligned(64)));

  ulong batch_ptrs[ FD_LTHASH_ADDER_PARA_MAX ]
  __attribute__((aligned(64)));

  uint  batch_sz[ FD_LTHASH_ADDER_PARA_MAX ];

#endif

};

typedef struct fd_lthash_adder fd_lthash_adder_t;

FD_PROTOTYPES_BEGIN

/* fd_lthash_adder_{new,delete} {initializes,destroys} an lthash_adder. */

fd_lthash_adder_t *
fd_lthash_adder_new( fd_lthash_adder_t * adder );

void *
fd_lthash_adder_delete( fd_lthash_adder_t * adder );

/* fd_lthash_adder_push enqueues the given input for hashing.  sum may
   or may not be updated with enqueued LtHash additions. */

static inline void
fd_lthash_adder_push( fd_lthash_adder_t * adder,
                      fd_lthash_value_t * sum,
                      void const *        input,
                      ulong               input_sz ) {
  ulong const batch_threshold = 512UL;
  fd_lthash_value_t value[1];
  if( FD_UNLIKELY( input_sz>batch_threshold ) ) {
    fd_blake3_t blake[1];
    fd_blake3_init( blake );
    fd_blake3_append( blake, input, input_sz );
    fd_blake3_fini_2048( blake, value->bytes );
    fd_lthash_add( sum, value );
    return;
  }

  uint    batch_idx = adder->batch_cnt++;
  uchar * slot      = (uchar *)adder->batch_ptrs[ batch_idx ];
  fd_memcpy( slot, input, input_sz );
  adder->batch_sz[ batch_idx ] = (uint)input_sz;

  if( batch_idx+1>=FD_BLAKE3_PARA_MAX ) {
# if FD_HAS_AVX512
    fd_blake3_lthash_batch16( (void const **)fd_type_pun_const( adder->batch_ptrs ), adder->batch_sz, value->words );
# elif FD_HAS_AVX
    fd_blake3_lthash_batch8 ( (void const **)fd_type_pun_const( adder->batch_ptrs ), adder->batch_sz, value->words );
# endif
    adder->batch_cnt = 0;
    fd_lthash_add( sum, value );
  }
}

/* fd_lthash_adder_flush commits all previously enqueued additions to
   sum. */

static inline void
fd_lthash_adder_flush( fd_lthash_adder_t * adder,
                       fd_lthash_value_t * sum ) {
  uint batch_cnt = adder->batch_cnt;
  for( uint i=0U; i<batch_cnt; i++ ) {
    fd_lthash_value_t value[1];
    fd_blake3_t blake[1];
    fd_blake3_init( blake );
    fd_blake3_append( blake, (void const *)adder->batch_ptrs[ i ], adder->batch_sz[ i ] );
    fd_blake3_fini_2048( blake, value->bytes );
    fd_lthash_add( sum, value );
  }
  adder->batch_cnt = 0U;
}

/* fd_lthash_adder_push_solana_account wraps fd_lthash_adder_push for
   Solana account inputs. */

static inline void
fd_lthash_adder_push_solana_account(
    fd_lthash_adder_t * adder,
    fd_lthash_value_t * sum,
    void const *        pubkey,
    uchar const *       data,
    ulong               data_sz,
    ulong               lamports,
    uchar               executable,
    void const *        owner
) {
  fd_lthash_value_t value[1];
  /* FIXME opportunities for memcpy hax here */

  ulong const static_sz       =  73UL;
  ulong const batch_threshold = 512UL;
  if( FD_UNLIKELY( data_sz > batch_threshold-static_sz || /* optimize for small appends */
                   FD_BLAKE3_PARA_MAX==0 ) ) {
    fd_blake3_t blake[1];
    fd_blake3_init( blake );
    fd_blake3_append( blake, &lamports, sizeof(ulong) );
    fd_blake3_append( blake, data,      data_sz       );
    uchar footer[ 65 ];
    footer[ 0 ] = executable;
    memcpy( footer+1,  owner,  32 );
    memcpy( footer+33, pubkey, 32 );
    fd_blake3_append( blake, footer, sizeof(footer) );
    fd_blake3_fini_2048( blake, value->bytes );
    fd_lthash_add( sum, value );
    return;
  }

  uint    batch_idx = adder->batch_cnt++;
  uchar * slot      = (uchar *)adder->batch_ptrs[ batch_idx ];
  uchar * p         = slot;

  /* Fixed size header */
  FD_STORE( ulong, p, lamports );
  p += sizeof(ulong);
  /* Variable size content */
  fd_memcpy( p, data, data_sz );
  p += data_sz;
  /* Fixed size footer */
  p[0] = executable;          p +=  1;
  fd_memcpy( p, owner,  32 ); p += 32;
  fd_memcpy( p, pubkey, 32 ); p += 32;

  adder->batch_sz[ batch_idx ] = (uint)( p-slot );

  if( batch_idx+1>=FD_BLAKE3_PARA_MAX ) {
# if FD_HAS_AVX512
    fd_blake3_lthash_batch16( (void const **)fd_type_pun_const( adder->batch_ptrs ), adder->batch_sz, value->words );
# elif FD_HAS_AVX
    fd_blake3_lthash_batch8 ( (void const **)fd_type_pun_const( adder->batch_ptrs ), adder->batch_sz, value->words );
# endif
    adder->batch_cnt = 0;
    fd_lthash_add( sum, value );
  }
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_lthash_fd_lthash_adder_h */
