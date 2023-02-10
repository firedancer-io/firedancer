#include "fd_microblock.h"

#include "../../util/sanitize/fd_sanitize.h"

#include <stddef.h>

/* Data layout checks */

FD_STATIC_ASSERT( offsetof( fd_microblock_hdr_t, hash_cnt )==0x00UL, alignment );
FD_STATIC_ASSERT( offsetof( fd_microblock_hdr_t, hash     )==0x08UL, alignment );
FD_STATIC_ASSERT( offsetof( fd_microblock_hdr_t, txn_cnt  )==0x28UL, alignment );
FD_STATIC_ASSERT( sizeof  ( fd_microblock_hdr_t           )==0x30UL, alignment );
FD_STATIC_ASSERT( alignof ( fd_microblock_hdr_t           )==0x01UL, alignment );

FD_STATIC_ASSERT( alignof(fd_microblock_t)== 64UL, alignment );
FD_STATIC_ASSERT( sizeof (fd_microblock_t)==128UL, alignment );

void
test_microblock() {
  /* Ensure footprint is multiple of align */

  for( ulong i=0UL; i<64UL; i++ ) {
    FD_TEST( ( fd_microblock_footprint( i ) % alignof(fd_microblock_t) )==0UL );
  }

  /* Test overflowing txn_max_cnt */

  FD_TEST( fd_microblock_footprint( 5167155202719762UL )==0xfffffffffffffbc0UL );
  FD_TEST( fd_microblock_footprint( 5167155202719763UL )==0UL  ); /* invalid */
  FD_TEST( fd_microblock_new      ( (void *)64UL, 5167155202719763UL )==NULL ); /* fake shmem, invalid footprint */

  /* Test failure cases for fd_microblock_new */

  FD_TEST( fd_microblock_new( NULL,        16UL )==NULL ); /* null shmem */
  FD_TEST( fd_microblock_new( (void *)1UL, 16UL )==NULL ); /* misaligned shmem */

  /* Test failure cases for fd_microblock_join */

  FD_TEST( fd_microblock_join( NULL        )==NULL ); /* null shblock */
  FD_TEST( fd_microblock_join( (void *)1UL )==NULL ); /* misaligned shblock */

  /* Test microblock creation */

  ulong txn_max_cnt = 16UL;
  ulong footprint = fd_microblock_footprint( txn_max_cnt );
  FD_TEST( footprint );

  void * shmem = fd_alloca( FD_MICROBLOCK_ALIGN, footprint );
  FD_TEST( shmem );

  void * shblock = fd_microblock_new( shmem, txn_max_cnt );

  fd_microblock_t * block = fd_microblock_join( shblock );
  FD_TEST( block );

  /* Test bad magic value */

  block->magic++;
  FD_TEST( fd_microblock_join( shblock )==NULL );
  block->magic--;

  /* Test microblock destruction */

  FD_TEST( fd_microblock_leave( NULL  )==NULL    ); /* null block */
  FD_TEST( fd_microblock_leave( block )==shblock ); /* ok */

  FD_TEST( fd_microblock_delete( NULL        )==NULL ); /* null shblock */
  FD_TEST( fd_microblock_delete( (void *)1UL )==NULL ); /* misaligned shblock */

  /* Test bad magic value.
     Note that at this point our `block` pointer is dangling. */
  block->magic++;
  FD_TEST( fd_microblock_delete( shblock )==NULL );
  block->magic--;

  FD_TEST( fd_microblock_delete( shblock )==shmem );
}

/* A serialized batch of entries.
   Sourced from the genesis of a `solana-test-validator`. */
FD_IMPORT_BINARY( localnet_batch_0, "src/ballet/shred/fixtures/localnet-slot0-batch0.bin" );

/* Target buffer for storing an `fd_microblock_t`.
   In production, this would be a workspace. */
static uchar __attribute__((aligned(FD_MICROBLOCK_ALIGN))) microblock_buf[ 0x40000 ];

struct fd_microblock_test_vec {
  uchar mixin[ FD_SHA256_HASH_SZ ];
  fd_microblock_hdr_t hdr;
};
typedef struct fd_microblock_test_vec fd_microblock_test_vec_t;

void
test_parse_localnet_batch_0( void ) {
  FD_TEST( localnet_batch_0_sz==3080UL );

  /* Peek the number of entries, which is the first ulong. */
  ulong microblock_cnt = *(ulong *)localnet_batch_0;
  FD_TEST( microblock_cnt==64UL );

  /* Move past the first ulong to the entries. */
  void * batch_buf = (void *)((uchar *)localnet_batch_0    + 8UL);
  ulong  batch_bufsz =                 localnet_batch_0_sz - 8UL ;

  /* Check whether our .bss buffer fits. */
  ulong const txn_max_cnt = 10;
  ulong footprint = fd_microblock_footprint( txn_max_cnt );
  FD_TEST( sizeof(microblock_buf)>=footprint );

  /* Mark buffer for storing `fd_microblock_t` as unallocated (poisoned).
     `fd_microblock_new` will partially unpoison the beginning of this buffer.

     This helps catch OOB accesses beyond the end of `fd_microblock_t`. */
  fd_asan_poison( microblock_buf, sizeof(microblock_buf) );

  /* Create new object in .bss buffer. */
  void * shblock = fd_microblock_new( microblock_buf, txn_max_cnt );
  FD_TEST( shblock );

  /* Get reference to newly created microblock. */
  fd_microblock_t * block = fd_microblock_join( shblock );
  FD_TEST( block );

  /* Deserialize all entries. */
  fd_txn_parse_counters_t counters_opt = {0};
  for( ulong i=0; i<microblock_cnt; i++ ) {
    FD_TEST( batch_buf );

    FD_TEST( fd_microblock_deserialize( block, &batch_buf, &batch_bufsz, &counters_opt ) );

    /* Each microblock in the genesis block has 0 txns, 0 hashes, and the same prev hash */
    FD_TEST( block->hdr.txn_cnt ==0UL );
    FD_TEST( block->hdr.hash_cnt==0UL );
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_microblock();
  test_parse_localnet_batch_0();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
