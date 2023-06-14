#include "fd_microblock.h"

#include "../bmtree/fd_bmtree.h"
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
test_microblock( void ) {
  /* Ensure footprint is multiple of align */

  for( ulong i=0UL; i<64UL; i++ ) {
    FD_TEST( ( fd_microblock_footprint( i ) % alignof(fd_microblock_t) )==0UL );
  }

  /* Test overflowing txn_max_cnt */

  // TODO
  //FD_TEST( fd_microblock_footprint( 5167155202719762UL )==0xfffffffffffffbc0UL );
  //FD_TEST( fd_microblock_footprint( 5167155202719763UL )==0UL  ); /* invalid */
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

  static uchar __attribute__((aligned(FD_MICROBLOCK_ALIGN))) shmem[ 0x10000 ];
  FD_TEST( sizeof(shmem)>=footprint );

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

/* Serialized batches of microblocks sourced from a `solana-test-validator`. */
FD_IMPORT_BINARY( test_slot0_batch0,   "src/ballet/shred/fixtures/localnet-slot0-batch0.bin"   );
FD_IMPORT_BINARY( test_slot210_batch6, "src/ballet/shred/fixtures/localnet-slot210-batch6.bin" );

/* Target buffer for storing an `fd_microblock_t`.
   In production, this would be a workspace. */
static uchar __attribute__((aligned(FD_MICROBLOCK_ALIGN))) microblock_buf[ 0x3c0000 ];

struct fd_microblock_test_vec {
  uchar mixin[ FD_SHA256_HASH_SZ ];
  fd_microblock_hdr_t hdr;
};
typedef struct fd_microblock_test_vec fd_microblock_test_vec_t;

/* The microblocks in the genesis slot don't contain any txns, and don't
   append PoH. Therefore the PoH state stays constant. */
static const ulong                    test_slot0_batch0_cnt = 64UL;
static const fd_microblock_test_vec_t test_slot0_batch0_tmpl =
  { .hdr = { .hash = "\x82\x46\x84\x5a\xc8\x8a\x7e\xea\x04\xe3\x25\x9b\xf6\xf3\x84\x8f\xc0\xb2\xe1\x04\xca\x71\xf0\xf3\x90\x9f\x4e\x2a\x23\xba\xce\x9f" } };

/* This batch was generated in a local `solana-test-validator` while
   `solana-bench-tps` was running. */
static const ulong                    test_slot210_batch6_cnt = 12UL;
static const fd_microblock_test_vec_t test_slot210_batch6_vec[12] = {
  {
    .hdr   = { .txn_cnt =  0UL, .hash_cnt = 1UL, .hash = "\x30\xa3\x74\xec\x33\x15\x52\x6a\x4f\xa5\xbd\xdd\x5d\x89\x19\xde\xd7\xb5\x7d\x49\x62\x40\x65\xf9\xf8\x32\x4d\x06\xa2\xe1\x1b\x9c" }
  },
  {
    .hdr   = { .txn_cnt =  1UL, .hash_cnt = 1UL, .hash = "\x60\x1c\x54\x12\x4e\x58\x21\x3c\x5f\x44\x87\x31\xba\x35\x08\x5e\x41\x1f\x38\x49\x0d\xa2\x21\x16\x6f\x1d\xe1\x64\x34\xa9\xe6\xc8" },
    .mixin = "\xaa\xf0\xe2\xfe\x5b\x5b\x0d\x01\x39\x27\x50\x52\x8d\x93\x3c\x79\x8a\x93\x0a\xce\x88\x60\x82\x51\xc4\xe1\x86\xa8\xed\x85\x3f\x15"
  },
  {
    .hdr   = { .txn_cnt =  3UL, .hash_cnt = 1UL, .hash = "\x60\x37\x69\x84\xac\x04\xdc\xfe\xbf\x86\x39\x95\xc2\x01\xf7\x76\xad\x45\xfd\x73\xde\xe0\x4d\xb7\xd0\xea\xd4\x44\x32\x6b\x80\xc4" },
    .mixin = "\xe0\x3c\xfa\xad\x6f\xd3\x89\x3c\x48\x87\x56\x26\x81\x3f\x49\xe1\xe7\x84\x5f\xc2\x70\x90\x2b\x54\x16\xb5\x46\x25\xd0\x84\x97\x40"
  },
  {
    .hdr   = { .txn_cnt =  2UL, .hash_cnt = 1UL, .hash = "\x57\x4e\x5e\x01\x52\xf3\x67\x13\x97\x77\x40\xf9\xdb\x65\xc0\x98\x11\x7c\x13\x81\x41\xa0\x01\xc4\x6b\xee\xe5\x36\x8d\x3a\x96\x17" },
    .mixin = "\xd6\x33\xf4\x7a\x93\x4e\x23\x65\xc4\xea\x3f\xa5\x36\x8f\xaa\x49\xe8\xc7\xbb\xd0\x1d\x11\x65\x94\x73\x2c\xd7\x9b\x5f\xbe\x36\x5b"
  },
  {
    .hdr   = { .txn_cnt =  5UL, .hash_cnt = 1UL, .hash = "\xf2\x90\xf4\x93\xb0\x1c\x49\xcd\xc7\xa7\x11\x1e\x67\xe4\xe8\x3b\x24\x4f\xbc\xfb\xda\xef\xae\x24\x3a\x2f\x31\x52\x42\xc1\x6c\xb6" },
    .mixin = "\x9b\x61\x78\x71\x7a\x7e\x71\xbc\x95\xc0\x9b\xad\xeb\x50\xc2\x6e\x88\xe4\x22\x6b\x38\xf7\x6c\xd0\x9c\x28\x57\x18\x61\xc6\xdd\x6d"
  },
  {
    .hdr   = { .txn_cnt =  0UL, .hash_cnt = 1UL, .hash = "\x47\xdb\xe7\x94\x4a\x2e\x0b\x6e\x73\xce\xc6\xd1\x16\xbb\x01\xd6\xf0\x1a\xca\xda\xb0\x90\x66\xaa\x1a\xad\x4f\x50\x4a\x8a\x8c\x63" },
  },
  {
    .hdr   = { .txn_cnt = 15UL, .hash_cnt = 1UL, .hash = "\xe3\x8b\xef\x51\x21\xb4\x94\x26\xbe\xb0\x42\xae\xe7\x66\x7b\x09\x58\xdb\xc9\x85\xa1\x85\x25\x84\x80\xca\xaf\x35\x67\x02\xb4\x84" },
    .mixin = "\x7b\x5a\x78\xe7\xd3\x5a\x90\x6b\xa0\xa2\x22\x16\x24\x45\x1e\xfb\x28\x76\xa2\xe7\x69\xec\xd7\x69\x91\x74\x95\xd4\x79\x01\xc6\x8b"
  },
  {
    .hdr   = { .txn_cnt = 46UL, .hash_cnt = 1UL, .hash = "\xfb\xd0\x10\xf1\xab\x24\x39\xc0\x1d\xcd\x94\x17\x43\x15\x26\x60\x80\xa6\xee\x4c\x7b\xd9\xd1\x8e\xb3\x70\xe6\x3d\x02\xe1\xcf\x7b" },
    .mixin = "\x6a\x10\x09\x65\xd0\x0a\x57\x7f\x24\x68\x59\xff\x10\x60\x83\xb1\xce\x4a\x51\xa7\xf9\xe2\x4d\xe1\xb5\x32\x7e\x78\x78\xda\x9b\x6f"
  },
  {
    .hdr   = { .txn_cnt =  0UL, .hash_cnt = 1UL, .hash = "\x40\x88\x75\x1b\x17\xe0\x09\x03\xeb\xb8\x59\x8e\x15\x02\x82\x81\xaa\x86\xfb\x5f\xdf\xf1\x96\xe4\x13\x0d\x08\x92\x72\xd4\x04\xcc" },
  },
  {
    .hdr   = { .txn_cnt = 64UL, .hash_cnt = 1UL, .hash = "\xa8\x58\xff\x98\x61\x30\xab\xdd\xf0\x1d\xb0\x28\x33\x02\xe2\xf5\xd3\x05\x2e\xa7\xc3\xf2\x84\xae\xc1\xd8\xa0\x31\xd5\x5c\x0c\xc9" },
    .mixin = "\xe0\x0d\x69\xd9\xa2\x40\xfc\xa5\xa3\x96\xb4\xed\x4a\xbc\x8c\x3c\xcc\x2d\x41\xee\xa1\xcd\x6d\x7d\xab\xf7\x55\x1b\xef\x96\xc0\x4d"
  },
  {
    .hdr   = { .txn_cnt =  0UL, .hash_cnt = 1UL, .hash = "\xbd\x02\x6f\xd4\x4f\xc4\x48\xf2\x5d\x1e\xd6\xd1\x14\xad\xaf\x40\xad\x3c\x68\x35\x95\x0c\xa1\x54\x17\x70\xca\x08\xe0\x78\x5d\x0d" }
  },
  {
    .hdr   = { .txn_cnt = 64UL, .hash_cnt = 1UL, .hash = "\x86\xca\x38\x38\x98\xa0\x58\xc9\x19\x50\xdc\x9a\xe8\xc6\x94\xee\x81\x63\x09\x3a\x49\xb9\x56\xee\x6e\xcd\x94\x82\xae\x4c\xe1\x86" },
    .mixin = "\x7e\xcd\x68\x87\x85\x9d\x9a\x7d\xd9\x68\x73\xfd\x5f\x7d\xc9\xb9\xc7\x8f\xc6\xd2\xa4\xf2\x2d\x3d\xe2\xe8\x8c\xe9\x98\xc2\xc9\xf7"
  }
};

void
test_parse_batch( uchar const * batch,
                  ulong         batch_sz,
                  fd_microblock_test_vec_t const * vec,
                  ulong                            cnt ) {
  /* Peek the number of microblocks, which is the first ulong. */
  ulong cnt_actual = *(ulong *)batch;
  FD_TEST( cnt_actual==cnt );

  /* Move past the first ulong to the microblocks. */
  uchar const * batch_buf   = batch    + 8UL;
  ulong         batch_bufsz = batch_sz - 8UL;

  /* Check whether our .bss buffer fits. */
  ulong const txn_max_cnt = 1024;
  ulong footprint = fd_microblock_footprint( txn_max_cnt );
  FD_LOG_NOTICE(( "fd_microblock_t with %lu txn requires %lu bytes",
                  txn_max_cnt, footprint ));
  FD_TEST( sizeof(microblock_buf)>=footprint );

  /* Mark buffer for storing `fd_microblock_t` as unallocated (poisoned).
     `fd_microblock_new` will partially unpoison the beginning of this buffer.

     This helps catch OOB accesses beyond the end of `fd_microblock_t`. */
  fd_asan_poison  ( microblock_buf, sizeof(microblock_buf) );
  fd_asan_unpoison( microblock_buf, footprint              );

  /* Create new object in .bss buffer. */
  void * shblock = fd_microblock_new( microblock_buf, txn_max_cnt );
  FD_TEST( shblock );

  /* Get reference to newly created microblock. */
  fd_microblock_t * block = fd_microblock_join( shblock );
  FD_TEST( block );

  /* Deserialize all microblocks. */
  fd_txn_parse_counters_t counters_opt = {0};
  for( ulong i=0; i<cnt; i++ ) {
    FD_TEST( batch_buf );

    ulong microblock_sz =
    fd_microblock_deserialize( block, batch_buf, batch_bufsz, &counters_opt );
    FD_TEST( microblock_sz>0UL );

    batch_buf   += microblock_sz;
    batch_bufsz -= microblock_sz;

    FD_TEST( 0==memcmp( &block->hdr, &vec[i].hdr, sizeof(fd_microblock_hdr_t) ) );
    if( FD_UNLIKELY( block->hdr.txn_cnt > 0UL ) ) {
      uchar mixin[ 32UL ];
      fd_microblock_mixin( block, mixin );
      FD_TEST( 0==memcmp( mixin, vec[i].mixin, FD_SHA256_HASH_SZ ) );
    }
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_microblock();

  fd_microblock_test_vec_t test_slot0_batch0_vec[64];
  for( ulong i=0UL; i<64UL; i++ ) test_slot0_batch0_vec[i] = test_slot0_batch0_tmpl;
  test_parse_batch( test_slot0_batch0,   test_slot0_batch0_sz,   test_slot0_batch0_vec,   test_slot0_batch0_cnt   );
  test_parse_batch( test_slot210_batch6, test_slot210_batch6_sz, test_slot210_batch6_vec, test_slot210_batch6_cnt );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
