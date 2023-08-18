#include "fd_wbmtree.h"

// Merkle tree of 3 nodes
//
// A . B . C
//
// root =
//      sha256([0x1] +
//        sha256([0x1] + sha256([0x0] + A) + sha256([0x0] + B)) |
//        sha256([0x1] + sha256([0x0] + C) + sha256([0x0] + C))
//      )
//

fd_wbmtree32_t*
fd_wbmtree32_init      ( void * mem, ulong leaf_cnt )
{
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_wbmtree32_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_memset(mem, 0, fd_wbmtree32_footprint(leaf_cnt));
  fd_wbmtree32_t* hdr = (fd_wbmtree32_t*) mem;
  hdr->leaf_cnt_max = leaf_cnt;
  hdr->leaf_cnt = 0;

  fd_sha256_batch_init(&hdr->sha256_batch);

  return mem;
}

fd_wbmtree32_t*
fd_wbmtree32_join      ( void * mem )
{
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_wbmtree32_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  fd_wbmtree32_t* hdr = (fd_wbmtree32_t*) mem;
  return hdr;
}

void *
fd_wbmtree32_leave      ( fd_wbmtree32_t* hdr ) {
  if( FD_UNLIKELY( !hdr ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  return (void *) hdr;
}

void
fd_wbmtree32_append    ( fd_wbmtree32_t * bmt, fd_wbmtree32_leaf_t const * leaf, ulong leaf_cnt, uchar *mbuf  )
{
  FD_TEST ((bmt->leaf_cnt + leaf_cnt) <= bmt->leaf_cnt_max);

  fd_wbmtree32_node_t *n = &((fd_wbmtree32_node_t *)bmt->data)[bmt->leaf_cnt];
  for (ulong i = 0; i < leaf_cnt; i++) {
    mbuf[0] = (uchar) 0;
    fd_memcpy(&mbuf[1], leaf->data, leaf->data_len);
    fd_sha256_batch_add(&bmt->sha256_batch, mbuf, leaf->data_len + 1, &n->hash[(i & 1) ? 0 : 1]);
    mbuf += leaf->data_len + 1;
    n++;
    leaf++;
  }
  fd_sha256_batch_fini(&bmt->sha256_batch);
  bmt->leaf_cnt += leaf_cnt;

  FD_TEST (leaf_cnt <= bmt->leaf_cnt_max);
}

uchar *
fd_wbmtree32_fini      ( fd_wbmtree32_t * bmt)
{
  FD_TEST ( bmt->leaf_cnt <= bmt->leaf_cnt_max );

  fd_wbmtree32_node_t *this = (fd_wbmtree32_node_t *)bmt->data;
  fd_wbmtree32_node_t *that = &((fd_wbmtree32_node_t *)bmt->data)[bmt->leaf_cnt + (bmt->leaf_cnt & 1)];

  while (bmt->leaf_cnt > 1) {
    // If the tree is uneven, we duplicate the last hash
    if (bmt->leaf_cnt & 1) {
      // In the source data, the bytes are offset by 1 to give us room
      // for the 1 byte... in the target, it is not offset by one..
      fd_memcpy(this[bmt->leaf_cnt].hash, &this[bmt->leaf_cnt - 1].hash[1], 32);
      bmt->leaf_cnt++;
    }
    for (ulong i = 0; i < bmt->leaf_cnt; i += 2) {
      uchar *d = this[i].hash;
      d[0] = (uchar) 1;
      ulong hi = i / 2; // Half of i .. ie, where is this going?
      fd_sha256_batch_add(&bmt->sha256_batch, d, 65, &that[hi].hash[(hi & 1) ? 0 : 1]);
    }
    // This leaves the batch object unusable...
    fd_sha256_batch_fini(&bmt->sha256_batch);
    bmt->leaf_cnt /= 2;

    // start over
    FD_TEST (fd_sha256_batch_init(&bmt->sha256_batch) == &bmt->sha256_batch);;

    fd_wbmtree32_node_t * a = that;
    that = this;
    this = a;
  }

  return &this[0].hash[1];
}

void *
fd_wbmtree32_delete( void * shblock ) {
  if( FD_UNLIKELY( !shblock ) ) {
    FD_LOG_WARNING(( "NULL shblock" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shblock, fd_wbmtree32_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shblock" ));
    return NULL;
  }

  return shblock;
}

ulong            fd_wbmtree32_align     ( void ) { return alignof(fd_wbmtree32_t); }

ulong            fd_wbmtree32_footprint ( ulong leaf_cnt ) {
  if (leaf_cnt & 1)
    leaf_cnt++;  // Round up to even numbers...
  return sizeof(fd_wbmtree32_t) + sizeof(fd_wbmtree32_node_t) * (leaf_cnt + (leaf_cnt / 2));
}
