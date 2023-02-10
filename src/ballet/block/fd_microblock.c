#include "fd_microblock.h"

#include "../bmtree/fd_bmtree.h"

FD_FN_CONST ulong
fd_microblock_align( void ) {
  return FD_MICROBLOCK_ALIGN;
}

FD_FN_CONST ulong
fd_microblock_footprint( ulong txn_cnt ) {
  /* Fixed-size data preceding VLA */
  ulong hdr_sz = sizeof(fd_microblock_t);

  /* Max required heap space for all txn descriptors */
  if( FD_UNLIKELY( txn_cnt > (ULONG_MAX-hdr_sz)/FD_TXN_MAX_SZ ) ) return 0; /* txn_cnt too large */
  ulong txn_tbl_sz = txn_cnt*FD_TXN_MAX_SZ;

  return fd_ulong_align_up( hdr_sz + txn_tbl_sz, FD_MICROBLOCK_ALIGN );
}

void *
fd_microblock_new( void * shmem,
                   ulong  txn_cnt ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_microblock_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  ulong footprint = fd_microblock_footprint( txn_cnt );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad txn_cnt (%lu)", txn_cnt ));
    return NULL;
  }

  fd_memset( shmem, 0, footprint );

  fd_microblock_t * hdr = (fd_microblock_t *)shmem;
  hdr->txn_max_cnt = txn_cnt;

  FD_COMPILER_MFENCE();
  hdr->magic = FD_MICROBLOCK_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

fd_microblock_t *
fd_microblock_join( void * shblock ) {

  if( FD_UNLIKELY( !shblock ) ) {
    FD_LOG_WARNING(( "NULL shblock" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shblock, fd_microblock_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shblock" ));
    return NULL;
  }

  fd_microblock_t * hdr = (fd_microblock_t *)shblock;
  if( FD_UNLIKELY( hdr->magic!=FD_MICROBLOCK_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return (fd_microblock_t *)shblock;
}

void *
fd_microblock_leave( fd_microblock_t * block ) {

  if( FD_UNLIKELY( !block ) ) {
    FD_LOG_WARNING(( "NULL block" ));
    return NULL;
  }

  return (void *)block;
}

void *
fd_microblock_delete( void * shblock ) {

  if( FD_UNLIKELY( !shblock ) ) {
    FD_LOG_WARNING(( "NULL shblock" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shblock, fd_microblock_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shblock" ));
    return NULL;
  }

  fd_microblock_t * hdr = (fd_microblock_t *)shblock;
  if( FD_UNLIKELY( hdr->magic!=FD_MICROBLOCK_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( hdr->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return shblock;
}

int
fd_microblock_deserialize( fd_microblock_t * block,
                           void **           buf,
                           ulong *           buf_sz,
                           fd_txn_parse_counters_t * counters_opt ) {
# define ADVANCE(n) do {                       \
  if( FD_UNLIKELY( *buf_sz < (n) ) ) return 0; \
  *buf     = (void *)((char *)*buf + (n));     \
  *buf_sz -= (n);                              \
} while(0)

  /* Copy microblock header */
  fd_microblock_hdr_t * hdr = (fd_microblock_hdr_t *)*buf;
  ADVANCE( sizeof(fd_microblock_hdr_t) );
  fd_memcpy( &block->hdr, hdr, sizeof(fd_microblock_hdr_t) );

  /* Parse transactions */
  fd_rawtxn_b_t * raw_tbl = block->raw_tbl;
  fd_txn_o_t    * txn_tbl = block->txn_tbl;
  for( ulong txn_idx=0; txn_idx < block->hdr.txn_cnt; txn_idx++ ) {
    /* Remember ptr of raw txn */
    fd_rawtxn_b_t * raw_txn = &raw_tbl[ txn_idx ];
    void * raw_ptr = *buf;

    /* Parse txn into descriptor table */
    fd_txn_t * out_txn = (fd_txn_t *)&txn_tbl[ txn_idx ];
    ulong txn_sz = fd_txn_parse( *buf, *buf_sz, out_txn, counters_opt );
    FD_LOG_NOTICE(( "fd_txn_parse: %lu", txn_sz ));

    if( FD_UNLIKELY( txn_sz==0UL ) ) return 0;
    ADVANCE( txn_sz );

    raw_txn->raw    = raw_ptr;
    raw_txn->txn_sz = (ushort)txn_sz;
  }

  return 1;

# undef ADVANCE
}

void
fd_microblock_mixin( fd_microblock_t const * block,
                     uchar *                 out_hash ) {
  ulong txn_cnt = block->hdr.txn_cnt;

  fd_bmtree32_commit_t * commit =
  fd_alloca( FD_MICROBLOCK_ALIGN, fd_bmtree32_commit_footprint( txn_cnt ) );

  if( FD_UNLIKELY( !commit ) )
    FD_LOG_ERR(( "fd_microblock_mixin: fd_alloca for microblock with %lu txns failed", txn_cnt ));

  fd_rawtxn_b_t const * raw_tbl = block->raw_tbl;
  fd_txn_o_t    const * txn_tbl = block->txn_tbl;

  for( ulong i=0; i<txn_cnt; i++ ) {
    void     const * raw =                    raw_tbl[ i ].raw;
    fd_txn_t const * txn = (fd_txn_t const *)&txn_tbl[ i ];

    fd_ed25519_sig_t const * sigs = fd_txn_get_signatures( txn, raw );

    fd_bmtree32_node_t leaf[1];
    fd_bmtree32_hash_leaf( leaf[0], &sigs[0], sizeof(fd_ed25519_sig_t) );
    fd_bmtree32_commit_append( commit, (fd_bmtree32_node_t const *)&leaf[0], 1 );
  }

  fd_bmtree32_node_t * root = fd_bmtree32_commit_fini( commit );
  fd_memcpy( out_hash, root, sizeof(fd_bmtree32_node_t) );
}
