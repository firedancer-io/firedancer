#include "fd_microblock.h"

#include "../bmtree/fd_bmtree.h"
#include "../pack/fd_pack.h"

#if !FD_HAS_ALLOCA
#error "This file requires FD_HAS_ALLOCA"
#endif

FD_FN_CONST ulong
fd_microblock_align( void ) {
  return FD_MICROBLOCK_ALIGN;
}

FD_FN_CONST ulong
fd_microblock_footprint( ulong txn_cnt ) {
  /* Fixed-size data preceding VLA */
  ulong sz = sizeof(fd_microblock_t);

  /* Max required heap space for all txn descriptors */
  sz += alignof(fd_txn_o_t);
  if( FD_UNLIKELY( txn_cnt > (ULONG_MAX-sz)/sizeof(fd_txn_o_t) ) ) return 0; /* txn_cnt too large */
  sz += txn_cnt*sizeof(fd_txn_o_t);

  /* Max required heap space for raw txn tbl */
  sz += alignof(fd_rawtxn_b_t);
  if( FD_UNLIKELY( txn_cnt > (ULONG_MAX-sz)/sizeof(fd_rawtxn_b_t) ) ) return 0; /* txn_cnt too large */
  sz += txn_cnt*sizeof(fd_rawtxn_b_t);

  return fd_ulong_align_up( sz, FD_MICROBLOCK_ALIGN );
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

  ulong hdr_end_laddr     = (ulong)hdr + sizeof(fd_microblock_t);
  ulong txn_tbl_laddr     = fd_ulong_align_up( hdr_end_laddr,     alignof(fd_txn_o_t)    );
  ulong txn_tbl_end_laddr = txn_tbl_laddr + txn_cnt*sizeof(fd_txn_o_t);
  ulong raw_tbl_laddr     = fd_ulong_align_up( txn_tbl_end_laddr, alignof(fd_rawtxn_b_t) );

  /* Assertion: raw_tbl_laddr <= (ulong)shmem+footprint */

  hdr->txn_tbl = (fd_txn_o_t    *)txn_tbl_laddr;
  hdr->raw_tbl = (fd_rawtxn_b_t *)raw_tbl_laddr;

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

ulong
fd_microblock_deserialize( fd_microblock_t * block,
                           uchar const *     buf,
                           ulong             buf_sz,
                           fd_txn_parse_counters_t * counters_opt ) {
# define ADVANCE(n) do {                      \
  if( FD_UNLIKELY( buf_sz < (n) ) ) return 0; \
  buf    += (n);                              \
  buf_sz -= (n);                              \
} while(0)

  ulong orig_buf_sz = buf_sz;

  /* Copy microblock header */
  fd_microblock_hdr_t * hdr = (fd_microblock_hdr_t *)buf;
  ADVANCE( sizeof(fd_microblock_hdr_t) );
  fd_memcpy( &block->hdr, hdr, sizeof(fd_microblock_hdr_t) );

  /* Bounds check txn count */
  if( FD_UNLIKELY( block->hdr.txn_cnt > block->txn_max_cnt ) )
    return 0UL;

  /* Parse transactions */
  fd_rawtxn_b_t * raw_tbl = block->raw_tbl;
  fd_txn_o_t    * txn_tbl = block->txn_tbl;
  for( ulong txn_idx=0; txn_idx < block->hdr.txn_cnt; txn_idx++ ) {
    /* Remember ptr of raw txn */
    fd_rawtxn_b_t * raw_txn = &raw_tbl[ txn_idx ];
    void * raw_ptr = (void *)buf;

    /* Parse txn into descriptor table */
    fd_txn_t * out_txn = (fd_txn_t *)&txn_tbl[ txn_idx ];

    ulong raw_txn_sz;
    ulong txn_sz = fd_txn_parse( buf, fd_ulong_min(buf_sz, FD_MTU), out_txn, counters_opt, &raw_txn_sz );

    if( FD_UNLIKELY( txn_sz==0UL ) ) 
      return 0;
    ADVANCE( raw_txn_sz );

    raw_txn->raw    = raw_ptr;
    raw_txn->txn_sz = (ushort)txn_sz;
  }

  return orig_buf_sz - buf_sz;

}

ulong
fd_microblock_skip(        uchar const *     buf,
                           ulong             buf_sz ) {
  ulong orig_buf_sz = buf_sz;

  fd_microblock_hdr_t * hdr = (fd_microblock_hdr_t *)buf;
  ADVANCE( sizeof(fd_microblock_hdr_t) );

  for( ulong txn_idx=0; txn_idx < hdr->txn_cnt; txn_idx++ ) {
    ulong raw_txn_sz;
    ulong txn_sz = fd_txn_parse( buf, fd_ulong_min(buf_sz, FD_MTU), NULL, NULL, &raw_txn_sz );

    if( FD_UNLIKELY( txn_sz==0UL ) ) 
      return 0;
    ADVANCE( raw_txn_sz );
  }

  return orig_buf_sz - buf_sz;

# undef ADVANCE
}


void
fd_microblock_mixin( fd_microblock_t const * block,
                     uchar *                 out_hash ) {
  ulong txn_cnt = block->hdr.txn_cnt;

  fd_bmtree32_commit_t * commit =
  fd_alloca( FD_BMTREE_COMMIT_ALIGN, fd_bmtree32_commit_footprint( txn_cnt ) );

  if( FD_UNLIKELY( !commit ) )
    FD_LOG_ERR(( "fd_microblock_mixin: fd_alloca for microblock with %lu txns failed", txn_cnt ));

  ulong scnt = 0;

  fd_rawtxn_b_t const * raw_tbl = block->raw_tbl;
  fd_txn_o_t    const * txn_tbl = block->txn_tbl;

  for( ulong i=0; i<txn_cnt; i++ ) {
    fd_txn_t const * txn = (fd_txn_t const *)&txn_tbl[ i ];
    scnt += txn->signature_cnt;
  }

  fd_bmtree32_commit_init( commit, scnt );

  for( ulong i=0; i<txn_cnt; i++ ) {
    void     const * raw =                    raw_tbl[ i ].raw;
    fd_txn_t const * txn = (fd_txn_t const *)&txn_tbl[ i ];

    fd_ed25519_sig_t const * sigs = fd_txn_get_signatures( txn, raw );

    for ( ulong j = 0; j < txn->signature_cnt; j++ ) {
      fd_bmtree32_node_t leaf;
      fd_bmtree32_hash_leaf( leaf, &sigs[j], sizeof(fd_ed25519_sig_t) );
      fd_bmtree32_commit_append( commit, (fd_bmtree32_node_t const *)&leaf, 1 );
    }
  }

  fd_bmtree32_node_t * root = fd_bmtree32_commit_fini( commit );
  memcpy( out_hash, root, sizeof(fd_bmtree32_node_t) );
}
