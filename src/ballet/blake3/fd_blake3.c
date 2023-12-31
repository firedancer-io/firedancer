#include "fd_blake3.h"
#include "fd_blake3_private.h"
#include <assert.h>

/* Hash state machine *************************************************/

static FD_FN_UNUSED fd_blake3_pos_t *
fd_blake3_pos_init( fd_blake3_pos_t * s,
                    uchar const *     data,
                    ulong             sz ) {
  *s = (fd_blake3_pos_t) {
    .input    = data,
    .input_sz = sz,
    .magic    = FD_BLAKE3_MAGIC,
  };
  return s;
}

/* fd_blake3_l0_complete returns 1 if all leaf nodes have been hashed,
   0 otherwise. */

FD_FN_PURE static inline int
fd_blake3_l0_complete( fd_blake3_pos_t const * s ) {
  return ( s->leaf_idx<<FD_BLAKE3_CHUNK_LG_SZ ) >= fd_ulong_max( s->input_sz, 64 );
}

FD_FN_PURE static inline int
fd_blake3_is_finished( fd_blake3_pos_t const * s,
                       ulong                   tick ) {
  int l0_complete = fd_blake3_l0_complete( s );
  int ln_complete = s->live_cnt == 1UL;
  int idle        = tick >= s->next_tick;
  return l0_complete & ln_complete & idle;
}

static fd_blake3_op_t *
fd_blake3_prepare_leaf( fd_blake3_pos_t * restrict s,
                        fd_blake3_buf_t * restrict buf,
                        fd_blake3_op_t *  restrict op,
                        ulong                      tick ) {

  ulong         msg_off = s->leaf_idx << FD_BLAKE3_CHUNK_LG_SZ;
  ulong         msg_sz  = fd_ulong_min( s->input_sz - msg_off, 1024UL );
  uchar const * msg     = s->input + msg_off;
  uchar       * out     = buf->slots[ s->layer ][ s->head.uc[ s->layer ] ];

  int flags = fd_int_if( s->input_sz <= FD_BLAKE3_CHUNK_SZ, FD_BLAKE3_FLAG_ROOT, 0 );

  *op = (fd_blake3_op_t) {
    .msg     = msg,
    .out     = out,
    .counter = s->leaf_idx,
    .sz      = (ushort)msg_sz,
    .flags   = (uchar)flags
  };

  s->head.uc[ 0 ] = (uchar)( s->head.uc[ 0 ]+1 );
  s->leaf_idx++;
  s->live_cnt++;
  s->next_tick = tick+1;

  return op;

}

static int
fd_blake3_seek_branch( fd_blake3_pos_t * restrict s,
                       fd_blake3_buf_t * restrict buf,
                       ulong                      tick ) {

  if( s->live_cnt == 1UL )
    return 0;

  if( !fd_blake3_l0_complete( s ) )
    return ( s->tail.uc[ s->layer - 1 ] + 1 ) <
           ( s->head.uc[ s->layer - 1 ]     );

# if FD_HAS_AVX

  wb_t diff = wb_sub( s->head.wb, s->tail.wb );

  uint mergeable_layers = (uint)_mm256_movemask_epi8( wb_gt( diff, wb_bcast( 1 ) ) );
  int  merge_layer = fd_uint_find_lsb_w_default( mergeable_layers, -1 );
  if( merge_layer>=0 ) {
    if( ((uint)merge_layer >= s->layer) & (tick < s->next_tick) )
      return 0;  /* still waiting for previous merge */
    s->layer = (uint)merge_layer+1U;
    return 1;
  }

  uint single_layers = (uint)_mm256_movemask_epi8( wb_eq( diff, wb_bcast( 1 ) ) );
  uint single_lo = (uint)fd_uint_find_lsb( single_layers );
  uint single_hi = (uint)fd_uint_find_lsb( single_layers & ( ~fd_uint_mask_lsb( (int)(single_lo+1U) ) ) );

  wb_t node = wb_ld( buf->slots[ single_lo ][ s->tail.uc[ single_lo ] ] );
              wb_st( buf->slots[ single_hi ][ s->head.uc[ single_hi ] ], node );

# else /* FD_HAS_AVX */

  uchar diff[ 32 ];
  for( ulong j=0UL; j<32UL; j++ ) diff[j] = (uchar)( s->head.uc[j] - s->tail.uc[j] );

  int merge_layer = -1;
  for( uint j=0U; j<32U; j++ ) {
    if( diff[j]>1 ) {
      merge_layer = (int)j;
      break;
    }
  }
  if( merge_layer>=0 ) {
    if( ((uint)merge_layer >= s->layer) & (tick < s->next_tick) )
      return 0;  /* still waiting for previous merge */
    s->layer = (uint)(merge_layer+1);
    return 1;
  }

  uint j=0UL;
  uint single_lo = 0UL;
  uint single_hi = 0UL;
  for( ; j<32U; j++ ) {
    if( diff[j] ) {
      single_lo = j;
      break;
    }
  }
  j++;
  for( ; j<32U; j++ ) {
    if( diff[j] ) {
      single_hi = j;
      break;
    }
  }

  memcpy( buf->slots[ single_hi ][ s->head.uc[ single_hi ] ],
          buf->slots[ single_lo ][ s->tail.uc[ single_lo ] ],
          32UL );

# endif /* FD_HAS_AVX */

  FD_BLAKE3_TRACE(( "fd_blake3_seek_branch: moving up %u/%u to %u/%u",
                    single_lo, s->tail.uc[ single_lo ],
                    single_hi, s->head.uc[ single_hi ] ));

  if( ((uint)single_hi >= s->layer) & (tick < s->next_tick) )
    return 0;  /* still waiting for previous merge */

  s->head.uc[ single_lo ] = (uchar)( s->head.uc[ single_lo ]-1 );
  s->head.uc[ single_hi ] = (uchar)( s->head.uc[ single_hi ]+1 );

  s->layer = (uint)single_hi+1U;
  return 1;
}

static fd_blake3_op_t *
fd_blake3_prepare_branch( fd_blake3_pos_t * restrict s,
                          fd_blake3_buf_t * restrict buf,
                          fd_blake3_op_t *  restrict op,
                          ulong                      tick ) {

  if( !fd_blake3_seek_branch( s, buf, tick ) )
    return NULL;

  assert( s->layer < FD_BLAKE3_ROW_CNT );

  uchar const * msg = buf->slots[ s->layer-1U ][ s->tail.uc[ s->layer-1U ] ];
  uchar       * out = buf->slots[ s->layer    ][ s->head.uc[ s->layer    ] ];

  s->head.uc[ s->layer   ] = (uchar)( s->head.uc[ s->layer   ]+1 );
  s->tail.uc[ s->layer-1 ] = (uchar)( s->tail.uc[ s->layer-1 ]+2 );
  s->live_cnt--;
  s->next_tick = tick+1;

  uint flags = FD_BLAKE3_FLAG_PARENT |
               fd_uint_if( s->live_cnt==1UL, FD_BLAKE3_FLAG_ROOT, 0u );

  *op = (fd_blake3_op_t) {
    .msg     = msg,
    .out     = out,
    .counter = 0UL,
    .sz      = 64U,
    .flags   = (uchar)flags
  };
  return op;

}

static void
fd_blake3_advance( fd_blake3_pos_t * restrict s ) {

# if FD_HAS_AVX

  wb_t mask = wb_eq( s->tail.wb, s->head.wb );
  s->tail.wb = wb_andnot( mask, s->tail.wb );
  s->head.wb = wb_andnot( mask, s->head.wb );

# else /* FD_HAS_AVX */

  for( ulong j=0UL; j<32UL; j++ ) {
    if( s->tail.uc[j] == s->head.uc[j] ) {
      s->tail.uc[j] = 0;
      s->head.uc[j] = 0;
    }
  }

# endif /* FD_HAS_AVX */

  if( s->head.uc[ s->layer ]==FD_BLAKE3_COL_CNT ) {
    s->layer++;
  }
  else if( ( s->layer > 0UL ) &&
           ( s->tail.uc[ s->layer-1 ] < s->head.uc[ s->layer-1 ] ) ) {
    /* pass */
  }
  else if( fd_blake3_l0_complete( s ) ) {
    s->layer++;
  }
  else if( s->layer > 0UL ) {
    s->layer = 0UL;
  }

}

static fd_blake3_op_t *
fd_blake3_prepare( fd_blake3_pos_t * restrict s,
                   fd_blake3_buf_t * restrict buf,
                   fd_blake3_op_t *  restrict op,
                   ulong                      tick ) {

  assert( s->layer < FD_BLAKE3_ROW_CNT );

  if( fd_blake3_is_finished( s, tick ) )
    return NULL;

  if( tick >= s->next_tick )
    fd_blake3_advance( s );

  if( s->layer != 0 )
    return fd_blake3_prepare_branch( s, buf, op, tick );

  if( ( s->head.uc[0] >= FD_BLAKE3_COL_CNT ) |
      ( fd_blake3_l0_complete( s )         ) ) {
    return NULL;
  }

  return fd_blake3_prepare_leaf( s, buf, op, tick );

}

#if FD_BLAKE3_PARA_MAX>1

/* fd_blake3_prepare_fast does streamlined hashing of full chunks or
   full branches. */

static fd_blake3_op_t *
fd_blake3_prepare_fast( fd_blake3_pos_t * restrict s,
                        fd_blake3_buf_t * restrict buf,
                        fd_blake3_op_t *  restrict op,
                        ulong                      n,
                        ulong                      min ) {

  if( s->layer && s->head.uc[ s->layer-1 ]==FD_BLAKE3_COL_CNT ) {
    op->msg     = buf->rows[ s->layer-1 ];
    op->out     = buf->rows[ s->layer ] + (s->head.uc[ s->layer ]<<FD_BLAKE3_OUTCHAIN_LG_SZ);
    op->counter = 0UL;
    op->flags   = FD_BLAKE3_FLAG_PARENT;

    /* Assume that branch layer is fully hashed (up to col cnt) */
    s->head.uc[ s->layer-1 ] =  0;
    s->head.uc[ s->layer   ] = (uchar)( (ulong)s->head.uc[ s->layer ]+n );
    s->live_cnt -= n;
    s->layer = fd_uint_if( s->head.uc[ s->layer ]==FD_BLAKE3_COL_CNT,
                           s->layer+1U, 0U );

    return op;
  }

  ulong pos   = s->leaf_idx << FD_BLAKE3_CHUNK_LG_SZ;
  ulong avail = fd_ulong_align_dn( s->input_sz - pos, FD_BLAKE3_CHUNK_SZ ) >> FD_BLAKE3_CHUNK_LG_SZ;
  n = fd_ulong_min( n, avail );

  /* This constants controls the threshold when to use the (slow)
     scheduler instead of fast single-message hashing.  Carefully tuned
     for best overall performance. */
  if( n<min ) return NULL;

  op->msg     = s->input + (s->leaf_idx<<FD_BLAKE3_CHUNK_LG_SZ);
  op->out     = buf->rows[0] + (s->head.uc[0]<<FD_BLAKE3_OUTCHAIN_LG_SZ);
  op->counter = s->leaf_idx;
  op->flags   = 0;

  s->head.uc[0] = (uchar)( (ulong)s->head.uc[0]+n );
  s->leaf_idx   += n;
  s->live_cnt   += n;
  s->layer      =  fd_uint_if( s->head.uc[0]==FD_BLAKE3_COL_CNT, 1U, 0U );

  return op;
}

static void
fd_blake3_batch_hash( fd_blake3_op_t const * ops,
                      ulong                  op_cnt ) {
  uchar const * batch_data   [ FD_BLAKE3_PARA_MAX ] __attribute__((aligned(64)));
  uint          batch_data_sz[ FD_BLAKE3_PARA_MAX ] = {0};
  uchar *       batch_hash   [ FD_BLAKE3_PARA_MAX ] __attribute__((aligned(64)));
  ulong         batch_ctr    [ FD_BLAKE3_PARA_MAX ];
  uint          batch_flags  [ FD_BLAKE3_PARA_MAX ];
  for( ulong j=0UL; j<op_cnt; j++ ) {
    batch_data   [ j ] = ops[ j ].msg;
    batch_hash   [ j ] = ops[ j ].out;
    batch_data_sz[ j ] = ops[ j ].sz;
    batch_ctr    [ j ] = ops[ j ].counter;
    batch_flags  [ j ] = ops[ j ].flags;
  }
#if FD_HAS_AVX512
  fd_blake3_avx512_compress16( op_cnt, batch_data, batch_data_sz, fd_type_pun( batch_hash ), batch_ctr, batch_flags );
#elif FD_HAS_AVX
  fd_blake3_avx_compress8( op_cnt, batch_data, batch_data_sz, fd_type_pun( batch_hash ), batch_ctr, batch_flags );
#else
  #error "FIXME missing para support"
#endif
}

#endif

/* Simple API *********************************************************/

ulong
fd_blake3_align( void ) {
  return FD_BLAKE3_ALIGN;
}

ulong
fd_blake3_footprint( void ) {
  return FD_BLAKE3_FOOTPRINT;
}

void *
fd_blake3_new( void * shmem ) {
  fd_blake3_t * sha = (fd_blake3_t *)shmem;

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_blake3_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  ulong footprint = fd_blake3_footprint();

  fd_memset( sha, 0, footprint );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( sha->pos.magic ) = FD_BLAKE3_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)sha;
}

fd_blake3_t *
fd_blake3_join( void * shsha ) {

  if( FD_UNLIKELY( !shsha ) ) {
    FD_LOG_WARNING(( "NULL shsha" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shsha, fd_blake3_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shsha" ));
    return NULL;
  }

  fd_blake3_t * sha = (fd_blake3_t *)shsha;

  if( FD_UNLIKELY( sha->pos.magic!=FD_BLAKE3_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return sha;
}

void *
fd_blake3_leave( fd_blake3_t * sha ) {

  if( FD_UNLIKELY( !sha ) ) {
    FD_LOG_WARNING(( "NULL sha" ));
    return NULL;
  }

  return (void *)sha;
}

void *
fd_blake3_delete( void * shsha ) {

  if( FD_UNLIKELY( !shsha ) ) {
    FD_LOG_WARNING(( "NULL shsha" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shsha, fd_blake3_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shsha" ));
    return NULL;
  }

  fd_blake3_t * sha = (fd_blake3_t *)shsha;

  if( FD_UNLIKELY( sha->pos.magic!=FD_BLAKE3_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( sha->pos.magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return (void *)sha;
}


fd_blake3_t *
fd_blake3_init( fd_blake3_t * sha ) {
  FD_BLAKE3_TRACE(( "fd_blake3_init(sha=%p)", (void *)sha ));
  fd_blake3_pos_init( &sha->pos, NULL, 0UL );
  sha->block_sz = 0UL;
  return sha;
}

#if FD_BLAKE3_PARA_MAX>1

static void
fd_blake3_append_blocks( fd_blake3_pos_t * s,
                         fd_blake3_buf_t * tbl,
                         uchar const *     data,
                         ulong             buf_cnt ) {
  s->input = data - (s->leaf_idx << FD_BLAKE3_CHUNK_LG_SZ); /* TODO HACKY!! */
  for( ulong i=0UL; i<buf_cnt; i++ ) {
    fd_blake3_op_t op[1];
    do {
      if( !fd_blake3_prepare_fast( s, tbl, op, FD_BLAKE3_PARA_MAX, FD_BLAKE3_PARA_MAX ) )
        return;
#if FD_HAS_AVX512
      fd_blake3_avx512_compress16_fast( op->msg, op->out, op->counter, op->flags );
#elif FD_HAS_AVX
      fd_blake3_avx_compress8_fast( op->msg, op->out, op->counter, op->flags );
#else
      #error "missing para support"
#endif
    } while( op->flags & FD_BLAKE3_FLAG_PARENT );
  }
}

#else

static void
fd_blake3_append_blocks( fd_blake3_pos_t * s,
                         fd_blake3_buf_t * tbl,
                         uchar const *     data,
                         ulong             buf_cnt ) {
  (void)buf_cnt;
  s->input = data - (s->leaf_idx << FD_BLAKE3_CHUNK_LG_SZ); /* TODO HACKY!! */
  fd_blake3_op_t op[1];
  while( buf_cnt ) {
    if( !fd_blake3_prepare( s, tbl, op, s->next_tick ) ) {
      FD_BLAKE3_TRACE(( "fd_blake3_append_blocks: no more ops to prepare" ));
      break;
    }
    if( op->flags & FD_BLAKE3_FLAG_PARENT ) {
      FD_BLAKE3_TRACE(( "fd_blake3_append_blocks: compressing output chaining values (layer %u)", s->layer ));
      fd_blake3_ref_compress1( op->out, op->msg, 64UL, op->counter, op->flags );
    } else {
      FD_BLAKE3_TRACE(( "fd_blake3_append_blocks: compressing %lu leaf chunks", FD_BLAKE3_COL_CNT ));
      fd_blake3_ref_compress1( op->out, op->msg, FD_BLAKE3_CHUNK_SZ, op->counter, op->flags );
      buf_cnt--;
    }
    s->next_tick++;
  }
}

#endif

fd_blake3_t *
fd_blake3_append( fd_blake3_t * sha,
                  void const *  _data,
                  ulong         sz ) {

  /* If no data to append, we are done */

  if( FD_UNLIKELY( !sz ) ) return sha;
  FD_BLAKE3_TRACE(( "fd_blake3_append(sha=%p,data=%p,sz=%lu)", (void *)sha, _data, sz ));

  /* Unpack inputs */

  fd_blake3_pos_t * s        = &sha->pos;
  fd_blake3_buf_t * tbl      = &sha->buf;
  uchar *           buf      = sha->block;
  ulong             buf_used = sha->block_sz;

  uchar const * data = (uchar const *)_data;

  /* Update input_sz */

  s->input_sz += sz;

  /* Edge case: For the first completed 1024 bytes of input, don't
     immediately hash, since it is not clear whether this chunk has
     the root flag set. */
  if( FD_UNLIKELY( FD_BLAKE3_PARA_MAX==1 && s->input_sz==1024UL ) ) {
    fd_memcpy( buf + buf_used, data, sz );
    sha->block_sz = FD_BLAKE3_CHUNK_SZ;
    return sha;
  }

  /* Handle buffered bytes from previous appends */

  if( FD_UNLIKELY( buf_used ) ) { /* optimized for well aligned use of append */

    /* If the append isn't large enough to complete the current block,
       buffer these bytes too and return */

    ulong buf_rem = FD_BLAKE3_PRIVATE_BUF_MAX - buf_used; /* In (0,FD_BLAKE3_PRIVATE_BUF_MAX) */
    if( FD_UNLIKELY( sz < buf_rem ) ) { /* optimize for large append */
      fd_memcpy( buf + buf_used, data, sz );
      sha->block_sz = buf_used + sz;
      return sha;
    }

    /* Otherwise, buffer enough leading bytes of data to complete the
       block, update the hash and then continue processing any remaining
       bytes of data. */

    fd_memcpy( buf + buf_used, data, buf_rem );
    data += buf_rem;
    sz   -= buf_rem;

    fd_blake3_append_blocks( s, tbl, buf, 1UL );
    sha->block_sz = 0UL;
  }

  /* Append the bulk of the data */

  ulong buf_cnt = sz >> FD_BLAKE3_PRIVATE_LG_BUF_MAX;
  if( FD_LIKELY( buf_cnt ) ) fd_blake3_append_blocks( s, tbl, data, buf_cnt ); /* optimized for large append */

  /* Buffer any leftover bytes */

  buf_used = sz & (FD_BLAKE3_PRIVATE_BUF_MAX-1UL); /* In [0,FD_BLAKE3_PRIVATE_BUF_MAX) */
  if( FD_UNLIKELY( buf_used ) ) { /* optimized for well aligned use of append */
    fd_memcpy( buf, data + (buf_cnt << FD_BLAKE3_PRIVATE_LG_BUF_MAX), buf_used );
    sha->block_sz = buf_used; /* In (0,FD_BLAKE3_PRIVATE_BUF_MAX) */
  }

  FD_BLAKE3_TRACE(( "fd_blake3_append: done" ));
  return sha;
}

static void const *
fd_blake3_single_hash( fd_blake3_pos_t * s,
                       fd_blake3_buf_t * tbl ) {
#if FD_BLAKE3_PARA_MAX>1
  ulong tick = 0UL;
  while( !fd_blake3_is_finished( s, tick ) ) {
    fd_blake3_op_t ops[ FD_BLAKE3_PARA_MAX ] = {0};
    ulong          op_cnt = 0UL;
    while( op_cnt<FD_BLAKE3_PARA_MAX ) {
      fd_blake3_op_t * op = &ops[ op_cnt ];
      if( !fd_blake3_prepare( s, tbl, op, tick ) )
        break;
      op_cnt++;
    }

    fd_blake3_batch_hash( ops, op_cnt );
    tick++;
  }
#else
  while( !fd_blake3_is_finished( s, s->next_tick ) ) {
    fd_blake3_op_t op[1] = {0};
    if( !fd_blake3_prepare( s, tbl, op, s->next_tick ) )
      break;
    s->next_tick++;
    FD_BLAKE3_TRACE(( "fd_blake3_single_hash: compressing %hu bytes at layer %u, counter %lu, flags 0x%x",
                      op->sz, s->layer, op->counter, op->flags ));
#   if FD_HAS_SSE
    fd_blake3_sse_compress1( op->out, op->msg, op->sz, op->counter, op->flags );
#   else
    fd_blake3_ref_compress1( op->out, op->msg, op->sz, op->counter, op->flags );
#   endif
  }
#endif
  return tbl->slots[ s->layer ][0];
}

void *
fd_blake3_fini( fd_blake3_t * sha,
                void *        hash ) {

  /* Unpack inputs */

  fd_blake3_pos_t * s        = &sha->pos;
  fd_blake3_buf_t * tbl      = &sha->buf;
  uchar *           buf      = sha->block;
  ulong             buf_used = sha->block_sz;
  FD_BLAKE3_TRACE(( "fd_blake3_fini(sha=%p,sz=%lu)", (void *)sha, s->input_sz ));

  /* TODO HACKY!! */
  s->input    = buf - ( s->leaf_idx << FD_BLAKE3_CHUNK_LG_SZ );
  s->input_sz = ( s->leaf_idx << FD_BLAKE3_CHUNK_LG_SZ ) + buf_used;

  void const * hash_ = fd_blake3_single_hash( s, tbl );
  memcpy( hash, hash_, 32UL );
  return hash;
}

void *
fd_blake3_fini_2048( fd_blake3_t * sha,
                     void *        hash ) {
  (void)sha;
  fd_memset( hash, 0, 2048UL );
  return NULL;
}

void *
fd_blake3_hash( void const * data,
                ulong        sz,
                void *       hash ) {

  fd_blake3_buf_t tbl[1];
  fd_blake3_pos_t s[1];
  fd_blake3_pos_init( s, data, sz );

#if FD_BLAKE3_PARA_MAX>1
  for(;;) {
    fd_blake3_op_t op[1];
    if( !fd_blake3_prepare_fast( s, tbl, op, FD_BLAKE3_PARA_MAX, 4 ) )
      break;
#if FD_HAS_AVX512
    fd_blake3_avx512_compress16_fast( op->msg, op->out, op->counter, op->flags );
#elif FD_HAS_AVX
    fd_blake3_avx_compress8_fast( op->msg, op->out, op->counter, op->flags );
#else
    #error "missing para support"
#endif
  }
#endif

  void const * hash_ = fd_blake3_single_hash( s, tbl );
  memcpy( hash, hash_, 32UL );
  return hash;
}
