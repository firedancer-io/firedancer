#include "fd_bin_parse.h"

/* Whereas the fd_slice*() APIs ensure that the bounds of the src input slice are not violated,
   these macros are responsible for ensuring that we do not read beyond the bounds of the particular
   input message blob that we're parsing. */
#define INPUT_BLOB_SZ_REMAINING (ctx->input_blob_sz - ((ulong)(ctx->src.cur - ctx->pre_parse_src_cur)))

#define CHECK_INPUT_BLOB_SZ_REMAINING(sz)  do {                               \
  if( FD_UNLIKELY( INPUT_BLOB_SZ_REMAINING<sz ) ) {                           \
    FD_LOG_WARNING(( "input blob too short" ));                               \
    return 0;                                                                 \
  }                                                                           \
} while( 0 )

/* These macros help to ensure that we don't write beyond the bounds of the
   destination buffer when serializing a gossip message struct out to
   raw bytes. */
#define OUTPUT_SZ_REMAINING ((ulong)(ctx->dst.end - ctx->dst.cur))

#define CHECK_OUTPUT_SZ_REMAINING(sz)  do {                                   \
  if( FD_UNLIKELY( OUTPUT_SZ_REMAINING < sz ) ) {                             \
    FD_LOG_WARNING(( "not enough space left in output buffer" ));             \
    return 0;                                                                 \
  }                                                                           \
} while( 0 )

/* This macro is used to assert that the parser context state is not invalid.
   A parser context should only become invalid in cases of serious programming
   errors. */
#define CHECK_CTX_STATE_IS_VALID( ctx ) do {                                  \
  if( FD_UNLIKELY( ctx->invalid_state ) ) {                                   \
    FD_LOG_ERR(( "parse context state is invalid" ));                         \
    return 0;  /* unreachable. process should be aborted. */                  \
  }                                                                           \
} while(0)

void
fd_bin_parse_init( fd_bin_parse_ctx_t * ctx,
                   void               * src,
                   ulong                src_sz,
                   void               * dst,
                   ulong                dst_sz  ) {
  ctx->src.cur = src;
  ctx->src.end = (uchar *)src + src_sz;
  ctx->dst.cur = dst;
  ctx->dst.end = (uchar *)dst + dst_sz;
  ctx->pre_parse_src_cur = ctx->src.cur;
  ctx->pre_parse_dst_cur = ctx->dst.cur;
  ctx->input_blob_sz = 0;
  ctx->invalid_state = 0;
}

/* Set size of next blob to parse from the src slice.
   This function contains defensive logic to help API misuse get caught during debugging.
   This function sets the parser context state to invalid in cases where the API user 
   incorrectly tries to set the input blob size to longer than the total input slice 
   itself. */
void
fd_bin_parse_set_input_blob_size( fd_bin_parse_ctx_t * ctx,
                                   ulong               input_blob_sz ) {
  if( FD_UNLIKELY( input_blob_sz>(ulong)(ctx->src.end-ctx->src.cur ) ) ) {
    FD_LOG_WARNING(( "input blob slice larger than total input slice size. setting context state to invalid" ));
    ctx->invalid_state = 1;
  } else {
    ctx->input_blob_sz = input_blob_sz;
    ctx->pre_parse_src_cur = ctx->src.cur;
    ctx->pre_parse_dst_cur = ctx->dst.cur;
  }
}

int
fd_bin_parse_is_state_ok_to_begin_parse( fd_bin_parse_ctx_t * ctx ) {
  CHECK_CTX_STATE_IS_VALID( ctx );
  return ( ctx->pre_parse_src_cur==ctx->src.cur && ctx->pre_parse_dst_cur==ctx->dst.cur );
}

int
fd_bin_parse_was_entire_input_blob_consumed( fd_bin_parse_ctx_t * ctx ) {
  return ( (ulong)(ctx->src.cur-ctx->pre_parse_src_cur) )==ctx->input_blob_sz;
}

/* If parsing of a blob succeeds, we advance the dst `cur` up to beyond
   where the parsed structures were written to, and there's no need to update the src
   `cur` pointer because this occurred fully during parsing. This invariant is further
   checked by a call to `fd_bin_parse_was_entire_input_blob_consumed`
   This function includes defensive logic that should be impossible to trigger. As such,
   this logic ensures that the destination slice has enough capacity to advance the `cur`
   pointer by n bytes. In practice (such as during gossip parsing) this should not be
   possible to trigger (such as via malformed gossip packets), hence this check is added
   to help catch serious programming errors (e.g. API misuse and invariant violations) */
void
fd_bin_parse_update_state_parse_succeeded( fd_bin_parse_ctx_t * ctx,
                                     ulong                data_written_sz ) {
  if( FD_UNLIKELY( !fd_slice_is_enough_space( &(ctx->dst), data_written_sz ) ) ) {
    FD_LOG_WARNING(( "not enough space to advance src `cur` by the requested size" ));
    ctx->invalid_state = 1;
  } else {
    fd_slice_increment_slice( &(ctx->dst), data_written_sz );
  }
}

/* If parsing of a blob fails, we advance the src `cur` beyond the
   bad payload so as to move onto the next one, and we rewind the dst `cur` back to where
   it was before the parse began.
   This function contains defensive logic to prevent should-be impossible conditions such 
   as the source `cur` being advanced beyond the end of the src slice. Since such conditions
   shouldn't be possible via normal and proper use of the API, these checks exist so as to
   help catch serious programming errors. */
void
fd_bin_parse_update_state_parse_failed( fd_bin_parse_ctx_t * ctx ) {
  if( FD_UNLIKELY( ( ( ctx->src.cur+ctx->input_blob_sz )>ctx->src.end ) || ( ( ctx->src.cur+ctx->input_blob_sz )<ctx->src.cur ) ) ) {
    ctx->invalid_state = 1;
    return;
  }
  ctx->src.cur = ctx->pre_parse_src_cur + ctx->input_blob_sz;
  ctx->dst.cur = ctx->pre_parse_dst_cur;
}

/* If an encode operation succeeds of a blob succeeds, we advance the src `cur` up to beyond
   where the input blob ends. Theres no need to update the dst `cur` pointer because this will
   have occurred fully during the encode operation.
   This function includes defensive logic that should be impossible to trigger. As such,
   this logic ensures that the destination slice has enough capacity to advance the `cur`
   pointer by n bytes. In practice (such as during gossip parsing) this should not be
   possible to trigger (such as via malformed gossip packets), hence this check is added
   to help catch serious programming errors (e.g. API misuse and invariant violations) */
void
fd_bin_parse_update_state_encode_succeeded( fd_bin_parse_ctx_t * ctx ) {
  if( FD_UNLIKELY( !fd_slice_is_enough_space( &(ctx->src), ctx->input_blob_sz ) ) ) {
    FD_LOG_WARNING(( "not enough space to advance src `cur` by the requested size" ));
    ctx->invalid_state = 1;
  } else {
    fd_slice_increment_slice( &(ctx->src), ctx->input_blob_sz );
  }
}

/* If an encoding operation for a blob fails, we advance the src `cur` beyond the
   bad payload so as to move onto the next one, and we rewind the dst `cur` back to where
   it was before the parse began.
   This function contains defensive logic to prevent should-be impossible conditions such 
   as the source `cur` being advanced beyond the end of the src slice. Since such conditions
   shouldn't be possible via normal and proper use of the API, these checks exist so as to
   help catch serious programming errors. */
void
fd_bin_parse_update_state_encode_failed( fd_bin_parse_ctx_t * ctx ) {
  if( FD_UNLIKELY( ( ( ctx->src.cur+ctx->input_blob_sz )>ctx->src.end ) || ( ( ctx->src.cur+ctx->input_blob_sz )<ctx->src.cur ) ) ) {
    ctx->invalid_state = 1;
    return;
  }
  ctx->src.cur = ctx->pre_parse_src_cur + ctx->input_blob_sz;
  ctx->dst.cur = ctx->pre_parse_dst_cur;
}

int
fd_bin_parse_is_enough_space_in_src( fd_bin_parse_ctx_t * ctx,
                                     ulong                sz   ) {
  return ( ctx->input_blob_sz>=sz && fd_slice_is_enough_space( &(ctx->src), sz ) );
}

int
fd_bin_parse_is_enough_space_in_dst( fd_bin_parse_ctx_t * ctx,
                                     ulong                sz   ) {
  return ( fd_slice_is_enough_space( &(ctx->dst), sz ) );
}

void *
fd_bin_parse_get_cur_dst( fd_bin_parse_ctx_t * ctx ) {
  return ctx->dst.cur;
}

void *
fd_bin_parse_get_cur_src( fd_bin_parse_ctx_t * ctx ) {
  return ctx->src.cur;
}

ulong
fd_bin_parse_total_dst_size_remaining( fd_bin_parse_ctx_t * ctx ) {
  return (ulong)(ctx->dst.end - ctx->dst.cur);
}

ulong
fd_bin_parse_total_src_size_remaining( fd_bin_parse_ctx_t * ctx ) {
  return (ulong)(ctx->src.end - ctx->src.cur);
}

ulong
fd_bin_parse_src_blob_size_remaining( fd_bin_parse_ctx_t * ctx ) {
  return (ulong)(ctx->input_blob_sz - (ulong)(ctx->src.cur - ctx->pre_parse_src_cur));
}

int
fd_bin_parse_dst_has_enough_size_remaining( fd_bin_parse_ctx_t * ctx, 
                                            ulong                sz   ) {
  return (ulong)(ctx->dst.end - ctx->dst.cur) >= sz;
}

ulong
fd_bin_parse_input_blob_size( fd_bin_parse_ctx_t * ctx ) {
  return ctx->input_blob_sz;
}

ulong fd_bin_parse_bytes_written_during_this_parse( fd_bin_parse_ctx_t * ctx ) {
  return (ulong)ctx->dst.cur - (ulong)ctx->pre_parse_dst_cur;
}

int
fd_bin_parse_read_u8( fd_bin_parse_ctx_t  * ctx,
                      uchar               * dest ) {
  CHECK_CTX_STATE_IS_VALID( ctx );
  CHECK_INPUT_BLOB_SZ_REMAINING( 1 );
  return fd_slice_read_u8( &(ctx->src), dest );
  
}

int
fd_bin_parse_read_u16( fd_bin_parse_ctx_t * ctx,
                       ushort             * dest ) {
  CHECK_CTX_STATE_IS_VALID( ctx );
  CHECK_INPUT_BLOB_SZ_REMAINING( 2 );
  return fd_slice_read_u16( &(ctx->src), dest );
}

int
fd_bin_parse_read_u32( fd_bin_parse_ctx_t * ctx,
                       uint               * dest ) {
  CHECK_CTX_STATE_IS_VALID( ctx );
  CHECK_INPUT_BLOB_SZ_REMAINING( 4 );
  return fd_slice_read_u32( &(ctx->src), dest );
}

int
fd_bin_parse_read_option_u32( fd_bin_parse_ctx_t * ctx,
                              uint               * dest ) {
  CHECK_CTX_STATE_IS_VALID( ctx );
  CHECK_INPUT_BLOB_SZ_REMAINING( 1 );

  uchar tag = 0;
  if( !fd_slice_read_u8( &(ctx->src), &tag ) ) {
    return 0;
  }

  if( !tag ) {
    *dest = (uint)-1;
    return 1;
  }

  CHECK_INPUT_BLOB_SZ_REMAINING( 4 );
  return fd_slice_read_u32( &(ctx->src), dest );
}

int
fd_bin_parse_read_u64( fd_bin_parse_ctx_t * ctx,
                   ulong      * dest ) {
  CHECK_CTX_STATE_IS_VALID( ctx );
  CHECK_INPUT_BLOB_SZ_REMAINING( 8 );
  return fd_slice_read_u64( &(ctx->src), dest );
}

int
fd_bin_parse_read_option_u64( fd_bin_parse_ctx_t * ctx,
                              ulong              * dest ) {

  CHECK_CTX_STATE_IS_VALID( ctx );
  CHECK_INPUT_BLOB_SZ_REMAINING( 1 );

  uchar tag = 0;
  if( !fd_slice_read_u8( &(ctx->src), &tag ) ) {
    return 0;
  }

  if( !tag ) {
    *dest = (ulong)-1;
    return 1;
  }

  CHECK_INPUT_BLOB_SZ_REMAINING( 8 );
  return fd_slice_read_u64( &(ctx->src), dest );
}

int
fd_bin_parse_read_varint_u( fd_bin_parse_ctx_t * ctx,
                            ulong              * x    ) {
  int success = 0;
  ulong b = 0;

#define READ_UCHAR  do {                                 \
    CHECK_INPUT_BLOB_SZ_REMAINING( 1 );                  \
    success = fd_bin_parse_read_u8( ctx, (uchar *)&b );  \
    if( !success ) {                                     \
      return 0;                                          \
    }                                                    \
} while(0)                      
  
  *x = 0;
  READ_UCHAR; *x|=(b&0x7f)<<(7*0); if (b<0x80) return 0+1;
  READ_UCHAR; *x|=(b&0x7f)<<(7*1); if (b<0x80) return 1+1;
  READ_UCHAR; *x|=(b&0x7f)<<(7*2); if (b<0x80) return 2+1;
  READ_UCHAR; *x|=(b&0x7f)<<(7*3); if (b<0x80) return 3+1;
  READ_UCHAR; *x|=(b&0x7f)<<(7*4); if (b<0x80) return 4+1;
  READ_UCHAR; *x|=(b&0x7f)<<(7*5); if (b<0x80) return 5+1;
  READ_UCHAR; *x|=(b&0x7f)<<(7*6); if (b<0x80) return 6+1;
  READ_UCHAR; *x|=(b&0x7f)<<(7*7); if (b<0x80) return 7+1;
  READ_UCHAR; *x|=(b&0x7f)<<(7*8); if (b<0x80) return 8+1;
  READ_UCHAR; *x|=(b&0x7f)<<(7*9); if (b<0x80) return 9+1;
  return 0;

#undef READ_UCHAR
}

int
fd_bin_parse_write_varint_u( fd_bin_parse_ctx_t * ctx, 
                             ulong                value ) {

  if( !fd_bin_parse_is_enough_space_in_dst( ctx, 10 ) ) {         
    FD_LOG_WARNING(( "not enough space left in dest buffer" ));   
    return 0;                                                     
  }  

  ulong n = 0;
  uchar * out_ptr = fd_bin_parse_get_cur_dst( ctx );

  n+=value>=0x80; out_ptr[0]=(uchar)value|0x80; value>>=7;
  n+=value>=0x80; out_ptr[1]=(uchar)value|0x80; value>>=7;
  n+=value>=0x80; out_ptr[2]=(uchar)value|0x80; value>>=7;
  n+=value>=0x80; out_ptr[3]=(uchar)value|0x80; value>>=7;
  n+=value>=0x80; out_ptr[4]=(uchar)value|0x80; value>>=7;
  n+=value>=0x80; out_ptr[5]=(uchar)value|0x80; value>>=7;
  n+=value>=0x80; out_ptr[6]=(uchar)value|0x80; value>>=7;
  n+=value>=0x80; out_ptr[7]=(uchar)value|0x80; value>>=7;
  n+=value>=0x80; out_ptr[8]=(uchar)value|0x80; value>>=7;
  n+=value>=0x80; out_ptr[9]=(uchar)value|0x80; value>>=7;
  out_ptr[n] ^= 0x80;

  fd_slice_increment_slice( &(ctx->dst), n+1 );
  return 1;
}

int
fd_bin_parse_read_varint_u64( fd_bin_parse_ctx_t * ctx,
                              ulong              * dest ) {
  CHECK_CTX_STATE_IS_VALID( ctx );
  return fd_bin_parse_read_varint_u( ctx, dest );
}

int
fd_bin_parse_read_varint_u32( fd_bin_parse_ctx_t * ctx,
                              uint               * dest ) {
  CHECK_CTX_STATE_IS_VALID( ctx );

  ulong tmp = 0;
  if( !fd_bin_parse_read_varint_u( ctx, &tmp ) ) {
    return 0;
  }

  if( tmp > UINT_MAX ) {
    return 0;
  }

  *dest = (uint)tmp;
  return 1;
}

int
fd_bin_parse_read_varint_u16( fd_bin_parse_ctx_t * ctx,
                              ushort             * dest ) {
  CHECK_CTX_STATE_IS_VALID( ctx );

  ulong tmp = 0;
  if( !fd_bin_parse_read_varint_u( ctx, &tmp ) ) {
    return 0;
  }

  if( tmp > USHORT_MAX ) {
    return 0;
  }

  *dest = (ushort)tmp;
  return 1;
}

int
fd_bin_parse_write_varint_u64( fd_bin_parse_ctx_t * ctx,
                               ulong                value ) {
  CHECK_CTX_STATE_IS_VALID( ctx );
  return fd_bin_parse_write_varint_u( ctx, value );
}

int
fd_bin_parse_write_varint_u32( fd_bin_parse_ctx_t * ctx,
                               uint                 value ) {
  CHECK_CTX_STATE_IS_VALID( ctx );
  return fd_bin_parse_write_varint_u( ctx, (uint)value );
}

int
fd_bin_parse_write_varint_u16( fd_bin_parse_ctx_t * ctx,
                               ushort               value ) {
  CHECK_CTX_STATE_IS_VALID( ctx );
  return fd_bin_parse_write_varint_u( ctx, (ushort)value );
}

int
fd_bin_parse_read_blob_of_size( fd_bin_parse_ctx_t * ctx,
                                ulong                size,
                                void               * dest  ) {
  CHECK_CTX_STATE_IS_VALID( ctx );
  CHECK_INPUT_BLOB_SZ_REMAINING( size );
  return fd_slice_read_blob_of_size( &(ctx->src), size, dest );
}

int
fd_bin_parse_decode_vector( fd_bin_parse_ctx_t * ctx,
                            ulong                type_sz,
                            void               * dst,
                            ulong                dst_sz,  
                            ulong              * nelems   ) {
  CHECK_CTX_STATE_IS_VALID( ctx );

  ulong vector_sz = 0;
  if( !fd_bin_parse_read_u64( ctx, &vector_sz ) ) {
    FD_LOG_WARNING(( "failed to read u64 as vector size" ));
    return 0;
  }

  if( FD_UNLIKELY( (vector_sz*type_sz)>dst_sz ) ) {
    FD_LOG_WARNING(( "dst size exceeded" ));
    return 0;
  }

  /* check for integer overflow wrap and bail out if so */
  if( FD_UNLIKELY( (vector_sz*type_sz)<vector_sz ) ) {
    FD_LOG_WARNING(( "vector size calculation integer overflow wrap" ));
    return 0;
  }

  uchar * ptr = (uchar *)dst;

  /* we now attempt to read `vector_sz` number of elements from the slice,
     each of length `type_sz`. */
  for( ulong i = 0; i<vector_sz; i++ ) {
    if( !fd_bin_parse_read_blob_of_size( ctx, type_sz, ptr ) ) {
      FD_LOG_WARNING(( "failed to read byte array of %ld bytes", type_sz ));
      return 0;
    }
    ptr += type_sz;
  }

  *nelems = vector_sz;
  return 1;
}

int
fd_bin_parse_decode_option_vector( fd_bin_parse_ctx_t * ctx,
                                   ulong                type_sz,
                                   void               * dst,
                                   ulong                dst_sz,  
                                   ulong              * nelems   ) {
  CHECK_CTX_STATE_IS_VALID( ctx );

  uchar tag = 0;
  if( !fd_bin_parse_read_u8( ctx, &tag ) ) {
    FD_LOG_WARNING(( "failed to read u8 as vector option" ));
    return 0;
  }

  /* the 'Optional' vector is not here, hence 0 elements were read, and the parse was a success */
  if( !tag ) {
    *nelems = 0;
    return 1;
  }

  return fd_bin_parse_decode_vector( ctx, type_sz, dst, dst_sz, nelems );
}

int
fd_bin_parse_read_pubkey( fd_bin_parse_ctx_t  * ctx,
                          fd_pubkey_t         * pubkey_out ) {

  if( !fd_bin_parse_read_blob_of_size( ctx, 32, (void *)pubkey_out ) ) {
    FD_LOG_WARNING(( "failed to parse pubkey" ));
    return 0;
  }

  return 1;
}

int
fd_bin_parse_write_u8( fd_bin_parse_ctx_t  * ctx,
                       uchar                 src ) {
  CHECK_CTX_STATE_IS_VALID( ctx );
  CHECK_OUTPUT_SZ_REMAINING( 1 );
  return fd_slice_write_u8( &(ctx->dst), src );
}

int
fd_bin_parse_write_u16( fd_bin_parse_ctx_t * ctx,
                        ushort               src ) {
  CHECK_CTX_STATE_IS_VALID( ctx );
  CHECK_OUTPUT_SZ_REMAINING( 2 );
  return fd_slice_write_u16( &(ctx->dst), src );
}

int
fd_bin_parse_write_u32( fd_bin_parse_ctx_t * ctx,
                        uint                 src ) {
  CHECK_CTX_STATE_IS_VALID( ctx );
  CHECK_OUTPUT_SZ_REMAINING( 4 );
  return fd_slice_write_u32( &(ctx->dst), src );
}

int
fd_bin_parse_write_u64( fd_bin_parse_ctx_t * ctx,
                        ulong                src ) {
  CHECK_CTX_STATE_IS_VALID( ctx );
  CHECK_OUTPUT_SZ_REMAINING( 8 );
  return fd_slice_write_u64( &(ctx->dst), src );
}

int
fd_bin_parse_write_blob_of_size( fd_bin_parse_ctx_t * ctx,
                                 void               * src,
                                 ulong                size ) {
  CHECK_CTX_STATE_IS_VALID( ctx );
  CHECK_OUTPUT_SZ_REMAINING( size );
  return fd_slice_write_blob_of_size( &(ctx->dst), src, size );
}

int fd_bin_parse_write_pubkey( fd_bin_parse_ctx_t  * ctx,
                               fd_pubkey_t         * pubkey ) {

  if( !fd_bin_parse_write_blob_of_size( ctx, pubkey->pubkey, 32 ) ) {
    FD_LOG_WARNING(( "failed to write pubkey to output buffer" ));
    return 0;
  }

  return 1;
}

#undef INPUT_BLOB_SZ_REMAINING
#undef CHECK_INPUT_BLOB_SZ_REMAINING
#undef CHECK_CTX_STATE_IS_VALID
