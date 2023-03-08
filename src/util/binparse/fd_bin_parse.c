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
} while(0)

void fd_bin_parse_init( fd_bin_parse_ctx_t * ctx,
                            void           * src,
                            ulong            src_sz,
                            void           * dst,
                            ulong            dst_sz ) {
  ctx->src.cur = src;
  ctx->src.end = (uchar *)src + src_sz;
  ctx->dst.cur = dst;
  ctx->dst.end = (uchar *)dst + dst_sz;
  ctx->pre_parse_src_cur = ctx->src.cur;
  ctx->pre_parse_dst_cur = ctx->dst.cur;
  ctx->input_blob_sz = 0;
}

void
fd_bin_parse_start_for_input_blob( fd_bin_parse_ctx_t * ctx,
                                   ulong                input_blob_sz ) {
  ctx->input_blob_sz = input_blob_sz;
  ctx->pre_parse_src_cur = ctx->src.cur;
  ctx->pre_parse_dst_cur = ctx->dst.cur;
}

int
fd_bin_parse_was_entire_input_blob_consumed( fd_bin_parse_ctx_t * ctx ) {
  return ( (ulong)(ctx->src.cur-ctx->pre_parse_src_cur) )==ctx->input_blob_sz;
}

/* If parsing of a gossip message succeeds, we advance the dst `cur` up to beyond
   where the parsed structures were written to, and there's no need to update the src
   `cur` pointer because this occurred fully during parsing. This invariant is further
   checked by a call to `fd_bin_parse_was_entire_input_blob_consumed` */
void
fd_bin_parse_update_state_succeeded( fd_bin_parse_ctx_t * ctx,
                                     ulong                data_written_sz ) {
  fd_slice_increment_slice( &(ctx->dst), data_written_sz );
}

/* If parsing of a gossip message fails, we advance the src `cur` beyond the
   bad payload so as to move onto the next one, and we rewind the dst `cur` back to where
   it was before the parse began. */
void
fd_bin_parse_update_state_failed( fd_bin_parse_ctx_t * ctx ) {
  ctx->src.cur = ctx->pre_parse_src_cur + ctx->input_blob_sz;
  ctx->dst.cur = ctx->pre_parse_dst_cur;
}

int
fd_bin_parse_is_enough_space_in_src( fd_bin_parse_ctx_t * ctx,
                                     ulong                sz   ) {
  return ( FD_LIKELY( ctx->input_blob_sz>=sz && fd_slice_is_enough_space( &(ctx->src), sz ) ) );
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
fd_bin_parse_dst_size_remaining( fd_bin_parse_ctx_t * ctx ) {
  return (ulong)(ctx->dst.end - ctx->dst.cur);
}

ulong
fd_bin_parse_src_size_remaining( fd_bin_parse_ctx_t * ctx ) {
  return (ulong)(ctx->src.end - ctx->src.cur);
}

int
fd_bin_parse_dst_has_enough_size_remaining( fd_bin_parse_ctx_t * ctx, 
                                            ulong                sz   ) {
  return (ulong)(ctx->dst.end - ctx->dst.cur) >= sz;
}

int
fd_bin_parse_read_u8( fd_bin_parse_ctx_t  * ctx,
                      uchar               * dest ) {

  CHECK_INPUT_BLOB_SZ_REMAINING( 1 );
  return fd_slice_read_u8( &(ctx->src), dest );
  
}

int
fd_bin_parse_read_u16( fd_bin_parse_ctx_t * ctx,
                       ushort             * dest ) {
  CHECK_INPUT_BLOB_SZ_REMAINING( 2 );
  return fd_slice_read_u16( &(ctx->src), dest );
}

int
fd_bin_parse_read_u32( fd_bin_parse_ctx_t * ctx,
                       uint               * dest ) {
  CHECK_INPUT_BLOB_SZ_REMAINING( 4 );
  return fd_slice_read_u32( &(ctx->src), dest );
}

int
fd_bin_parse_read_option_u32( fd_bin_parse_ctx_t * ctx,
                              uint               * dest ) {
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
  CHECK_INPUT_BLOB_SZ_REMAINING( 8 );
  return fd_slice_read_u64( &(ctx->src), dest );
}

int
fd_bin_parse_read_option_u64( fd_bin_parse_ctx_t * ctx,
                              ulong              * dest ) {

  
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
fd_bin_parse_read_blob_of_size( fd_bin_parse_ctx_t * ctx,
                                ulong                size,
                                void               * dest  ) {

  CHECK_INPUT_BLOB_SZ_REMAINING( size );
  return fd_slice_read_blob_of_size( &(ctx->src), size, dest );
}

int
fd_bin_parse_decode_vector( fd_bin_parse_ctx_t * ctx,
                            ulong                type_sz,
                            void               * dst,
                            ulong                dst_sz,  
                            ulong              * nelems   ) {
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
    FD_LOG_WARNING(( "detected int overflow in int overflow protection logic" ));
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

int fd_bin_parse_read_pubkey( fd_bin_parse_ctx_t  * ctx,
                              fd_pubkey_t         * pubkey_out ) {

  if( !fd_bin_parse_read_blob_of_size( ctx, 32, (void *)pubkey_out ) ) {
    FD_LOG_WARNING(( "failed to parse pubkey" ));
    return 0;
  }

  return 1;
}

#undef INPUT_BLOB_SZ_REMAINING
#undef CHECK_INPUT_BLOB_SZ_REMAINING
