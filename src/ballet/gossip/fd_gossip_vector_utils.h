#ifndef HEADER_fd_src_util_gossip_fd_gossip_vector_utils_h
#define HEADER_fd_src_util_gossip_fd_gossip_vector_utils_h

/* Vector deserialization utility macros.
   Used when decoding vector representations (such as `fd_gossip_vector_descriptor_t`) 
   for vector data found in gossip message and CRDS payloads.
   These are alone in their own header file because they're not supposed to be used outside of 
   this module, and therefore shouldn't be included as part of the gossip module's interface. */
   
#define DST_CUR             ptr
#define DST_BYTES_REMAINING (ulong)(out_buf_sz - ((ulong)((uchar *)ptr - (uchar *)out_buf)))

#define ADVANCE_DST_PTR( n_bytes )  do {                                      \
  if( FD_UNLIKELY( DST_BYTES_REMAINING<n_bytes ) ) {                          \
    FD_LOG_WARNING(( "destination too short" ));                              \
    return 0;                                                                 \
  }                                                                           \
  ptr += n_bytes;                                                             \
} while( 0 )

#define DST_CUR_DATA_OFFSET   ((ulong)((uchar *)ptr - (uchar *)out_buf))
#define TOTAL_DATA_OUT_SZ DST_CUR_DATA_OFFSET

/* Vector serialization utility macros.
   These are used for serializing vectors in gossip message structs out to raw bytes
   for transmission over the network. */
#define SRC_CUR  ptr
#define SRC_BYTES_REMAINING (ulong)(in_buf_sz - ((ulong)((uchar *)ptr - (uchar *)in_buf)))

#define ADVANCE_SRC_PTR( n_bytes )  do {                                      \
  if( FD_UNLIKELY( SRC_BYTES_REMAINING<n_bytes ) ) {                          \
    FD_LOG_WARNING(( "src too short" ));                                      \
    return 0;                                                                 \
  }                                                                           \
  ptr += n_bytes;                                                             \
} while( 0 )                                                                  \

#define SRC_CUR_DATA_OFFSET ((ulong)((uchar *)ptr - (uchar *)in_buf))
#define TOTAL_DATA_CONSUMED_SZ SRC_CUR_DATA_OFFSET

#endif
