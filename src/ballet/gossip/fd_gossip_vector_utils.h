#ifndef HEADER_fd_src_util_gossip_fd_gossip_vector_utils_h
#define HEADER_fd_src_util_gossip_fd_gossip_vector_utils_h

/* Used when building vector representations (such as `fd_gossip_vector_descriptor_t`) 
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
} while(0)

#define CUR_DATA_OFFSET   ((ulong)((uchar *)ptr - (uchar *)out_buf))
#define TOTAL_DATA_OUT_SZ CUR_DATA_OFFSET

#endif
