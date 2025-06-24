#include "fd_contact_info.h"
#include "fd_gossip_private.h"
#include "../../util/bits/fd_bits.h"

#define SER_INIT( payload, payload_sz, offset )   \
  ushort         i              = (offset);         \

int
fd_gossip_pull_request_encode_ctx_init( uchar *                               payload,
                                        ulong                                 payload_sz FD_PARAM_UNUSED,
                                        ulong                                 num_keys,
                                        ulong                                 bloom_bits_cnt,
                                        fd_gossip_pull_request_encode_ctx_t * out_ctx ){
  SER_INIT( payload, payload_sz, 0U );
  FD_STORE( uint, payload+i, FD_GOSSIP_MESSAGE_PULL_REQUEST ); out_ctx->tag = payload+i; i+=4UL;
  FD_STORE( ulong, payload+i, num_keys ); out_ctx->bloom_keys_len = (ulong *)(payload+i); i+=8UL;
  out_ctx->bloom_keys = (ulong *)(payload+i); i+=8UL*num_keys;
  if( FD_LIKELY( !!bloom_bits_cnt ) ) {
    /* Bloom bits is a bitvec<u64>, so we need to be careful about converting bloom bits count to vector lengths */
    ulong bloom_vec_len = (bloom_bits_cnt+63UL)/64UL;
    FD_STORE( uchar, payload+i, 1 ); out_ctx->has_bits = payload+i; i+=1UL;
    FD_STORE( ulong, payload+i, bloom_vec_len ); out_ctx->bloom_vec_len = (ulong *)(payload+i); i+=8UL;
    out_ctx->bloom_bits = (ulong *)(payload+i); i+=8UL*bloom_vec_len;
    FD_STORE( ulong, payload+i, bloom_bits_cnt ); out_ctx->bloom_bits_count = (ulong *)(payload+i); i+=8UL;
    FD_STORE( ulong, payload+i, 0 ); out_ctx->bloom_num_bits_set = (ulong *)(payload+i); i+=8UL;
  } else {
    FD_STORE( uchar, payload+i, 0 ); out_ctx->has_bits = payload+i; i+=1UL;
    out_ctx->bloom_vec_len = NULL;
    out_ctx->bloom_bits = NULL;
    out_ctx->bloom_bits_count = NULL;
    out_ctx->bloom_num_bits_set = NULL;
  }
  FD_STORE( ulong, payload+i, 0 ); out_ctx->mask = (ulong *)(payload+i); i+=8UL;
  FD_STORE( uint, payload+i, 0 ); out_ctx->mask_bits = (ulong *)(payload+i); i+=4UL;
  out_ctx->contact_info = payload+i; /* Offset to the start of contact info in payload */

  return 0;
}

int
fd_gossip_pull_request_encode_bloom_keys( fd_gossip_pull_request_encode_ctx_t * ctx,
                                          ulong const *                         bloom_keys,
                                          ulong                                 bloom_keys_len ){
  /* This should break if encode ctx was not correctly initialized with bloom_keys_len */
  if( FD_UNLIKELY( *ctx->bloom_keys_len != bloom_keys_len ) ){
    FD_LOG_ERR(( "Bloom keys length mismatch: expected %lu, got %lu", *ctx->bloom_keys_len, bloom_keys_len ));
  }
  fd_memcpy( ctx->bloom_keys, bloom_keys, bloom_keys_len * sizeof(ulong) );
  return 0;
}

int
fd_gossip_pull_request_encode_bloom_bits( fd_gossip_pull_request_encode_ctx_t * ctx,
                                          ulong const *                         bloom_bits,
                                          ulong                                 bloom_bits_cnt ){
  if( FD_UNLIKELY( !ctx->has_bits || !ctx->bloom_vec_len || !ctx->bloom_bits ) ) {
    FD_LOG_ERR(( "Bloom bits not initialized in encode context" ));
  }
  if( FD_UNLIKELY( *ctx->bloom_bits_count != bloom_bits_cnt ) ){
    FD_LOG_ERR(( "Bloom bits length mismatch: expected %lu, got %lu", *ctx->bloom_bits_count, bloom_bits_cnt ));
  }

  fd_memcpy( ctx->bloom_bits, bloom_bits, *ctx->bloom_vec_len * sizeof(ulong) );
  return 0;
}

static inline ulong
varint_encoded_sz( ulong u64 ) {
  if( FD_UNLIKELY( u64==0UL ) ) return 1UL; /* 0 is encoded as 1 byte */
  ulong sz = 0UL;
  while( u64 ) {
    sz++;
    u64 >>= 7UL;
  }
  return sz;
}

static inline int
varint_encode( ulong u64, uchar * out_buf, ulong out_buf_sz ) {
  ulong i = 0UL;
  do {
    uchar byte = (uchar)(u64 & 0x7FUL);
    u64 >>= 7UL;
    if( u64 ) byte |= 0x80U; /* Set continuation bit */
    if( FD_UNLIKELY( i >= out_buf_sz ) ) return -3; /* Output buffer overflow */
    FD_STORE( uchar, out_buf+i, byte );
    i++;
  } while( u64 );

  return 0; /* Return number of bytes written */
}

static inline int
encode_version( fd_contact_info_t const * contact_info,
                uchar *                   out_buf,
                ulong                     out_buf_sz,
                ushort                    start_offset,
                ushort *                  updated_offset ) {
  SER_INIT( out_buf, out_buf_sz, start_offset );

  ulong encoded_sz = varint_encoded_sz( contact_info->version.major );
  varint_encode( contact_info->version.major, out_buf+i, out_buf_sz-i ); i+=encoded_sz;

  encoded_sz = varint_encoded_sz( contact_info->version.minor );
  varint_encode( contact_info->version.minor, out_buf+i, out_buf_sz-i ); i+=encoded_sz;

  encoded_sz = varint_encoded_sz( contact_info->version.patch );
  varint_encode( contact_info->version.patch, out_buf+i, out_buf_sz-i ); i+=encoded_sz;

  FD_STORE( uint, out_buf+i, contact_info->version.commit ); i+=4UL;

  FD_STORE( uint, out_buf+i, contact_info->version.feature_set ); i+=4UL;

  encoded_sz = varint_encoded_sz( contact_info->version.client );
   varint_encode( contact_info->version.client, out_buf+i, out_buf_sz-i ); i+=encoded_sz;

  if( updated_offset ) {
    *updated_offset = (ushort)i;
  }

  return 0;
}

int
fd_gossip_contact_info_encode( fd_contact_info_t const *     contact_info,
                               uchar *                       out_buf,
                               ulong                         out_buf_sz,
                               ulong *                       opt_encoded_sz ) {
  SER_INIT( out_buf, out_buf_sz, 0U );

  i+=64UL; /* Reserve space for signature */

  FD_STORE( uint, out_buf+i, FD_GOSSIP_VALUE_CONTACT_INFO )                             ; i+=4UL;
  fd_memcpy( out_buf+i, contact_info->pubkey, 32UL )                                    ; i+=32UL;

  ulong wallclock            = (ulong)FD_NANOSEC_TO_MILLI( contact_info->wallclock_nanos );
  int enc_sz = varint_encode( wallclock, out_buf+i, out_buf_sz-i )                      ; i+=enc_sz;

  ulong instance_creation_wallclock = (ulong)FD_NANOSEC_TO_MILLI( contact_info->instance_creation_wallclock_nanos );
  FD_STORE( ulong, out_buf+i, instance_creation_wallclock )                             ; i+=8UL;
  FD_STORE( ushort, out_buf+i, contact_info->shred_version )                            ; i+=2UL;

  if( FD_UNLIKELY( encode_version( contact_info, out_buf, out_buf_sz, i, &i ) != 0 ) ) {
    return -1;
  };

  /* fd_contact_info_t has a fixed-size array of addresses and sockets, while
     the encoded representation is a variable-length array of addrs and
     sockets, where sockets are sorted by port offsets and index into addrs
     to specify address.

     TODO: This is awkwardly placed. Caller should be in charge of setting these
     data structures, leaving encode with the sole role of serializing them to
     bytes.*/
  uint                                  addrs[ FD_CONTACT_INFO_SOCKET_MAX ];
  uchar                                 addrs_cnt;
  fd_gossip_contact_info_socket_entry_t socket_entries[ FD_CONTACT_INFO_SOCKET_MAX ];
  uchar                                 socket_entries_cnt;

  if( FD_UNLIKELY( fd_contact_info_convert_sockets( contact_info, socket_entries, &socket_entries_cnt, addrs, &addrs_cnt ) ) ) {
    FD_LOG_ERR(( "Failed to convert contact info sockets, check arguments to fd_contact_info_convert_sockets" ));
    return -1;
  }

  /* Encode addrs and socket entries. Assumptions made:
     - length of either array never exceeds FD_GOSSIP_SOCKET_TAG_MAX, which
       is 13 < 2^7. This means we can assume the length is always encoded as
       a single byte varint */
  FD_STORE( uchar, out_buf+i, addrs_cnt )                                               ; i+=1UL;

  for( ulong j=0UL; j<addrs_cnt; j++ ) {
    /* Each address is 8 bytes including discriminant */
    FD_STORE( uint, out_buf+i, 0U )                                                     ; i+=4UL; /* Enum discriminant */
    FD_STORE( uint, out_buf+i, addrs[j] )                                               ; i+=4UL;
  }

  FD_STORE( uchar, out_buf+i, socket_entries_cnt )                                      ; i+=1UL;

  for( ulong j=0UL; j<socket_entries_cnt; j++ ) {
    FD_STORE( uchar, out_buf+i, socket_entries[j].tag )                                 ; i+=1UL; /* Socket tag */
    FD_STORE( uchar, out_buf+i, socket_entries[j].addr_index )                          ; i+=1UL; /* Address index */

    int enc_sz = varint_encode( socket_entries[j].port_offset, out_buf+i, out_buf_sz-i ); i+=enc_sz; /* Port offset */
  }

  /* No extensions for now, but because of a quirk in short_vec we need to encode
     the length (which is 0) */
  FD_STORE( uchar, out_buf+i, 0U )                                                      ; i+=1UL;

  if( opt_encoded_sz ) {
    *opt_encoded_sz = i;
  }
  return 0;
}

int
fd_gossip_init_msg_payload( uchar * payload,
                            ulong   payload_sz FD_PARAM_UNUSED,
                            uchar   tag,
                            ulong * start_cursor ) {
  SER_INIT( payload, payload_sz, 0U );
  if( FD_UNLIKELY( tag>FD_GOSSIP_MESSAGE_LAST ) ) {
    FD_LOG_ERR(( "Invalid message tag %d", tag ));
  }
  payload[i] = tag; i+=4UL; /* tag is encoded as int */
  if( start_cursor ) {
    *start_cursor = i; /* Return the offset where the message payload starts */
  }
  return 0;
}
