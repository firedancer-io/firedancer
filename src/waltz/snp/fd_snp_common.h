#ifndef HEADER_fd_src_waltz_snp_fd_snp_common_h
#define HEADER_fd_src_waltz_snp_fd_snp_common_h

/* Common definitions between fd_snp.h and fd_snp_app.h. */

#include "../../util/fd_util_base.h"
#include "../../util/bits/fd_bits.h"

/* Debug and trace flags, useful for debugging logs (running a
   non-production validator) or tracing (running tests). */
#define FD_SNP_DEBUG_ENABLED (0)
#define FD_SNP_TRACE_ENABLED (0)

#define FD_SNP_META_PROTO_UDP     (0x0000000000000000UL)
#define FD_SNP_META_PROTO_V1      (0x0100000000000000UL)
#define FD_SNP_META_PROTO_V2      (0x0200000000000000UL)

#define FD_SNP_META_OPT_BUFFERED  (0x1000000000000000UL)
#define FD_SNP_META_OPT_HANDSHAKE (0x2000000000000000UL)
#define FD_SNP_META_OPT_BROADCAST (0x4000000000000000UL)

#define FD_SNP_META_IP_MASK       (0x00000000FFFFFFFFUL)
#define FD_SNP_META_PORT_MASK     (0x0000FFFF00000000UL)
#define FD_SNP_META_PEER_MASK     (0x0000FFFFFFFFFFFFUL)
#define FD_SNP_META_APP_MASK      (0x000F000000000000UL)
#define FD_SNP_META_PROTO_MASK    (0x0F00000000000000UL)
#define FD_SNP_META_OPT_MASK      (0xF000000000000000UL)

#define FD_SNP_SUCCESS ( 0)
#define FD_SNP_FAILURE (-1)

#define FD_SNP_FRAME_EMPTY       (0x00) /* Bytes padded to 0 are essentially empty TLVs */
#define FD_SNP_FRAME_PING        (0x01)
#define FD_SNP_FRAME_DATAGRAM    (0x31)
#define FD_SNP_FRAME_AUTH        (0x41)
#define FD_SNP_FRAME_MAX_DATA    (0x10)
#define FD_SNP_FRAME_CONN_CLOSE  (0x1D)
#define FD_SNP_FRAME_MC_ANNOUNCE (0x51)
#define FD_SNP_FRAME_MC_STATE    (0x52)

#define FD_SNP_IP_DST_ADDR_OFF   (30UL)

#define FD_SNP_APPS_CNT_MAX      (8UL)

/* TYPES */

/* fd_snp_app_peer_t is a type to represent a peer identifier.
   Currently, it encodes the peer IPv4 + port, but the application
   should not make any assumption. */
typedef ulong fd_snp_peer_t;

/* fd_snp_app_meta_t is a type to represent connection metadata. */
typedef ulong fd_snp_meta_t;

/* fd_snp_tlv_t holds type and length of the TLV, as well as a pointer
   to the begining of the memory location where the value is located.
   IMPORTANT: do NOT cast a pointer to a buffer as (fd_snp_tlv_t *).
   Instead, use either the extract or iterator methods to obtain type,
   len and ptr. */
struct fd_snp_tlv {
  uchar const * ptr;
  ushort        len;
  uchar         type;
};
typedef struct fd_snp_tlv fd_snp_tlv_t;

/* fd_snp_tlv_iter_t contains the iterator's metadata.  Off indicates
   the offset inside the given buffer, whereas rem indicates the
   remaining amount of bytes (signed, in order to simplify checks). */
struct fd_snp_tlv_iter {
  ulong         off;
  long          rem;
};
typedef struct fd_snp_tlv_iter fd_snp_tlv_iter_t;

FD_PROTOTYPES_BEGIN

/* ALLOC */

static inline fd_snp_meta_t
fd_snp_meta_from_parts( ulong  snp_proto,
                        uchar  snp_app_id,
                        uint   ip4,
                        ushort port ) {
  return ( snp_proto & FD_SNP_META_PROTO_MASK )
    | (( (ulong) ( snp_app_id & 0x0F ) ) << 48 )
    | (( (ulong) port ) << 32 )
    | (( (ulong) ip4 ));
}

static inline void
fd_snp_meta_into_parts( ulong *       snp_proto,
                        uchar *       snp_app_id,
                        uint *        ip4,
                        ushort *      port,
                        fd_snp_meta_t meta ) {
  if( snp_proto  ) *snp_proto = meta & FD_SNP_META_PROTO_MASK;
  if( snp_app_id ) *snp_app_id = (uchar)( ( meta & FD_SNP_META_APP_MASK ) >> 48 );
  if( ip4        ) *ip4       = (uint  )( meta );
  if( port       ) *port      = (ushort)( meta >> 32 );
}

static inline ulong
fd_snp_peer_addr_from_meta( fd_snp_meta_t meta ) {
  return meta & FD_SNP_META_PEER_MASK;
}

static inline ulong
fd_snp_peer_addr_from_parts( uint   ip4,
                             ushort port ) {
  return (( (ulong) port ) << 32 )
       | (( (ulong) ip4 ));
}

static inline void
fd_snp_peer_addr_into_parts( uint *   ip4,
                             ushort * port,
                             ulong    peer_addr ) {
  if( ip4  ) *ip4  = (uint  )( peer_addr );
  if( port ) *port = (ushort)( peer_addr >> 32 );
}

static inline int
fd_snp_ip_is_multicast( uchar const * packet ) {
  return 224 <= packet[FD_SNP_IP_DST_ADDR_OFF] && packet[FD_SNP_IP_DST_ADDR_OFF] <= 239;
}

/* fd_snp_tlv_extract_{type/len/ptr/tlv} extracts the corresponding
   values from a pointer to the beginning of a TLV set.  None of these
   methods returns the value itself, but rather a pointer to the
   beginning of the location in memory where the value is located. */
FD_FN_CONST static inline uchar
fd_snp_tlv_extract_type( uchar const * tlv_ptr ) {
  return fd_uchar_load_1( tlv_ptr );
}

FD_FN_CONST static inline ushort
fd_snp_tlv_extract_len( uchar const * tlv_ptr ) {
  return fd_ushort_load_2( tlv_ptr + 1UL );
}

FD_FN_CONST static inline uchar const *
fd_snp_tlv_extract_ptr( uchar const * tlv_ptr ) {
  return tlv_ptr + 3UL;
}

static inline fd_snp_tlv_t
fd_snp_tlv_extract_tlv( uchar const * tlv_ptr ) {
  fd_snp_tlv_t tlv;
  tlv.type = fd_snp_tlv_extract_type( tlv_ptr );
  tlv.len  = fd_snp_tlv_extract_len(  tlv_ptr );
  tlv.ptr  = fd_snp_tlv_extract_ptr(  tlv_ptr );
  return tlv;
}

/* fd_snp_tlv_iter_{init/done/next} are basic methods to iterate over
   a given buffer containing a sequence of TLVs.
   fd_snp_tlv_iter_{type/len/ptr/tlv} extract the corresponding TLV
   parts at the current location of the iterator.  None of these
   methods returns the value itself, which needs to be deduced using
   ptr and len (and probably type as well).  The application needs to
   verify that tlv.len holds a "reasonable" length value, since it can
   theoretically be in the range [0, 1<<16).
   Typical usage:

   for( fd_snp_tlv_iter_t iter = fd_snp_tlv_iter_init( data_sz );
        !fd_snp_tlv_iter_done( iter, data );
        iter = fd_snp_tlv_iter_next( iter, data ) ) {
      ...
      uchar         type = fd_snp_tlv_iter_type( iter, data );
      ushort        len  = fd_snp_tlv_iter_len(  iter, data );
      uchar const * ptr  = fd_snp_tlv_iter_ptr(  iter, data );
      fd_snp_tlv_t  tlv  = fd_snp_tlv_iter_tlv(  iter, data );
      ...
      uchar   u8 = fd_uchar_load_1(  tlv.ptr ); // if len==1
      ushort u16 = fd_ushort_load_2( tlv.ptr ); // if len==2
      uint   u32 = fd_uint_load_4(   tlv.ptr ); // if len==4
      ulong  u64 = fd_ulong_load_8(  tlv.ptr ); // if len==8
      fd_memcpy( value_buf, tlv.ptr, tlv.len ); // otherwise
      ...
    } */
FD_FN_CONST static inline fd_snp_tlv_iter_t
fd_snp_tlv_iter_init( ulong data_sz ) {
  fd_snp_tlv_iter_t iter;
  iter.off = 0UL;
  iter.rem = fd_long_if( !!(data_sz>>63), 0UL/*overflow size*/, (long)data_sz );
  return iter;
}

FD_FN_CONST static inline int
fd_snp_tlv_iter_done( fd_snp_tlv_iter_t iter,
                      uchar const *     data FD_PARAM_UNUSED ) {
  /* TLV "header" part (i.e. TL is 3 bytes long). */
  return iter.rem < 3L;
}

FD_FN_CONST static inline fd_snp_tlv_iter_t
fd_snp_tlv_iter_next( fd_snp_tlv_iter_t iter,
                      uchar const *     data ) {
  ulong tlv_sz = fd_snp_tlv_extract_len( data + iter.off ) + 3UL;
  iter.off += tlv_sz;
  iter.rem -= (long)tlv_sz; /* tlv_sz in range [3, (1<<16)+3). */
  return iter;
}

FD_FN_CONST static inline uchar
fd_snp_tlv_iter_type( fd_snp_tlv_iter_t iter,
                      uchar const *     data ) {
  return fd_snp_tlv_extract_type( data + iter.off );
}

FD_FN_CONST static inline ushort
fd_snp_tlv_iter_len( fd_snp_tlv_iter_t iter,
                     uchar const *     data ) {
  return fd_snp_tlv_extract_len( data + iter.off );
}

FD_FN_CONST static inline uchar const *
fd_snp_tlv_iter_ptr( fd_snp_tlv_iter_t iter,
                     uchar const *     data ) {
  return fd_snp_tlv_extract_ptr( data + iter.off );
}

FD_FN_CONST static inline fd_snp_tlv_t
fd_snp_tlv_iter_tlv( fd_snp_tlv_iter_t iter,
                     uchar const *     data ) {
  return fd_snp_tlv_extract_tlv( data + iter.off );
}

FD_PROTOTYPES_END

#if FD_SNP_TRACE_ENABLED
#undef  FD_SNP_DEBUG_ENABLED
#define FD_SNP_DEBUG_ENABLED (1)
#define FD_SNP_LOG_TRACE(...) FD_LOG_NOTICE(( __VA_ARGS__ ))
#else
#define FD_SNP_LOG_TRACE(...)
#endif

#if FD_SNP_DEBUG_ENABLED
#define FD_SNP_LOG_DEBUG_N(...) FD_LOG_NOTICE(( __VA_ARGS__ ))
#define FD_SNP_LOG_DEBUG_W(...) FD_LOG_WARNING(( __VA_ARGS__ ))
#define FD_SNP_LOG_CONN( conn ) fd_snp_log_conn( conn )
#else
#define FD_SNP_LOG_DEBUG_N(...)
#define FD_SNP_LOG_DEBUG_W(...)
#define FD_SNP_LOG_CONN( conn ) ""
#endif

#endif /* HEADER_fd_src_waltz_snp_fd_snp_common_h */
