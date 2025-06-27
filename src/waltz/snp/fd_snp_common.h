#ifndef HEADER_fd_src_waltz_snp_fd_snp_common_h
#define HEADER_fd_src_waltz_snp_fd_snp_common_h

#include "../../util/fd_util_base.h"
#include "../../util/bits/fd_bits.h"

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

struct tlv_meta {
  union {
    uchar         u8;
    ushort        u16;
    uint          u32;
    ulong         u64;
    uchar const * ptr;
  };
  ushort          len;
  uchar           type;
};
typedef struct tlv_meta tlv_meta_t;

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

/* fd_snp_tlv_extract() parses a tlv set pointed to by buf + offset,
   it populates meta accordingly, and returns the offset of the next
   tlv in the buffer.  If the length (l) is in {1,2,4,8}, then meta
   will hold the corresponding value in {u8,u16,u32,u64} accordingly,
   otherwise meta->ptr will be pointing to the begining of value (v)
   inside the buffer. */
static inline ulong
fd_snp_tlv_extract( uchar const * buf,
                    ulong         offset,
                    tlv_meta_t *  meta ) {
  uchar const * p = buf + offset;
  meta->type = fd_uchar_load_1( p );
  ushort l   = fd_ushort_load_2( p + 1UL );
  meta->len  = l;
  meta->ptr  = NULL; /* reset v */
  if( FD_LIKELY( fd_ushort_popcnt( l & 0x000fU ) == 1 ) ) {
    /* Optimized cases with l in {1U, 2U, 4U, 8U} */
    fd_memcpy( &meta->u64, p + 3UL, l );
  } else {
    meta->ptr = p + 3UL;
  }
  return offset + 3UL + l;
}

/* fd_snp_tlv_extract_fast() performs a fast parsing of the tlv set
   pointed to by buf + offset, it populates meta partially, and
   returns the offset of the next tlv in the buffer.  It does not
   attempt to parse the value (v) depending on the length (l).
   Instead, it only computes meta-ptr, pointing to the begining of
   value (v) inside the buffer.  Useful when doing a fast scan of all
   tlv(s) inside a buffer. */
static inline ulong
fd_snp_tlv_extract_fast( uchar const * buf,
                         ulong         offset,
                         tlv_meta_t *  meta ) {
  uchar const * p = buf + offset;
  meta->type = fd_uchar_load_1( p );
  ushort l   = fd_ushort_load_2( p + 1UL );
  meta->len  = l;
  meta->ptr  = p + 3UL;
  return offset + 3UL + l;
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



#endif
