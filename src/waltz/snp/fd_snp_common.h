#ifndef HEADER_fd_src_waltz_snp_fd_snp_common_h
#define HEADER_fd_src_waltz_snp_fd_snp_common_h

#include "../../util/fd_util_base.h"
#include "../../util/bits/fd_bits.h"
#include "../../util/net/fd_net_headers.h"

#define FD_SNP_META_PROTO_UDP    (0x0000000000000000UL)
#define FD_SNP_META_PROTO_V1     (0x0100000000000000UL)
#define FD_SNP_META_PROTO_V2     (0x0200000000000000UL)

#define FD_SNP_META_OPT_BUFFERED (0x1000000000000000UL)

#define FD_SNP_META_IP_MASK      (0x00000000FFFFFFFFUL)
#define FD_SNP_META_PORT_MASK    (0x0000FFFF00000000UL)
#define FD_SNP_META_PEER_MASK    (0x0000FFFFFFFFFFFFUL)
#define FD_SNP_META_APP_MASK     (0x000F000000000000UL)
#define FD_SNP_META_PROTO_MASK   (0x0F00000000000000UL)
#define FD_SNP_META_OPT_MASK     (0xF000000000000000UL)

#define FD_SNP_SUCCESS ( 0)
#define FD_SNP_FAILURE (-1)

/* TYPES */

/* fd_snp_app_peer_t is a type to represent a peer identifier.
   Currently it encodes the peer IPv4 + port, but the application
   should not make any assumption. */
typedef ulong fd_snp_peer_t;

/* fd_snp_app_meta_t is a type to represent connection metadata. */
typedef ulong fd_snp_meta_t;

FD_PROTOTYPES_BEGIN

/* ALLOC */

static inline fd_snp_meta_t
fd_snp_meta_from_parts( ulong  snp_proto,
                        uchar  snp_app_id,
                        uint   ip4,
                        ushort port ) {
  return ( snp_proto )
    | (( (ulong) ( snp_app_id & 0x0F ) ) << 48 )
    | (( (ulong) port ) << 32 )
    | (( (ulong) ip4 ));
}

static inline void
fd_snp_meta_into_parts( ulong *       snp_proto,
                        uchar *       snp_app_id,
                        uint *        ip4,
                        ushort *      port, // TODO: should we bswap?
                        fd_snp_meta_t meta ) {
  if( snp_proto  ) *snp_proto = meta & FD_SNP_META_PROTO_MASK;
  if( snp_app_id ) *snp_app_id = (uchar)( ( meta & FD_SNP_META_APP_MASK ) >> 48 );
  if( ip4        ) *ip4       = (uint  )( meta );
  if( port       ) *port      = (ushort)( meta >> 32 );
}

FD_PROTOTYPES_END

#endif
