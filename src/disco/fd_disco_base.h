#ifndef HEADER_fd_src_disco_fd_disco_base_h
#define HEADER_fd_src_disco_fd_disco_base_h

#include "../tango/fd_tango.h"
#include "../ballet/shred/fd_shred.h"
#include "../ballet/txn/fd_txn.h"

#include "../util/wksp/fd_wksp_private.h"

#define DST_PROTO_OUTGOING (0UL)
#define DST_PROTO_TPU_UDP  (1UL)
#define DST_PROTO_TPU_QUIC (2UL)
#define DST_PROTO_SHRED    (3UL)
#define DST_PROTO_REPAIR   (4UL)
#define DST_PROTO_GOSSIP   (5UL)

#define POH_PKT_TYPE_MICROBLOCK    (0UL)
#define POH_PKT_TYPE_BECAME_LEADER (1UL)
#define POH_PKT_TYPE_DONE_PACKING  (2UL)
#define POH_PKT_REACHED_LEADER     (3UL)

#define REPLAY_FLAG_FINISHED_BLOCK      (0x01UL)
#define REPLAY_FLAG_PACKED_MICROBLOCK   (0x02UL)
#define REPLAY_FLAG_MICROBLOCK          (0x04UL)
#define REPLAY_FLAG_CATCHING_UP         (0x08UL)
#define REPLAY_FLAG_INIT                (0x10UL)


/* FD_NET_MTU is the max full packet size, with ethernet, IP, and UDP
   headers that can go in or out of the net tile.  2048 is the maximum
   XSK entry size, so this value follows naturally. */
#define FD_NET_MTU (2048UL)

/* FD_TPU_MTU is the max serialized byte size of a txn sent over TPU.

   This is minimum MTU of IPv6 packet - IPv6 header - UDP header
                                 1280 -          40 -          8 */
#define FD_TPU_MTU (1232UL)

/* FD_GOSSIP_MTU is the max sz of a gossip packet which is the same as
   above. */
#define FD_GOSSIP_MTU (FD_TPU_MTU)

/* FD_SHRED_STORE_MTU is the size of an fd_shred34_t (statically
   asserted in fd_shred_tile.c). */
#define FD_SHRED_STORE_MTU (41792UL)

#define FD_NETMUX_SIG_MIN_HDR_SZ    ( 42UL) /* The default header size, which means no vlan tags and no IP options. */
#define FD_NETMUX_SIG_IGNORE_HDR_SZ (102UL) /* Outside the allowable range, but still fits in 4 bits when compressed */

FD_PROTOTYPES_BEGIN

 /* hdr_sz is the total size of network headers, including eth, ip, udp.
    Ignored for outgoing packets.
    For incoming packets, hash_{ip_addr,port} are the source IP and port,
    for outgoing packets, they are the destination IP and port. */
FD_FN_CONST static inline ulong
fd_disco_netmux_sig( uint   hash_ip_addr,
                     ushort hash_port,
                     uint   dst_ip_addr,
                     ulong  proto,
                     ulong  hdr_sz ) {
  /* The size of an Ethernet header is 14+4k bytes, where 0<=k<=3 (?) is
     the number of vlan tags.  The size of an IP header is 4j, where
     5<=j<=15 is the size given in the header.  The size of a UDP header
     is 8B.  Thus, the total sum of these is 42+4i, where i=k+j-5,
     0<=i<=13.  Since bits are at a premium here, we compress the header
     size by just storing i. */
  ulong hdr_sz_i = ((hdr_sz - 42UL)>>2)&0xFUL;
  ulong hash     = 0xfffffUL & fd_ulong_hash( (ulong)hash_ip_addr | ((ulong)hash_port<<32) );
  return (hash<<44) | ((hdr_sz_i&0xFUL)<<40UL) | ((proto&0xFFUL)<<32UL) | ((ulong)dst_ip_addr);
}

FD_FN_CONST static inline ulong fd_disco_netmux_sig_hash  ( ulong sig ) { return (sig>>44UL); }
FD_FN_CONST static inline ulong fd_disco_netmux_sig_proto ( ulong sig ) { return (sig>>32UL) & 0xFFUL; }
FD_FN_CONST static inline uint  fd_disco_netmux_sig_dst_ip( ulong sig ) { return (uint)(sig & 0xFFFFFFFFUL); }

/* fd_disco_netmux_sig_hdr_sz extracts the total size of the Ethernet,
   IP, and UDP headers from the netmux signature field.  The UDP payload
   of the packet stored in the corresponding frag begins at the returned
   offset. */
FD_FN_CONST static inline ulong  fd_disco_netmux_sig_hdr_sz( ulong sig ) { return 4UL*((sig>>40UL) & 0xFUL) + 42UL; }

FD_FN_CONST static inline ulong
fd_disco_poh_sig( ulong slot,
                  ulong pkt_type,
                  ulong bank_tile ) {
   /* The high 6 bits of the low byte of the signature field is the bank
      idx.  Banks will filter to only handle frags with their own idx.
      The higher 7 bytes are the slot number.  Technically, the slot
      number is a ulong, but it won't hit 256^7 for about 10^9 years at
      the current rate.  The lowest bits of the low byte is the packet
      type. */
  return (slot << 8) | ((bank_tile & 0x3FUL) << 2) | (pkt_type & 0x3UL);
}

FD_FN_CONST static inline ulong fd_disco_poh_sig_pkt_type( ulong sig ) { return (sig & 0x3UL); }
FD_FN_CONST static inline ulong fd_disco_poh_sig_slot( ulong sig ) { return (sig >> 8); }
FD_FN_CONST static inline ulong fd_disco_poh_sig_bank_tile( ulong sig ) { return (sig >> 2) & 0x3FUL; }

FD_FN_CONST static inline ulong
fd_disco_bank_sig( ulong slot,
                   ulong microblock_idx ) {
  return (slot << 32) | microblock_idx;
}

FD_FN_CONST static inline ulong fd_disco_bank_sig_slot( ulong sig ) { return (sig >> 32); }
FD_FN_CONST static inline ulong fd_disco_bank_sig_microblock_idx( ulong sig ) { return sig & 0xFFFFFFFFUL; }

/* TODO remove with store_int */

FD_FN_CONST static inline ulong
fd_disco_replay_old_sig( ulong slot,
                     ulong flags ) {
   /* The low byte of the signature field is the flags for replay message.
      The higher 7 bytes are the slot number.  These flags indicate the status
      of a microblock as it transits through the replay system.  Technically,
      the slot number is a ulong, but it won't hit 256^7 for about 10^9 years
      at the current rate.  The lowest bit of the low byte is the packet
      type. */
  return (slot << 8) | (flags & 0xFFUL);
}

FD_FN_CONST static inline ulong fd_disco_replay_old_sig_flags( ulong sig ) { return (sig & 0xFFUL); }
FD_FN_CONST static inline ulong fd_disco_replay_old_sig_slot( ulong sig ) { return (sig >> 8); }

/* fd_disco_shred_replay_sig constructs a sig for the shred->replay
   link.  The encoded fields vary depending on the type of the sig.  The
   diagram below describes the encoding.

   type (1) | is_code or data_completes (1) | slot (32) | fec_set_idx (15) | shred_idx or data_cnt or parent_off (15)
   [63]     | [62]                          | [30, 61]  | [15, 29]         | [0, 14]

   The first bit of the sig is the sig type.

   When type is 0, the sig describes a shred header.  In this case, the
   second bit describes whether it is a coding shred (is_code) and the
   last 15 bits describe either a shred_idx or data_cnt if it's a data
   (is_code = 0) or coding (is_code = 1) shred.

   When type is 1, the sig describes a completed FEC set.  In this case,
   the fec_set_idx is the FEC set that completed, and the second bit is
   describes whether the last data shred in the FEC set is also marked
   with a DATA_COMPLETES flag.  This indicates that this FEC set is the
   last one in the entry batch.  The last 15 bits describe the parent
   slot offset (parent_off) from slot. */

FD_FN_CONST static inline ulong
fd_disco_shred_replay_sig( int type, int is_code_or_data_completes, ulong slot, uint fec_set_idx, uint shred_idx_or_data_cnt_or_parent_off ) {
  ulong type_ul                                = (ulong)type;
  ulong is_code_or_data_completes_ul           = (ulong)is_code_or_data_completes;
  ulong slot_ul                                = fd_ulong_min( (ulong)slot, (ulong)UINT_MAX );
  ulong fec_set_idx_ul                         = fd_ulong_min( (ulong)fec_set_idx, (ulong)FD_SHRED_MAX_PER_SLOT );
  ulong shred_idx_or_data_cnt_or_parent_off_ul = fd_ulong_extract( fd_ulong_min( (ulong)shred_idx_or_data_cnt_or_parent_off, (ulong)FD_SHRED_MAX_PER_SLOT ), 0, 14 );
  return type_ul << 63 | is_code_or_data_completes_ul << 62 | slot_ul << 30 | fec_set_idx_ul << 15 | shred_idx_or_data_cnt_or_parent_off_ul;
}

/* fd_disco_shred_replay_sig_{...} are accessors for the fields encoded
   in the sig described above. */

FD_FN_CONST static inline int   fd_disco_shred_replay_sig_type          ( ulong sig ) { return       fd_ulong_extract_bit( sig, 63     ); }
FD_FN_CONST static inline int   fd_disco_shred_replay_sig_is_code       ( ulong sig ) { return       fd_ulong_extract_bit( sig, 62     ); } /* type 0 */
FD_FN_CONST static inline int   fd_disco_shred_replay_sig_data_completes( ulong sig ) { return       fd_ulong_extract_bit( sig, 62     ); } /* type 1 */
FD_FN_CONST static inline ulong fd_disco_shred_replay_sig_slot          ( ulong sig ) { return       fd_ulong_extract    ( sig, 30, 61 ); }
FD_FN_CONST static inline uint  fd_disco_shred_replay_sig_fec_set_idx   ( ulong sig ) { return (uint)fd_ulong_extract    ( sig, 15, 29 ); }
FD_FN_CONST static inline uint  fd_disco_shred_replay_sig_shred_idx     ( ulong sig ) { return (uint)fd_ulong_extract_lsb( sig, 15     ); } /* type 0, is_code 0 */
FD_FN_CONST static inline uint  fd_disco_shred_replay_sig_data_cnt      ( ulong sig ) { return (uint)fd_ulong_extract_lsb( sig, 15     ); } /* type 0, is_code 1 */
FD_FN_CONST static inline uint  fd_disco_shred_replay_sig_parent_off    ( ulong sig ) { return (uint)fd_ulong_extract_lsb( sig, 15     ); } /* type 1 */


FD_FN_PURE static inline ulong
fd_disco_compact_chunk0( void * wksp ) {
  return (((struct fd_wksp_private *)wksp)->gaddr_lo) >> FD_CHUNK_LG_SZ;
}

FD_FN_PURE static inline ulong
fd_disco_compact_wmark( void * wksp, ulong mtu ) {
  ulong chunk_mtu  = ((mtu + 2UL*FD_CHUNK_SZ-1UL) >> (1+FD_CHUNK_LG_SZ)) << 1;
  ulong wksp_hi = ((struct fd_wksp_private *)wksp)->gaddr_hi;
  return (wksp_hi >> FD_CHUNK_LG_SZ) - chunk_mtu;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_fd_disco_base_h */
