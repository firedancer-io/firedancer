#ifndef HEADER_fd_src_disco_fd_disco_base_h
#define HEADER_fd_src_disco_fd_disco_base_h

#include "../tango/fd_tango.h"
#include "../ballet/shred/fd_shred.h"
#include "../ballet/txn/fd_txn.h"
#include "../flamenco/types/fd_types_custom.h"
#include "../util/wksp/fd_wksp_private.h"

#define DST_PROTO_OUTGOING (0UL)
#define DST_PROTO_TPU_UDP  (1UL)
#define DST_PROTO_TPU_QUIC (2UL)
#define DST_PROTO_SHRED    (3UL)
#define DST_PROTO_REPAIR   (4UL)
#define DST_PROTO_GOSSIP   (5UL)
#define DST_PROTO_SEND     (6UL)

#define POH_PKT_TYPE_MICROBLOCK    (0UL)
#define POH_PKT_TYPE_BECAME_LEADER (1UL)
#define POH_PKT_TYPE_FEAT_ACT_SLOT (2UL)

/* FD_NET_MTU is the max full packet size, with ethernet, IP, and UDP
   headers that can go in or out of the net tile.  2048 is the maximum
   XSK entry size, so this value follows naturally. */

#define FD_NET_MTU (2048UL)

/* FD_TPU_MTU is the max serialized byte size of a txn sent over TPU.

   For legacy/v0 transactions, this was limited to the minimum MTU of
   IPv6 packet - IPv6 header - UDP header = 1280 - 40 - 8 = 1232 bytes.

   For v1 transactions (SIMD-0296), this limit is increased to 4096 bytes,
   which can be transmitted over QUIC with fragmentation/reassembly. */

#define FD_TPU_MTU (4096UL)

/* FD_GOSSIP_MTU is the max sz of a gossip packet which is the same as
   above. */

#define FD_GOSSIP_MTU (FD_TPU_MTU)

/* FD_SHRED_STORE_MTU is the size of an fd_shred34_t (statically
   asserted in fd_shred_tile.c). */

#define FD_SHRED_STORE_MTU (41792UL)

/* FD_SHRED_OUT_MTU is the maximum size of a frag on the shred_out
   link.  This is the size of a data shred header + merkle root
   + chained merkle root. */

#define FD_SHRED_OUT_MTU (FD_SHRED_DATA_HEADER_SZ + 2*FD_SHRED_MERKLE_ROOT_SZ + sizeof(int))
FD_STATIC_ASSERT( FD_SHRED_OUT_MTU == 156UL , update FD_SHRED_OUT_MTU );

#define FD_NETMUX_SIG_MIN_HDR_SZ    ( 42UL) /* The default header size, which means no vlan tags and no IP options. */
#define FD_NETMUX_SIG_IGNORE_HDR_SZ (102UL) /* Outside the allowable range, but still fits in 4 bits when compressed */

/* These limits are defined here to prevent circular dependencies, and
   statically asserted they are calculated correctly in the relevant
   places.  We get one bound using transactions that consume the minimum
   number of CUs and another bound using the minimum size transactions.
   The overall bound is the lower of the two. */
#define FD_MAX_TXN_PER_SLOT_CU    98039UL
#define FD_MAX_TXN_PER_SLOT_SHRED 272635UL
#define FD_MAX_TXN_PER_SLOT       98039UL
FD_STATIC_ASSERT( FD_MAX_TXN_PER_SLOT<=FD_MAX_TXN_PER_SLOT_CU&&FD_MAX_TXN_PER_SLOT<=FD_MAX_TXN_PER_SLOT_SHRED, max_txn_per_slot );
FD_STATIC_ASSERT( FD_MAX_TXN_PER_SLOT>=FD_MAX_TXN_PER_SLOT_CU||FD_MAX_TXN_PER_SLOT>=FD_MAX_TXN_PER_SLOT_SHRED, max_txn_per_slot );


FD_PROTOTYPES_BEGIN

 /* hdr_sz is the total size of network headers, including eth, ip, udp.
    Ignored for outgoing packets.
    For incoming packets, hash_{ip_addr,port} are the source IP and port,
    for outgoing packets, they are the destination IP and port. */
FD_FN_CONST static inline ulong
fd_disco_netmux_sig( uint   hash_ip_addr,
                     ushort hash_port,
                     uint   ip_addr,
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
  return (hash<<44) | ((hdr_sz_i&0xFUL)<<40UL) | ((proto&0xFFUL)<<32UL) | ((ulong)ip_addr);
}

FD_FN_CONST static inline ulong fd_disco_netmux_sig_hash ( ulong sig ) { return (sig>>44UL); }
FD_FN_CONST static inline ulong fd_disco_netmux_sig_proto( ulong sig ) { return (sig>>32UL) & 0xFFUL; }
FD_FN_CONST static inline uint  fd_disco_netmux_sig_ip   ( ulong sig ) { return (uint)(sig & 0xFFFFFFFFUL); }

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
                   ulong pack_idx ) {
  return (slot << 32) | pack_idx;
}

FD_FN_CONST static inline ulong fd_disco_bank_sig_slot( ulong sig ) { return (sig >> 32); }
FD_FN_CONST static inline ulong fd_disco_bank_sig_pack_idx( ulong sig ) { return sig & 0xFFFFFFFFUL; }

/* TODO remove */

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

/* fd_disco_shred_out_shred_sig constructs a sig for the shred_out link.
   The encoded fields vary depending on the type of the sig.  The
   diagram below describes the encoding.

   is_turbine (1) | slot (32) | fec_set_idx (15) | is_code (1) | shred_idx or data_cnt (15)
   [63]           | [31, 62]  | [16, 30]         | [15]        | [0, 14]

   There are two types of messages on the shred_out link.  The first
   type is a generic shred message. The second is a FEC set completion
   message. Since we have run out of bits, the receiver must look at the
   sz of the dcache entry to determine which type of message it is.

   For the first message type (SHRED):

   The first bit [63] describes whether this shred source was turbine
   or repair.

   The next 32 bits [31, 62] describe the slot number. Note: if the slot
   number is >= UINT_MAX, the sender will store the value UINT_MAX in
   this field. If the receiver sees a value of UINT_MAX in the field, it
   must read the actual slot number from the dcache entry.

   The following 15 bits [16, 30] describe the fec_set_idx.  This is a
   15-bit value because shreds are bounded to 2^15 per slot, so in the
   worst case there is an independent FEC set for every shred, which
   results in at most 2^15 FEC sets per slot.

   The next bit [15] describes whether it is a coding shred (is_code).
   If is_code = 0, the sig describes a data shred, and the last 15 bits
   [0, 14] encode the shred_idx.  If is_code = 1, the sig describes a
   coding shred, and the last 15 bits encode the data_cnt.

   For the second message type (FEC):

   Only the slot and fec_set_idx bits are populated. The data in the
   frag is the full shred header of the last data shred in the FEC set,
   the merkle root of the FEC set, and the chained merkle root of the
   FEC. Each field immediately follows the other field. */

/* TODO this shred_out_sig can be greatly simplified when FEC sets
   are uniformly coding shreds and fixed size. */

FD_FN_CONST static inline ulong
fd_disco_shred_out_shred_sig( int   is_turbine,
                              ulong slot,
                              uint  fec_set_idx,
                              int   is_code,
                              uint  shred_idx_or_data_cnt ) {
   ulong slot_ul                  = fd_ulong_min( slot, (ulong)UINT_MAX );
   ulong shred_idx_or_data_cnt_ul = fd_ulong_min( (ulong)shred_idx_or_data_cnt, (ulong)FD_SHRED_BLK_MAX );
   ulong fec_set_idx_ul           = fd_ulong_min( (ulong)fec_set_idx, (ulong)FD_SHRED_BLK_MAX );
   ulong is_turbine_ul            = !!is_turbine;
   ulong is_code_ul               = !!is_code;

  return is_turbine_ul << 63 | slot_ul << 31 | fec_set_idx_ul << 16 | is_code_ul << 15 | shred_idx_or_data_cnt_ul;
}

/* fd_disco_shred_out_shred_sig_{...} are accessors for the fields encoded
   in the sig described above. */

FD_FN_CONST static inline int   fd_disco_shred_out_shred_sig_is_turbine ( ulong sig ) { return       fd_ulong_extract_bit( sig, 63     ); }
FD_FN_CONST static inline ulong fd_disco_shred_out_shred_sig_slot       ( ulong sig ) { return       fd_ulong_extract    ( sig, 31, 62 ); }
FD_FN_CONST static inline uint  fd_disco_shred_out_shred_sig_fec_set_idx( ulong sig ) { return (uint)fd_ulong_extract    ( sig, 16, 30 ); }
FD_FN_CONST static inline int   fd_disco_shred_out_shred_sig_is_code    ( ulong sig ) { return       fd_ulong_extract_bit( sig, 15     ); }
FD_FN_CONST static inline uint  fd_disco_shred_out_shred_sig_shred_idx  ( ulong sig ) { return (uint)fd_ulong_extract_lsb( sig, 15     ); } /* only when is_code = 0 */
FD_FN_CONST static inline uint  fd_disco_shred_out_shred_sig_data_cnt   ( ulong sig ) { return (uint)fd_ulong_extract_lsb( sig, 15     ); } /* only when is_code = 1 */

/*
   | slot (32) | fec_set_idx (15) | data_cnt (15) | is_data_complete (1) | is_batch_complete (1) |
   | [32, 63]  | [17, 31]         | [2, 16]       | [1]                  | [0]                   |

*/
FD_FN_CONST static inline ulong
fd_disco_shred_out_fec_sig( ulong slot, uint fec_set_idx, uint data_cnt, int is_slot_complete, int is_batch_complete ) {
  ulong slot_ul          = fd_ulong_min( slot, (ulong)UINT_MAX );
  ulong fec_set_idx_ul   = fd_ulong_min( (ulong)fec_set_idx, (ulong)FD_SHRED_BLK_MAX );
  ulong data_cnt_ul      = fd_ulong_min( (ulong)data_cnt, (ulong)FD_SHRED_BLK_MAX );
  ulong is_slot_complete_ul = !!is_slot_complete;
  ulong is_batch_complete_ul = !!is_batch_complete;
  return slot_ul << 32 | fec_set_idx_ul << 17 | data_cnt_ul << 2 | is_slot_complete_ul << 1 | is_batch_complete_ul;
}

FD_FN_CONST static inline ulong fd_disco_shred_out_fec_sig_slot             ( ulong sig ) { return         fd_ulong_extract    ( sig, 32, 63 ); }
FD_FN_CONST static inline uint  fd_disco_shred_out_fec_sig_fec_set_idx      ( ulong sig ) { return (uint)  fd_ulong_extract    ( sig, 17, 31 ); }
FD_FN_CONST static inline uint  fd_disco_shred_out_fec_sig_data_cnt         ( ulong sig ) { return (uint)  fd_ulong_extract    ( sig, 2, 16  ); }
FD_FN_CONST static inline int   fd_disco_shred_out_fec_sig_is_slot_complete ( ulong sig ) { return         fd_ulong_extract_bit( sig, 1     ); }
FD_FN_CONST static inline int   fd_disco_shred_out_fec_sig_is_batch_complete( ulong sig ) { return         fd_ulong_extract_bit( sig, 0     ); }

/* Exclusively used for force completion messages */

FD_FN_CONST static inline ulong
fd_disco_repair_shred_sig( uint last_shred_idx ){
   return (ulong) last_shred_idx;
}

FD_FN_CONST static inline uint fd_disco_repair_shred_sig_last_shred_idx( ulong sig ) { return (uint) sig; }


FD_FN_CONST static inline ulong
fd_disco_repair_replay_sig( ulong slot, ushort parent_off, uint data_cnt, int slot_complete ) {
  /*
   | slot (32) | parent_off (16) | data_cnt (15) | slot_complete(1)
   | [32, 63]  | [16, 31]        | [1, 15]       | [0]
  */
  ulong slot_ul          = fd_ulong_min( slot, (ulong)UINT_MAX );
  ulong parent_off_ul    = (ulong)parent_off;
  ulong data_cnt_ul      = fd_ulong_min( (ulong)data_cnt, (ulong)FD_SHRED_BLK_MAX );
  ulong slot_complete_ul = !!slot_complete;
  return slot_ul << 32 | parent_off_ul << 16 | data_cnt_ul << 1 | slot_complete_ul;
}

FD_FN_CONST static inline ulong  fd_disco_repair_replay_sig_slot         ( ulong sig ) { return         fd_ulong_extract    ( sig, 32, 63 ); }
FD_FN_CONST static inline ushort fd_disco_repair_replay_sig_parent_off   ( ulong sig ) { return (ushort)fd_ulong_extract    ( sig, 16, 31 ); }
FD_FN_CONST static inline uint   fd_disco_repair_replay_sig_data_cnt     ( ulong sig ) { return (uint)  fd_ulong_extract    ( sig, 1,  15 ); }
FD_FN_CONST static inline int    fd_disco_repair_replay_sig_slot_complete( ulong sig ) { return         fd_ulong_extract_bit( sig, 0      ); }

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
