#ifndef HEADER_fd_src_disco_fd_disco_base_h
#define HEADER_fd_src_disco_fd_disco_base_h

#include "../tango/fd_tango.h"
#include "../ballet/txn/fd_txn.h"
#include "../ballet/shred/fd_shred.h"

#include "../util/wksp/fd_wksp_private.h"

#define SRC_TILE_NET   (0UL)
#define SRC_TILE_QUIC  (1UL)
#define SRC_TILE_SHRED (2UL)

#define POH_PKT_TYPE_MICROBLOCK    (0UL)
#define POH_PKT_TYPE_BECAME_LEADER (1UL)

/* FD_NET_MTU is the max full packet size, with ethernet, IP, and UDP
   headers that can go in or out of the net tile.  2048 is the maximum
   XSK entry size, so this value follows naturally. */
#define FD_NET_MTU (2048UL)

/* FD_TPU_MTU is the max serialized byte size of a txn sent over TPU. */
#define FD_TPU_MTU (1232UL)

/* FD_SHRED_STORE_MTU is the size of an fd_shred34_t (statically
   asserted in fd_shred_tile.c). */
#define FD_SHRED_STORE_MTU (41792UL)

/* FD_TPU_DCACHE_MTU is the max size of a dcache entry */
#define FD_TPU_DCACHE_MTU (FD_TPU_MTU + FD_TXN_MAX_SZ + 2UL)
/* The literal value of FD_TPU_DCACHE_MTU is used in some of the Rust
   shims, so if the value changes, this acts as a reminder to change it
   in the Rust code. */
FD_STATIC_ASSERT( FD_TPU_DCACHE_MTU==2086UL, tpu_dcache_mtu_check );

#define FD_NETMUX_SIG_MIN_HDR_SZ    ( 42UL) /* The default header size, which means no vlan tags and no IP options. */
#define FD_NETMUX_SIG_IGNORE_HDR_SZ (102UL) /* Outside the allowable range, but still fits in 4 bits when compressed */

/* fd_shred34 is a collection of up to 34 shreds batched in a way that's
   convenient for use in a dcache and for access from Rust. The limit of
   34 comes so that sizeof( fd_shred34_t ) < USHORT_MAX. */

struct __attribute__((aligned(FD_CHUNK_ALIGN))) fd_shred34 {
  ulong shred_cnt;
  ulong stride;
  ulong offset;
  ulong shred_sz; /* The size of each shred */
  /* For i in [0, shred_cnt), shred i's payload spans bytes
     [i*stride+offset, i*stride+offset+shred_sz ), counting from the
     start of the struct, not this point. */
  union {
    fd_shred_t shred;
    uchar      buffer[ FD_SHRED_MAX_SZ ];
  } pkts[ 34 ];
};
typedef struct fd_shred34 fd_shred34_t;

struct fd_became_leader {
  /* Start time of the slot in nanoseconds. */
  long   slot_start_ns;

  /* An opaque pointer to a Rust Arc<Bank> object, which should only
     be used with fd_ext_* functions to execute transactions or drop
     the bank.  The ownership is complicated, but basically any bank
     tile that receives this frag has a strong refcnt to the bank and
     should release it when done, other tiles should ignore and never
     use the bank. */
  void const * bank;
};

typedef struct fd_became_leader fd_became_leader_t;

struct fd_microblock_trailer {
  /* A *const SanitizedTransation pointer, created by the bank which
     the PoH tile should use to commit the transactions.  This is a
     Rust ABI compatible array of SanitizedTransaction-s.  It is not
     heap allocated and should not be freed.  It lives in workspace
     memory for the bank tile that sent the microblock.  The bank
     tile promises it won't reclaim this memory until the PoH tile
     indicates it's done, by pushing a busy sequence number greater
     or equal to the busy_seq given below. */
  void * abi_txns;

  /* Opaque pointer to Rust Box<LoadAndExecuteOutput> object, created
     by the bank before executing the microblock.  Ownership belongs
     to the PoH tile when it receives the microblock, and it will
     need to be freed. */
  void * load_and_execute_output;

  /* Opaque pointer to Rust Box<PreBalanceInfo> object, created by
     the bank before executing the microblock.  Ownership belongs
     to the PoH tile when it receives the microblock, and it will
     need to be freed. */
  void * pre_balance_info;

  /* The sequence number of the mcache frag that this microblock was
     sent from pack to bank with.  This is the sequence number we
     need to report back in the bank busy fseq to tell the bank that
     the transactions have been committed and the relevant accounts
     can now be reused. */
  ulong  busy_seq;
};

typedef struct fd_microblock_trailer fd_microblock_trailer_t;

FD_PROTOTYPES_BEGIN

 /* hdr_sz is the total size of network headers, including eth, ip, udp.
    Ignored for outgoing packets. */
FD_FN_CONST static inline ulong
fd_disco_netmux_sig( ulong  ip_addr,
                     ushort port,
                     ulong  hdr_sz,
                     ushort src_tile,
                     ushort dst_idx ) {
  /* The size of an Ethernet header is 14+4k bytes, where 0<=k<=3 (?) is
     the number of vlan tags.  The size of an IP header is 4j, where
     5<=j<=15 is the size given in the header.  The size of a UDP header
     is 8B.  Thus, the total sum of these is 42+4i, where i=k+j-5,
     0<=i<=13.  Since bits are at a premium here, we compress the header
     size by just storing i. */
  ulong hdr_sz_i = ((hdr_sz - 42UL)>>2)&0xFUL;
  return (((ulong)ip_addr)<<32UL) | (((ulong)port)<<16UL) | ((src_tile&0xFUL)<<12UL) | ((hdr_sz_i&0xFUL)<<4UL) | (dst_idx&0xFUL);
}

FD_FN_CONST static inline uint   fd_disco_netmux_sig_ip_addr ( ulong sig ) { return (uint)((sig>>32UL) & 0xFFFFFFFFUL); }
FD_FN_CONST static inline ushort fd_disco_netmux_sig_port    ( ulong sig ) { return (sig>>16UL) & 0xFFFFUL; }
FD_FN_CONST static inline ushort fd_disco_netmux_sig_src_tile( ulong sig ) { return (sig>>12UL) & 0xFUL; }
FD_FN_CONST static inline ushort fd_disco_netmux_sig_dst_idx ( ulong sig ) { return (sig>> 0UL) & 0xFUL; }

FD_FN_CONST static inline ulong
fd_disco_poh_sig( ulong slot,
                  ulong pkt_type,
                  ulong bank_tile ) {
   /* The high 7 bits of the low byte of the signature field is the bank
      idx.  Banks will filter to only handle frags with their own idx.
      The higher 7 bytes are the slot number.  Technically, the slot
      number is a ulong, but it won't hit 256^7 for about 10^9 years at
      the current rate.  The lowest bit of the low byte is the packet
      type. */
  return (slot << 8) | ((bank_tile & 0x7FUL) << 1) | (pkt_type & 0x1UL);
}

FD_FN_CONST static inline ulong fd_disco_poh_sig_pkt_type( ulong sig ) { return (sig & 0x1UL); }
FD_FN_CONST static inline ulong fd_disco_poh_sig_slot( ulong sig ) { return (sig >> 8); }
FD_FN_CONST static inline ulong fd_disco_poh_sig_bank_tile( ulong sig ) { return (sig >> 1) & 0x7FUL; }

/* fd_disco_netmux_sig_hdr_sz extracts the total size of the Ethernet,
   IP, and UDP headers from the netmux signature field.  The UDP payload
   of the packet stored in the corresponding frag begins at the returned
   offset. */
FD_FN_CONST static inline ulong  fd_disco_netmux_sig_hdr_sz  ( ulong sig ) { return 4UL*((sig>>4UL) & 0xFUL) + 42UL; }

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

