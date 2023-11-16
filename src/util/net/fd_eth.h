#ifndef HEADER_fd_src_util_net_fd_eth_h
#define HEADER_fd_src_util_net_fd_eth_h

#include "../bits/fd_bits.h"

/* Host side ethernet protocol crash course:

   In terms of logical bytes on the wire, a non-Jumbo normal ethernet
   packet looks like:

              |     | <- 4B*TAG_CNT --> | <------ at most 1500B -------> |     |
              |     |      |     |      |                                |     |
              | eth | vlan |     | vlan |              eth               |     |
     preamble | hdr | tag  |     | tag  |            payload             | fcs | ifg
       ~8B    | 14B |  4B  | ... |  4B  | [max(0B,46B-4B*TAG_CNT),1500B] | 4B  | ~12B
              |                                                          |     |
              |               what hardware typically shows              |     |
              | <---------- at most 14B + 4B*TAG_CNT + 1500B ----------> |     |
              |                                                                |
              | <----------------------- at least 64B -----------------------> |

   The preamble (an oscillatory bit pattern), FCS (frame check sequence
   / CRC / cyclic redundancy check) and IFG (interframe gap / quiet
   time) are usually not shown to threads receiving a packet from an
   Ethernet LAN (these are historically for helping synchronize a
   receiver with a sender on receipt of a packet from the sender and
   validating a packet was received correctly with reasonably high
   probability).  Packets with a bad FCS may or may not be shown to an
   application depending on the hardware, interface and how it was
   configured.

   Threads sending packets usually do not worry about the preamble, FCS
   or IFG.  These are typically stripped by the underlying hardware on
   receive and inserted in the appropriate locations on send.  Just as
   often, hardware given a "runt" payload to send (smaller than the
   minimum size above) will zero pad the payload to the minimal payload
   size and the fcs will cover this zero padding too).

   VLAN tags have an unfortunately far wider range of behaviors in the
   wild due to the rather messy set of protocols that have accumulated
   over the decades.

   TAG_CNT can only be determined by parsing the packet headers.  0 (raw
   Ethernet) or 1 (VLAN tagged ethernet) are common but there isn't an
   obvious theoretical upper limit to TAG_CNT (nobody seems to have
   seriously thought about it).  For example, queue-in-queue network
   configs and/or various capture devices might insert additional tags
   to further decorate a packet.  Thus, 2 vlan tags isn't unheard of
   (e.g. queue-in-queue or a capture device adding a tag to vlan tagged
   ethernet indicating timestamp info has been provided for the packet
   somehow) or even 3 (e.g. capture device tagging a 2 vlan tag packet).

   Similarly, hardware might insert or strip VLAN tags behind a thread's
   back depending on the network, hardware, interface and how it was
   configured.  And different hardware devices and hardware-software
   interfaces have ideas as to what applications should be exposed to.
   And depending where a packet is inspected, it might have different
   number of tags.

   As a practical matter, most applications have some set of VLAN tag
   behaviors they understand / expect for the combination of LAN, WAN,
   NIC and interface they support.  Often this is implicit / evolved as
   most application devs are blissfully unaware of all this.  E.g. the
   maximum number of VLAN tags they can handle is implicitly bounded by
   their buffer sizes / buffer management, their range of expected
   behaviors is bounded by what worked in testing on their combination
   of lab hardware and equipment, etc.

   MAC addresses have 6 bytes.  Bit 0 in the byte 0 indicates whether or
   not the MAC address multicast or unicast.  Bit 1 in byte 0 indicates
   whether or not the MAC address is locally administered.  For standard
   unicast MAC addresses (not locally admin'd), the first 3 bytes encode
   an OUI (organizationally unique identifier).  The last 3 bytes are
   then assigned by the organization to hardware such that Ethernet
   conformant hardware will all have globally unique MAC addresses.  Most
   anything goes for locally admin'd addresses.  Additional notes are
   below.

   It is notable that:

   - The FCS does not protect against header or VLAN tag corruption.
     Applications, even in non-malicious scenarios, can not assume the
     headers are valid.  In most non-malicious scenarios though,
     applications can assume that that corrupted headers are reasonably
     rare and thus need not be optimized.  In some non-malicious
     scenarios though, header corrupt is common enough to warrant
     optimized handling.

   - Routing and flow steering mechanisms for Ethernet tend to not be
     precise.  That is, applications should not assume they will only
     receive packets they care about.  Like the above, in non-malicious
     scenarios, applications usually can assume they will mostly receive
     packets they care about and that the record of packets they care
     about is reasonably complete (such that they don't need to worry
     optimize filtering irrelevant packets or optimizing for drop
     recovery).  There are notable non-malicious exceptions though.

   - The FCS does not provide sufficiently strong protection against
     invalid packet receipt in many modern real world scenarios, even
     non-malicious.  Various combination of high bandwidth links, large
     number of senders, large number of receivers and high BER links
     create situations where corrupted payloads pass the FCS check and
     thus get exposed to the application.  Application need to be able
     to detect and recover from to their satisfaction.  In non-malicious
     scenarios, this rate tends to be low enough relative to the overall
     application packet rates so as to not require optimized handling
     (e.g. fast detect, treat as drop and use standard drop recovery
     mechanisms). */

#define FD_ETH_HDR_TYPE_IP   ((ushort)0x0800) /* (In host byte order) This hdr/tag is followed by an IP packet */
#define FD_ETH_HDR_TYPE_ARP  ((ushort)0x0806) /* (In host byte order) This hdr/tag is followed by an ARP packet */
#define FD_ETH_HDR_TYPE_VLAN ((ushort)0x8100) /* (In host byte order) This hdr/tag is followed by a VLAN tag */

#define FD_ETH_FCS_APPEND_SEED (0U) /* Seed to start an incremental fcs calculation */

/* FD_ETH_PAYLOAD_{MAX,MIN_RAW} return the appropriate payload size
   limits in bytes as a ulong for a normal untagged ethernet packet.

   FD_ETH_PAYLOAD_MIN returns the minimum size payload in bytes for an
   ethernet packet with the tag_cnt vlan tags.  Should be compile time
   const given compile time tag_cnt.  User promises tag_cnt is in
   [0,11].  Payloads smaller than this in software will get zero padded
   to this by hardware under the hood typically.  Note:
   FD_ETH_PAYLOAD_MIN(0)==FD_ETH_PAYLOAD_MIN_RAW. */

#define FD_ETH_PAYLOAD_MAX          (1500UL)
#define FD_ETH_PAYLOAD_MIN_RAW      (46UL)
#define FD_ETH_PAYLOAD_MIN(tag_cnt) (FD_ETH_PAYLOAD_MIN_RAW-4UL*(ulong)(tag_cnt))

/* Ethernet header */

struct fd_eth_hdr {
  uchar  dst[6];   /* Destination MAC address */
  uchar  src[6];   /* Source MAC address */
  ushort net_type; /* Type of packet encapsulated, net order */
};

typedef struct fd_eth_hdr fd_eth_hdr_t;

/* FD_ETH_MAC_FMT / FD_ETH_MAC_FMT_ARGS are used to pretty print a MAC
   address by a printf style formatter.  m must be safe against multiple
   evaluation.  Example usage:

     fd_eth_hdr_t * hdr = ...;
     FD_LOG_NOTICE(( "DST MAC: " FD_ETH_MAC_FMT, FD_ETH_MAC_FMT_ARGS( hdr->dst ) */

#define FD_ETH_MAC_FMT         "%02x:%02x:%02x:%02x:%02x:%02x"
#define FD_ETH_MAC_FMT_ARGS(m) (uint)((m)[0]), (uint)((m)[1]), (uint)((m)[2]), (uint)((m)[3]), (uint)((m)[4]), (uint)((m)[5])

/* FIXME: CONSIDER PRETTY PRINTERS FOR THE WHOLE HDR? */

/* VLAN tag */

struct fd_vlan_tag {
  ushort net_vid;  /* [3-bit priority=0:7 ... 0 is lowest], [1-bit CFI=0], [12-bit VLAN tag], net order */
  ushort net_type; /* ethertype, net order */
};

typedef struct fd_vlan_tag fd_vlan_tag_t;

/* FIXME: CONSIDER PRETTY PRINTERS FOR THE TAG? */

FD_PROTOTYPES_BEGIN

/* fd_eth_mac_is_{mcast,local,bcast,ip4_mcast} test if a mac address is:
     mcast:     multicast (broadcast and ip4 multicast are special cases)
     local:     locally administered
     bcast:     Ethernet broadcast (implies mcast, implies local, implies not ip4_mcast)
     ip4_mcast: IP4 multicast (implies mcast, implies not local, implies not bcast) */

FD_FN_PURE static inline int fd_eth_mac_is_mcast( uchar const * mac ) { return !!(((uint)mac[0]) & 1U); }

FD_FN_PURE static inline int fd_eth_mac_is_local( uchar const * mac ) { return !!(((uint)mac[0]) & 2U); }

FD_FN_PURE static inline int
fd_eth_mac_is_bcast( uchar const * mac ) {
  return (fd_ulong_load_4_fast( mac ) + fd_ulong_load_2_fast( mac+4 ))==(0xffffffffUL + 0xffffUL);
}

FD_FN_PURE static inline int
fd_eth_mac_is_ip4_mcast( uchar const * mac ) {
  return fd_ulong_load_3_fast( mac )==0x5e0001UL;
}

/* fd_eth_fcs / fd_eth_fcs_append compute / incrementally update the fcs
   of an ethernet frame.  That is, if buf points to the bytes of an
   ethernet frame containing sz bytes (first byte of the ethernet header
   to the last byte of the ethernet payload inclusive), the ethernet fcs
   can be computed and appended to buf via something like:

     fcs = fd_eth_fcs( buf, sz );
     *((uint *)(buf+sz)) = fcs;

   (This assumes the platform is okay with potentially unaligned memory
   accesses.  The current implementation assumes a little endian
   platform as well but not too hard to make a variant for big endian
   platforms if necessary).

   This calculation can be done incrementally if useful.  E.g.:

     fcs = fd_eth_fcs       (      part1, part1_sz ); // or fd_eth_fcs_append( FD_ETH_FCS_APPEND_SEED, part1, part1_sz )
     fcs = fd_eth_fcs_append( fcs, part2, part2_sz );
     ...
     fcs = fd_eth_fcs_append( fcs, partn, partn_sz );

   yields the same result as:

     fcs = fd_eth_fcs( buf, sz )

   if buf/sz are the concatenation with no padding of the parts.

   The FCS computation under the hood is the IEEE802.3 crc32.  This
   currently is not a particularly fast implementation (byte at a time
   table lookup based) nor a particularly good hash function
   theoretically.  Rather, this is here for the rare application that
   needs to manually compute / validate an Ethernet FCS. */

FD_FN_PURE uint
fd_eth_fcs_append( uint         fcs,
                   void const * buf,
                   ulong        sz );

FD_FN_PURE static inline uint
fd_eth_fcs( void const * buf,
            ulong        sz ) {
  return fd_eth_fcs_append( (uint)FD_ETH_FCS_APPEND_SEED, buf, sz );
}

/* fd_eth_mac_ip4_mcast populates the 6 byte memory region whose first
   byte is pointed to by mac with the Ethernet MAC address corresponding
   to the given multicast IP4 addr in ip4_addr_mcast (i.e. x.y.z.w where
   the caller promises that x is in [224,239] and given such that x is
   in bits 0:7, y is in bits 8:15, z is in bits 16:23, w is in bits
   24:31 ... exactly how they would be if read directly from an IP hdr
   into a uint on this platform).  Returns mac. */

static inline uchar *
fd_eth_mac_ip4_mcast( uchar * mac,
                      uint    ip4_addr_mcast ) {
  FD_STORE( uint,   mac,   0x5e0001U | (((ip4_addr_mcast >> 8) & 0x7fU) << 24) );
  FD_STORE( ushort, mac+4, (ushort)((ip4_addr_mcast >> 16) & 0xffffU)          );
  return mac;
}

/* fd_eth_mac_bcast populates the 6 byte memory region whose first byte
   is pointed to by mac with the Ethernet MAC address corresponding to
   LAN broadcast.  Returns dst. */

static inline uchar *
fd_eth_mac_bcast( uchar * mac ) {
  FD_STORE( uint,   mac,   0xffffffffU    );
  FD_STORE( ushort, mac+4, (ushort)0xffff );
  return mac;
}

/* fd_eth_mac_cpy populates the 6 byte memory region whose first byte is
   pointed to by mac with the MAC address pointed whose first byte is
   pointed to by _mac.  mac should either not overlap or overlap with
   mac <= _mac.  Overlap with mac > _mac is not supported.  Returns mac. */

static inline uchar *
fd_eth_mac_cpy( uchar       * mac,
                uchar const * _mac ) {
  FD_STORE( uint,   mac,   FD_LOAD( uint,   _mac   ) );
  FD_STORE( ushort, mac+4, FD_LOAD( ushort, _mac+4 ) );
  return mac;
}

/* fd_vlan_tag populates the memory region of size sizeof(fd_vlan_tag_t)
   and whose first byte is pointed to by the non-NULL _tag into a vlan
   tag for vlan vid and the given type with 0 priority and 0 CFI
   (priority and CFI are meant for router side use typically).  Returns
   _tag.  FIXME: OPTIMIZE BSWAPS? */

static inline fd_vlan_tag_t *
fd_vlan_tag( void * _tag,
             ushort vid,     /* Assumed in [0,4095], host order */
             ushort type ) { /* What follows this tag? */
  fd_vlan_tag_t * tag = (fd_vlan_tag_t *)_tag;
  /* FIXME: USE FD_STORE? */
  tag->net_vid  = fd_ushort_bswap( vid  );
  tag->net_type = fd_ushort_bswap( type );
  return tag;
}

/* fd_cstr_to_mac_addr parses a MAC address matching format
   FD_ETH_MAC_FMT from the given cstr and stores the result into mac.
   On success returns mac.  On failure, returns NULL and leaves mac in
   an undefined state.  On success, exactly 17 characters of s were
   processed. */

uchar *
fd_cstr_to_mac_addr( char const * s,
                     uchar      * mac );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_net_fd_eth_h */
