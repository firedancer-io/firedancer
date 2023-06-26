#ifndef HEADER_fd_src_util_net_fd_udp_h
#define HEADER_fd_src_util_net_fd_udp_h

#include "fd_ip4.h" /* UDP is tightly tied to IP regardless of standard intent due to pseudo header layer violating BS */

/* FIXME: UDP CRASH COURSE HERE */

union fd_udp_hdr {
  struct {
    ushort net_sport; /* src port, net order */
    ushort net_dport; /* dst port, net order */
    ushort net_len;   /* datagram length, from first byte of this header to last byte of the udp payload */
    ushort check;     /* UDP checksum ("invariant" order), from first byte of pseudo header prepended before this header to last
                         byte of udp payload with zero padding to even length inclusive.  In IP4, 0 indicates no checksum. */
  };
  uint u[2];
};

typedef union fd_udp_hdr fd_udp_hdr_t;

/* FIXME: CONSIDER A PRETTY PRINTER FOR A FD_UDP_HDR? */

FD_PROTOTYPES_BEGIN

/* fd_ip4_udp_check is used for udp check field computation and
   validation.  If the dgram has no checksum (check==0), this returns
   the value to use for check.  If the dgram has a checksum (check!=0),
   this returns 0 if the message has a valid checksum or non-zero if
   not.  ip4_saddr and ip4_daddr are the ip4 source and destination
   addresses to use for the udp pseudo header.  udp is a non-NULL
   pointer to the first byte of a memory region containing the udp
   header and dgram is a non-NULL pointer to the first byte of a memory
   region containing a datagram of size:

     dgram_sz = fd_ushort_bswap(udp->net_len) - sizeof(fd_udp_hdr_t)

   bytes.  This assumes it is safe to read up to 3 bytes past the end of
   dgram (technically it will read the fd_align_up(dgram_sz,4UL) bytes
   dgram).  The contents of the tail read region are irrelevant.

   This is neither a particularly fast calculation (reasonably fast
   O(dgram_sz)) nor a particularly robust and it can inhibit cut-through
   usage.  So in general it is best to avoid UDP checksums, usually by
   exploiting their optionality in IP4 (note that the Ethernet CRC is
   reasonably strong and still provides protection).

   As such, this is mostly here for the rare application that needs to
   manually compute / validate UDP checksums (e.g. overhead doesn't
   matter or when the hardware sending/receiving the packet doesn't do
   various checksum offload computations and UDP checksums are
   required).

   WARNING!  With strict aliasing optimizations enabled and having this
   inline, the caller might need to type pun the dgram value passed to
   this (e.g. fd_type_pun_const(my_dgram)), wrap their dgram structure
   in a union like seen above for the udp_hdr_t or play various games
   with the may_alias attribute.  fd_type_pun_const is the quickest way
   to handle this but can inhibit various optimizations.  Wrapping in a
   union type is the fastest and most conformant way to handle this.
   The compiler is pretty good at catching when this is necessary and
   warning about it but be careful here.  FIXME: CONSIDER NOT INLINING
   THIS? */

FD_FN_PURE static inline ushort
fd_ip4_udp_check( uint                 ip4_saddr,
                  uint                 ip4_daddr,
                  fd_udp_hdr_t const * udp,
                  void const *         dgram ) { /* Assumed safe to tail read up to 3 bytes past end of msg */
  ushort net_len = udp->net_len; /* In net order */
  uint   rem     = (uint)fd_ushort_bswap( net_len ) - (uint)sizeof(fd_udp_hdr_t);

  /* Sum the pseudo header and UDP header words */
  uint const * u = udp->u;
  ulong ul = ((((ulong)FD_IP4_HDR_PROTOCOL_UDP)<<8) | (((ulong)net_len)<<16))
           + ((ulong)ip4_saddr)
           + ((ulong)ip4_daddr)
           + ((ulong)u[0])
           + ((ulong)u[1]);

  /* Sum the dgram words (reads up to 4 past end of msg) */
  u = (uint const *)dgram; /* See warning above */
  for( ; rem>3U; rem-=4U, u++ ) ul += (ulong)u[0];
  ul += (ulong)( u[0] & ((1U<<(8U*rem))-1U) );

  /* Reduce the sum to a 16-bit one's complement sum */
  ul  = ( ul>>32            ) +
        ((ul>>16) & 0xffffUL) +
        ( ul      & 0xffffUL);
  ul  = ( ul>>16            ) +
        ( ul      & 0xffffUL);
  ul += ( ul>>16            );

  /* And complement it */
  return (ushort)~ul;
}

/* fd_udp_hdr_bswap reverses the endianness of all fields in the UDP
   header. */

static inline void
fd_udp_hdr_bswap( fd_udp_hdr_t * hdr ) {
  hdr->net_sport = (ushort)fd_ushort_bswap( hdr->net_sport    );
  hdr->net_dport = (ushort)fd_ushort_bswap( hdr->net_dport    );
  hdr->net_len   = (ushort)fd_ushort_bswap( hdr->net_len      );
  hdr->check     = (ushort)fd_ushort_bswap( hdr->check        );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_net_fd_udp_h */
