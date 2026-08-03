#ifndef HEADER_fd_src_util_net_fd_ip6_h
#define HEADER_fd_src_util_net_fd_ip6_h

#include "../bits/fd_bits.h"

/* IPv6 address with an optional scope. */

struct fd_ip6_addr {
  uchar addr[ 16 ];
  uint  scope_id; /* 0 implies global */
};

typedef struct fd_ip6_addr fd_ip6_addr_t;

FD_PROTOTYPES_BEGIN

static inline void
fd_ip6_addr_ip4_mapped( uchar      ip6_addr[16],
                        uint const ip4_addr ) {
  memset( ip6_addr, 0, 10 );
  ip6_addr[ 10 ] = (uchar)0xff;
  ip6_addr[ 11 ] = (uchar)0xff;
  memcpy( ip6_addr+12, &ip4_addr, 4 );
}

static inline int
fd_ip6_addr_is_ip4_mapped( uchar const ip6_addr[16] ) {
  return (
    (ip6_addr[  0 ]==0x00) & (ip6_addr[  1 ]==0x00) &
    (ip6_addr[  2 ]==0x00) & (ip6_addr[  3 ]==0x00) &
    (ip6_addr[  4 ]==0x00) & (ip6_addr[  5 ]==0x00) &
    (ip6_addr[  6 ]==0x00) & (ip6_addr[  7 ]==0x00) &
    (ip6_addr[  8 ]==0x00) & (ip6_addr[  9 ]==0x00) &
    (ip6_addr[ 10 ]==0xff) & (ip6_addr[ 11 ]==0xff)
  );
}

static inline uint
fd_ip6_addr_to_ip4( uchar const ip6_addr[16] ) {
  uint ip4_addr;
  memcpy( &ip4_addr, ip6_addr+12, 4 );
  return ip4_addr;
}

/* fd_ip6_addr_is_unspecified returns 1 if the given address is the
   wildcard address (::), otherwise 0.  Binding a socket to the wildcard
   address listens on all addresses of all interfaces (both IPv6 and,
   unless IPV6_V6ONLY is set, IPv4). */

static inline int
fd_ip6_addr_is_unspecified( uchar const ip6_addr[16] ) {
  ulong hi, lo;
  memcpy( &hi, ip6_addr,   8 );
  memcpy( &lo, ip6_addr+8, 8 );
  return !(hi|lo);
}

/* fd_ip6_addr_is_scoped returns 1 if the given address has a scope
   narrower than global, i.e. a zone ID is required to identify which
   interface the address belongs to.  These are the link-local unicast
   addresses (fe80::/10) and the multicast addresses with a scope field
   below 'global' (ff00::/8 with the low nibble of byte 1 <0xe). */

static inline int
fd_ip6_addr_is_scoped( uchar const ip6_addr[16] ) {
  int link_local = (ip6_addr[0]==0xfe) & ((ip6_addr[1]&0xc0)==0x80);
  int multicast  = (ip6_addr[0]==0xff) & ((ip6_addr[1]&0x0f)< 0x0e);
  return link_local | multicast;
}

/* fd_cstr_to_ip6_addr parses an IPv6 address literal (RFC 4291), with
   an optional zone ID suffix (RFC 4007) naming the interface that the
   address belongs to.  The zone ID is either an interface name or a
   numeric interface index, e.g. "fe80::1%eth0" or "fe80::1%2".

   On success, stores the address to out and returns 1.  On failure,
   returns 0 and leaves out untouched.  Fails if a zone ID is given for
   an address that is not scoped, or names an interface that does not
   exist.

   Calls libc if_nametoindex (requires ioctl/Netlink access). */

int
fd_cstr_to_ip6_addr( char const *    s,
                     fd_ip6_addr_t * out );

/* fd_cstr_to_ip46_addr is like fd_cstr_to_ip6_addr, but additionally
   accepts an IPv4 address literal, which is stored as an IPv4-mapped
   IPv6 address (::ffff:a.b.c.d).  Note that the IPv4 wildcard address
   (0.0.0.0) maps to ::ffff:0.0.0.0.

   Calls libc if_nametoindex (requires ioctl/Netlink access).  */

int
fd_cstr_to_ip46_addr( char const *    s,
                      fd_ip6_addr_t * out );

/* FD_IP6_ADDR_CSTR_MAX is the buffer size required by
   fd_ip6_addr_cstr. */

#define FD_IP6_ADDR_CSTR_MAX (80UL)

/* fd_ip6_addr_cstr pretty prints an address for use as the host part of
   an URL, in the canonical text representation (RFC 5952).  IPv4-mapped
   addresses without a zone ID print as an IPv4 dotted quad (1.2.3.4),
   all others print bracketed, with a numeric zone ID suffix if the
   address is scoped (e.g. [fe80::1%2]).  Returns buf. */

char *
fd_ip6_addr_cstr( char                  buf[ static FD_IP6_ADDR_CSTR_MAX ],
                  fd_ip6_addr_t const * addr );

#define FD_IP6_ADDR_CSTR( name, addr ) \
  char name[ FD_IP6_ADDR_CSTR_MAX ]; fd_ip6_addr_cstr( name, (addr) )

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_net_fd_ip6_h */
