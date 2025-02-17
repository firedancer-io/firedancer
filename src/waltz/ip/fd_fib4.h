#ifndef HEADER_fd_src_waltz_ip_fd_fib4_h
#define HEADER_fd_src_waltz_ip_fd_fib4_h

/* A fib4 stores IPv4 routes in a query-optimized data structure.

   fib4 does not scale well to large numbers of routes.  Every route
   lookup is O(n) where n is the number of routes in the FIB.

   fib4 only supports a minimal set of features required for end devices
   to operate.  Packet forwarding is not supported.

   fib4 supports multi-threaded operation in a x86-TSO like environment.
   (many reader threads, one writer thread)  Refer to each function for
   thread safety.

   A fib4 always has a dummy route at index 0.

   FIXME: CONSIDER TRIE BASED DATA STRUCTURE

   Trivia: https://en.wikipedia.org/wiki/Forwarding_information_base */

#include "../../util/fd_util_base.h"

#define FD_FIB4_ALIGN (16UL)

/* FD_FIB4_RTYPE_{...} enumerate route types.
   These match Linux RTN_UNICAST, etc. */

#define FD_FIB4_RTYPE_UNSPEC    (0) /* invalid */
#define FD_FIB4_RTYPE_UNICAST   (1) /* "normal" path */
#define FD_FIB4_RTYPE_LOCAL     (2) /* address on local host */
#define FD_FIB4_RTYPE_BROADCAST (3) /* reserved for future use */
#define FD_FIB4_RTYPE_MULTICAST (5) /* reserved for future use */
#define FD_FIB4_RTYPE_BLACKHOLE (6) /* drop packet */
#define FD_FIB4_RTYPE_THROW     (9) /* continue in next table */

/* fd_fib4_t is a local handle to a fib4 object.  Use fd_fib4_{align,
   footprint,new,delete,join,leave} to construct and join a fib4. */

struct fd_fib4;
typedef struct fd_fib4 fd_fib4_t;

/* fd_fib4_hop_t holds a FIB lookup result (see fd_fib4_lookup) */

struct __attribute__((aligned(16))) fd_fib4_hop {
  uint  ip4_gw;   /* gateway address (big endian) */
  uint  if_idx;   /* output interface index */
  uint  ip4_src;  /* override source address (big endian). 0 implies unset */
  uchar rtype;    /* route type (e.g. FD_FIB4_RTYPE_UNICAST) */
  uchar scope;    /* used to select source address */
  uchar flags;    /* app-specific flags */
};

#define FD_FIB4_FLAG_RTA_UNSUPPORTED   ((uchar)0x01U) /* unsupported route attribute */
#define FD_FIB4_FLAG_RTA_PARSE_ERR     ((uchar)0x02U) /* failed to interpret route attribute */
#define FD_FIB4_FLAG_RTYPE_UNSUPPORTED ((uchar)0x03U) /* unsupported route type */

typedef struct fd_fib4_hop fd_fib4_hop_t;

FD_PROTOTYPES_BEGIN

/* Constructor APIs ******************************************************/

FD_FN_CONST ulong
fd_fib4_align( void );

FD_FN_CONST ulong
fd_fib4_footprint( ulong route_max );

void *
fd_fib4_new( void * mem,
             ulong  route_max );

fd_fib4_t *
fd_fib4_join( void * mem );

void *
fd_fib4_leave( fd_fib4_t * fib4 );

void *
fd_fib4_delete( void * mem );

/* Write APIs *************************************************************

   Currently, any updates to a fib4 require a full rewrite (incremental
   updates are not supported).  During an update, fd_fib4_lookup calls
   temporarily return a route entry with FD_FIB4_RTYPE_BLACKHOLE, which
   means outgoing packets get dropped.  (This is preferable to potentially
   making an incorrect routing decision based on a partial route table.) */

/* fd_fib4_clear removes all route table entries but the first.  Sets
   the first route table entry to "throw 0.0.0.0/0 metric ((2<<32)-1)". */

void
fd_fib4_clear( fd_fib4_t * fib );

/* fd_fib4_append attempts to add a new route entry.  If
   fd_fib4_free_cnt(fib) returned non-zero immediately prior to calling
   append, then append is guaranteed to succeed.

   Returns a hop object to be filled by the caller on success.  On
   failure, returns NULL and logs warning. */

fd_fib4_hop_t *
fd_fib4_append( fd_fib4_t * fib,
                uint        ip4_dst,
                int         prefix,
                uint        prio );

/* Read APIs *************************************************************/

/* fd_fib4_lookup resolves the next hop for an arbitrary IPv4 address.
   If route was not found, retval->rtype is set to FD_FIB4_RTYPE_THROW.

   Thread safe: Multiple threads can use the read API concurrently without
   affecting each other.  If a write by one thread is in progress, all
   other threads calling fd_fib4_lookup may briefly see a blackhole route
   being returned.  (Until of the effects of the write become visible to
   all CPUs in the system) */

fd_fib4_hop_t const *
fd_fib4_lookup( fd_fib4_t const * fib,
                fd_fib4_hop_t *   out,
                uint              ip4_dst,
                ulong             flags );

/* fd_fib4_hop_or is a helper to chain together multiple FIB lookups. */

FD_FN_PURE static inline fd_fib4_hop_t const *
fd_fib4_hop_or( fd_fib4_hop_t const * left,
                fd_fib4_hop_t const * right ) {
  return left->rtype!=FD_FIB4_RTYPE_THROW ? left : right;
}

/* fd_fib4_max returns the max number of routes in the table. */

FD_FN_PURE ulong
fd_fib4_max( fd_fib4_t const * fib );

/* fd_fib4_cnt returns the number of routes in the table. */

FD_FN_PURE ulong
fd_fib4_cnt( fd_fib4_t const * fib );

/* fd_fib4_free_cnt returns the number of fd_fib4_append calls that are
   guaranteed to succeed. */

ulong
fd_fib4_free_cnt( fd_fib4_t const * fib );

#if FD_HAS_HOSTED

/* fd_fib4_fprintf prints the routing table to the given FILE * pointer (or
   target equivalent).  Order of routes is undefined but guaranteed to be
   stable between calls.  Outputs ASCII encoding with LF newlines.  Returns
   errno on failure and 0 on success. */

int
fd_fib4_fprintf( fd_fib4_t const * fib,
                 void *            file );

#endif

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_ip_fd_fib4_h */
