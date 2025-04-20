#ifndef HEADER_fd_src_disco_dns_fd_dns_cache_h
#define HEADER_fd_src_disco_dns_fd_dns_cache_h

/* fd_dns_cache.h provides a shared memory dual-stack DNS client cache.
   For an arbitrary domain, holds multiple IP addresses.  Not designed
   to store arbitrary DNS responses (writer should not insert queries
   for untrusted domain names, and should limit the number of IPs per
   domain name).  Cache does not contain tombstones/errors.

   Is self-contained in a contiguous memory region, supports arbitrarily
   many concurrent readers and one writer, and is position-independent.
   Optimized for heavy reads and rare writes.  The current concurrency
   algorithms in use assume TSO.

   Internally, it is a separately chained hash map (fd_map_para).  Each
   map entry corresponds to a domain in the cache.  Each domain points
   to the head of a doubly linked list of address entries.  Domain and
   address entries are acquired from object pools.

   Any modifications to dns_cache (both domain name and address level)
   must be guarded by a map_chain_para modify lock.  Queries are done
   lockfree.  Modifications overrun longer running queries, but this is
   detected gracefully (by checking whether the lock changed since the
   beginning of a query operation).  Modifications must not be long-
   running since readers spin on locks.

   FIXME THIS DATA STRUCTURE ONLY SUPPORTS ONE CONCURRENT WRITER ...
         FIX THIS BY USING POOL_PARA? */

#include "../../util/log/fd_log.h"

/* FD_DNS_CACHE_ALIGN is the min alignment of a dns_cache object. */
#define FD_DNS_CACHE_ALIGN (64UL)

/* fd_dns_cache_addr_t is an IPv4 or IPv6 address entry.  IPv4 addresses
   are stored in IPv4-mapped-IPv6 format. */

struct __attribute__((aligned(16))) fd_dns_cache_addr {
  uchar ip6[16];
  uint  prev;
  uint  next;
};

typedef struct fd_dns_cache_addr fd_dns_cache_addr_t;

/* Declare a doubly-linked list over DNS cache addresses.
   FIXME this could be a singly-linked list */

#define DLIST_NAME  fd_dns_cache_addr_list
#define DLIST_T     fd_dns_cache_addr_t
#define DLIST_ELE_T fd_dns_cache_addr_t
#define DLIST_IDX_T uint
#include "../../util/tmpl/fd_dlist.c"

/* fd_dns_cache_ele_t is a DNS cache map entry. */

struct fd_dns_cache_key {
  char  name[ 256 ];
  uchar name_len;
};
typedef struct fd_dns_cache_key fd_dns_cache_key_t;

struct __attribute__((aligned(16))) fd_dns_cache_ele {
  ulong memo;
  long  resolve_time;
  uint  next; /* FIXME make this ulong? */

  fd_dns_cache_addr_list_t addr_list[1];

  fd_dns_cache_key_t key;
  // schar gai_err; -- future use
};

typedef struct fd_dns_cache_ele fd_dns_cache_ele_t;

FD_FN_PURE static inline int
fd_dns_cache_key_eq( fd_dns_cache_key_t const * k1,
                     fd_dns_cache_key_t const * k2 ) {
  if( k1->name_len != k2->name_len ) return 0;
  return fd_memeq( k1->name, k2->name, k1->name_len );
}

/* Declare prototypes for the DNS cache hash map. */

#define MAP_NAME               fd_dns_cache_map
#define MAP_ELE_T              fd_dns_cache_ele_t
#define MAP_KEY_EQ_IS_SLOW     1
#define MAP_MEMOIZE            1
#define MAP_IMPL_STYLE         1
#define MAP_IDX_T              uint
#define MAP_KEY_T              fd_dns_cache_key_t
#define MAP_KEY_EQ(k1,k2)      fd_dns_cache_key_eq( (k1), (k2) )
#define MAP_KEY_HASH(key,seed) fd_hash( (seed), (key)->name, (key)->name_len )
#include "../../util/tmpl/fd_map_chain_para.c"

/* fd_dns_cache_join_t is a handle describing a join to a shared
   dns_cache.  Each reader/writer of dns_cache has its own join struct. */

struct fd_dns_cache_join {
  fd_dns_cache_map_t    map[1]; /* map join handle */
  fd_dns_cache_ele_t *  name_pool;
  fd_dns_cache_addr_t * addr_pool;
};

typedef struct fd_dns_cache_join fd_dns_cache_join_t;

/* fd_dns_cache_t is an opaque handle to a shared dns_cache object. */

struct fd_dns_cache_private;
typedef struct fd_dns_cache_private fd_dns_cache_t;

/* fd_dns_cache_query_t is an in-progress DNS query. */

struct fd_dns_cache_query {
  fd_dns_cache_map_query_t q[1];    /* name query */
  fd_dns_cache_addr_t      addr[1]; /* address query */
};

typedef struct fd_dns_cache_query fd_dns_cache_query_t;

FD_PROTOTYPES_BEGIN

/* Constructors */

/* fd_dns_cache_{align,footprint} describe a memory region suitable to
   hold a dns_cache.  domains_max and addrs_max are in [1,2^31).
   fd_dns_cache_footprint silently returns 0UL if the given params are
   invalid, and is thus suitable as a validation function. */

FD_FN_CONST ulong
fd_dns_cache_align( void );

FD_FN_CONST ulong
fd_dns_cache_footprint( ulong domains_max,
                        ulong addrs_max );

/* fd_dns_cache_new formats the memory region at shmem for use as a
   dns_cache.  hash_seed is an arbitrary 64-bit integer used to seed the
   hash map.  Returns shmem on success or NULL on failure (logs reason). */

fd_dns_cache_t *
fd_dns_cache_new( void * shmem,
                  ulong  domains_max,
                  ulong  addrs_max,
                  ulong  hash_seed );

/* fd_dns_cache_join joins the caller to the dns_cache.  shcache points
   to the dns_cache in the local address space.  ljoin is backed by
   local memory and is populated with join information (pointers, etc).
   Returns ljoin on success or NULL on failure (logs reason).
   dns_cache has a read-write interest in ljoin until leave or unless
   join fails. */

fd_dns_cache_join_t *
fd_dns_cache_join( fd_dns_cache_t *      shcache,
                   fd_dns_cache_join_t * ljoin );

/* fd_dns_cache_leave undoes a local join to a dns_cache object.
   Returns ownership of join back to the caller (semantically and as the
   return value). */

void *
fd_dns_cache_leave( fd_dns_cache_join_t * join );

/* fd_dns_cache_delete destroys a dns_cache object and releases the
   backing memory region.  The caller ensures that there is no active or
   in-progress join to shcache (use-after-free).  Returns shcache. */

void *
fd_dns_cache_delete( fd_dns_cache_t * shcache );

/* Write API */

/* fd_dns_cache_put inserts or replaces a cache record.  fqdn points to
   a fully-qualified domain name of fqdn_len characters.  resolve_time
   is the wallclock timestamp when the server returned the query.
   ip6_addr_tbl points to a contiguous table containing IPv6 addresses.

   FIXME insertion failures are silent */

fd_dns_cache_ele_t *
fd_dns_cache_put(
    fd_dns_cache_join_t *  ljoin,
    char const *           fqdn,
    ulong                  fqdn_len,  /* in [1,255] */
    long                   resolve_time,
    uchar *                ip6_addr_tbl,
    ulong                  ip6_addr_cnt
);

/* fd_dns_cache_remove removes a cache record.  No-op if record did not
   exist. */

void
fd_dns_cache_remove(
    fd_dns_cache_join_t *  ljoin,
    char const *           fqdn,
    ulong                  fqdn_len  /* in [1,255] */
);

/* Read API */

/* fd_dns_cache_query_start looks up a fully-qualified domain name in
   the cache.  ljoin is a join to dns_cache.  query is a scratch
   variable to hold the result.  memo is an optional hash from an
   earlier query for the same domain name (purely an optimization).
   fqdn points to a string of fqdn_len chars.  Returns an address object
   holding the first address of the lookup on success (stored within
   query object).  Lifetime of returned pointer is the lifetime of the
   query object, or until query is invalidated.  If no record was found,
   or a writer overran us while reading, returns NULL.
   Use fd_dns_cache_query_test( query->q ) to check whether an overrun
   occurred or whether the end of the address list was reached
   gracefully. */

fd_dns_cache_addr_t *
fd_dns_cache_query_start(
    fd_dns_cache_join_t *  ljoin,
    fd_dns_cache_query_t * query,       /* out var */
    char const *           fqdn,
    ulong                  fqdn_len    /* in [1,255] */
    //ulong                  memo
);

/* fd_dns_cache_query_next fetches the next entry of a lookup operation
   started by fd_dns_cache_query_start.  Can be used to iterate multiple
   addresses for the same domain name.  query is the object populated by
   an earlier fd_dns_cache_query_{start,next} call.  Any previous result
   stored in query is invalidated.  Return value behavior is the same
   as for fd_dns_cache_query_start. */

fd_dns_cache_addr_t *
fd_dns_cache_query_next(
    fd_dns_cache_join_t *  ljoin,
    fd_dns_cache_query_t * query
);

/* Utilities */

#if FD_HAS_HOSTED

/* fd_dns_gai_strerror returns a static lifetime string describing the
   given EAI_* error code. */

FD_FN_CONST char const *
fd_dns_gai_strerror( int err );

#endif /* FD_HAS_HOSTED */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_dns_fd_dns_cache_h */
