#ifndef HEADER_fd_src_waltz_fd_h2_hdr_match_h
#define HEADER_fd_src_waltz_fd_h2_hdr_match_h

/* fd_h2_hdr_match.h provides utils for building lookup tables for HTTP
   header names.

   Example usage:

     // Define a custom header ID
     #define MYAPP_HDR_FOO 1

     // Initialize a matcher
     ulong seed;
     static fd_h2_hdr_matcher_t matcher[1];
     fd_h2_hdr_matcher_init( matcher, seed );
     fd_h2_hdr_matcher_add_literal( matcher, MYAPP_HDR_FOO, "x-myapp-foo" );

     // Usage
     FD_TEST( fd_h2_hdr_match( matcher, ":authority",  10 )==FD_H2_HDR_AUTHORITY );
     FD_TEST( fd_h2_hdr_match( matcher, "x-myapp-foo", 11 )==MYAPP_HDR_FOO       );

   See test_h2_hdr_match.c for more examples. */

#include "../../ballet/siphash13/fd_siphash13.h"
#include "fd_hpack.h"

/* Declare an open-addressed hash table mapping header name strings to
   arbitrary IDs (usually constants provided by the user). */

struct __attribute__((packed)) fd_h2_hdr_match_key {
  char const * hdr;
  ushort       hdr_len;
};

typedef struct fd_h2_hdr_match_key fd_h2_hdr_match_key_t;

static inline int
fd_h2_hdr_match_key_eq( fd_h2_hdr_match_key_t k1,
                        fd_h2_hdr_match_key_t k2 ) {
  return k1.hdr_len == k2.hdr_len && fd_memeq( k1.hdr, k2.hdr, k1.hdr_len );
}

struct __attribute__((aligned(16))) fd_h2_hdr_match_entry {
  fd_h2_hdr_match_key_t key;
  short id;
  uint  hash;
};

typedef struct fd_h2_hdr_match_entry fd_h2_hdr_match_entry_t;

extern fd_h2_hdr_match_entry_t const fd_h2_hdr_match_entry_null;

#define FD_H2_HDR_MATCH_LG_SLOT_CNT   9  /* 512 slots */
#define FD_H2_HDR_MATCH_MAX         300  /* target 0.7 load factor */

/* FIXME hack to work around lack of hash seed support in fd_map.c */
extern FD_TL ulong fd_h2_hdr_match_seed;

#define MAP_NAME              fd_h2_hdr_map
#define MAP_T                 fd_h2_hdr_match_entry_t
#define MAP_KEY_T             fd_h2_hdr_match_key_t
#define MAP_KEY               key
#define MAP_HASH_T            uint
#define MAP_HASH              hash
#define MAP_KEY_HASH(k)       (uint)fd_siphash13_hash( k.hdr, k.hdr_len, fd_h2_hdr_match_seed, 0UL )
#define MAP_MEMOIZE           1
#define MAP_LG_SLOT_CNT       FD_H2_HDR_MATCH_LG_SLOT_CNT
#define MAP_KEY_NULL          (fd_h2_hdr_match_key_t){0}
#define MAP_KEY_INVAL(k)      ((k).hdr==NULL)
#define MAP_KEY_EQUAL(k1,k2)  fd_h2_hdr_match_key_eq( (k1),(k2) )
#define MAP_KEY_EQUAL_IS_SLOW 1
#include "../../util/tmpl/fd_map.c"

/* A h2_hdr_matcher is used to build a hash table for common header
   names.  It is primarly designed for compile-time static lists of
   headers that a user might be interested in.  The user should not
   insert arbitrary entries into the map. */

struct fd_h2_hdr_matcher {
  fd_h2_hdr_match_entry_t entry[ 1<<FD_H2_HDR_MATCH_LG_SLOT_CNT ];

  ulong seed;
  ulong entry_cnt; /* excluding HPACK entries */
};

typedef struct fd_h2_hdr_matcher fd_h2_hdr_matcher_t;

FD_PROTOTYPES_BEGIN

/* fd_h2_hpack_matcher maps HPACK static table indices to common header
   IDs.  For context, HTTP/2 (via HPACK) can refer to a common header
   name by a table index instead of a literal string to save space.
   Indices in range [1,61] are predefined. */

extern schar const __attribute__((aligned(16)))
fd_h2_hpack_matcher[ 62 ];

/* fd_h2_hdr_matcher_init initializes a new matcher object.  mem points
   to a memory region matching alignof(fd_h2_hdr_matcher_t) and
   sizeof(fd_h2_hdr_matcher_t).  seed is an arbitrary 64-bit value that
   permutes the hash function.  Typically, seed is chosen using
   fd_rng_secure on application startup.

   The map is initialized with common HTTP headers which have negative
   IDs. See FD_H2_HDR_* at the end of this header file. */

fd_h2_hdr_matcher_t *
fd_h2_hdr_matcher_init( void * mem,
                        ulong  seed );

/* fd_h2_hdr_matcher_fini destroys a matcher object, and returns the
   underlying buffer back to the caller. */

void *
fd_h2_hdr_matcher_fini( fd_h2_hdr_matcher_t * matcher );

/* fd_h2_hdr_matcher_insert adds a custom header name to the matcher.
   Calling fd_h2_hdr_match with the same name will return id.

   name points to an array of name_len chars (not null terminated).
   name is lowercase.  name_len is in [1,2^16).  If name was already
   added (or is part of the static list), is a no-op.

   id is in [1,2^15).  Aborts the application with an error log if an
   out-of-bounds value is given.

   Up to FD_H2_HDR_MATCH_MAX names can be added to a matcher.  Aborts
   the application with an error log if this limit is exceeded. */

void
fd_h2_hdr_matcher_insert( fd_h2_hdr_matcher_t * matcher,
                          int                   id,
                          char const *          name, /* static lifetime */
                          ulong                 name_len );

/* fd_h2_hdr_matcher_insert_literal is a safe wrapper for the above. */

#define fd_h2_hdr_matcher_insert_literal(matcher,id,literal) \
  fd_h2_hdr_matcher_insert( (matcher), (id), literal, sizeof(literal)-1 )

/* fd_h2_hdr_match queries the given header name in the matcher map.
   hpack_hint is the `hint` field from `fd_h2_hdr_t`, or 0 if not
   available.  name is lowercase.  name_len is in [1,2^16).

   Returns ...
   - Zero (FD_H2_HDR_UNKNOWN) if the given name is unknown
   - Negative (FD_H2_HDR_*) if the entry matched a HTTP/2 builtin name
   - Positive if the entry matched a value previously added with
     fd_h2_hdr_matcher_add */

FD_FN_PURE static inline int
fd_h2_hdr_match( fd_h2_hdr_matcher_t const * matcher,
                 char const *                name,
                 ulong                       name_len,
                 uint                        hpack_hint ) {
  if( hpack_hint & FD_H2_HDR_HINT_NAME_INDEXED ) {
    ulong index = hpack_hint & FD_H2_HDR_HINT_GET_INDEX( hpack_hint );
    if( FD_LIKELY( index && index<=61 ) ) {
      return (int)fd_h2_hpack_matcher[ index ];
    }
  }
  if( FD_UNLIKELY( !name_len ) ) return 0;

  fd_h2_hdr_match_seed = matcher->seed;
  fd_h2_hdr_match_key_t key = { .hdr=name, .hdr_len=(ushort)name_len };
  fd_h2_hdr_match_entry_t const * entry =
    fd_h2_hdr_map_query_const( matcher->entry, key, &fd_h2_hdr_match_entry_null );
  return (int)entry->id;
}

FD_PROTOTYPES_END

/* Define common header IDs (non-standard) */

// Group 1: HPACK table
#define FD_H2_HDR_UNKNOWN                         0  // *** sentinel ***
#define FD_H2_HDR_AUTHORITY                      -1  // :authority
#define FD_H2_HDR_METHOD                         -2  // :method
#define FD_H2_HDR_PATH                           -3  // :path
#define FD_H2_HDR_SCHEME                         -4  // :scheme
#define FD_H2_HDR_STATUS                         -5  // :status
#define FD_H2_HDR_ACCEPT_CHARSET                 -6  // accept-charset
#define FD_H2_HDR_ACCEPT_ENCODING                -7  // accept-encoding
#define FD_H2_HDR_ACCEPT_LANGUAGE                -8  // accept-language
#define FD_H2_HDR_ACCEPT_RANGES                  -9  // accept-ranges
#define FD_H2_HDR_ACCEPT                        -10  // accept
#define FD_H2_HDR_ACCESS_CONTROL_ALLOW_ORIGIN   -11  // access-control-allow-origin
#define FD_H2_HDR_AGE                           -12  // age
#define FD_H2_HDR_ALLOW                         -13  // allow
#define FD_H2_HDR_AUTHORIZATION                 -14  // authorization
#define FD_H2_HDR_CACHE_CONTROL                 -15  // cache-control
#define FD_H2_HDR_CONTENT_DISPOSITION           -16  // content-disposition
#define FD_H2_HDR_CONTENT_ENCODING              -17  // content-encoding
#define FD_H2_HDR_CONTENT_LANGUAGE              -18  // content-language
#define FD_H2_HDR_CONTENT_LENGTH                -19  // content-length
#define FD_H2_HDR_CONTENT_LOCATION              -20  // content-location
#define FD_H2_HDR_CONTENT_RANGE                 -21  // content-range
#define FD_H2_HDR_CONTENT_TYPE                  -22  // content-type
#define FD_H2_HDR_COOKIE                        -23  // cookie
#define FD_H2_HDR_DATE                          -24  // date
#define FD_H2_HDR_ETAG                          -25  // etag
#define FD_H2_HDR_EXPECT                        -26  // expect
#define FD_H2_HDR_EXPIRES                       -27  // expires
#define FD_H2_HDR_FROM                          -28  // from
#define FD_H2_HDR_HOST                          -29  // host
#define FD_H2_HDR_IF_MATCH                      -30  // if-match
#define FD_H2_HDR_IF_MODIFIED_SINCE             -31  // if-modified-since
#define FD_H2_HDR_IF_NONE_MATCH                 -32  // if-none-match
#define FD_H2_HDR_IF_RANGE                      -33  // if-range
#define FD_H2_HDR_IF_UNMODIFIED_SINCE           -34  // if-unmodified-since
#define FD_H2_HDR_LAST_MODIFIED                 -35  // last-modified
#define FD_H2_HDR_LINK                          -36  // link
#define FD_H2_HDR_LOCATION                      -37  // location
#define FD_H2_HDR_MAX_FORWARDS                  -38  // max-forwards
#define FD_H2_HDR_PROXY_AUTHENTICATE            -39  // proxy-authenticate
#define FD_H2_HDR_PROXY_AUTHORIZATION           -40  // proxy-authorization
#define FD_H2_HDR_RANGE                         -41  // range
#define FD_H2_HDR_REFERER                       -42  // referer
#define FD_H2_HDR_REFRESH                       -43  // refresh
#define FD_H2_HDR_RETRY_AFTER                   -44  // retry-after
#define FD_H2_HDR_SERVER                        -45  // server
#define FD_H2_HDR_SET_COOKIE                    -46  // set-cookie
#define FD_H2_HDR_STRICT_TRANSPORT_SECURITY     -47  // strict-transport-security
#define FD_H2_HDR_TRANSFER_ENCODING             -48  // transfer-encoding
#define FD_H2_HDR_USER_AGENT                    -49  // user-agent
#define FD_H2_HDR_VARY                          -50  // vary
#define FD_H2_HDR_VIA                           -51  // via
#define FD_H2_HDR_WWW_AUTHENTICATE              -52  // www-authenticate

// Group 2: Other common
#define FD_H2_SEC_WEBSOCKET_KEY                 -53  // sec-websocket-key
#define FD_H2_SEC_WEBSOCKET_EXTENSIONS          -54  // sec-websocket-extensions
#define FD_H2_SEC_WEBSOCKET_ACCEPT              -55  // sec-websocket-accept
#define FD_H2_SEC_WEBSOCKET_PROTOCOL            -56  // sec-websocket-protocol
#define FD_H2_SEC_WEBSOCKET_VERSION             -57  // sec-websocket-version

#endif /* HEADER_fd_src_waltz_fd_h2_hdr_match_h */

