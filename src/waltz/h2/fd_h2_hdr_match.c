#include "fd_h2_hdr_match.h"
#include "fd_hpack_private.h"

FD_TL ulong fd_h2_hdr_match_seed;

fd_h2_hdr_match_entry_t const fd_h2_hdr_match_entry_null = {0};

static fd_h2_hdr_match_entry_t *
fd_h2_hdr_matcher_insert1( fd_h2_hdr_match_entry_t * map,
                           int                       id,
                           char const *              name, /* static lifetime */
                           ulong                     name_len ) {
  fd_h2_hdr_match_key_t key = { .hdr=name, .hdr_len=(ushort)name_len };
  fd_h2_hdr_match_entry_t * entry = fd_h2_hdr_map_insert( map, key );
  if( FD_UNLIKELY( !entry ) ) return NULL;
  entry->id = (short)id;
  return entry;
}

fd_h2_hdr_matcher_t *
fd_h2_hdr_matcher_init( void * mem,
                        ulong  seed ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, alignof(fd_h2_hdr_matcher_t) ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_h2_hdr_matcher_t * matcher = mem;
  if( FD_UNLIKELY( !fd_h2_hdr_map_join( fd_h2_hdr_map_new( matcher->entry ) ) ) ) {
    return NULL;
  }
  fd_h2_hdr_match_entry_t * map = matcher->entry;
  matcher->seed      = seed;
  matcher->entry_cnt = 0UL;

  fd_h2_hdr_match_seed = seed;

  int last_header_id = 0;
  for( ulong i=1UL; i<=61; i++ ) {
    int header_id = (int)fd_h2_hpack_matcher[ i ];
    if( last_header_id==header_id ) continue;
    char const * name     = fd_hpack_static_table[ i ].entry;
    ulong        name_len = fd_hpack_static_table[ i ].name_len;
    fd_h2_hdr_matcher_insert1( map, header_id, name, name_len );
    last_header_id = header_id;
  }
  fd_h2_hdr_matcher_insert1( map, FD_H2_SEC_WEBSOCKET_KEY,        "sec-websocket-key",        17UL );
  fd_h2_hdr_matcher_insert1( map, FD_H2_SEC_WEBSOCKET_EXTENSIONS, "sec-websocket-extensions", 25UL );
  fd_h2_hdr_matcher_insert1( map, FD_H2_SEC_WEBSOCKET_PROTOCOL,   "sec-websocket-protocol",   22UL );
  fd_h2_hdr_matcher_insert1( map, FD_H2_SEC_WEBSOCKET_ACCEPT,     "sec-websocket-accept",     20UL );
  fd_h2_hdr_matcher_insert1( map, FD_H2_SEC_WEBSOCKET_VERSION,    "sec-websocket-version",    21UL );

  /* matcher->entry_cnt still 0, which is deliberate */
  return matcher;
}

void *
fd_h2_hdr_matcher_fini( fd_h2_hdr_matcher_t * matcher ) {
  return matcher;
}

void
fd_h2_hdr_matcher_insert( fd_h2_hdr_matcher_t * matcher,
                          int                   id,
                          char const *          name, /* static lifetime */
                          ulong                 name_len ) {
  if( FD_UNLIKELY( id<1 || id>SHORT_MAX ) ) {
    FD_LOG_ERR(( "id %d out of bounds", id ));
  }
  if( FD_UNLIKELY( matcher->entry_cnt>=FD_H2_HDR_MATCH_MAX ) ) {
    FD_LOG_ERR(( "too many header entries (%lu)", matcher->entry_cnt ));
  }
  if( FD_UNLIKELY( name_len==0 || name_len>USHORT_MAX ) ) {
    FD_LOG_ERR(( "invalid name_len: %lu", name_len ));
  }
  fd_h2_hdr_match_seed = matcher->seed;
  if( FD_UNLIKELY( !fd_h2_hdr_matcher_insert1( matcher->entry, id, name, name_len ) ) ) return;
  matcher->entry_cnt++;
}

schar const __attribute__((aligned(16)))
fd_h2_hpack_matcher[ 62 ] = {
  [  1 ] = FD_H2_HDR_AUTHORITY,
  [  2 ] = FD_H2_HDR_METHOD,
  [  3 ] = FD_H2_HDR_METHOD,
  [  4 ] = FD_H2_HDR_PATH,
  [  5 ] = FD_H2_HDR_PATH,
  [  6 ] = FD_H2_HDR_SCHEME,
  [  7 ] = FD_H2_HDR_SCHEME,
  [  8 ] = FD_H2_HDR_STATUS,
  [  9 ] = FD_H2_HDR_STATUS,
  [ 10 ] = FD_H2_HDR_STATUS,
  [ 11 ] = FD_H2_HDR_STATUS,
  [ 12 ] = FD_H2_HDR_STATUS,
  [ 13 ] = FD_H2_HDR_STATUS,
  [ 14 ] = FD_H2_HDR_STATUS,
  [ 15 ] = FD_H2_HDR_ACCEPT_CHARSET,
  [ 16 ] = FD_H2_HDR_ACCEPT_ENCODING,
  [ 17 ] = FD_H2_HDR_ACCEPT_LANGUAGE,
  [ 18 ] = FD_H2_HDR_ACCEPT_RANGES,
  [ 19 ] = FD_H2_HDR_ACCEPT,
  [ 20 ] = FD_H2_HDR_ACCESS_CONTROL_ALLOW_ORIGIN,
  [ 21 ] = FD_H2_HDR_AGE,
  [ 22 ] = FD_H2_HDR_ALLOW,
  [ 23 ] = FD_H2_HDR_AUTHORIZATION,
  [ 24 ] = FD_H2_HDR_CACHE_CONTROL,
  [ 25 ] = FD_H2_HDR_CONTENT_DISPOSITION,
  [ 26 ] = FD_H2_HDR_CONTENT_ENCODING,
  [ 27 ] = FD_H2_HDR_CONTENT_LANGUAGE,
  [ 28 ] = FD_H2_HDR_CONTENT_LENGTH,
  [ 29 ] = FD_H2_HDR_CONTENT_LOCATION,
  [ 30 ] = FD_H2_HDR_CONTENT_RANGE,
  [ 31 ] = FD_H2_HDR_CONTENT_TYPE,
  [ 32 ] = FD_H2_HDR_COOKIE,
  [ 33 ] = FD_H2_HDR_DATE,
  [ 34 ] = FD_H2_HDR_ETAG,
  [ 35 ] = FD_H2_HDR_EXPECT,
  [ 36 ] = FD_H2_HDR_EXPIRES,
  [ 37 ] = FD_H2_HDR_FROM,
  [ 38 ] = FD_H2_HDR_HOST,
  [ 39 ] = FD_H2_HDR_IF_MATCH,
  [ 40 ] = FD_H2_HDR_IF_MODIFIED_SINCE,
  [ 41 ] = FD_H2_HDR_IF_NONE_MATCH,
  [ 42 ] = FD_H2_HDR_IF_RANGE,
  [ 43 ] = FD_H2_HDR_IF_UNMODIFIED_SINCE,
  [ 44 ] = FD_H2_HDR_LAST_MODIFIED,
  [ 45 ] = FD_H2_HDR_LINK,
  [ 46 ] = FD_H2_HDR_LOCATION,
  [ 47 ] = FD_H2_HDR_MAX_FORWARDS,
  [ 48 ] = FD_H2_HDR_PROXY_AUTHENTICATE,
  [ 49 ] = FD_H2_HDR_PROXY_AUTHORIZATION,
  [ 50 ] = FD_H2_HDR_RANGE,
  [ 51 ] = FD_H2_HDR_REFERER,
  [ 52 ] = FD_H2_HDR_REFRESH,
  [ 53 ] = FD_H2_HDR_RETRY_AFTER,
  [ 54 ] = FD_H2_HDR_SERVER,
  [ 55 ] = FD_H2_HDR_SET_COOKIE,
  [ 56 ] = FD_H2_HDR_STRICT_TRANSPORT_SECURITY,
  [ 57 ] = FD_H2_HDR_TRANSFER_ENCODING,
  [ 58 ] = FD_H2_HDR_USER_AGENT,
  [ 59 ] = FD_H2_HDR_VARY,
  [ 60 ] = FD_H2_HDR_VIA,
  [ 61 ] = FD_H2_HDR_WWW_AUTHENTICATE
};
