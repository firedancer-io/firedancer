#include "fd_backtest_shredcap.h"
#include "../../ballet/shred/fd_shred.h"
#include "../../util/net/fd_eth.h"
#include "../../util/net/fd_ip4.h"
#include "../../util/net/fd_udp.h"
#include "../../util/net/fd_pcapng.h"
#include "fd_shredcap.h"
#include <stdio.h>

struct fd_backtest_shredcap_private {
  FILE *             file;
  void *             iter_mem;
  fd_pcapng_iter_t * iter;
  ulong              slot;
  uchar              bank_hash[32];
};

FD_FN_CONST ulong
fd_backtest_shredcap_align( void ) {
  return fd_ulong_max( alignof(fd_backtest_shredcap_t), fd_pcapng_iter_align() );
}

FD_FN_CONST ulong
fd_backtest_shredcap_footprint( void ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_backtest_shredcap_t), sizeof(fd_backtest_shredcap_t) );
  l = FD_LAYOUT_APPEND( l, fd_pcapng_iter_align(),          fd_pcapng_iter_footprint()     );
  return FD_LAYOUT_FINI( l, fd_backtest_shredcap_align() );
}

fd_backtest_shredcap_t *
fd_backtest_shredcap_new( void *       shmem,
                          char const * path ) {
  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_backtest_shredcap_t * db       = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_backtest_shredcap_t), sizeof(fd_backtest_shredcap_t) );
  void *                   iter_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_pcapng_iter_align(),          fd_pcapng_iter_footprint()     );
  FD_SCRATCH_ALLOC_FINI( l, fd_backtest_shredcap_align() );
  memset( db, 0, sizeof(fd_backtest_shredcap_t) );

  FILE * file = fopen( path, "rb" );
  if( FD_UNLIKELY( !file ) ) {
    FD_LOG_WARNING(( "fopen(%s,rb) failed", path ));
    return NULL;
  }

  db->file     = file;
  db->iter_mem = iter_mem;
  db->iter     = NULL;
  return db;
}

void *
fd_backtest_shredcap_delete( fd_backtest_shredcap_t * db ) {
  FD_TEST( db->file );
  if( FD_UNLIKELY( 0!=fclose( db->file ) ) ) FD_LOG_ERR(( "fclose failed" ));
  memset( db, 0, sizeof(fd_backtest_shredcap_t) );
  return (void *)db;
}

#define SEEK_UNTIL( DB, COND )             \
  __extension__({                          \
    fd_pcapng_iter_t * iter = (DB)->iter;  \
    fd_pcapng_frame_t * frame;             \
    for(;;) {                              \
      frame = fd_pcapng_iter_next( iter ); \
      if( !frame ) break;                  \
      if( COND ) break;                    \
    }                                      \
    frame;                                 \
  })

static fd_shredcap_bank_hash_v0_t *
frame_peek_bank_hash( fd_pcapng_frame_t const *    frame,
                      fd_shredcap_bank_hash_v0_t * out ) {
  if( frame->type!=FD_PCAPNG_FRAME_ENHANCED ) return NULL;
  if( !frame->idb ) return NULL;
  fd_pcapng_idb_desc_t const * idb = frame->idb;
  if( idb->link_type!=FD_PCAPNG_LINKTYPE_USER0 ) return NULL;
  if( 0!=strcmp( idb->opts.name, "shredcap0" ) ) return NULL;
  if( frame->data_sz<sizeof(uint)+sizeof(fd_shredcap_bank_hash_v0_t) ) return NULL;
  uint type = FD_LOAD( uint, frame->data );
  if( type!=FD_SHREDCAP_TYPE_BANK_HASH_V0 ) return NULL;
  memcpy( out, frame->data+sizeof(uint), sizeof(fd_shredcap_bank_hash_v0_t) );
  return out;
}

static ulong
frame_peek_root_slot( fd_pcapng_frame_t const * frame ) {
  fd_shredcap_bank_hash_v0_t bh;
  if( !frame_peek_bank_hash( frame, &bh ) ) return ULONG_MAX;
  return bh.slot;
}

void
fd_backtest_shredcap_init( fd_backtest_shredcap_t * db,
                           ulong                    root_slot ) {
  if( FD_UNLIKELY( fseek( db->file, 0L, SEEK_SET )!=0L ) ) {
    FD_LOG_ERR(( "fseek failed" ));
  }
  db->iter = fd_pcapng_iter_new( db->iter_mem, db->file );

  fd_pcapng_iter_next( db->iter );
  SEEK_UNTIL( db, __extension__({
    ulong found = frame_peek_root_slot( frame );
    found!=ULONG_MAX && found>=root_slot;
  }));
}

int
fd_backtest_shredcap_next_root_slot( fd_backtest_shredcap_t * db,
                                     ulong *                  root_slot,
                                     ulong *                  shred_cnt ) {
  fd_pcapng_frame_t const * frame = SEEK_UNTIL( db, (frame_peek_root_slot( frame )!=ULONG_MAX) );
  if( FD_UNLIKELY( !frame ) ) return 0;

  fd_shredcap_bank_hash_v0_t bh;
  if( FD_UNLIKELY( !frame_peek_bank_hash( frame, &bh ) ) ) {
    /* FIXME gracefully skip over unexpected control packets */
    FD_LOG_ERR(( "expected bank_hash frame, found something else" ));
  }

  *root_slot = db->slot = bh.slot;
  *shred_cnt = bh.data_shred_cnt;
  memcpy( db->bank_hash, bh.bank_hash, 32 );
  return 1;
}

static uchar const *
find_ip4_hdr( fd_pcapng_frame_t const * frame,
              ulong *                   psz ) {
  *psz = 0UL;
  if( !frame->idb ) return NULL;

  FD_TEST( frame->type==FD_PCAPNG_FRAME_ENHANCED );
  FD_TEST( frame->idb );
  switch( frame->idb->link_type ) {
  case FD_PCAPNG_LINKTYPE_USER0:
    /* FIXME gracefully skip over unexpected control packets */
    FD_LOG_ERR(( "expected shred, got control frag" ));
  case FD_PCAPNG_LINKTYPE_ETHERNET: {
    FD_TEST( frame->data_sz>=sizeof(fd_eth_hdr_t) );
    fd_eth_hdr_t const * eth_hdr = (fd_eth_hdr_t const *)frame->data;
    FD_TEST( eth_hdr->net_type==fd_ushort_bswap( FD_ETH_HDR_TYPE_IP ) );
    *psz = frame->data_sz - sizeof(fd_eth_hdr_t);
    return frame->data + sizeof(fd_eth_hdr_t);
  }
  case FD_PCAPNG_LINKTYPE_RAW:
  case FD_PCAPNG_LINKTYPE_IPV4:
    *psz = frame->data_sz;
    return frame->data;
  default:
    return NULL;
  }
}

static uchar const *
find_udp_payload( fd_pcapng_frame_t const * frame,
                  ulong *                   psz ) {
  *psz = 0UL;
  ulong ip4_sz;
  uchar const * raw = find_ip4_hdr( frame, &ip4_sz );
  fd_ip4_hdr_t const * ip4 = (fd_ip4_hdr_t const *)raw;
  if( FD_UNLIKELY( !raw ) ) return NULL;
  if( FD_UNLIKELY( ip4_sz<sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t) ) ) return NULL;
  if( FD_UNLIKELY( FD_IP4_GET_VERSION( *ip4 )!=4 ) ) return NULL;
  ulong ip4_hdr_len = FD_IP4_GET_LEN( *ip4 );
  if( FD_UNLIKELY( ip4_sz<ip4_hdr_len+sizeof(fd_udp_hdr_t) ) ) return NULL;
  if( FD_UNLIKELY( ip4->protocol!=FD_IP4_HDR_PROTOCOL_UDP ) ) return NULL;
  *psz = ip4_sz - ip4_hdr_len - sizeof(fd_udp_hdr_t);
  return raw + ip4_hdr_len + sizeof(fd_udp_hdr_t);
}

void const *
fd_backtest_shredcap_shred( fd_backtest_shredcap_t * db,
                            ulong                    slot,
                            ulong                    shred_idx ) {
  fd_pcapng_frame_t const * frame = fd_pcapng_iter_next( db->iter );
  if( FD_UNLIKELY( !frame ) ) return NULL;

  ulong shred_sz = 0UL;
  fd_shred_t const * shred = fd_type_pun_const( find_udp_payload( frame, &shred_sz ) );
  ulong shred_type = fd_shred_type( shred->variant );
  if( FD_UNLIKELY( !shred_sz || !fd_shred_is_data( shred_type ) ) ) FD_LOG_ERR(( "failed to read shred %lu:%lu", slot, shred_idx ));
  if( FD_UNLIKELY( fd_shred_sz( shred )<shred_sz ) ) FD_LOG_ERR(( "corrupt shred %lu:%lu", slot, shred_idx ));
  if( FD_UNLIKELY( shred->slot!=slot ) ) FD_LOG_ERR(( "expected shred slot %lu, got %lu", slot, shred->slot ));
  if( FD_UNLIKELY( shred->idx!=shred_idx ) ) FD_LOG_ERR(( "expected shred idx %lu, got %u", shred_idx, shred->idx ));
  return shred;
}

uchar const *
fd_backtest_shredcap_bank_hash( fd_backtest_shredcap_t * db,
                                ulong                    slot ) {
  FD_TEST( slot==db->slot );
  return db->bank_hash;
}
