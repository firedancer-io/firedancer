#include "fd_backtest_src.h"

#include "fd_libc_zstd.h"

#include "../../util/net/fd_eth.h"
#include "../../util/net/fd_ip4.h"
#include "../../util/net/fd_pcap.h"
#include "../../util/net/fd_pcapng.h"
#include "../../util/net/fd_udp.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#if FD_HAS_ZSTD
#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>
#define FD_BACKT_ZSTD_WINDOW_SZ (1UL<<21UL)
#endif

extern fd_backt_src_vt_t const fd_backt_src_pcap_vt;

#define FD_BACKT_SRC_FMT_PCAP    0x02u
#define FD_BACKT_SRC_FMT_PCAPNG  0x03u
#define FD_BACKT_SRC_FLAG_ZSTD   0x08u


struct fd_backt_src_pcap {
  fd_backt_src_t src[1];

  FILE * file;
  uint   format;

  union {
    fd_pcap_iter_t *   pcap;
    fd_pcapng_iter_t * pcapng;
  } iter;

  void * iter_mem;

#if FD_HAS_ZSTD
  ZSTD_DStream * zstd;
#endif
};

typedef struct fd_backt_src_pcap fd_backt_src_pcap_t;

static uchar const *
find_ip4_hdr( uchar const * pkt,
              ulong         pkt_sz,
              uint          format,
              ulong *       ip4_sz ) {
  *ip4_sz = 0UL;

  if( format==FD_BACKT_SRC_FMT_PCAPNG ) {
    fd_pcapng_frame_t const * frame = (fd_pcapng_frame_t const *)pkt;
    if( FD_UNLIKELY( !frame->idb ) ) return NULL;

    switch( frame->idb->link_type ) {
    case FD_PCAPNG_LINKTYPE_USER0:
      return NULL;
    case FD_PCAPNG_LINKTYPE_ETHERNET: {
      if( FD_UNLIKELY( frame->data_sz<sizeof(fd_eth_hdr_t) ) ) return NULL;
      fd_eth_hdr_t const * eth = (fd_eth_hdr_t const *)frame->data;
      if( FD_UNLIKELY( eth->net_type!=fd_ushort_bswap( FD_ETH_HDR_TYPE_IP ) ) ) return NULL;
      *ip4_sz = frame->data_sz - sizeof(fd_eth_hdr_t);
      return frame->data + sizeof(fd_eth_hdr_t);
    }
    case FD_PCAPNG_LINKTYPE_RAW:
    case FD_PCAPNG_LINKTYPE_IPV4:
      *ip4_sz = frame->data_sz;
      return frame->data;
    default:
      return NULL;
    }
  }

  if( FD_UNLIKELY( pkt_sz<sizeof(fd_eth_hdr_t) ) ) return NULL;
  fd_eth_hdr_t const * eth = (fd_eth_hdr_t const *)pkt;
  if( FD_UNLIKELY( eth->net_type!=fd_ushort_bswap( FD_ETH_HDR_TYPE_IP ) ) ) return NULL;
  *ip4_sz = pkt_sz - sizeof(fd_eth_hdr_t);
  return pkt + sizeof(fd_eth_hdr_t);
}

static uchar const *
find_udp_payload( uchar const * pkt,
                  ulong         pkt_sz,
                  uint          format,
                  ulong *       payload_sz ) {
  *payload_sz = 0UL;

  ulong ip4_sz = 0UL;
  uchar const * raw = find_ip4_hdr( pkt, pkt_sz, format, &ip4_sz );
  if( FD_UNLIKELY( !raw ) ) return NULL;
  if( FD_UNLIKELY( ip4_sz<sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t) ) ) return NULL;

  fd_ip4_hdr_t const * ip4 = (fd_ip4_hdr_t const *)raw;
  if( FD_UNLIKELY( FD_IP4_GET_VERSION( *ip4 )!=4 ) ) return NULL;

  ulong ip4_hdr_len = FD_IP4_GET_LEN( *ip4 );
  if( FD_UNLIKELY( ip4_hdr_len<sizeof(fd_ip4_hdr_t) ) ) return NULL;
  if( FD_UNLIKELY( ip4_sz<ip4_hdr_len+sizeof(fd_udp_hdr_t) ) ) return NULL;
  if( FD_UNLIKELY( ip4->protocol!=FD_IP4_HDR_PROTOCOL_UDP ) ) return NULL;

  *payload_sz = ip4_sz - ip4_hdr_len - sizeof(fd_udp_hdr_t);
  return raw + ip4_hdr_len + sizeof(fd_udp_hdr_t);
}

static ulong
peek_first_shred_from_file( FILE * file,
                            uint   format,
                            uchar *buf,
                            ulong  buf_sz ) {
  if( FD_UNLIKELY( fseek( file, 0L, SEEK_SET ) ) ) {
    FD_LOG_WARNING(( "fseek failed" ));
    return 0UL;
  }

  if( format==FD_BACKT_SRC_FMT_PCAP ) {
    fd_pcap_iter_t * iter = fd_pcap_iter_new( file );
    if( FD_UNLIKELY( !iter ) ) {
      FD_LOG_WARNING(( "fd_pcap_iter_new failed" ));
      return 0UL;
    }

    uchar pkt[ FD_TPU_MTU ];
    long  ts = 0L;
    ulong pkt_sz;
    while( !!( pkt_sz = fd_pcap_iter_next( iter, pkt, sizeof(pkt), &ts ) ) ) {
      ulong shred_sz = 0UL;
      uchar const * shred = find_udp_payload( pkt, pkt_sz, format, &shred_sz );
      if( FD_UNLIKELY( !shred ) ) continue;
      if( FD_UNLIKELY( shred_sz>buf_sz ) ) {
        FD_LOG_WARNING(( "first shred does not fit buffer (sz=%lu buf_sz=%lu)", shred_sz, buf_sz ));
        fd_pcap_iter_delete( iter );
        return 0UL;
      }
      fd_memcpy( buf, shred, shred_sz );
      fd_pcap_iter_delete( iter );
      return shred_sz;
    }

    fd_pcap_iter_delete( iter );
    FD_LOG_WARNING(( "pcap does not contain any shreds" ));
    return 0UL;
  }

  void * iter_mem = aligned_alloc( fd_pcapng_iter_align(), fd_pcapng_iter_footprint() );
  if( FD_UNLIKELY( !iter_mem ) ) FD_LOG_ERR(( "out of memory" ));

  fd_pcapng_iter_t * iter = fd_pcapng_iter_new( iter_mem, file );
  if( FD_UNLIKELY( !iter ) ) {
    free( iter_mem );
    FD_LOG_WARNING(( "fd_pcapng_iter_new failed" ));
    return 0UL;
  }

  for(;;) {
    fd_pcapng_frame_t const * frame = fd_pcapng_iter_next( iter );
    if( FD_UNLIKELY( !frame ) ) break;

    ulong shred_sz = 0UL;
    uchar const * shred = find_udp_payload( (uchar const *)frame, 0UL, format, &shred_sz );
    if( FD_UNLIKELY( !shred ) ) continue;
    if( FD_UNLIKELY( shred_sz>buf_sz ) ) {
      FD_LOG_WARNING(( "first shred does not fit buffer (sz=%lu buf_sz=%lu)", shred_sz, buf_sz ));
      free( fd_pcapng_iter_delete( iter ) );
      return 0UL;
    }
    fd_memcpy( buf, shred, shred_sz );
    free( fd_pcapng_iter_delete( iter ) );
    return shred_sz;
  }

  free( fd_pcapng_iter_delete( iter ) );
  FD_LOG_WARNING(( "pcapng does not contain any shreds" ));
  return 0UL;
}

static void
fd_backt_src_pcap_fini_iter( fd_backt_src_pcap_t * src ) {
  if( src->format==FD_BACKT_SRC_FMT_PCAP ) {
    if( src->iter.pcap ) src->file = fd_pcap_iter_delete( src->iter.pcap );
    src->iter.pcap = NULL;
    return;
  }

  if( src->iter.pcapng ) fd_pcapng_iter_delete( src->iter.pcapng );
  src->iter.pcapng = NULL;
}

static int
fd_backt_src_pcap_rewind( fd_backt_src_pcap_t * src ) {
  fd_backt_src_pcap_fini_iter( src );

#if FD_HAS_ZSTD
  if( FD_UNLIKELY( src->zstd ) ) {
    if( FD_UNLIKELY( fseek( src->file, 0L, SEEK_SET ) ) ) {
      FD_LOG_WARNING(( "fseek failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      return 0;
    }
    ZSTD_initDStream( src->zstd );
  }
#endif

  if( src->format==FD_BACKT_SRC_FMT_PCAP ) {
    if( FD_UNLIKELY( fseek( src->file, 0L, SEEK_SET ) ) ) {
      FD_LOG_WARNING(( "fseek failed" ));
      return 0;
    }

    src->iter.pcap = fd_pcap_iter_new( src->file );
    if( FD_UNLIKELY( !src->iter.pcap ) ) {
      FD_LOG_WARNING(( "fd_pcap_iter_new failed" ));
      return 0;
    }

    return 1;
  }

  if( FD_UNLIKELY( fseek( src->file, 0L, SEEK_SET ) ) ) {
    FD_LOG_WARNING(( "fseek failed" ));
    return 0;
  }

  src->iter.pcapng = fd_pcapng_iter_new( src->iter_mem, src->file );
  if( FD_UNLIKELY( !src->iter.pcapng ) ) {
    FD_LOG_WARNING(( "fd_pcapng_iter_new failed" ));
    return 0;
  }

  return 1;
}

fd_backt_src_t *
fd_backt_src_pcap_create( fd_backtest_src_opts_t const * opts,
                          uint                          format,
                          uint                          flags ) {
  (void)flags;
  FILE * file = fopen( opts->path, "rb" );
  if( FD_UNLIKELY( !file ) ) {
    FD_LOG_WARNING(( "fopen(%s,rb) failed", opts->path ));
    return NULL;
  }

#if FD_HAS_ZSTD
  ZSTD_DStream * zstd = NULL;
  if( flags & FD_BACKT_SRC_FLAG_ZSTD ) {
    zstd = ZSTD_createDStream();
    if( FD_UNLIKELY( !zstd ) ) FD_LOG_ERR(( "ZSTD_createDStream failed" ));
    FILE * zstd_file = fd_zstd_rstream_open( file, zstd, 128UL<<10 );
    if( FD_UNLIKELY( !zstd_file ) ) {
      FD_LOG_WARNING(( "fd_zstd_rstream_open(%s) failed", opts->path ));
      ZSTD_freeDStream( zstd );
      fclose( file );
      return NULL;
    }
    file = zstd_file;
  }
#endif

  fd_backt_src_pcap_t * src = calloc( 1UL, sizeof(fd_backt_src_pcap_t) );
  if( FD_UNLIKELY( !src ) ) FD_LOG_ERR(( "out of memory" ));

  *src = (fd_backt_src_pcap_t){
    .src = {{ .vt = &fd_backt_src_pcap_vt }},
    .file = file,
    .format = format,
#if FD_HAS_ZSTD
    .zstd = zstd,
#endif
  };

  if( format==FD_BACKT_SRC_FMT_PCAP ) {
    src->iter.pcap = fd_pcap_iter_new( file );
    if( FD_UNLIKELY( !src->iter.pcap ) ) {
      fd_backt_src_pcap_vt.destroy( src->src );
      FD_LOG_WARNING(( "fd_pcap_iter_new failed" ));
      return NULL;
    }
  } else {
    src->iter_mem = aligned_alloc( fd_pcapng_iter_align(), fd_pcapng_iter_footprint() );
    if( FD_UNLIKELY( !src->iter_mem ) ) FD_LOG_ERR(( "out of memory" ));
    src->iter.pcapng = fd_pcapng_iter_new( src->iter_mem, file );
    if( FD_UNLIKELY( !src->iter.pcapng ) ) {
      fd_backt_src_pcap_vt.destroy( src->src );
      FD_LOG_WARNING(( "fd_pcapng_iter_new failed" ));
      return NULL;
    }
  }

  return src->src;
}

void
fd_backt_src_pcap_destroy( fd_backt_src_t * this ) {
  if( FD_UNLIKELY( !this ) ) return;
  fd_backt_src_pcap_t * src = (fd_backt_src_pcap_t *)this;

  fd_backt_src_pcap_fini_iter( src );

  free( src->iter_mem );

  if( src->file ) fclose( src->file );

#if FD_HAS_ZSTD
  if( src->zstd ) ZSTD_freeDStream( src->zstd );
#endif

  free( src );
}

ulong
fd_backt_src_pcap_first_shred( fd_backt_src_t * this,
                               uchar *          buf,
                               ulong            buf_sz ) {
  fd_backt_src_pcap_t * src = (fd_backt_src_pcap_t *)this;

  ulong shred_sz = peek_first_shred_from_file( src->file, src->format, buf, buf_sz );
  if( FD_UNLIKELY( !fd_backt_src_pcap_rewind( src ) ) ) return 0UL;
  return shred_sz;
}

ulong
fd_backt_src_pcap_shred( fd_backt_src_t * this,
                         uchar *          buf,
                         ulong            buf_sz ) {
  fd_backt_src_pcap_t * src = (fd_backt_src_pcap_t *)this;

  if( src->format==FD_BACKT_SRC_FMT_PCAP ) {
    uchar pkt[ FD_TPU_MTU ];
    long  ts = 0L;

    for(;;) {
      ulong pkt_sz = fd_pcap_iter_next( src->iter.pcap, pkt, sizeof(pkt), &ts );
      if( FD_UNLIKELY( !pkt_sz ) ) return ULONG_MAX;

      ulong shred_sz = 0UL;
      uchar const * shred = find_udp_payload( pkt, pkt_sz, src->format, &shred_sz );
      if( FD_UNLIKELY( !shred ) ) continue;
      if( FD_UNLIKELY( shred_sz>buf_sz ) ) {
        FD_LOG_WARNING(( "shred does not fit buffer (sz=%lu buf_sz=%lu)", shred_sz, buf_sz ));
        return ULONG_MAX;
      }

      fd_memcpy( buf, shred, shred_sz );
      return shred_sz;
    }
  }

  for(;;) {
    fd_pcapng_frame_t const * frame = fd_pcapng_iter_next( src->iter.pcapng );
    if( FD_UNLIKELY( !frame ) ) return ULONG_MAX;

    ulong shred_sz = 0UL;
    uchar const * shred = find_udp_payload( (uchar const *)frame, 0UL, src->format, &shred_sz );
    if( FD_UNLIKELY( !shred ) ) continue;
    if( FD_UNLIKELY( shred_sz>buf_sz ) ) {
      FD_LOG_WARNING(( "shred does not fit buffer (sz=%lu buf_sz=%lu)", shred_sz, buf_sz ));
      return ULONG_MAX;
    }

    fd_memcpy( buf, shred, shred_sz );
    return shred_sz;
  }
}

fd_backt_slot_info_t *
fd_backt_src_pcap_slot_info( fd_backt_src_t *       this,
                             fd_backt_slot_info_t * out,
                             ulong                  slot ) {
  fd_backt_src_pcap_t * src = (fd_backt_src_pcap_t *)this;
  (void)src;

  fd_memset( out, 0, sizeof(fd_backt_slot_info_t) );
  out->slot = slot;
  return out;
}

fd_backt_src_vt_t const fd_backt_src_pcap_vt = {
  .destroy     = fd_backt_src_pcap_destroy,
  .first_shred = fd_backt_src_pcap_first_shred,
  .shred       = fd_backt_src_pcap_shred,
  .slot_info   = fd_backt_src_pcap_slot_info
};
