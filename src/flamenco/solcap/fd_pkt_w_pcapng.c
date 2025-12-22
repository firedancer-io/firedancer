#include "fd_pkt_w_pcapng.h"
#include "../../util/fd_util_base.h"
#include "../../util/net/fd_pcapng_private.h"
#include "../../util/net/fd_ip4.h"
#include <errno.h>
#include <stddef.h>
#include <unistd.h>

void
fd_pkt_w_pcapng_fini( void * self_ ) {
  fd_pkt_w_pcapng_t * w = (fd_pkt_w_pcapng_t *)self_;
  if( FD_UNLIKELY( 0!=fclose( w->file ) ) ) {
    FD_LOG_WARNING(( "fclose failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    w->io_errno = errno;
  }
}

int
fd_pkt_w_pcapng_write( FILE *        file,
                       uchar const * buf,
                       ulong         sz,
                       long          ts ) {
  ulong payload_sz = sizeof(uint) + sizeof(fd_ip4_hdr_t) + sz;
  ulong block_sz   = fd_ulong_align_up( sizeof(fd_pcapng_epb_t)+payload_sz, 4UL ) + 4UL;

  /* Write header */

  struct __attribute__((packed)) {
    fd_pcapng_epb_t epb;
    uint            l3_type;  /* host order */
    fd_ip4_hdr_t    ip4;
  } header = {
    .epb = {
      .block_type = FD_PCAPNG_BLOCK_TYPE_EPB,
      .block_sz   = (uint)block_sz,
      .if_idx     = 0,
      .ts_hi      = (uint)( (ulong)ts >> 32UL ),
      .ts_lo      = (uint)( (ulong)ts         ),
      .cap_len    = (uint)payload_sz,
      .orig_len   = (uint)payload_sz
    },
    .l3_type = 2U, /* IPv4 */
    .ip4 = {
      .verihl       = FD_IP4_VERIHL( 4, 5 ),
      .tos          = 0,
      .net_tot_len  = fd_ushort_bswap( (ushort)( 20+sz ) ),
      .net_id       = 0,
      .net_frag_off = fd_ushort_bswap( FD_IP4_HDR_FRAG_OFF_DF ),
      .ttl          = 64,
      .protocol     = FD_IP4_HDR_PROTOCOL_UDP,
      .check        = 0,
      .saddr        = FD_IP4_ADDR( 127,0,0,1 ),
      .daddr        = FD_IP4_ADDR( 127,0,0,1 ),
    }
  };
  header.ip4.check = fd_ip4_hdr_check_fast( &header.ip4 );
  FD_STATIC_ASSERT( offsetof( __typeof__(header), epb     )== 0, layout );
  FD_STATIC_ASSERT( offsetof( __typeof__(header), l3_type )==28, layout );
  FD_STATIC_ASSERT( offsetof( __typeof__(header), ip4     )==32, layout );
  FD_STATIC_ASSERT( sizeof  ( __typeof__(header)          )==52, layout );

  if( FD_UNLIKELY( 1UL!=fwrite( &header, sizeof(header), 1UL, file ) ) ) {
    return errno;
  }

  /* Write payload */

  if( FD_UNLIKELY( 1UL!=fwrite( buf, sz, 1UL, file ) ) ) {
    return errno;
  }

  /* Write trailer */

  struct __attribute__((packed)) {
    uchar pad[4];
    uint  block_sz;
  } trailer = {
    .pad      = {0},
    .block_sz = (uint)block_sz
  };
  if( FD_UNLIKELY( 1UL!=fwrite( &trailer, sizeof(trailer), 1UL, file ) ) ) {
    return errno;
  }

  return 0;
}

void
fd_pkt_w_pcapng_post( void *  self_,
                      ulong   sz ) {
  fd_pkt_w_pcapng_t * w   = (fd_pkt_w_pcapng_t *)self_;
  void const *        buf = fd_chunk_to_laddr( w->base.base, w->base.chunk );

  int err = fd_pkt_w_pcapng_write( w->file, buf, sz, fd_log_wallclock() );
  if( FD_UNLIKELY( err ) ) w->io_errno = err;
}

void
fd_pkt_w_pcapng_flush( void * self_ ) {
  fd_pkt_w_pcapng_t * w = (fd_pkt_w_pcapng_t *)self_;
  if( FD_UNLIKELY( 0!=fflush( w->file ) ) ) {
    FD_LOG_WARNING(( "fflush failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    w->io_errno = errno;
  }
}

static fd_pkt_writer_vt_t const fd_pkt_w_pcapng_vt = {
  .fini  = fd_pkt_w_pcapng_fini,
  .post  = fd_pkt_w_pcapng_post,
  .flush = fd_pkt_w_pcapng_flush
};

fd_pkt_writer_t *
fd_pkt_w_pcapng_new( fd_pkt_w_pcapng_t * w,
                     int                 pcapng_fd,
                     uchar *             dcache,
                     ulong               mtu ) {
  FILE * file = fdopen( pcapng_fd, "wb" );
  if( FD_UNLIKELY( !file ) ) {
    FD_LOG_WARNING(( "fdopen(fd=%d) on pcapng_fd failed (%i-%s)", pcapng_fd, errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( 0!=close( pcapng_fd ) ) ) {
      FD_LOG_WARNING(( "close(fd=%d) on pcapng_fd failed (%i-%s)", pcapng_fd, errno, fd_io_strerror( errno ) ));
    }
    return NULL;
  }

  *w = (fd_pkt_w_pcapng_t) {
    .base = {
      .vt     = &fd_pkt_w_pcapng_vt,
      .mtu    = mtu,
      .quota  = 0UL,
      .base   = dcache,
      .chunk0 = fd_dcache_compact_chunk0( dcache, dcache ),
      .wmark  = fd_dcache_compact_wmark ( dcache, dcache, mtu ),
      .chunk  = fd_dcache_compact_chunk0( dcache, dcache )
    },
    .file     = file,
    .io_errno = 0
  };

  fd_pcapng_shb_opts_t shb_opts;
  fd_pcapng_shb_defaults( &shb_opts );
  if( FD_UNLIKELY( !fd_pcapng_fwrite_shb( &shb_opts, file ) ) ) goto fail;

  fd_pcapng_idb_opts_t idb_opts = {
    .name = "eth0"
  };
  if( FD_UNLIKELY( !fd_pcapng_fwrite_idb( FD_PCAPNG_LINKTYPE_NULL, &idb_opts, file ) ) ) goto fail;

  return &w->base;

fail:
  FD_LOG_WARNING(( "failed to write pcapng header" ));  /* FIXME log errno */
  if( FD_UNLIKELY( 0!=fclose( file ) ) ) {
    FD_LOG_WARNING(( "fclose(pcapng_file) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  return NULL;
}
