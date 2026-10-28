#include "fd_shredcap_trim.h"
#include "fd_backtest_src.h"
#include "fd_libc_zstd.h"
#include "fd_shredcap.h"
#include "../../ballet/shred/fd_shred.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <zstd.h>

/* Compress buf into a new file at path */

static void
write_zstd( char const *  path,
            uchar const * buf,
            ulong         buf_sz ) {
  FILE * out = fopen( path, "wb" );
  if( FD_UNLIKELY( !out ) ) FD_LOG_ERR(( "fopen(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  ZSTD_CCtx * cctx = ZSTD_createCCtx();
  if( FD_UNLIKELY( !cctx ) ) FD_LOG_ERR(( "ZSTD_createCCtx failed" ));
  ZSTD_CCtx_setParameter( cctx, ZSTD_c_compressionLevel, 1 );
  ulong   obuf_sz = ZSTD_CStreamOutSize();
  uchar * obuf    = malloc( obuf_sz );
  if( FD_UNLIKELY( !obuf ) ) FD_LOG_ERR(( "out of memory" ));
  ZSTD_inBuffer src = { buf, buf_sz, 0UL };
  for(;;) {
    ZSTD_outBuffer dst = { obuf, obuf_sz, 0UL };
    ulong ret = ZSTD_compressStream2( cctx, &dst, &src, ZSTD_e_end );
    if( FD_UNLIKELY( ZSTD_isError( ret ) ) ) FD_LOG_ERR(( "ZSTD_compressStream2 failed: %s", ZSTD_getErrorName( ret ) ));
    if( FD_UNLIKELY( fwrite( obuf, 1UL, dst.pos, out )!=dst.pos ) ) FD_LOG_ERR(( "write(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    if( !ret ) break;
  }
  free( obuf );
  ZSTD_freeCCtx( cctx );
  if( FD_UNLIKELY( fclose( out ) ) ) FD_LOG_ERR(( "fclose(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
}

int
fd_shredcap_trim( char const *               in_path,
                  char const *               out_path,
                  ulong                      start_slot,
                  ulong                      end_slot,
                  fd_shredcap_trim_stats_t * stats ) {
  *stats = (fd_shredcap_trim_stats_t){ .first_slot = ULONG_MAX };

  uint fmt = fd_backtest_src_detect( in_path );
  if( FD_UNLIKELY( (fmt&FD_BACKT_SRC_FMT_MASK)!=FD_BACKT_SRC_FMT_PCAPNG ) ) {
    FD_LOG_WARNING(( "%s is not a pcapng shredcap", in_path ));
    return -1;
  }
  FILE * in = fopen( in_path, "rb" );
  if( FD_UNLIKELY( !in ) ) FD_LOG_ERR(( "fopen(%s) failed (%i-%s)", in_path, errno, fd_io_strerror( errno ) ));
  ZSTD_DStream * dstream = NULL;
  if( fmt&FD_BACKT_SRC_FLAG_ZSTD ) {
    dstream = ZSTD_createDStream();
    if( FD_UNLIKELY( !dstream ) ) FD_LOG_ERR(( "ZSTD_createDStream failed" ));
    in = fd_zstd_rstream_open( in, dstream, 128UL<<10 );
    if( FD_UNLIKELY( !in ) ) FD_LOG_ERR(( "fd_zstd_rstream_open(%s) failed", in_path ));
  }
  void * iter_mem = aligned_alloc( fd_pcapng_iter_align(), fd_pcapng_iter_footprint() );
  if( FD_UNLIKELY( !iter_mem ) ) FD_LOG_ERR(( "out of memory" ));
  fd_pcapng_iter_t * iter = fd_pcapng_iter_new( iter_mem, in );
  if( FD_UNLIKELY( !iter ) ) FD_LOG_ERR(( "%s is not a pcapng file", in_path ));

  /* The trimmed capture is built in memory and compressed at the end */
  char * buf    = NULL;
  ulong  buf_sz = 0UL;
  FILE * out = open_memstream( &buf, &buf_sz );
  if( FD_UNLIKELY( !out ) ) FD_LOG_ERR(( "open_memstream failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( !fd_shredcap_fwrite_hdr( out ) ) ) FD_LOG_ERR(( "writing the pcapng header failed" ));

  int   err             = 0;
  ulong start_shred_cnt = 0UL;
  int   start_rooted    = 0;
  ulong shred_slot      = ULONG_MAX;
  ulong prev_slot       = ULONG_MAX;
  int   has_bank_hash   = 1;
  for(;;) {
    fd_pcapng_frame_t const * frame = fd_pcapng_iter_next( iter );
    if( !frame ) {
      /* Error -1 is the end of the file.  The iterator logs the
         others. */
      err = fd_pcapng_iter_err( iter )!=-1;
      break;
    }

    ulong slot;
    uint  type     = 0U;
    int   is_shred = 0;
    if( frame->idb && frame->idb->link_type==FD_PCAPNG_LINKTYPE_USER0 ) {
      /* Records start with a uint type and a ulong slot */
      if( FD_UNLIKELY( frame->data_sz<sizeof(uint)+sizeof(ulong) ) ) continue;
      type = FD_LOAD( uint,  frame->data );
      slot = FD_LOAD( ulong, frame->data+sizeof(uint) );
    } else {
      if( FD_UNLIKELY( !frame->idb || frame->idb->link_type!=FD_PCAPNG_LINKTYPE_IPV4 ) ) {
        FD_LOG_WARNING(( "%s has a shred frame that is not IPv4", in_path ));
        err = 1;
        break;
      }
      ulong payload_sz;
      uchar const * payload = fd_backtest_src_pcap_udp_payload( frame, &payload_sz );
      if( FD_UNLIKELY( !payload ) ) continue;
      fd_shred_t const * shred = fd_shred_parse( payload, payload_sz, FD_SHRED_BLK_MAX );
      if( FD_UNLIKELY( !shred ) ) {
        FD_LOG_WARNING(( "%s has an invalid shred", in_path ));
        err = 1;
        break;
      }
      slot     = shred->slot;
      is_shred = 1;

      /* Slots come in order, so the first shred after end_slot ends
         the copy */
      if( slot>end_slot ) break;
    }
    if( is_shred && stats->first_slot==ULONG_MAX ) stats->first_slot = slot;
    if( is_shred && slot<start_slot ) prev_slot = slot;
    if( slot<start_slot || slot>end_slot ) continue;

    if( FD_UNLIKELY( !fd_pcapng_fwrite_pkt1( out, frame->data, frame->data_sz, NULL, 0UL, is_shred ? 0U : 1U, frame->ts ) ) ) {
      FD_LOG_ERR(( "writing a pcapng frame failed" ));
    }

    stats->last_slot = fd_ulong_max( stats->last_slot, slot );
    if( is_shred ) stats->shred_cnt++;
    if( type==FD_SHREDCAP_TYPE_BANK_HASH_V0 ) stats->bank_hash_cnt++;
    if( slot==start_slot && is_shred ) start_shred_cnt++;
    if( slot==start_slot && type==FD_SHREDCAP_TYPE_ROOT_SLOT_V0 ) start_rooted = 1;

    /* A slot's bank hash record comes after its shreds.  Stop when the
       next slot starts and the current one has no record. */
    if( is_shred && slot!=shred_slot ) {
      if( FD_UNLIKELY( !has_bank_hash ) ) break;
      shred_slot    = slot;
      has_bank_hash = 0;
    }
    if( type==FD_SHREDCAP_TYPE_BANK_HASH_V0 && slot==shred_slot ) has_bank_hash = 1;
  }

  free( fd_pcapng_iter_delete( iter ) );
  fclose( in );
  if( dstream ) ZSTD_freeDStream( dstream );
  if( FD_UNLIKELY( fclose( out ) ) ) FD_LOG_ERR(( "fclose(memstream) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  if( FD_UNLIKELY( !err && !start_shred_cnt ) ) {
    if( prev_slot!=ULONG_MAX ) FD_LOG_WARNING(( "%s has no shreds for slot %lu, the nearest earlier slot with shreds is %lu", in_path, start_slot, prev_slot ));
    else                       FD_LOG_WARNING(( "%s has no shreds for slot %lu", in_path, start_slot ));
    err = 1;
  }
  if( FD_UNLIKELY( !err && !start_rooted ) ) {
    FD_LOG_WARNING(( "%s has no root record for slot %lu", in_path, start_slot ));
    err = 1;
  }
  if( FD_UNLIKELY( !err && !has_bank_hash ) ) {
    FD_LOG_WARNING(( "%s has no bank hash record for slot %lu", in_path, shred_slot ));
    err = 1;
  }
  if( FD_LIKELY( !err ) ) write_zstd( out_path, (uchar const *)buf, buf_sz );
  free( buf );
  return err ? -1 : 0;
}
