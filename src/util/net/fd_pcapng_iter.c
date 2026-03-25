#include "fd_pcapng_private.h"
#include "../fd_util.h"
#include <errno.h>
#include <stdio.h>

FD_FN_CONST ulong
fd_pcapng_iter_align( void ) {
  return alignof(fd_pcapng_iter_t);
}

FD_FN_CONST ulong
fd_pcapng_iter_footprint( void ) {
  return sizeof(fd_pcapng_iter_t);
}

static char const *
fd_pcapng_iter_strerror( int    error,
                         FILE * file ) {
  static FD_TL char err_cstr_buf[ 1024UL ];
  char * err_cstr = fd_cstr_init( err_cstr_buf );
  if( error==EPROTO ) {
    return fd_cstr_printf( err_cstr, sizeof(err_cstr_buf), NULL, "parse error at %#lx", (ulong)ftell(file) );
  } else if( error==-1 && !feof( file ) ) {
    return "end of section";
  } else {
    return fd_cstr_printf( err_cstr, sizeof(err_cstr_buf), NULL, "%i-%s", error, fd_io_strerror( error ) );
  }
}

static int
fd_pcapng_read_block( FILE *                  stream,
                      fd_pcapng_iter_t *      iter,
                      fd_pcapng_block_hdr_t * _hdr ) {

  /* Remember offset of block */
  long pos = ftell( stream );
  if( FD_UNLIKELY( pos<0L ) )
    return ferror( stream );
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)pos, 4U ) ) ) {
    FD_LOG_DEBUG(( "pcapng: misaligned stream at %#lx", (ulong)pos ));
    return EPROTO;
  }

  /* Read header */
  fd_pcapng_block_hdr_t hdr;
  if( FD_UNLIKELY( 1UL!=fread( &hdr, sizeof(fd_pcapng_block_hdr_t), 1, stream ) ) ) {
    if( FD_LIKELY( feof( stream ) ) ) return -1; /* eof */
    else                              return ferror( stream );
  }

  /* Coherence check length field */
  if( FD_UNLIKELY( (hdr.block_sz <   12U) /* header and footer are mandatory */
                 | (hdr.block_sz >32768U) /* way too large */
                 | (!fd_ulong_is_aligned( hdr.block_sz, 4U )) ) ) {
    FD_LOG_DEBUG(( "pcapng: block with invalid size %#x at %#lx", hdr.block_sz, (ulong)pos ));
    return EPROTO;
  }

  if( FD_UNLIKELY( hdr.block_sz>FD_PCAPNG_BLOCK_SZ ) ) {
    FD_LOG_DEBUG(( "pcapng: block too large for buffer (%#x)", hdr.block_sz ));
    return EPROTO;
  }

  memcpy( iter->block_buf, &hdr, sizeof(fd_pcapng_block_hdr_t) );
  ulong remaining = hdr.block_sz - sizeof(fd_pcapng_block_hdr_t);

  /* Read rest of block */
  if( FD_UNLIKELY( 1UL!=fread( iter->block_buf + sizeof(fd_pcapng_block_hdr_t), remaining, 1, stream ) ) )
    return ferror( stream );

  iter->block_buf_sz  = hdr.block_sz;
  iter->block_buf_pos = sizeof(fd_pcapng_block_hdr_t);

  /* Verify footer */
  uint * footer = (uint *)( iter->block_buf + hdr.block_sz - sizeof(uint) );
  uint block_sz = *footer;

  /* Check that header and footer match */
  if( FD_UNLIKELY( hdr.block_sz != block_sz ) ) {
    FD_LOG_DEBUG(( "pcapng: block size in header and footer don't match at %#lx", (ulong)pos ));
    return EPROTO;
  }

  *_hdr = hdr;

  return 0; /* success */
}

static int
fd_pcapng_read_option( fd_pcapng_iter_t *   iter,
                       fd_pcapng_option_t * opt ) {

  if( FD_UNLIKELY( iter->block_buf_pos + 4UL > iter->block_buf_sz ) ) {
    opt->type  = 0;
    opt->sz    = 0;
    opt->value = NULL;
    return 0;
  }

  struct __attribute__((packed)) {
    ushort type;
    ushort sz;
  } opt_hdr;
  memcpy( &opt_hdr, iter->block_buf + iter->block_buf_pos, 4UL );
  iter->block_buf_pos += 4UL;
  if( FD_UNLIKELY( opt_hdr.sz > (iter->block_buf_sz - iter->block_buf_pos) ) ) {
    iter->error = EPROTO;
    FD_LOG_WARNING(( "option size out of bounds" ));
    return EPROTO;
  }

  uint read_sz = fd_uint_min( opt_hdr.sz, opt->sz );
  opt->type = opt_hdr.type;
  opt->sz   = (ushort)read_sz;

  if( read_sz ) {
    if( FD_UNLIKELY( iter->block_buf_pos + read_sz > iter->block_buf_sz ) ) {
    iter->error = EPROTO;
      FD_LOG_WARNING(( "out of bounds option" ));
      return EPROTO;
    }
    memcpy( opt->value, iter->block_buf + iter->block_buf_pos, read_sz );
  }

  iter->block_buf_pos += fd_uint_align_up( opt_hdr.sz, 4U );
  if( FD_UNLIKELY( iter->block_buf_pos > iter->block_buf_sz ) )
    return EPROTO;

  return 0; /* success */
}

fd_pcapng_iter_t *
fd_pcapng_iter_new( void * mem,
                    void * _file ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, alignof(fd_pcapng_iter_t) ) ) ) {
    FD_LOG_WARNING(( "unaligned mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !_file ) ) {
    FD_LOG_WARNING(( "NULL file" ));
    return NULL;
  }

  FILE * file = (FILE *)_file;

  memset( mem, 0, sizeof(fd_pcapng_iter_t) );
  fd_pcapng_iter_t * iter = (fd_pcapng_iter_t *)mem;
  iter->stream = (FILE *)file;
  iter->empty  = 1;

  /* File starts with a Section Header Block */

  fd_pcapng_block_hdr_t shb_hdr;
  int err = fd_pcapng_read_block( file, iter, &shb_hdr );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "pcapng: SHB read failed (%s)", fd_pcapng_iter_strerror( err, file ) ));
    return NULL;
  }
  if( FD_UNLIKELY( shb_hdr.block_type!=FD_PCAPNG_BLOCK_TYPE_SHB
                || shb_hdr.block_sz  < sizeof(fd_pcapng_shb_t)  ) ) {
    FD_LOG_WARNING(( "pcapng: not a valid Section Header Block" ));
    return NULL;
  }


  fd_pcapng_shb_t shb = FD_LOAD( fd_pcapng_shb_t, iter->block_buf );
  if( FD_UNLIKELY( (shb.version_major!=1) | (shb.version_minor!=0) ) ) {
    FD_LOG_WARNING(( "pcapng: unsupported file format version %u.%u",
                     shb.version_major, shb.version_minor ));
    return NULL;
  }

  return iter;
}

void *
fd_pcapng_iter_delete( fd_pcapng_iter_t * iter ) {
  void * mem = (void *)iter;
  memset( mem, 0, sizeof(fd_pcapng_iter_t) );
  return mem;
}

static fd_pcapng_frame_t *
fd_pcapng_iter_next1( fd_pcapng_iter_t * iter ) {
  fd_pcapng_frame_t * pkt = &iter->pkt;

  /* Clear fields */
  pkt->ts      = 0L;
  pkt->type    = 0U;
  pkt->data_sz = 0U;
  pkt->orig_sz = 0U;
  pkt->if_idx  = 0U;
  pkt->idb     = NULL;

  FILE * stream = iter->stream;

  /* Attempt a number of times to find a frame of known type.
     Abort if there are too many unknown frames. */
  for( uint attempt=0U; attempt<256U; attempt++ ) {

    fd_pcapng_block_hdr_t hdr;
    if( FD_UNLIKELY( 0!=(iter->error = fd_pcapng_read_block( stream, iter, &hdr )) ) ) {
      if( FD_UNLIKELY( iter->error != -1 ) )
        FD_LOG_WARNING(( "pcapng: read failed (%s)", fd_pcapng_iter_strerror( iter->error, stream ) ));
      return NULL;
    }

    switch( hdr.block_type ) {
    case FD_PCAPNG_BLOCK_TYPE_SHB: {
      iter->error = -1; /* eof */
      /* FIXME CONSIDER SILENTLY CONTINUING? */
      return NULL;
    }
    case FD_PCAPNG_BLOCK_TYPE_IDB: {
      /* Read IDB */
      if( FD_UNLIKELY( hdr.block_sz<sizeof(fd_pcapng_idb_t) ) ) {
        iter->error = EPROTO;
        FD_LOG_WARNING(( "pcapng: invalid IDB block size (%#x)", hdr.block_sz ));
        return NULL;
      }
      fd_pcapng_idb_t idb = FD_LOAD( fd_pcapng_idb_t, iter->block_buf );
      iter->block_buf_pos = sizeof(fd_pcapng_idb_t);

      /* Add interface to list */
      if( FD_UNLIKELY( iter->iface_cnt>=FD_PCAPNG_IFACE_CNT ) ) {
        iter->error = EPROTO;
        FD_LOG_WARNING(( "pcapng: too many interfaces (max %d)", FD_PCAPNG_IFACE_CNT ));
        return NULL;
      }

      fd_pcapng_idb_desc_t * iface = &iter->iface[ iter->iface_cnt++ ];
      memset( iface, 0, sizeof(fd_pcapng_idb_desc_t) );
      iface->link_type = idb.link_type;

      /* Read options */
      for( uint j=0; j<FD_PCAPNG_MAX_OPT_CNT; j++ ) {
        uchar opt_buf[ 128UL ] __attribute__((aligned(32UL)));
        fd_pcapng_option_t opt = { .sz=sizeof(opt_buf), .value=&opt_buf };
        if( FD_UNLIKELY( 0!=(iter->error = fd_pcapng_read_option( iter, &opt )) ) ) {
          FD_LOG_WARNING(( "pcapng: read failed (%s)", fd_pcapng_iter_strerror( iter->error, stream ) ));
          return NULL;
        }
        if( !opt.type ) break;
        switch( opt.type ) {
        case FD_PCAPNG_OPT_COMMENT:
          FD_LOG_HEXDUMP_DEBUG(( "IDB comment", opt_buf, opt.sz ));
          break;
        case FD_PCAPNG_IDB_OPT_NAME:
          fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( iface->opts.name ), (char const *)opt_buf, fd_ulong_min( sizeof(iface->opts.name)-1, opt.sz ) ) );
          iface->opts.name[ sizeof(iface->opts.name)-1 ] = '\0';
          break;
        case FD_PCAPNG_IDB_OPT_HARDWARE:
          fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( iface->opts.hardware ), (char const *)opt_buf, fd_ulong_min( sizeof(iface->opts.hardware)-1, opt.sz ) ) );
          iface->opts.hardware[ sizeof(iface->opts.hardware)-1 ] = '\0';
          break;
        case FD_PCAPNG_IDB_OPT_IPV4_ADDR:
          if( FD_UNLIKELY( opt.sz!=4U ) )
            continue;
          memcpy( iface->opts.ip4_addr, opt_buf, 4UL );
          break;
        case FD_PCAPNG_IDB_OPT_MAC_ADDR:
          if( FD_UNLIKELY( opt.sz!=6U ) )
            continue;
          memcpy( iface->opts.mac_addr, opt_buf, 6UL );
          break;
        case FD_PCAPNG_IDB_OPT_TSRESOL:
          if( FD_UNLIKELY( opt.sz!=1U ) )
            continue;
          iface->opts.tsresol = opt_buf[ 0 ];
          break;
        default:
          FD_LOG_DEBUG(( "Ignoring unknown IDB option type %#x", opt.type ));
          break;
        }
      }

      break;
    }
    case FD_PCAPNG_BLOCK_TYPE_SPB: {
      /* Read SPB */
      if( FD_UNLIKELY( hdr.block_sz<sizeof(fd_pcapng_spb_t) ) ) {
        iter->error = EPROTO;
        FD_LOG_WARNING(( "pcapng: invalid SPB block size (%#x)", hdr.block_sz ));
        return NULL;
      }

      uint hdr_sz  = sizeof(fd_pcapng_spb_t);
      uint data_sz = hdr.block_sz - hdr_sz;

      fd_pcapng_spb_t spb = FD_LOAD( fd_pcapng_spb_t, iter->block_buf );
      iter->block_buf_pos = hdr_sz;

      if( FD_UNLIKELY( spb.orig_len > (iter->block_buf_sz - iter->block_buf_pos) ) ) {
        iter->error = EPROTO;
        FD_LOG_WARNING(( "pcapng: invalid SPB block size (%#x)", hdr.block_sz ));
        return NULL;
      }
      pkt->data = iter->block_buf + iter->block_buf_pos;

      pkt->type    = FD_PCAPNG_FRAME_SIMPLE;
      pkt->data_sz = (ushort)data_sz;
      pkt->orig_sz = (ushort)spb.orig_len;
      return pkt;
    }
    case FD_PCAPNG_BLOCK_TYPE_EPB: {
      /* Read EPB */
      if( FD_UNLIKELY( hdr.block_sz<sizeof(fd_pcapng_epb_t) ) ) {
        iter->error = EPROTO;
        FD_LOG_WARNING(( "pcapng: invalid EPB block size (%#x)", hdr.block_sz ));
        return NULL;
      }

      fd_pcapng_epb_t epb = FD_LOAD( fd_pcapng_epb_t, iter->block_buf );
      iter->block_buf_pos = sizeof(fd_pcapng_epb_t);

      if( FD_UNLIKELY( epb.cap_len > (iter->block_buf_sz - iter->block_buf_pos) ) ) {
        iter->error = EPROTO;
        FD_LOG_WARNING(( "pcapng: invalid EPB block size (%#x)", hdr.block_sz ));
        return NULL;
      }
      pkt->data = iter->block_buf + iter->block_buf_pos;
      iter->block_buf_pos += fd_uint_align_up( epb.cap_len, 4U );

      /* Read options */
      for( uint j=0; j<FD_PCAPNG_MAX_OPT_CNT; j++ ) {
        uchar opt_buf[ 128UL ] __attribute__((aligned(32UL)));
        fd_pcapng_option_t opt = { .sz=sizeof(opt_buf), .value=&opt_buf };
        if( FD_UNLIKELY( 0!=(iter->error = fd_pcapng_read_option( iter, &opt )) ) ) {
          FD_LOG_WARNING(( "pcapng: read failed (%s)", fd_pcapng_iter_strerror( iter->error, stream ) ));
          return NULL;
        }
        if( !opt.type ) break;
        switch( opt.type ) {
        case FD_PCAPNG_OPT_COMMENT:
          FD_LOG_HEXDUMP_DEBUG(( "Packet comment", opt_buf, opt.sz ));
          break;
        default:
          FD_LOG_DEBUG(( "Ignoring unknown EPB option type %#x", opt.type ));
          break;
        }
      }

      if( FD_LIKELY( epb.if_idx < iter->iface_cnt ) ) {
        ulong raw = ( ((ulong)epb.ts_hi << 32UL) | (ulong)epb.ts_lo );
        /* FIXME support more timestamp resolutions */
        if( iter->iface[ epb.if_idx ].opts.tsresol == FD_PCAPNG_TSRESOL_NS ) {
          pkt->ts = (long)raw;
        }
      }

      pkt->type    = FD_PCAPNG_FRAME_ENHANCED;
      pkt->data_sz = (ushort)epb.cap_len;
      pkt->orig_sz = (ushort)epb.orig_len;
      pkt->if_idx  = epb.if_idx;
      pkt->idb     = (epb.if_idx<iter->iface_cnt) ? &iter->iface[ epb.if_idx ] : NULL;
      return pkt;
    }
    case FD_PCAPNG_BLOCK_TYPE_DSB: {
      /* Read DSB */
      if( FD_UNLIKELY( hdr.block_sz<sizeof(fd_pcapng_dsb_t) ) ) {
        iter->error = EPROTO;
        FD_LOG_WARNING(( "pcapng: invalid DSB block size (%#x)", hdr.block_sz ));
        return NULL;
      }

      fd_pcapng_dsb_t dsb = FD_LOAD( fd_pcapng_dsb_t, iter->block_buf );
      iter->block_buf_pos = sizeof(fd_pcapng_dsb_t);

      if( FD_UNLIKELY( dsb.secret_sz > (iter->block_buf_sz - iter->block_buf_pos) ) ) {
        iter->error = EPROTO;
        FD_LOG_WARNING(( "pcapng: invalid DSB block size (%#x)", hdr.block_sz ));
        return NULL;
      }
      pkt->data = iter->block_buf + sizeof(fd_pcapng_dsb_t);
      iter->block_buf_pos += fd_uint_align_up( dsb.secret_sz, 4U );

      /* Read options */
      for( uint j=0; j<FD_PCAPNG_MAX_OPT_CNT; j++ ) {
        uchar opt_buf[ 128UL ] __attribute__((aligned(32UL)));
        fd_pcapng_option_t opt = { .sz=sizeof(opt_buf), .value=&opt_buf };
        if( FD_UNLIKELY( 0!=(iter->error = fd_pcapng_read_option( iter, &opt )) ) ) {
          FD_LOG_WARNING(( "pcapng: read failed (%s)", fd_pcapng_iter_strerror( iter->error, stream ) ));
          return NULL;
        }
        if( !opt.type ) break;
        switch( opt.type ) {
        case FD_PCAPNG_OPT_COMMENT:
          FD_LOG_HEXDUMP_DEBUG(( "Decryption secrets comment", opt_buf, opt.sz ));
          break;
        default:
          FD_LOG_DEBUG(( "Ignoring unknown DSB option type %#x", opt.type ));
          break;
        }
      }

      if( dsb.secret_type!=FD_PCAPNG_SECRET_TYPE_TLS ) {
        FD_LOG_DEBUG(( "Ignoring secret (type %#x)", dsb.secret_type ));
        break;
      }

      pkt->type    = FD_PCAPNG_FRAME_TLSKEYS;
      pkt->data_sz = dsb.secret_sz;
      return pkt;
    }
    default:
      FD_LOG_DEBUG(( "pcapng: skipping unknown block (type=%#x)", hdr.block_type ));
      break;
    }
  }

  /* Found no blocks that are interesting to user */
  iter->error = EPROTO;
  FD_LOG_WARNING(( "pcapng: aborting, too many non-packet frames" ));
  return NULL;
}

fd_pcapng_frame_t *
fd_pcapng_iter_next( fd_pcapng_iter_t * iter ) {
  fd_pcapng_frame_t * frame = fd_pcapng_iter_next1( iter );
  iter->empty = !frame;
  return frame;
}

fd_pcapng_frame_t *
fd_pcapng_iter_ele( fd_pcapng_iter_t * iter ) {
  if( FD_UNLIKELY( iter->empty ) ) return NULL;
  return &iter->pkt;
}

FD_FN_PURE int
fd_pcapng_iter_err( fd_pcapng_iter_t const * iter ) {
  return iter->error;
}
