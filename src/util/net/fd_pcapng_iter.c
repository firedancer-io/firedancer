#include "fd_pcapng_private.h"
#include "../fd_util.h"
#include <errno.h>
#include <stdio.h>

/* FIXME Option parsing spec violation

     https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-00.html#name-options

     > Code that reads pcapng files MUST NOT assume an option list will
     have an opt_endofopt option at the end; it MUST also check for the
     end of the block, and SHOULD treat blocks where the option list has
     no opt_endofopt option as if the option list had an opt_endofopt
     option at the end.

     This parser currently does not handle missing opt_endofopt */

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
fd_pcapng_peek_block( FILE *                  stream,
                      fd_pcapng_block_hdr_t * _hdr,
                      long *                  end_ptr ) {

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

  /* Seek to block footer */
  if( FD_UNLIKELY( 0!=fseek( stream, (long)(hdr.block_sz - 12U), SEEK_CUR ) ) )
    return errno;

  /* Read footer */
  uint block_sz;
  if( FD_UNLIKELY( 1UL!=fread( &block_sz, sizeof(uint), 1, stream ) ) )
    return ferror( stream );

  /* Restore cursor */
  if( FD_UNLIKELY( 0!=fseek( stream, pos, SEEK_SET ) ) )
    return errno;

  /* Check that header and footer match */
  if( FD_UNLIKELY( hdr.block_sz != block_sz ) ) {
    FD_LOG_DEBUG(( "pcapng: block size in header and footer don't match at %#lx", (ulong)pos ));
    return EPROTO;
  }

  *_hdr = hdr;
  if( end_ptr ) *end_ptr = pos + (long)fd_uint_align_up( hdr.block_sz, 4U );

  return 0; /* success */
}

static int
fd_pcapng_read_option( FILE *               stream,
                       fd_pcapng_option_t * opt ) {

  struct __attribute__((packed)) {
    ushort type;
    ushort sz;
  } opt_hdr;

  if( FD_UNLIKELY( 1UL!=fread( &opt_hdr, 4UL, 1UL, stream ) ) )
    return ferror( stream );

  uint end_off = fd_uint_align_up( opt_hdr.sz, 4U );
  uint read_sz = fd_uint_min( opt_hdr.sz, opt->sz );
  opt->type = opt_hdr.type;
  opt->sz   = (ushort)read_sz;

  if( read_sz ) {
    if( FD_UNLIKELY( 1UL!=fread( opt->value, read_sz, 1UL, stream ) ) )
      return ferror( stream );
    end_off -= read_sz;
  }

  if( FD_UNLIKELY( 0!=fseek( stream, end_off, SEEK_CUR ) ) )
    return errno;

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
  int err = fd_pcapng_peek_block( file, &shb_hdr, NULL );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "pcapng: SHB read failed (%s)", fd_pcapng_iter_strerror( err, file ) ));
    return NULL;
  }
  if( FD_UNLIKELY( shb_hdr.block_type!=FD_PCAPNG_BLOCK_TYPE_SHB
                || shb_hdr.block_sz  < sizeof(fd_pcapng_shb_t)  ) ) {
    FD_LOG_WARNING(( "pcapng: not a valid Section Header Block" ));
    return NULL;
  }

  /* Read Section Header Block */

  fd_pcapng_shb_t shb;
  if( FD_UNLIKELY( 1UL!=fread( &shb, sizeof(fd_pcapng_shb_t), 1UL, file )
                || 0  !=fseek( file, (long)shb_hdr.block_sz - (long)sizeof(fd_pcapng_shb_t), SEEK_CUR ) ) ) {
    FD_LOG_WARNING(( "pcapng: SHB read failed (%s)", fd_pcapng_iter_strerror( err, file ) ));
    return NULL;
  }

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
    long                  end;
    if( FD_UNLIKELY( 0!=(iter->error = fd_pcapng_peek_block( stream, &hdr, &end )) ) ) {
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
      fd_pcapng_idb_t idb;
      if( FD_UNLIKELY( 1UL!=fread( &idb, sizeof(fd_pcapng_idb_t), 1UL, stream ) ) ) {
        iter->error = ferror( stream );
        FD_LOG_WARNING(( "pcapng: read failed (%s)", fd_pcapng_iter_strerror( iter->error, stream ) ));
        return NULL;
      }

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
        if( FD_UNLIKELY( 0!=(iter->error = fd_pcapng_read_option( stream, &opt )) ) ) {
          FD_LOG_WARNING(( "pcapng: read failed (%s)", fd_pcapng_iter_strerror( iter->error, stream ) ));
          return NULL;
        }
        if( !opt.type ) break;
        switch( opt.type ) {
        case FD_PCAPNG_OPT_COMMENT:
          FD_LOG_HEXDUMP_DEBUG(( "IDB comment", opt_buf, opt.sz ));
          break;
        case FD_PCAPNG_IDB_OPT_NAME:
          fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( iface->opts.name ), (char const *)opt_buf, fd_ulong_min( sizeof(iface->opts.name)-1, opt.sz ) ) );
          iface->opts.name[ sizeof(iface->opts.name)-1 ] = '\0';
          break;
        case FD_PCAPNG_IDB_OPT_HARDWARE:
          fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( iface->opts.hardware ), (char const *)opt_buf, fd_ulong_min( sizeof(iface->opts.hardware)-1, opt.sz ) ) );
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

      /* Seek to end of block */
      if( FD_UNLIKELY( 0!=fseek( stream, end, SEEK_SET ) ) ) {
        iter->error = errno;
        FD_LOG_WARNING(( "pcapng: seek failed (%s)", fd_pcapng_iter_strerror( iter->error, stream ) ));
        return NULL;
      }

      /* Next */
      break;
    }
    case FD_PCAPNG_BLOCK_TYPE_SPB: {
      /* Read SPB */
      if( FD_UNLIKELY( hdr.block_sz<sizeof(fd_pcapng_spb_t)
                    || hdr.block_sz>FD_PCAPNG_FRAME_SZ ) ) {
        iter->error = EPROTO;
        FD_LOG_WARNING(( "pcapng: invalid SPB block size (%#x)", hdr.block_sz ));
        return NULL;
      }

      uint hdr_sz  = sizeof(fd_pcapng_spb_t);
      uint data_sz = hdr.block_sz - hdr_sz;

      fd_pcapng_spb_t spb;
      if( FD_UNLIKELY( 1UL!=fread( &spb,      hdr_sz,  1UL, stream ) ) ) {
        iter->error = ferror( stream );
        FD_LOG_WARNING(( "pcapng: read failed (%s)", fd_pcapng_iter_strerror( iter->error, stream ) ));
        return NULL;
      }
      if( FD_UNLIKELY( 1UL!=fread( pkt->data, data_sz, 1UL, stream ) ) ) {
        iter->error = ferror( stream );
        FD_LOG_WARNING(( "pcapng: read failed (%s)", fd_pcapng_iter_strerror( iter->error, stream ) ));
        return NULL;
      }

      /* Seek to end of block */
      if( FD_UNLIKELY( 0!=fseek( stream, end, SEEK_SET ) ) ) {
        iter->error = errno;
        FD_LOG_WARNING(( "pcapng: seek failed (%s)", fd_pcapng_iter_strerror( iter->error, stream ) ));
        return NULL;
      }

      pkt->type    = FD_PCAPNG_FRAME_SIMPLE;
      pkt->data_sz = (ushort)data_sz;
      pkt->orig_sz = (ushort)spb.orig_len;
      return pkt;
    }
    case FD_PCAPNG_BLOCK_TYPE_EPB: {
      /* Read EPB */
      if( FD_UNLIKELY( hdr.block_sz<sizeof(fd_pcapng_epb_t)
                    || hdr.block_sz>FD_PCAPNG_FRAME_SZ ) ) {
        iter->error = EPROTO;
        FD_LOG_WARNING(( "pcapng: invalid EPB block size (%#x)", hdr.block_sz ));
        return NULL;
      }

      fd_pcapng_epb_t epb;
      if( FD_UNLIKELY( 1UL!=fread( &epb, sizeof(fd_pcapng_epb_t), 1UL, stream ) ) ) {
        iter->error = ferror( stream );
        FD_LOG_WARNING(( "pcapng: read failed (%s)", fd_pcapng_iter_strerror( iter->error, stream ) ));
        return NULL;
      }
      if( FD_UNLIKELY( epb.cap_len>FD_PCAPNG_FRAME_SZ ) ) {
        iter->error = EPROTO;
        FD_LOG_WARNING(( "pcapng: oversize EPB data (%#x)", epb.cap_len ));
        return NULL;
      }
      if( FD_UNLIKELY( 1UL!=fread( pkt->data, epb.cap_len, 1UL, stream ) ) ) {
        iter->error = ferror( stream );
        FD_LOG_WARNING(( "pcapng: read failed (%s)", fd_pcapng_iter_strerror( iter->error, stream ) ));
        return NULL;
      }

      /* Read options */
      for( uint j=0; j<FD_PCAPNG_MAX_OPT_CNT; j++ ) {
        uchar opt_buf[ 128UL ] __attribute__((aligned(32UL)));
        fd_pcapng_option_t opt = { .sz=sizeof(opt_buf), .value=&opt_buf };
        if( FD_UNLIKELY( 0!=(iter->error = fd_pcapng_read_option( stream, &opt )) ) ) {
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

      /* Seek to end of block */
      if( FD_UNLIKELY( 0!=fseek( stream, end, SEEK_SET ) ) ) {
        iter->error = errno;
        FD_LOG_WARNING(( "pcapng: seek failed (%s)", fd_pcapng_iter_strerror( iter->error, stream ) ));
        return NULL;
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
      if( FD_UNLIKELY( hdr.block_sz<sizeof(fd_pcapng_dsb_t)
                    || hdr.block_sz>FD_PCAPNG_FRAME_SZ ) ) {
        iter->error = EPROTO;
        FD_LOG_WARNING(( "pcapng: invalid DSB block size (%#x)", hdr.block_sz ));
        return NULL;
      }

      fd_pcapng_dsb_t dsb;
      if( FD_UNLIKELY( 1UL!=fread( &dsb, sizeof(fd_pcapng_dsb_t), 1UL, stream ) ) ) {
        iter->error = ferror( stream );
        FD_LOG_WARNING(( "pcapng: read failed (%s)", fd_pcapng_iter_strerror( iter->error, stream ) ));
        return NULL;
      }
      if( FD_UNLIKELY( dsb.secret_sz>FD_PCAPNG_FRAME_SZ ) ) {
        iter->error = EPROTO;
        FD_LOG_WARNING(( "pcapng: oversize DSB data (%#x)", dsb.secret_sz ));
        return NULL;
      }
      if( FD_UNLIKELY( 1UL!=fread( pkt->data, dsb.secret_sz, 1UL, stream ) ) ) {
        iter->error = ferror( stream );
        FD_LOG_WARNING(( "pcapng: read failed (%s)", fd_pcapng_iter_strerror( iter->error, stream ) ));
        return NULL;
      }

      /* Read options */
      for( uint j=0; j<FD_PCAPNG_MAX_OPT_CNT; j++ ) {
        uchar opt_buf[ 128UL ] __attribute__((aligned(32UL)));
        fd_pcapng_option_t opt = { .sz=sizeof(opt_buf), .value=&opt_buf };
        if( FD_UNLIKELY( 0!=(iter->error = fd_pcapng_read_option( stream, &opt )) ) ) {
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

      /* Seek to end of block */
      if( FD_UNLIKELY( 0!=fseek( stream, end, SEEK_SET ) ) ) {
        iter->error = errno;
        FD_LOG_WARNING(( "pcapng: seek failed (%s)", fd_pcapng_iter_strerror( iter->error, stream ) ));
        return NULL;
      }

      pkt->type    = FD_PCAPNG_FRAME_TLSKEYS;
      pkt->data_sz = dsb.secret_sz;
      return pkt;
    }
    default:
      FD_LOG_DEBUG(( "pcapng: skipping unknown block (type=%#x)", hdr.block_type ));
      if( FD_UNLIKELY( 0!=fseek( stream, hdr.block_sz, SEEK_CUR ) ) ) {
        iter->error = errno;
        FD_LOG_WARNING(( "pcapng: seek failed (%s)", fd_pcapng_iter_strerror( iter->error, stream ) ));
        return NULL;
      }
    }

    /* Read block that is not interesting to user, continue to next */
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
