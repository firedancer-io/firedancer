#include "fd_pcapng_private.h"
#include "../fd_util.h"

/* Capture related ****************************************************/

#include <errno.h>
#if defined(__linux__)
#include <net/if.h>
#endif /* defined(__linux__) */

void
fd_pcapng_shb_defaults( fd_pcapng_shb_opts_t * opt ) {
# if FD_HAS_X86
  opt->hardware = "x86_64";
# endif

# if defined(__linux__)
  opt->os       = "Linux";
# endif

  opt->userappl = "Firedancer";
}

int
fd_pcapng_idb_defaults( fd_pcapng_idb_opts_t * opt,
                        uint                   if_idx ) {
# if defined(__linux__)
  static FD_TL char _name[ IF_NAMESIZE ];
  char * name = if_indextoname( if_idx, _name );
  if( FD_UNLIKELY( !name ) ) return 0;
  FD_STATIC_ASSERT( 16>=IF_NAMESIZE, ifname_sz );
  memcpy( opt->name, _name, 16UL );
# endif

  opt->tsresol = FD_PCAPNG_TSRESOL_NS;

  /* TODO get ip4_addr, mac_addr, hardware from rtnetlink */

  return 1;
}

#if FD_HAS_HOSTED

#include <stdio.h>

/* Parsers ************************************************************/

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
  switch( error ) {
  case FD_PCAPNG_ITER_OK:
    err_cstr = fd_cstr_append_cstr( err_cstr, "ok" );
    break;
  case FD_PCAPNG_ITER_EOF:
    if( feof( file ) ) err_cstr = fd_cstr_append_cstr( err_cstr, "end of file"    );
    else               err_cstr = fd_cstr_append_cstr( err_cstr, "end of section" );
    break;
  case FD_PCAPNG_ITER_ERR_PARSE:
    return fd_cstr_printf( err_cstr, sizeof(err_cstr_buf), NULL, "parse error at %#lx", ftell(file) );
  case FD_PCAPNG_ITER_ERR_STREAM:
  case FD_PCAPNG_ITER_ERR_IO: {
    int _errno = error==FD_PCAPNG_ITER_ERR_STREAM ? ferror( file ) : errno;
    return fd_cstr_printf( err_cstr, sizeof(err_cstr_buf), NULL, "%i-%s", _errno, fd_io_strerror(_errno) );
  }
  default:
    err_cstr = fd_cstr_append_cstr( err_cstr, "???" );
    break;
  }

  return err_cstr_buf;
}

static int
fd_pcapng_peek_block( FILE *                  stream,
                      fd_pcapng_block_hdr_t * _hdr,
                      long *                  end_ptr ) {

  /* Remember offset of block */
  long pos = ftell( stream );
  if( FD_UNLIKELY( pos<0L ) )
    return FD_PCAPNG_ITER_ERR_STREAM;
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)pos, 4U ) ) ) {
    FD_LOG_DEBUG(( "pcapng: misaligned stream at %#lx", pos ));
    return FD_PCAPNG_ITER_ERR_PARSE;
  }

  /* Read header */
  fd_pcapng_block_hdr_t hdr;
  if( FD_UNLIKELY( 1UL!=fread( &hdr, sizeof(fd_pcapng_block_hdr_t), 1, stream ) ) ) {
    if( FD_LIKELY( feof( stream ) ) ) return FD_PCAPNG_ITER_EOF;
    else                              return FD_PCAPNG_ITER_ERR_STREAM;
  }

  /* Coherence check length field */
  if( FD_UNLIKELY( (hdr.block_sz <   12U) /* header and footer are mandatory */
                 | (hdr.block_sz >32768U) /* way too large */
                 | (!fd_ulong_is_aligned( hdr.block_sz, 4U )) ) ) {
    FD_LOG_DEBUG(( "pcapng: block with invalid size %#x at %#lx", hdr.block_sz, pos ));
    return FD_PCAPNG_ITER_ERR_PARSE;
  }

  /* Seek to block footer */
  if( FD_UNLIKELY( 0!=fseek( stream, (long)(hdr.block_sz - 12U), SEEK_CUR ) ) )
    return FD_PCAPNG_ITER_ERR_IO;

  /* Read footer */
  uint block_sz;
  if( FD_UNLIKELY( 1UL!=fread( &block_sz, sizeof(uint), 1, stream ) ) )
    return FD_PCAPNG_ITER_ERR_STREAM;

  /* Restore cursor */
  if( FD_UNLIKELY( 0!=fseek( stream, pos, SEEK_SET ) ) )
    return FD_PCAPNG_ITER_ERR_IO;

  /* Check that header and footer match */
  if( FD_UNLIKELY( hdr.block_sz != block_sz ) ) {
    FD_LOG_DEBUG(( "pcapng: block size in header and footer don't match at %#lx", pos ));
    return FD_PCAPNG_ITER_ERR_PARSE;
  }

  *_hdr = hdr;
  if( end_ptr ) *end_ptr = pos + (long)fd_uint_align_up( hdr.block_sz, 4U );

  return FD_PCAPNG_ITER_OK;
}

static int
fd_pcapng_read_option( FILE *               stream,
                       fd_pcapng_option_t * opt ) {

  struct __attribute__((packed)) {
    ushort type;
    ushort sz;
  } opt_hdr;

  if( FD_UNLIKELY( 1UL!=fread( &opt_hdr, 4UL, 1UL, stream ) ) )
    return FD_PCAPNG_ITER_ERR_STREAM;

  uint end_off = fd_uint_align_up( opt_hdr.sz, 4U );
  uint read_sz = fd_uint_min( end_off, opt->sz );

  if( read_sz ) {
    if( FD_UNLIKELY( 1UL!=fread( opt->value, read_sz, 1UL, stream ) ) )
      return FD_PCAPNG_ITER_ERR_STREAM;
    end_off -= read_sz;
  }

  if( FD_UNLIKELY( 0!=fseek( stream, end_off, SEEK_CUR ) ) )
    return FD_PCAPNG_ITER_ERR_IO;

  return FD_PCAPNG_ITER_OK;
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

fd_pcapng_frame_t const *
fd_pcapng_iter_next( fd_pcapng_iter_t * iter ) {

  static FD_TL fd_pcapng_frame_t pkt;

  /* Clear fields */
  pkt.ts      = 0L;
  pkt.type    = 0U;
  pkt.data_sz = 0U;
  pkt.orig_sz = 0U;
  pkt.if_idx  = 0U;

  FILE * stream = iter->stream;

  /* Attempt a number of times to find a frame of known type.
     Abort if there are too many unknown frames. */
  for( uint attempt=0U; attempt<256U; attempt++ ) {

    fd_pcapng_block_hdr_t hdr;
    long                  end;
    if( FD_UNLIKELY( 0!=(iter->error = fd_pcapng_peek_block( stream, &hdr, &end )) ) ) {
      if( FD_UNLIKELY( iter->error != FD_PCAPNG_ITER_EOF ) )
        FD_LOG_WARNING(( "pcapng: read failed (%s)", fd_pcapng_iter_strerror( iter->error, stream ) ));
      return NULL;
    }

    switch( hdr.block_type ) {
    case FD_PCAPNG_BLOCK_TYPE_SHB: {
      iter->error = FD_PCAPNG_ITER_EOF;
      return NULL;
    }
    case FD_PCAPNG_BLOCK_TYPE_IDB: {
      /* Read IDB */
      if( FD_UNLIKELY( hdr.block_sz<sizeof(fd_pcapng_idb_t) ) ) {
        iter->error = FD_PCAPNG_ITER_ERR_PARSE;
        FD_LOG_WARNING(( "pcapng: invalid IDB block size (%#x)", hdr.block_sz ));
        return NULL;
      }
      fd_pcapng_idb_t idb;
      if( FD_UNLIKELY( 1UL!=fread( &idb, sizeof(fd_pcapng_idb_t), 1UL, stream ) ) ) {
        iter->error = FD_PCAPNG_ITER_ERR_STREAM;
        FD_LOG_WARNING(( "pcapng: read failed (%s)", fd_pcapng_iter_strerror( iter->error, stream ) ));
        return NULL;
      }

      /* Add interface to list */
      if( FD_UNLIKELY( iter->iface_cnt>=FD_PCAPNG_IFACE_CNT ) ) {
        iter->error = FD_PCAPNG_ITER_ERR_PARSE;
        FD_LOG_WARNING(( "pcapng: too many interfaces (max %d)", FD_PCAPNG_IFACE_CNT ));
        return NULL;
      }

      fd_pcapng_idb_desc_t * iface = &iter->iface[ iter->iface_cnt++ ];
      memset( iface, 0, sizeof(fd_pcapng_idb_desc_t) );

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
          fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( iface->opts.name     ), (char const *)opt_buf, sizeof(opt_buf) ) );
          break;
        case FD_PCAPNG_IDB_OPT_HARDWARE:
          fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( iface->opts.hardware ), (char const *)opt_buf, sizeof(opt_buf) ) );
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
        iter->error = FD_PCAPNG_ITER_ERR_IO;
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
        iter->error = FD_PCAPNG_ITER_ERR_PARSE;
        FD_LOG_WARNING(( "pcapng: invalid SPB block size (%#x)", hdr.block_sz ));
        return NULL;
      }

      uint hdr_sz  = sizeof(fd_pcapng_spb_t);
      uint data_sz = hdr.block_sz - hdr_sz;

      fd_pcapng_spb_t spb;
      if( FD_UNLIKELY( 1UL!=fread( &spb,      hdr_sz,  1UL, stream ) ) ) {
        iter->error = FD_PCAPNG_ITER_ERR_STREAM;
        FD_LOG_WARNING(( "pcapng: read failed (%s)", fd_pcapng_iter_strerror( iter->error, stream ) ));
        return NULL;
      }
      if( FD_UNLIKELY( 1UL!=fread( &pkt.data, data_sz, 1UL, stream ) ) ) {
        iter->error = FD_PCAPNG_ITER_ERR_STREAM;
        FD_LOG_WARNING(( "pcapng: read failed (%s)", fd_pcapng_iter_strerror( iter->error, stream ) ));
        return NULL;
      }

      /* Seek to end of block */
      if( FD_UNLIKELY( 0!=fseek( stream, end, SEEK_SET ) ) ) {
        iter->error = FD_PCAPNG_ITER_ERR_IO;
        FD_LOG_WARNING(( "pcapng: seek failed (%s)", fd_pcapng_iter_strerror( iter->error, stream ) ));
        return NULL;
      }

      pkt.type    = FD_PCAPNG_FRAME_SIMPLE;
      pkt.data_sz = (ushort)data_sz;
      pkt.orig_sz = (ushort)spb.orig_len;
      return &pkt;
    }
    case FD_PCAPNG_BLOCK_TYPE_EPB: {
      /* Read EPB */
      if( FD_UNLIKELY( hdr.block_sz<sizeof(fd_pcapng_epb_t)
                    || hdr.block_sz>FD_PCAPNG_FRAME_SZ ) ) {
        iter->error = FD_PCAPNG_ITER_ERR_PARSE;
        FD_LOG_WARNING(( "pcapng: invalid EPB block size (%#x)", hdr.block_sz ));
        return NULL;
      }

      fd_pcapng_epb_t epb;
      if( FD_UNLIKELY( 1UL!=fread( &epb, sizeof(fd_pcapng_epb_t), 1UL, stream ) ) ) {
        iter->error = FD_PCAPNG_ITER_ERR_STREAM;
        FD_LOG_WARNING(( "pcapng: read failed (%s)", fd_pcapng_iter_strerror( iter->error, stream ) ));
        return NULL;
      }
      if( FD_UNLIKELY( epb.cap_len>FD_PCAPNG_FRAME_SZ ) ) {
        iter->error = FD_PCAPNG_ITER_ERR_PARSE;
        FD_LOG_WARNING(( "pcapng: oversize EPB data (%#x)", epb.cap_len ));
        return NULL;
      }
      if( FD_UNLIKELY( 1UL!=fread( &pkt.data, epb.cap_len, 1UL, stream ) ) ) {
        iter->error = FD_PCAPNG_ITER_ERR_STREAM;
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
          pkt.ts = (long)raw;
        }
      }

      /* Seek to end of block */
      if( FD_UNLIKELY( 0!=fseek( stream, end, SEEK_SET ) ) ) {
        iter->error = FD_PCAPNG_ITER_ERR_IO;
        FD_LOG_WARNING(( "pcapng: seek failed (%s)", fd_pcapng_iter_strerror( iter->error, stream ) ));
        return NULL;
      }

      pkt.type    = FD_PCAPNG_FRAME_ENHANCED;
      pkt.data_sz = (ushort)epb.cap_len;
      pkt.orig_sz = (ushort)epb.orig_len;
      pkt.if_idx  = epb.if_idx;
      return &pkt;
    }
    case FD_PCAPNG_BLOCK_TYPE_DSB: {
      /* Read DSB */
      if( FD_UNLIKELY( hdr.block_sz<sizeof(fd_pcapng_dsb_t)
                    || hdr.block_sz>FD_PCAPNG_FRAME_SZ ) ) {
        iter->error = FD_PCAPNG_ITER_ERR_PARSE;
        FD_LOG_WARNING(( "pcapng: invalid DSB block size (%#x)", hdr.block_sz ));
        return NULL;
      }

      fd_pcapng_dsb_t dsb;
      if( FD_UNLIKELY( 1UL!=fread( &dsb, sizeof(fd_pcapng_dsb_t), 1UL, stream ) ) ) {
        iter->error = FD_PCAPNG_ITER_ERR_STREAM;
        FD_LOG_WARNING(( "pcapng: read failed (%s)", fd_pcapng_iter_strerror( iter->error, stream ) ));
        return NULL;
      }
      if( FD_UNLIKELY( dsb.secret_sz>FD_PCAPNG_FRAME_SZ ) ) {
        iter->error = FD_PCAPNG_ITER_ERR_PARSE;
        FD_LOG_WARNING(( "pcapng: oversize DSB data (%#x)", dsb.secret_sz ));
        return NULL;
      }
      if( FD_UNLIKELY( 1UL!=fread( &pkt.data, dsb.secret_sz, 1UL, stream ) ) ) {
        iter->error = FD_PCAPNG_ITER_ERR_STREAM;
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
        iter->error = FD_PCAPNG_ITER_ERR_IO;
        FD_LOG_WARNING(( "pcapng: seek failed (%s)", fd_pcapng_iter_strerror( iter->error, stream ) ));
        return NULL;
      }

      pkt.type    = FD_PCAPNG_FRAME_TLSKEYS;
      pkt.data_sz = dsb.secret_sz;
      return &pkt;
    }
    default:
      FD_LOG_DEBUG(( "pcapng: skipping unknown block (type=%#x)", hdr.block_type ));
      if( FD_UNLIKELY( 0!=fseek( stream, hdr.block_sz, SEEK_CUR ) ) ) {
        iter->error = FD_PCAPNG_ITER_ERR_IO;
        FD_LOG_WARNING(( "pcapng: seek failed (%s)", fd_pcapng_iter_strerror( iter->error, stream ) ));
        return NULL;
      }
    }

    /* Read block that is not interesting to user, continue to next */
  }

  /* Found no blocks that are interesting to user */
  iter->error = FD_PCAPNG_ITER_ERR_PARSE;
  FD_LOG_WARNING(( "pcapng: aborting, too many non-packet frames" ));
  return NULL;
}

FD_FN_PURE int
fd_pcapng_iter_err( fd_pcapng_iter_t const * iter ) {
  return iter->error;
}

/* fwrite-style funcs *************************************************/

/* What follows are a bunch of serialization / writer functions.  They
   maintain the following properties:

     - file handle is 4 byte aligned
     - buf is the write buffer up to
     - cursor is the next free byte in buffer (or next byte after end of
       buf is space exhausted)
     - Invariant: cursor <= FD_PCAPNG_BLOCK_SZ
     - fwrite is called once per func and write size is 4 byte aligned
       and no larger than FD_PCAPNG_BLOCK_SZ */

/* FD_PCAPNG_FWRITE_OPT writes an option in the context of an fwrite-
   style function.  Assumes that given length is <=65532.

   Args:
     ushort t (option type)
     ushort l (option length)
     void * v (ptr to option data) */

#define FD_PCAPNG_FWRITE_OPT(t,l,v)                                    \
  do {                                                                 \
    ulong _sz       = (ushort)( l );                                   \
    ulong _sz_align = (ushort)fd_ulong_align_up( _sz, 4UL );           \
    if( FD_UNLIKELY( cursor+4UL+_sz_align > FD_PCAPNG_BLOCK_SZ ) ) {   \
      FD_LOG_WARNING(( "oversz pcapng block" ));                       \
      return 0UL;                                                      \
    }                                                                  \
    *(ushort *)( buf+cursor ) = ( (ushort)(t) ); cursor+=2UL;          \
    *(ushort *)( buf+cursor ) = ( (ushort)_sz ); cursor+=2UL;          \
    fd_memcpy  ( buf+cursor, (v), _sz );                               \
    fd_memset  ( buf+cursor+_sz, 0, _sz_align-_sz );                   \
    cursor+=_sz_align;                                                 \
  } while(0);

/* FD_PCAPNG_FWRITE_BLOCK_TERM terminates a block buffer being
   serialized in the context of an fwrite-style function. */

#define FD_PCAPNG_FWRITE_BLOCK_TERM()                                  \
  do {                                                                 \
    if( FD_UNLIKELY( cursor+4UL > FD_PCAPNG_BLOCK_SZ ) ) {             \
      FD_LOG_WARNING(( "oversz pcapng block" ));                       \
      return 0UL;                                                      \
    }                                                                  \
    block->block_sz         = (uint)(cursor+4UL);                      \
    *(uint *)( buf+cursor ) = (uint)(cursor+4UL);                      \
    cursor+=4UL;                                                       \
  } while(0);

ulong
fd_pcapng_fwrite_shb( fd_pcapng_shb_opts_t const * opt,
                      void *                       file ) {

  uchar buf[ FD_PCAPNG_BLOCK_SZ ];

  fd_pcapng_shb_t * block = (fd_pcapng_shb_t *)buf;

  ulong cursor = sizeof(fd_pcapng_shb_t);
  *block = (fd_pcapng_shb_t) {
    .block_type       = FD_PCAPNG_BLOCK_TYPE_SHB,
    /* block_sz set later */
    .byte_order_magic = FD_PCAPNG_BYTE_ORDER_MAGIC,
    .version_major    = (ushort)1,
    .version_minor    = (ushort)0,
    .section_sz       = ULONG_MAX
  };

  if( opt ) {
    if( opt->hardware ) FD_PCAPNG_FWRITE_OPT( FD_PCAPNG_SHB_OPT_HARDWARE, strlen( opt->hardware ), opt->hardware );
    if( opt->os       ) FD_PCAPNG_FWRITE_OPT( FD_PCAPNG_SHB_OPT_OS,       strlen( opt->os       ), opt->os       );
    if( opt->userappl ) FD_PCAPNG_FWRITE_OPT( FD_PCAPNG_SHB_OPT_USERAPPL, strlen( opt->userappl ), opt->userappl );
  }
  FD_PCAPNG_FWRITE_OPT( 0, 0, NULL );

  FD_PCAPNG_FWRITE_BLOCK_TERM();

  return fwrite( buf, cursor, 1UL, (FILE *)file );
}

ulong
fd_pcapng_fwrite_idb( uint                         link_type,
                      fd_pcapng_idb_opts_t const * opt,
                      void *                       file ) {

  uchar buf[ FD_PCAPNG_BLOCK_SZ ];

  fd_pcapng_idb_t * block = (fd_pcapng_idb_t *)buf;

  ulong cursor = sizeof(fd_pcapng_idb_t);
  *block = (fd_pcapng_idb_t) {
    .block_type       = FD_PCAPNG_BLOCK_TYPE_IDB,
    /* block_sz set later */
    .link_type        = (ushort)link_type,
    .snap_len         = 0U, /* FIXME should appropriately set snap_len
                               But this is not trivial.  Needs balancing
                               between buffer space available for meta
                               and payload. (meta is variable length) */
  };

  if( opt ) {

    if( opt->name[0] )
      FD_PCAPNG_FWRITE_OPT( FD_PCAPNG_IDB_OPT_NAME,      fd_cstr_nlen( opt->name, 16UL ),     opt->name     );
    if( fd_uint_load_4( opt->ip4_addr ) )
      FD_PCAPNG_FWRITE_OPT( FD_PCAPNG_IDB_OPT_IPV4_ADDR, 4UL,                                 opt->ip4_addr );
    if( fd_ulong_load_6( opt->mac_addr ) )
      FD_PCAPNG_FWRITE_OPT( FD_PCAPNG_IDB_OPT_MAC_ADDR,  6UL,                                 opt->mac_addr );

  /**/FD_PCAPNG_FWRITE_OPT( FD_PCAPNG_IDB_OPT_TSRESOL,   1UL,                                 &opt->tsresol );

    if( opt->hardware[0] )
      FD_PCAPNG_FWRITE_OPT( FD_PCAPNG_IDB_OPT_HARDWARE,  fd_cstr_nlen( opt->hardware, 64UL ), opt->hardware );

  }
  FD_PCAPNG_FWRITE_OPT( 0, 0, NULL );

  FD_PCAPNG_FWRITE_BLOCK_TERM();

  return fwrite( buf, cursor, 1UL, (FILE *)file );
}

ulong
fd_pcapng_fwrite_pkt( long         ts,
                      void const * payload,
                      ulong        payload_sz,
                      void *       _file ) {

  FILE * file = (FILE *)_file;
  FD_TEST( fd_ulong_is_aligned( (ulong)ftell( file ), 4UL ) );

  ulong cursor = sizeof(fd_pcapng_epb_t);
  fd_pcapng_epb_t block = {
    .block_type = FD_PCAPNG_BLOCK_TYPE_EPB,
    /* block_sz set later */
    .if_idx     = 0U,
    .ts_hi      = (uint)( (ulong)ts >> 32UL ),
    .ts_lo      = (uint)( (ulong)ts         ),
    .cap_len    = (uint)payload_sz,
    .orig_len   = (uint)payload_sz
  };

  ulong payload_sz_align = fd_ulong_align_up( payload_sz, 4UL );
  uchar pad[8UL]={0};
  ulong pad_sz = payload_sz_align-payload_sz;
  cursor+=payload_sz_align;

  /* Empty option list */
  cursor+=4UL;

  /* Trailer */
  block.block_sz = (uint)cursor+4U;

  /* write header */
  if( FD_UNLIKELY( 1UL!=fwrite( &block,  sizeof(fd_pcapng_epb_t), 1UL, file ) ) )
    return 0UL;
  /* copy payload */
  if( FD_UNLIKELY( 1UL!=fwrite( payload, payload_sz,              1UL, file ) ) )
    return 0UL;
  /* align */
  if( pad_sz )
    if( FD_UNLIKELY( 1UL!=fwrite( pad, pad_sz, 1UL, file ) ) )
      return 0UL;
  /* empty options */
  if( FD_UNLIKELY( 1UL!=fwrite( pad, 4UL,    1UL, file ) ) )
    return 0UL;
  /* write length trailer */
  if( FD_UNLIKELY( 1UL!=fwrite( &block.block_sz, 4UL, 1UL, file ) ) )
    return 0UL;

  return 1UL;
}

ulong
fd_pcapng_fwrite_tls_key_log( uchar const * log,
                              uint          log_sz,
                              void *        _file ) {

  FILE * file = (FILE *)_file;
  FD_TEST( fd_ulong_is_aligned( (ulong)ftell( file ), 4UL ) );

  ulong cursor = sizeof(fd_pcapng_dsb_t);
  fd_pcapng_dsb_t block = {
    .block_type  = FD_PCAPNG_BLOCK_TYPE_DSB,
    /* block_sz set later */
    .secret_type = FD_PCAPNG_SECRET_TYPE_TLS,
    .secret_sz   = log_sz
  };

  uint log_sz_align = fd_uint_align_up( log_sz, 4UL );
  uchar pad[8] = {0};
  ulong pad_sz = log_sz_align-log_sz;
  cursor+=log_sz_align;

  /* end of options block */
  cursor+=4UL;

  /* derive size ahead of time */
  block.block_sz = (uint)cursor + 4U;

  /* write header */
  if( FD_UNLIKELY( 1UL!=fwrite( &block, sizeof(fd_pcapng_dsb_t), 1UL, file ) ) )
    return 0UL;
  /* copy log */
  if( FD_UNLIKELY( 1UL!=fwrite( log, log_sz, 1UL, file ) ) )
    return 0UL;
  /* align */
  if( pad_sz )
    if( FD_UNLIKELY( 1UL!=fwrite( pad, pad_sz, 1UL, file ) ) )
      return 0UL;
  /* empty options */
  if( FD_UNLIKELY( 1UL!=fwrite( pad, 4UL,    1UL, file ) ) )
    return 0UL;
  /* write length trailer */
  if( FD_UNLIKELY( 1UL!=fwrite( &block.block_sz, sizeof(uint), 1, file ) ) )
    return 0UL;

  return 1UL;
}

#endif /* FD_HAS_HOSTED */
