#include "fd_backtest_src.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include "../../util/net/fd_pcap.h"
#include "../../util/net/fd_pcapng_private.h"
#if FD_HAS_ZSTD
#include <zstd.h>
#include "fd_libc_zstd.h"
#endif

#define FD_BACKT_SRC_INVAL       0x00
#define FD_BACKT_SRC_FMT_ROCKSDB 0x01
#define FD_BACKT_SRC_FMT_PCAP    0x02
#define FD_BACKT_SRC_FMT_PCAPNG  0x03
#define FD_BACKT_SRC_FMT_MASK    0x07
#define FD_BACKT_SRC_FLAG_ZSTD   0x08

extern fd_backt_src_t *
fd_backt_src_rocksdb_create( fd_backtest_src_opts_t const * opts );

extern fd_backt_src_t *
fd_backt_src_pcap_create( fd_backtest_src_opts_t const * opts,
                          uint                          format,
                          uint                          flags );

static uint
detect_src_type( char const * path ) {

  char path_tmp[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path_tmp, PATH_MAX, NULL, "%s/CURRENT", path ) );
  struct stat st;
  if( 0==stat( path_tmp, &st ) ) return FD_BACKT_SRC_FMT_ROCKSDB;

  int fd = open( path, O_RDONLY );
  if( FD_UNLIKELY( fd<0 ) ) {
    FD_LOG_WARNING(( "ledger auto detect failed: open(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    return FD_BACKT_SRC_INVAL;
  }

  uint magic;
  ulong _sz;
  if( FD_UNLIKELY( 0!=fd_io_read( fd, &magic, sizeof(uint), sizeof(uint), &_sz ) ) ) {
    FD_LOG_WARNING(( "ledger auto detect failed: cannot read file (%i-%s)", errno, fd_io_strerror( errno ) ));
    close( fd );
    return FD_BACKT_SRC_INVAL;
  }
  close( fd );

  if( magic == 0xa1b2c3d4U || magic == 0xa1b23c4dU ) {
    return FD_BACKT_SRC_FMT_PCAP;
  } else if( magic == FD_PCAPNG_BLOCK_TYPE_SHB ) {
    return FD_BACKT_SRC_FMT_PCAPNG;
  }

# if !FD_HAS_ZSTD
  FD_LOG_WARNING(( "ledger auto detect: unsupported file type" ));
  return FD_BACKT_SRC_INVAL;
# else
  if( magic != ZSTD_MAGICNUMBER ) {
    FD_LOG_WARNING(( "ledger auto detect failed: file type of \"%s\" is not recognized", path ));
    return FD_BACKT_SRC_INVAL;
  }

  FILE * file = fopen( path, "rb" );
  if( FD_UNLIKELY( !file ) ) {
    FD_LOG_WARNING(( "fopen(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    return FD_BACKT_SRC_INVAL;
  }

  ZSTD_DStream * dstream = ZSTD_createDStream();
  if( FD_UNLIKELY( !dstream ) ) FD_LOG_ERR(( "ZSTD_createDStream failed" ));

  FILE * zst_file = fd_zstd_rstream_open( file, dstream, 4UL<<20 );
  if( FD_UNLIKELY( !zst_file ) ) {
    FD_LOG_WARNING(( "fd_zstd_rstream_open(%s) failed", path ));
    FD_TEST( 0==fclose( file ) );
    ZSTD_freeDStream( dstream );
    return FD_BACKT_SRC_INVAL;
  }

  ulong nr_read = fread( &magic, sizeof(uint), 1, zst_file );
  int   err     = ferror( zst_file );
  FD_TEST( 0==fclose( zst_file ) );
  ZSTD_freeDStream( dstream );
  if( FD_UNLIKELY( nr_read!=1 ) ) {
    FD_LOG_WARNING(( "fread failed (%i-%s)", err, fd_io_strerror( err ) ));
    return FD_BACKT_SRC_INVAL;
  }

  if( magic == 0xa1b2c3d4U || magic == 0xa1b23c4dU ) {
    return FD_BACKT_SRC_FMT_PCAP | FD_BACKT_SRC_FLAG_ZSTD;
  } else if( magic == FD_PCAPNG_BLOCK_TYPE_SHB ) {
    return FD_BACKT_SRC_FMT_PCAPNG | FD_BACKT_SRC_FLAG_ZSTD;
  } else {
    FD_LOG_WARNING(( "ledger auto detect failed: compressed content of \"%s\" is not recognized (magic number %08x)", path, fd_uint_bswap( magic ) ));
    return FD_BACKT_SRC_INVAL;
  }
# endif
}

ulong
fd_backtest_src_first_shred( fd_backtest_src_opts_t const * opts,
                             uchar *                        buf,
                             ulong                          buf_sz ) {
  fd_backt_src_t * src = fd_backtest_src_create( opts );
  if( FD_UNLIKELY( !src ) ) return 0UL;
  ulong sz = src->vt->first_shred( src, buf, buf_sz );
  src->vt->destroy( src );
  return sz;
}

fd_backt_src_t *
fd_backtest_src_create( fd_backtest_src_opts_t const * opts ) {

  if( FD_UNLIKELY( !opts ) ) {
    FD_LOG_WARNING(( "NULL opts" ));
    return NULL;
  }
  if( FD_UNLIKELY( !opts->format ) ) {
    FD_LOG_WARNING(( "NULL opts.format" ));
    return NULL;
  }
  if( FD_UNLIKELY( !opts->path ) ) {
    FD_LOG_WARNING(( "NULL opts.path" ));
    return NULL;
  }

  uint src_type = detect_src_type( opts->path );
  uint fmt      = src_type & FD_BACKT_SRC_FMT_MASK;
  uint flags    = src_type & (uint)~FD_BACKT_SRC_FMT_MASK;

  if( 0==strcmp( opts->format, "auto" ) ) {
    if( src_type==FD_BACKT_SRC_INVAL ) return NULL;
  } else if( 0==strcmp( opts->format, "pcap" ) ) {
    if( !( fmt==FD_BACKT_SRC_FMT_PCAP || fmt==FD_BACKT_SRC_FMT_PCAPNG ) ) {
      FD_LOG_WARNING(( "cannot open ledger" ));
      return NULL;
    }
  } else if( 0==strcmp( opts->format, "rocksdb" ) ) {
    if( fmt!=FD_BACKT_SRC_FMT_ROCKSDB ) {
      FD_LOG_WARNING(( "cannot open ledger" ));
      return NULL;
    }
  } else {
    FD_LOG_WARNING(( "unsupported opts.format \"%s\"", opts->format ));
    return NULL;
  }

  switch( fmt ) {
    case FD_BACKT_SRC_FMT_ROCKSDB: return fd_backt_src_rocksdb_create( opts );
    case FD_BACKT_SRC_FMT_PCAP:
    case FD_BACKT_SRC_FMT_PCAPNG:  return fd_backt_src_pcap_create( opts, fmt, flags );
    default:
      FD_LOG_WARNING(( "unsupported detected source type" ));
      return NULL;
  }
}
