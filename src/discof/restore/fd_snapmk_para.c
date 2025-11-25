 #include "../../util/fd_util.h"
#include "../../tango/fd_tango.h"
#include "../../util/archive/fd_tar.h"
#include <errno.h>
#include <stdio.h>
#include <zstd.h>

#define SNAPMK_MAGIC        (0xf212f209fd944ba2UL)
#define SNAPMK_PARA_ENABLE  (0x72701281047a55b8UL)
#define SNAPMK_PARA_DISABLE (0xd629be3208ad6fb4UL)

#define WKSP_TAG (1UL)

#define COMP_TILE_MAX (63UL)

#define ORIG_PARA_ENABLE   1  /* start of parallel section */
#define ORIG_PARA_DISABLE  2  /* end of parallel section */
#define ORIG_SHUTDOWN      3  /* shutdown signal */

struct link {
  fd_frag_meta_t * mcache;
  uchar *          dcache;
  ulong            chunk0;
  ulong            chunk;
  ulong            wmark;
};

typedef struct link link_t;

static struct {
  fd_wksp_t * wksp;
  ulong       comp_cnt;
  ulong       comp_depth;
  ulong       comp_mtu;
  ulong *     wr_fseqs [ COMP_TILE_MAX ];
  link_t      tar_links[ COMP_TILE_MAX ];
  link_t      zst_links[ COMP_TILE_MAX ];
  ulong *     comp_fseq[ COMP_TILE_MAX ];
  FILE *      in_file;
  ulong       in_file_sz;
  FILE *      out_file;
  ulong       frame_sz;
} glob;

static int
rd_tile_exec( int     argc,
              char ** argv ) {
  (void)argc; (void)argv;

  fd_wksp_t * wksp       = glob.wksp;
  FILE *      in_file    = glob.in_file;
  ulong       in_file_sz = glob.in_file_sz;
  ulong       comp_cnt   = glob.comp_cnt;
  ulong       comp_depth = glob.comp_depth;
  link_t *    tar_links  = glob.tar_links;
  ulong **    comp_fseqs = glob.comp_fseq;
  ulong       out_seqs [ COMP_TILE_MAX ] = {0UL};
  fd_fctl_t * fctls    [ COMP_TILE_MAX ] = {0UL};
  ulong       cr_avails[ COMP_TILE_MAX ] = {0UL};
  ulong       mtu        = glob.comp_mtu;
  ulong       frame_off  = 0UL;

  ulong slow_diag = 0UL;
  uchar fctl_mem[ COMP_TILE_MAX*FD_FCTL_FOOTPRINT( 1UL ) ] __attribute__((aligned(FD_FCTL_ALIGN)));
  for( ulong i=0UL; i<comp_cnt; i++ ) {
    fd_fctl_t * fctl = fd_fctl_join( fd_fctl_new( fctl_mem+(i*FD_FCTL_FOOTPRINT( 1UL )), COMP_TILE_MAX ) );
    FD_TEST( fctl );
    FD_TEST( fd_fctl_cfg_rx_add( fctl, comp_depth, comp_fseqs[i], &slow_diag ) );
    FD_TEST( fd_fctl_cfg_done( fctl, 1UL, 0UL, 0UL, 0UL ) );
    fctls[ i ] = fctl;
  }

  /* Enable load-balancing once first accounts/ file was found */
  _Bool enable_lb = 0;

  FD_LOG_NOTICE(( "Reader start" ));

  ulong out_idx       = 0UL;
  ulong last_stat_off = 0UL;
  long  last_stat     = fd_log_wallclock();
  for(;;) {
    long off = ftell( in_file );
    if( FD_LIKELY( off>=0L ) ) {
      ulong since_last_stat = (ulong)off - last_stat_off;
      if( FD_UNLIKELY( since_last_stat>=(1UL<<27) ) ) {
        long now = fd_log_wallclock();
        last_stat_off = (ulong)off;
        FD_LOG_NOTICE(( "%8.3f / %8.3f GB (%4.1f %%)  %8.2f MB/s",
            (double)last_stat_off/1e9,
            (double)in_file_sz   /1e9,
            100.0 * (double)last_stat_off/(double)in_file_sz,
            ((double)since_last_stat*1e3) / (double)(now - last_stat) ));
        last_stat = now;
      }
    }

    /* Process TAR header */

    ulong   chunk       = tar_links[ out_idx ].chunk;
    void *  chunk_laddr = fd_chunk_to_laddr( wksp, chunk );
    union {
      fd_tar_meta_t hdr;
      uchar         buf[512];
    } * tar = chunk_laddr;
    if( FD_UNLIKELY( fread( tar, sizeof(tar->hdr), 1UL, in_file )!=1UL ) ) {
      int err = ferror( in_file );
      FD_LOG_ERR(( "fread failed (%i-%s)", err, fd_io_strerror( err ) ));
    }

    if( FD_UNLIKELY( memcmp( tar->hdr.magic, FD_TAR_MAGIC, 5UL ) ) ) {
      int not_zero = 0;
      for( ulong i=0UL; i<512UL; i++ ) not_zero |= tar->buf[i];
      if( FD_UNLIKELY( not_zero ) ) FD_LOG_ERR(( "invalid tar header magic `%s`", tar->hdr.magic ));

      /* EOF marker reached */

      /* Broadcast barrier signal, for non-zero tile also shutdown signal */
      for( ulong out2=0UL; out2<comp_cnt; out2++ ) {
        while( cr_avails[ out2 ]<3 ) {
          cr_avails[ out2 ] = fd_fctl_tx_cr_update( fctls[ out2 ], cr_avails[ out2 ], out_seqs[ out2 ] );
        }
        fd_mcache_publish(
            tar_links[ out2 ].mcache,
            comp_depth,
            out_seqs[ out2 ]++,
            0UL,
            0UL,
            0UL,
            fd_frag_meta_ctl( 0UL, 0, 1, 0 ),
            0UL,
            0UL
        );
        fd_mcache_publish(
            tar_links[ out2 ].mcache,
            comp_depth,
            out_seqs[ out2 ]++,
            0UL,
            0UL,
            0UL,
            fd_frag_meta_ctl( ORIG_PARA_DISABLE, 0, 1, 0 ),
            0UL,
            0UL
        );
        cr_avails[ out2 ]--;
        if( out2>0UL ) {
          fd_mcache_publish(
              tar_links[ out2 ].mcache,
              comp_depth,
              out_seqs[ out2 ]++,
              0UL,
              0UL,
              0UL,
              fd_frag_meta_ctl( ORIG_SHUTDOWN, 0, 1, 0 ),
              0UL,
              0UL
          );
          cr_avails[ out2 ]--;
        }
      }

      /* Seek back since we need to retransmit EOF marker */
      if( FD_UNLIKELY( fseek( in_file, -512L, SEEK_CUR ) ) ) {
        FD_LOG_ERR(( "fseek failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      }

      break;
    }

    ulong const file_sz = fd_tar_meta_get_size( &tar->hdr );
    if( FD_UNLIKELY( file_sz==ULONG_MAX ) ) FD_LOG_ERR(( "invalid tar file size" ));

    if( FD_UNLIKELY( tar->hdr.typeflag!=FD_TAR_TYPE_DIR && !fd_tar_meta_is_reg( &tar->hdr ) ) ) {
      FD_LOG_WARNING(( "invalid tar header type %d", tar->hdr.typeflag ));
    }
    ulong const align_sz = fd_ulong_align_up( file_sz, 512UL );

    /* See if we can switch to load-balancing */

    if( FD_UNLIKELY( !enable_lb ) ) {
      if( 0==strncmp( tar->hdr.name, "accounts/", 9UL ) ) {
        /* Send barrier signal */
        while( !cr_avails[ out_idx ] ) {
          cr_avails[ out_idx ] = fd_fctl_tx_cr_update( fctls[ out_idx ], cr_avails[ out_idx ], out_seqs[ out_idx ] );
        }
        fd_mcache_publish(
            tar_links[ out_idx ].mcache,
            comp_depth,
            out_seqs[ out_idx ]++,
            0UL,
            0UL,
            0UL,
            fd_frag_meta_ctl( ORIG_PARA_ENABLE, 0, 1, 0 ),
            0UL,
            0UL
        );
        /* Poll for barrier receive */
        ulong * wr_fseq = glob.wr_fseqs[0];
        for(;;) {
          FD_COMPILER_MFENCE();
          ulong sig = FD_VOLATILE_CONST( wr_fseq[1] );
          FD_COMPILER_MFENCE();
          if( sig==1UL ) break;
          FD_SPIN_PAUSE();
        }
        FD_LOG_NOTICE(( "Reader enabling load-balancing" ));
        enable_lb = 1;
      }
    }

    /* Send data frags */

    _Bool   eom      = 0;
    ulong   rem      = align_sz;
    uchar * data     = (uchar *)( tar+1 );
    ulong   data_max = mtu - 512UL;
    do {
      while( !cr_avails[ out_idx ] ) {
        cr_avails[ out_idx ] = fd_fctl_tx_cr_update( fctls[ out_idx ], cr_avails[ out_idx ], out_seqs[ out_idx ] );
      }

      ulong data_sz = fd_ulong_min( rem, data_max );
      if( data_sz ) {
        if( FD_UNLIKELY( fread( data, data_sz, 1UL, in_file )!=1UL ) ) {
          FD_LOG_ERR(( "fread failed (%i-%s)", errno, fd_io_strerror( errno ) ));
        }
      }
      rem -= data_sz;
      if( !rem ) {
        frame_off += 512UL + align_sz;
        eom = frame_off>=glob.frame_sz;
      }

      //if( eom ) FD_LOG_NOTICE(( "finished burst out_idx=%lu out_seq=%lu sz=%lu", out_idx, out_seqs[ out_idx ], frame_off ));
      ulong frag_sz = (ulong)data+data_sz-(ulong)chunk_laddr;
      fd_mcache_publish(
          tar_links[ out_idx ].mcache,
          comp_depth,
          out_seqs[ out_idx ]++,
          frag_sz,
          chunk,
          0UL,
          fd_frag_meta_ctl( 0UL, 0, eom, 0 ),
          0UL,
          0UL
      );
      cr_avails[ out_idx ]--;

      chunk       = fd_dcache_compact_next( chunk, frag_sz, tar_links[ out_idx ].chunk0, tar_links[ out_idx ].wmark );
      chunk_laddr = fd_chunk_to_laddr( wksp, chunk );
      data        = chunk_laddr;
      data_max    = mtu;
      tar_links[ out_idx ].chunk = chunk;
    } while( rem );

    /* Select next index */

    if( eom && enable_lb ) {
      frame_off = 0UL;
      out_idx++;
      if( out_idx>=comp_cnt ) out_idx = 0UL;
    }
  }

  /* Send tail end of data to tile 0 */
  for(;;) {
    size_t read_sz = fread( fd_chunk_to_laddr( wksp, tar_links[ 0UL ].chunk ), 1UL, mtu, in_file );
    if( FD_UNLIKELY( read_sz==0UL ) ) {
      if( feof( in_file ) ) break;
      FD_LOG_ERR(( "fread failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    while( !cr_avails[ 0UL ] ) {
      cr_avails[ 0UL ] = fd_fctl_tx_cr_update( fctls[ 0UL ], cr_avails[ 0UL ], out_seqs[ 0UL ] );
    }
    fd_mcache_publish(
        tar_links[ 0UL ].mcache,
        comp_depth,
        out_seqs[ 0UL ]++,
        read_sz,
        tar_links[ 0UL ].chunk,
        0UL,
        fd_frag_meta_ctl( 0UL, 0, 0, 0 ),
        0UL,
        0UL
    );
    cr_avails[ 0UL ]--;
    tar_links[ 0UL ].chunk = fd_dcache_compact_next( tar_links[ 0UL ].chunk, read_sz, tar_links[ 0UL ].chunk0, tar_links[ 0UL ].wmark );
  }

  /* Write shutdown signal */
  while( cr_avails[ 0 ]<2 ) cr_avails[ 0 ] = fd_fctl_tx_cr_update( fctls[ 0 ], cr_avails[ 0 ], out_seqs[ 0 ] );
  fd_mcache_publish(
      tar_links[ 0 ].mcache,
      comp_depth,
      out_seqs[ 0 ]++,
      0UL,
      0UL,
      0UL,
      fd_frag_meta_ctl( 0UL, 0, 1, 0 ),
      0UL,
      0UL
  );
  fd_mcache_publish(
      tar_links[ 0 ].mcache,
      comp_depth,
      out_seqs[ 0 ]++,
      0UL,
      tar_links[ 0 ].chunk,
      0UL,
      fd_frag_meta_ctl( ORIG_SHUTDOWN, 0, 1, 0 ),
      0UL,
      0UL
  );
  cr_avails[ 0 ]--;

  FD_LOG_NOTICE(( "Reader done" ));

  return 0;
}

static int
comp_tile_exec( int     argc,
                char ** argv ) {
  (void)argc; (void)argv;

  uint rng_seed = (uint)fd_ulong_hash( (uint)fd_tickcount()+fd_tile_idx() );
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, rng_seed, 0UL ) );

  fd_wksp_t *      wksp       = glob.wksp;
  ulong            comp_idx   = fd_tile_idx()-2UL; FD_TEST( fd_tile_idx()>=2UL );
  ulong            depth      = glob.comp_depth;
  fd_frag_meta_t * in_mcache  = glob.tar_links[ comp_idx ].mcache;
  ulong            in_seq     = 0UL;
  ulong *          fseq       = glob.comp_fseq[ comp_idx ];
  fd_frag_meta_t * out_mcache = glob.zst_links[ comp_idx ].mcache;
  uchar *          out_dcache = glob.zst_links[ comp_idx ].dcache;
  ulong            out_chunk0 = glob.zst_links[ comp_idx ].chunk0;
  ulong            out_seq    = 0UL;

  uchar fctl_mem[ FD_FCTL_FOOTPRINT( 1UL ) ] __attribute__((aligned(FD_FCTL_ALIGN)));
  fd_fctl_t * fctl = fd_fctl_join( fd_fctl_new( fctl_mem, 1UL ) );
  FD_TEST( fctl );
  ulong slow_diag;
  FD_TEST( fd_fctl_cfg_rx_add( fctl, depth, glob.wr_fseqs[ comp_idx ], &slow_diag ) );
  FD_TEST( fd_fctl_cfg_done( fctl, 1UL, 0UL, 0UL, 0UL ) );

  ulong async_min = 1UL<<7;
  ulong async_rem = 1UL; /* Do housekeeping on first iteration */
  ulong cr_avail  = 0UL;

  ZSTD_CStream * zst = ZSTD_createCStream();
  if( FD_UNLIKELY( !zst ) ) FD_LOG_ERR(( "ZSTD_createCStream() failed" ));
  ZSTD_initCStream( zst, 3 );

  ulong out_chunk = out_chunk0;
  ulong out_mtu   = ZSTD_COMPRESSBOUND( glob.comp_mtu );
  ZSTD_outBuffer zst_out = {
    .dst  = fd_chunk_to_laddr( wksp, out_chunk ),
    .size = out_mtu,
    .pos  = 0UL
  };

  for(;;) {
    fd_frag_meta_t const * mline;
    ulong                  seq_found;
    long                   diff;

    ulong in_sig;
    ulong in_chunk;
    ulong in_sz;
    ulong in_ctl;
    ulong in_tsorig;
    ulong in_tspub;
    FD_MCACHE_WAIT_REG( in_sig, in_chunk, in_sz, in_ctl, in_tsorig, in_tspub, mline, seq_found, diff, async_rem, in_mcache, depth, in_seq );
    (void)mline; (void)seq_found; (void)in_sz; (void)in_tsorig; (void)in_tspub;

    if( FD_UNLIKELY( !async_rem ) ) {
      fd_fctl_rx_cr_return( fseq, in_seq );
      cr_avail = fd_fctl_tx_cr_update( fctl, cr_avail, out_seq );
      async_rem = fd_tempo_async_reload( rng, async_min );
      continue;
    }

    if( FD_UNLIKELY( diff>0 ) ) {
      FD_LOG_ERR(( "Overrun while polling" ));
    }
    FD_TEST( diff==0 );

    ulong in_orig = fd_frag_meta_ctl_orig( in_ctl );
    if( FD_UNLIKELY( in_orig ) ) {
      FD_TEST( zst_out.pos==0 );

      /* Forward control signal */
      while( !cr_avail ) cr_avail = fd_fctl_tx_cr_update( fctl, cr_avail, out_seq );
      fd_mcache_publish( out_mcache, depth, out_seq++, 0UL, 0UL, 0UL, fd_frag_meta_ctl( in_orig, 0, 0, 0 ), 0UL, 0UL );
      in_seq = fd_seq_inc( in_seq, 1UL );

      if( in_orig==ORIG_SHUTDOWN ) break;
      continue;
    }

    ZSTD_inBuffer zst_in = {
      .src    = fd_chunk_to_laddr( wksp, in_chunk ),
      .size   = in_sig,
      .pos    = 0UL
    };
    for(;;) {
      size_t const ret = ZSTD_compressStream( zst, &zst_out, &zst_in );
      if( FD_UNLIKELY( ZSTD_isError( ret ) ) ) {
        FD_LOG_ERR(( "ZSTD_compressStream() failed: %s", ZSTD_getErrorName( ret ) ));
      }
      if( FD_LIKELY( zst_in.pos==zst_in.size ) ) break;

      /* Flush */
      ulong chunk_sz = zst_out.pos;
      while( !cr_avail ) cr_avail = fd_fctl_tx_cr_update( fctl, cr_avail, out_seq );
      fd_mcache_publish( out_mcache, depth, out_seq++, chunk_sz, out_chunk, 0UL, fd_frag_meta_ctl( 0UL, 0, 0, 0 ), 0UL, 0UL );
      out_chunk = fd_dcache_compact_next( out_chunk, chunk_sz, out_chunk0, glob.zst_links[ comp_idx ].wmark );
      cr_avail--;
      zst_out.dst = fd_chunk_to_laddr( wksp, out_chunk );
      zst_out.pos = 0UL;
    }

    if( fd_frag_meta_ctl_eom( in_ctl ) ) {
      for(;;) {
        ulong ret = ZSTD_endStream( zst, &zst_out );
        if( FD_UNLIKELY( ZSTD_isError( ret ) ) ) {
          FD_LOG_ERR(( "ZSTD_endStream() failed: %s", ZSTD_getErrorName( ret ) ));
        }

        /* Flush */
        int eom = !ret;
        ulong chunk_sz = zst_out.pos;
        while( !cr_avail ) cr_avail = fd_fctl_tx_cr_update( fctl, cr_avail, out_seq );
        fd_mcache_publish( out_mcache, depth, out_seq++, chunk_sz, out_chunk, 0UL, fd_frag_meta_ctl( 0UL, 0, eom, 0 ), 0UL, 0UL );
        out_chunk = fd_dcache_compact_next( out_chunk, chunk_sz, out_chunk0, glob.zst_links[ comp_idx ].wmark );
        cr_avail--;
        zst_out.dst = fd_chunk_to_laddr( wksp, out_chunk );
        zst_out.pos = 0UL;
        // if( eom ) FD_LOG_NOTICE(( "finished burst comp_idx=%lu in_seq=%lu out_seq=%lu", comp_idx, in_seq, out_seq-1UL ));
        if( eom ) break;
      }
    }

    in_seq = fd_seq_inc( in_seq, 1UL );
  }

  if( zst_out.pos < zst_out.size ) {
    /* Flush */
    ulong chunk_sz = zst_out.pos;
    while( !cr_avail ) cr_avail = fd_fctl_tx_cr_update( fctl, cr_avail, out_seq );
    fd_mcache_publish( out_mcache, depth, out_seq++, chunk_sz, out_chunk, 0UL, fd_frag_meta_ctl( 0UL, 0, 1, 0 ), 0UL, 0UL );
    out_chunk = fd_dcache_compact_next( out_chunk, chunk_sz, out_chunk0, glob.zst_links[ comp_idx ].wmark );
    cr_avail--;
    zst_out.dst = fd_chunk_to_laddr( out_dcache, out_chunk );
    zst_out.pos = 0UL;
  }

  fd_mcache_seq_update( fd_mcache_seq_laddr( out_mcache ), out_seq );

  fd_rng_delete( fd_rng_leave( rng ) );

  return 0;
}

static int
wr_tile_exec( int     argc,
              char ** argv ) {
  (void)argc; (void)argv;

  uint rng_seed = (uint)fd_ulong_hash( (uint)fd_tickcount()+fd_tile_idx() );
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, rng_seed, 0UL ) );

  fd_wksp_t * wksp    = glob.wksp;
  ulong      comp_cnt = glob.comp_cnt;
  ulong      depth    = glob.comp_depth;
  FILE *     out_file = glob.out_file;
  ulong **   fseqs    = glob.wr_fseqs;
  ulong      in_seqs[ COMP_TILE_MAX ] = {0UL};

  ulong active_set = (1UL<<comp_cnt)-1UL;
  ulong drain_set  = (1UL<<comp_cnt)-1UL;
  ulong dirty_set  = 0UL;

  uchar fctl_mem[ FD_FCTL_FOOTPRINT( COMP_TILE_MAX ) ] __attribute__((aligned(FD_FCTL_ALIGN)));
  fd_fctl_t * fctl = fd_fctl_join( fd_fctl_new( fctl_mem, COMP_TILE_MAX ) );
  FD_TEST( fctl );
  ulong slow_diag;
  for( ulong i=0UL; i<comp_cnt; i++ ) {
    FD_TEST( fd_fctl_cfg_rx_add( fctl, glob.comp_depth, glob.comp_fseq[i], &slow_diag ) );
  }
  FD_TEST( fd_fctl_cfg_done( fctl, 1UL, 0UL, 0UL, 0UL ) );

  ulong async_min = 1UL<<7;
  ulong async_rem = 1UL; /* Do housekeeping on first iteration */

  ulong in_idx = 0UL;

  _Bool sent_enable = 0;

  FD_LOG_NOTICE(( "Writer running" ));

  for(;;) {

    fd_frag_meta_t * in_mcache = glob.zst_links[ in_idx ].mcache;

    fd_frag_meta_t const * mline;
    ulong                  seq_found;
    long                   diff;

    ulong in_sig;
    ulong in_chunk;
    ulong in_sz;
    ulong in_ctl;
    ulong in_tsorig;
    ulong in_tspub;
    FD_MCACHE_WAIT_REG( in_sig, in_chunk, in_sz, in_ctl, in_tsorig, in_tspub, mline, seq_found, diff, async_rem, in_mcache, depth, in_seqs[ in_idx ] );
    (void)mline; (void)seq_found; (void)in_sz; (void)in_tsorig; (void)in_tspub;

    if( FD_UNLIKELY( !async_rem ) ) {
      if( FD_UNLIKELY( !active_set ) ) break;

      if( !fd_ulong_extract_bit( dirty_set, (int)in_idx ) ) {
        in_idx++;
        if( in_idx>=comp_cnt ) in_idx = 0UL;
      }

      for( ulong i=0UL; i<comp_cnt; i++ ) {
        fd_fctl_rx_cr_return( fseqs[i], in_seqs[i] );
      }
      async_rem = fd_tempo_async_reload( rng, async_min );
      continue;
    }

    if( FD_UNLIKELY( diff>0 ) ) {
      FD_LOG_ERR(( "Overrun while polling" ));
    }
    FD_TEST( diff==0 );

    ulong in_orig = fd_frag_meta_ctl_orig( in_ctl );
    if( FD_UNLIKELY( in_orig ) ) {
      if( in_orig==ORIG_PARA_ENABLE && !sent_enable ) {
        struct __attribute__((packed)) {
          uint  magic;
          uint  frame_sz;
          ulong user;
        } header = {
          .magic    = 0x184D2A50U,
          .frame_sz = 8U,
          .user     = SNAPMK_PARA_ENABLE
        };
        if( FD_UNLIKELY( fwrite( &header, sizeof(header), 1UL, out_file )!=1UL ) ) {
          FD_LOG_ERR(( "fwrite failed (%i-%s)", errno, fd_io_strerror( errno ) ));
        }
        FD_VOLATILE( fseqs[ in_idx ][1] ) = 1UL;
        sent_enable = 1;
      } else if( in_orig==ORIG_PARA_DISABLE ) {
        drain_set = fd_ulong_clear_bit( drain_set, (int)in_idx );
        if( drain_set ) continue;

        struct __attribute__((packed)) {
          uint  magic;
          uint  frame_sz;
          ulong user;
        } header = {
          .magic    = 0x184D2A50U,
          .frame_sz = 8U,
          .user     = SNAPMK_PARA_DISABLE
        };
        if( FD_UNLIKELY( fwrite( &header, sizeof(header), 1UL, out_file )!=1UL ) ) {
          FD_LOG_ERR(( "fwrite failed (%i-%s)", errno, fd_io_strerror( errno ) ));
        }

      } else if( in_orig==ORIG_SHUTDOWN ) {
        FD_TEST( !fd_ulong_extract_bit( dirty_set, (int)in_idx ) );
        active_set = fd_ulong_clear_bit( active_set, (int)in_idx );
      }
      in_seqs[ in_idx ] = fd_seq_inc( in_seqs[ in_idx ], 1UL );
      if( in_orig==ORIG_SHUTDOWN || in_orig==ORIG_PARA_DISABLE ) {
        in_idx++;
        if( in_idx>=comp_cnt ) in_idx = 0UL;
      }
      continue;
    }

    if( in_sig ) {
      void const * in_frag = fd_chunk_to_laddr( wksp, in_chunk );
      ulong wr_sz = fwrite( in_frag, in_sig, 1UL, out_file );
      if( FD_UNLIKELY( wr_sz!=1UL ) ) {
        FD_LOG_ERR(( "fwrite failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      }
    }

    in_seqs[ in_idx ] = fd_seq_inc( in_seqs[ in_idx ], 1UL );

    int eom = fd_frag_meta_ctl_eom( in_ctl );
    if( eom ) {
      // FD_LOG_NOTICE(( "finished write comp_idx=%lu in_seq=%lu", in_idx, in_seqs[ in_idx ]-1UL ));
      dirty_set = fd_ulong_clear_bit( dirty_set, (int)in_idx );
      in_idx++;
      if( in_idx>=comp_cnt ) in_idx = 0UL;
      // FD_LOG_NOTICE(( "switching to comp_idx=%lu", in_idx ));
    } else {
      dirty_set = fd_ulong_set_bit( dirty_set, (int)in_idx );
    }
  }

  FD_LOG_NOTICE(( "Writer done" ));

  return 0;
}

__attribute__((noreturn)) static void
usage( int rc ) {
  fputs( "Usage: fd_snapmk_para --in FILE.tar --out FILE.tar.zst\n", stderr );
  exit( rc );
}

int
main( int     argc,
      char ** argv ) {
  if( fd_env_strip_cmdline_contains( &argc, &argv, "--help" ) ) {
    fputs( "fd_snapmk creates a backwards-compatible Firedancer-optimized Solana snapshot\n", stderr );
    usage( EXIT_SUCCESS );
  }

  fd_boot( &argc, &argv );

  char const * _page_sz  = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--page-sz",    NULL,      "gigantic" );
  ulong        page_cnt  = fd_env_strip_cmdline_ulong ( &argc, &argv, "--page-cnt",   NULL,             1UL );
  ulong        near_cpu  = fd_env_strip_cmdline_ulong ( &argc, &argv, "--near-cpu",   NULL, fd_log_cpu_id() );
  char const * in_path    = fd_env_strip_cmdline_cstr ( &argc, &argv, "--in",         NULL,            NULL );
  char const * out_path   = fd_env_strip_cmdline_cstr ( &argc, &argv, "--out",        NULL,            NULL );
  ulong        frame_sz   = fd_env_strip_cmdline_ulong( &argc, &argv, "--frame-sz",   NULL,      33554432UL );
  ulong        depth      = fd_env_strip_cmdline_ulong( &argc, &argv, "--depth",      NULL,            32UL );
  ulong        mtu        = fd_env_strip_cmdline_ulong( &argc, &argv, "--mtu",        NULL,         1UL<<20 );

  if( FD_UNLIKELY( !in_path ) ) usage( EXIT_FAILURE );
  if( !out_path ) {
    ulong in_len = strlen( in_path );
    if( FD_UNLIKELY( in_len+strlen( ".zst" )+1UL>PATH_MAX ) ) FD_LOG_ERR(( "--in argument is too long" ));
    static char output_path[ PATH_MAX ];
    fd_cstr_fini( fd_cstr_append_cstr( fd_cstr_append_text( fd_cstr_init( output_path ), in_path, in_len ), ".zst" ) );
    out_path = output_path;
  }

  if( FD_UNLIKELY( fd_tile_cnt()<3 ) ) FD_LOG_ERR(( "This program requires at least 3 tiles" ));
  ulong comp_cnt = fd_tile_cnt() - 2UL;
  comp_cnt = fd_ulong_min( comp_cnt, COMP_TILE_MAX );

  FILE * in_file = fopen( in_path, "rb" );
  if( FD_UNLIKELY( !in_file ) ) {
    FD_LOG_ERR(( "fopen(%s,\"rb\") failed (%i-%s)", in_path, errno, fd_io_strerror( errno ) ));
  }
  ulong in_file_sz;
  if( FD_UNLIKELY( fseek( in_file, 0L, SEEK_END )!=0 ) ) {
    FD_LOG_ERR(( "fseek(%s,0,SEEK_END) failed (%i-%s)", in_path, errno, fd_io_strerror( errno ) ));
  }
  long ftell_res = ftell( in_file );
  if( FD_UNLIKELY( ftell_res<0L ) ) {
    FD_LOG_ERR(( "ftell(%s) failed (%i-%s)", in_path, errno, fd_io_strerror( errno ) ));
  }
  in_file_sz = (ulong)ftell_res;
  if( FD_UNLIKELY( fseek( in_file, 0L, SEEK_SET )!=0 ) ) {
    FD_LOG_ERR(( "fseek(%s,0,SEEK_SET) failed (%i-%s)", in_path, errno, fd_io_strerror( errno ) ));
  }
  glob.in_file    = in_file;
  glob.in_file_sz = in_file_sz;

  FILE * out_file = fopen( out_path, "wb" );
  if( FD_UNLIKELY( !out_file ) ) {
    FD_LOG_ERR(( "fopen(%s,\"wb\") failed (%i-%s)", out_path, errno, fd_io_strerror( errno ) ));
  }
  glob.out_file = out_file;

  struct __attribute__((packed)) {
    uint  magic;
    uint  frame_sz;
    ulong user;
  } header = {
    .magic    = 0x184D2A50U,
    .frame_sz = 8U,
    .user     = SNAPMK_MAGIC
  };
  if( FD_UNLIKELY( fwrite( &header, sizeof(header), 1UL, out_file )!=1UL ) ) {
    FD_LOG_ERR(( "fwrite header to %s failed (%i-%s)", out_path, errno, fd_io_strerror( errno ) ));
  }

  FD_LOG_NOTICE(( "--wksp not specified, using an anonymous local workspace, --page-sz %s, --page-cnt %lu, --near-cpu %lu",
                  _page_sz, page_cnt, near_cpu ));
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, near_cpu, "wksp", 0UL );

  if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "Unable to attach to wksp" ));
  glob.wksp       = wksp;
  glob.comp_cnt   = comp_cnt;
  glob.comp_depth = depth;
  glob.frame_sz   = frame_sz;
  glob.comp_mtu   = mtu;

  ulong tar_dcache_sz = fd_dcache_req_data_sz( mtu, depth, 1UL, 1 );
  ulong zst_dcache_sz = fd_dcache_req_data_sz( ZSTD_COMPRESSBOUND( mtu ), depth, 1UL, 1 );

  for( ulong i=0UL; i<comp_cnt; i++ ) {
    link_t * tar = &glob.tar_links[i];
    tar->mcache = fd_mcache_join( fd_mcache_new( fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( depth, 0UL ), WKSP_TAG ), depth, 0UL, 0UL ) );
    FD_TEST( tar->mcache );
    tar->dcache = fd_dcache_join( fd_dcache_new( fd_wksp_alloc_laddr( wksp, fd_dcache_align(), fd_dcache_footprint( tar_dcache_sz, 0UL ), WKSP_TAG ), tar_dcache_sz, 0UL ) );
    FD_TEST( tar->dcache );
    tar->chunk0 = fd_dcache_compact_chunk0( wksp, tar->dcache );
    tar->chunk  = tar->chunk0;
    tar->wmark  = fd_dcache_compact_wmark ( wksp, tar->dcache, mtu );

    link_t * zst = &glob.zst_links[i];
    zst->mcache = fd_mcache_join( fd_mcache_new( fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( depth, 0UL ), WKSP_TAG ), depth, 0UL, 0UL ) );
    FD_TEST( zst->mcache );
    zst->dcache = fd_dcache_join( fd_dcache_new( fd_wksp_alloc_laddr( wksp, fd_dcache_align(), fd_dcache_footprint( zst_dcache_sz, 0UL ), WKSP_TAG ), zst_dcache_sz, 0UL ) );
    FD_TEST( zst->dcache );
    zst->chunk0 = fd_dcache_compact_chunk0( wksp, zst->dcache );
    zst->chunk  = zst->chunk0;
    zst->wmark  = fd_dcache_compact_wmark ( wksp, zst->dcache, mtu );

    glob.wr_fseqs[i] = fd_fseq_join( fd_fseq_new( fd_wksp_alloc_laddr( wksp, fd_fseq_align(), fd_fseq_footprint(), WKSP_TAG ), 0UL ) );
    FD_TEST( glob.wr_fseqs[i] );

    glob.comp_fseq[i] = fd_fseq_join( fd_fseq_new( fd_wksp_alloc_laddr( wksp, fd_fseq_align(), fd_fseq_footprint(), WKSP_TAG ), 0UL ) );
    FD_TEST( glob.comp_fseq[i] );
  }

  fd_tile_exec_t * wr_exec = fd_tile_exec_new( 1UL, wr_tile_exec, 0, NULL );
  FD_TEST( wr_exec );

  fd_tile_exec_t * comp_exec[ COMP_TILE_MAX ];
  for( ulong i=0UL; i<comp_cnt; i++ ) {
    comp_exec[ i ] = fd_tile_exec_new( 2UL+i, comp_tile_exec, 0, NULL );
  }

  long dt = -fd_log_wallclock();
  rd_tile_exec( 0, NULL );

  for( ulong i=0UL; i<comp_cnt; i++ ) {
    FD_TEST( !fd_tile_exec_delete( comp_exec[ i ], NULL ) );
  }
  FD_TEST( !fd_tile_exec_delete( wr_exec, NULL ) );

  if( FD_UNLIKELY( 0!=fclose( in_file ) ) ) {
    FD_LOG_ERR(( "fclose(%s) failed (%i-%s)", in_path, errno, fd_io_strerror( errno ) ));
  }

  ftell_res = ftell( out_file );
  if( FD_UNLIKELY( ftell_res<0L ) ) {
    FD_LOG_ERR(( "ftell(%s) failed (%i-%s)", out_path, errno, fd_io_strerror( errno ) ));
  }
  ulong out_file_sz = (ulong)ftell_res;

  if( FD_UNLIKELY( 0!=fclose( out_file ) ) ) {
    FD_LOG_ERR(( "fclose(%s) failed (%i-%s)", out_path, errno, fd_io_strerror( errno ) ));
  }
  dt += fd_log_wallclock();
  FD_LOG_NOTICE(( "Compressed %.3f GiB to %.3f GiB in %.3f s (%.3f GB/s, ratio %.2f)",
                  (double)in_file_sz/(double)(1UL<<30),
                  (double)out_file_sz/(double)(1UL<<30),
                  (double)dt/1e9,
                  ((double)in_file_sz)/((double)dt),
                  (double)in_file_sz/(double)out_file_sz ));

  fd_wksp_delete_anonymous( wksp );

  fd_halt();
  return 0;
}
