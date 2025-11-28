#include "fd_vinyl.h"

ulong
fd_vinyl_align( void ) {
  return alignof(fd_vinyl_t);
}

ulong
fd_vinyl_footprint( void ) {
  return sizeof(fd_vinyl_t);
}

fd_vinyl_t *
fd_vinyl_init( fd_tpool_t * tpool, ulong t0, ulong t1, int level,
               void * _vinyl,
               void * _cnc,  ulong cnc_footprint,
               void * _meta, ulong meta_footprint,
               void * _line, ulong line_footprint,
               void * _ele,  ulong ele_footprint,
               void * _obj,  ulong obj_footprint,
               fd_vinyl_io_t * io,
               ulong           seed,
               void *          obj_laddr0,
               ulong           async_min,
               ulong           async_max,
               ulong           part_thresh,
               ulong           gc_thresh,
               int             gc_eager,
               int             style ) {
  if( t1<=t0 ) t0 = 0UL, t1 = 1UL;

  FD_LOG_NOTICE(( "Testing vinyl configuration" ));

# define TEST( c ) do { if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: %s", #c )); return NULL; } } while(0)

  TEST( _vinyl ); TEST( fd_ulong_is_aligned( (ulong)_vinyl, fd_vinyl_align()             ) );
  TEST( _cnc   ); TEST( fd_ulong_is_aligned( (ulong)_cnc,   fd_cnc_align()               ) );
  TEST( _meta  ); TEST( fd_ulong_is_aligned( (ulong)_meta,  fd_vinyl_meta_align()        ) );
  TEST( _line  ); TEST( fd_ulong_is_aligned( (ulong)_line,  alignof(fd_vinyl_line_t)     ) );
  TEST( _ele   ); TEST( fd_ulong_is_aligned( (ulong)_ele,   alignof(fd_vinyl_meta_ele_t) ) );
  TEST( _obj   ); TEST( fd_ulong_is_aligned( (ulong)_obj,   alignof(fd_vinyl_data_obj_t) ) );

  TEST( cnc_footprint >= fd_cnc_footprint( FD_VINYL_CNC_APP_SZ ) );

  ulong ele_max   = fd_ulong_pow2_dn( ele_footprint / sizeof( fd_vinyl_meta_ele_t ) );
  ulong lock_cnt  = fd_vinyl_meta_lock_cnt_est( ele_max );
  ulong probe_max = ele_max;

  TEST( ele_max>=4UL );
  TEST( meta_footprint >= fd_vinyl_meta_footprint( ele_max, lock_cnt, probe_max ) );

  ulong pair_max = ele_max - 1UL;
  ulong line_cnt = fd_ulong_min( line_footprint / sizeof( fd_vinyl_line_t ), pair_max );

  TEST( (3UL<=line_cnt) & (line_cnt<=FD_VINYL_LINE_MAX) );

  TEST( io );

  /* seed is arb */

  TEST( (0UL<async_min) & (async_min<=async_max) );

  /* part_thresh is arb */

  /* gc_thresh is arb */

  TEST( (-1<=gc_eager) & (gc_eager<=63) );

  TEST( (style==FD_VINYL_BSTREAM_CTL_STYLE_RAW) | (style==FD_VINYL_BSTREAM_CTL_STYLE_LZ4) );

  FD_LOG_NOTICE(( "Vinyl config"
                  "\n\tline_cnt    %lu pairs"
                  "\n\tpair_max    %lu pairs"
                  "\n\tseed        0x%016lx"
                  "\n\tasync_min   %lu min iterations per async"
                  "\n\tasync_max   %lu max iterations per async"
                  "\n\tpart_thresh %lu bytes"
                  "\n\tgc_thresh   %lu bytes"
                  "\n\tgc_eager    %i"
                  "\n\tstyle       \"%s\" (0x%x)",
                  line_cnt, pair_max, seed, async_min, async_max, part_thresh, gc_thresh, gc_eager,
                  fd_vinyl_bstream_ctl_style_cstr( style ), (uint)style ));

  fd_vinyl_t * vinyl = (fd_vinyl_t *)_vinyl;

  /* Note that fd_vinyl_meta_new does not initialize the underlying meta
     element cache.  Similarly, fd_vinyl_data_init does not initialize
     the underlying data object cache.  Those initializations are
     handled (and then massively thread parallel) by the recover below. */

  memset( vinyl, 0, fd_vinyl_footprint() );

  vinyl->cnc  = fd_cnc_join( fd_cnc_new( _cnc, FD_VINYL_CNC_APP_SZ, FD_VINYL_CNC_TYPE, fd_log_wallclock() ) ); TEST( vinyl->cnc );
  vinyl->line = (fd_vinyl_line_t *)_line;
  vinyl->io   = io;

  vinyl->line_cnt  = line_cnt;
  vinyl->pair_max  = pair_max;
  vinyl->async_min = async_min;
  vinyl->async_max = async_max;

  vinyl->part_thresh  = part_thresh;
  vinyl->gc_thresh    = gc_thresh;
  vinyl->gc_eager     = gc_eager;
  vinyl->style        = style;
  vinyl->line_idx_lru = 0U;
  vinyl->pair_cnt     = 0UL;
  vinyl->garbage_sz   = 0UL;

  TEST( fd_vinyl_meta_join( vinyl->meta, fd_vinyl_meta_new( _meta, ele_max, lock_cnt, probe_max, seed ), _ele )==vinyl->meta );

  TEST( fd_vinyl_data_init( vinyl->data, _obj, obj_footprint, obj_laddr0 )==vinyl->data );

  vinyl->cnc_footprint  = cnc_footprint;
  vinyl->meta_footprint = meta_footprint;
  vinyl->line_footprint = line_footprint;
  vinyl->ele_footprint  = ele_footprint;
  vinyl->obj_footprint  = obj_footprint;

  FD_LOG_NOTICE(( "Recovering bstream past (level %i)", level ));

  TEST( fd_vinyl_seq_eq( fd_vinyl_recover( tpool,t0,t1, level, vinyl ), fd_vinyl_io_seq_present( io ) ) );

# undef TEST

  FD_LOG_NOTICE(( "Initializing complete" ));

  return vinyl;
}

void *
fd_vinyl_fini( fd_vinyl_t * vinyl ) {

  if( FD_UNLIKELY( !vinyl ) ) {
    FD_LOG_WARNING(( "NULL vinyl" ));
    return NULL;
  }

  /* Note: does not sync.  App should decide if sync is appropriate
     before calling fini. */

  fd_vinyl_data_fini( vinyl->data );

  void * _meta = fd_vinyl_meta_shmap( vinyl->meta );
  fd_vinyl_meta_leave( vinyl->meta );
  fd_vinyl_meta_delete( _meta );

  fd_cnc_delete( fd_cnc_leave( vinyl->cnc ) );

  return vinyl;
}

char *
fd_vinyl_cnc_signal_cstr( ulong  signal,
                          char * buf ) {
  if( FD_LIKELY( buf ) ) {
    switch( signal ) {
    case FD_VINYL_CNC_SIGNAL_RUN:          strcpy( buf, "run"          ); break;
    case FD_VINYL_CNC_SIGNAL_BOOT:         strcpy( buf, "boot"         ); break;
    case FD_VINYL_CNC_SIGNAL_FAIL:         strcpy( buf, "fail"         ); break;
    case FD_VINYL_CNC_SIGNAL_HALT:         strcpy( buf, "halt"         ); break;
    case FD_VINYL_CNC_SIGNAL_SYNC:         strcpy( buf, "sync"         ); break;
    case FD_VINYL_CNC_SIGNAL_GET:          strcpy( buf, "get"          ); break;
    case FD_VINYL_CNC_SIGNAL_SET:          strcpy( buf, "set"          ); break;
    case FD_VINYL_CNC_SIGNAL_CLIENT_JOIN:  strcpy( buf, "client_join"  ); break;
    case FD_VINYL_CNC_SIGNAL_CLIENT_LEAVE: strcpy( buf, "client_leave" ); break;
    default:                               fd_cstr_printf( buf, FD_VINYL_CNC_SIGNAL_CSTR_BUF_MAX, NULL, "%lu", signal ); break;
    }
  }
  return buf;
}
