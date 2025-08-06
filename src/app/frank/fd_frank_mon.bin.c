#include "fd_frank.h"

#if FD_HAS_FRANK

/**********************************************************************/
/* FIXME: These APIs are probably useful to move to a monitor lib */

#include <stdio.h>
#include <string.h>

/* TEXT_* are quick-and-dirty color terminal hacks.  Probably should
   do something more robust longer term. */

#define TEXT_ALTBUF_ENABLE  "\033[?1049h"
#define TEXT_ALTBUF_DISABLE "\033[?1049l"
#define TEXT_CUP_HOME       "\033[H"
#define TEXT_ED             "\033[J"
#define TEXT_EL             "\033[K"
#define TEXT_NEWLINE         TEXT_EL "\n"

#define TEXT_NORMAL "\033[0m"
#define TEXT_BLUE   "\033[34m"
#define TEXT_GREEN  "\033[32m"
#define TEXT_YELLOW "\033[93m"
#define TEXT_RED    "\033[31m"

/* snprintf_age prints _dt in ns as an age to stdout, will be exactly 10
   char wide.  Since pretty printing this value will often require
   rounding it, the rounding is in a round toward zero sense. */

static int
snprintf_age( char * buf, size_t sz, long _dt ) {
  if( FD_UNLIKELY( _dt< 0L ) ) return snprintf( buf, sz, "   invalid" );
  if( FD_UNLIKELY( _dt==0L ) ) return snprintf( buf, sz, "        0s" );
  ulong rem = (ulong)_dt;
  ulong ns = rem % 1000UL; rem /= 1000UL; if( !rem ) return snprintf( buf, sz, "      %3lun", ns );
  ulong us = rem % 1000UL; rem /= 1000UL; if( !rem ) return snprintf( buf, sz, "  %3lu.%03luu", us, ns );
  ulong ms = rem % 1000UL; rem /= 1000UL; if( !rem ) return snprintf( buf, sz, "%3lu.%03lu%02lum", ms, us, ns/10UL );
  ulong  s = rem %   60UL; rem /=   60UL; if( !rem ) return snprintf( buf, sz, "%2lu.%03lu%03lus", s, ms, us );
  ulong  m = rem %   60UL; rem /=   60UL; if( !rem ) return snprintf( buf, sz, "%2lu:%02lu.%03lu%1lu", m, s, ms, us/100UL );
  ulong  h = rem %   24UL; rem /=   24UL; if( !rem ) return snprintf( buf, sz, "%2lu:%02lu:%02lu.%1lu", h, m, s, ms/100UL );
  ulong  d = rem %    7UL; rem /=    7UL; if( !rem ) return snprintf( buf, sz, "  %1lud %2lu:%02lu", d, h, m );
  ulong  w = rem;                        if( w<=99UL ) return snprintf( buf, sz, "%2luw %1lud %2luh", w, d, h );
  return snprintf( buf, sz, "%6luw %1lud", w, d );
}

/* snprintf_stale is snprintf_age with the tweak that ages less than or
   equal to expire (in ns) will be suppressed to limit visual chatter.
   Will be exactly 10 char wide and color coded. */

static int
snprintf_stale( char * buf, size_t sz, long age, long expire ) {
  if( FD_UNLIKELY( age <= expire ) )
    return snprintf( buf, sz, TEXT_GREEN "         -" TEXT_NORMAL );
  char tmp[32];
  snprintf_age(tmp, sizeof(tmp), age);
  return snprintf( buf, sz, TEXT_YELLOW "%s" TEXT_NORMAL, tmp );
}

/* snprintf_heart will print to stdout whether or not a heartbeat was
   detected.  Will be exactly 5 char wide and color coded. */

static int
snprintf_heart( char * buf, size_t sz, long hb_now, long hb_then ) {
  long dt = hb_now - hb_then;
  return snprintf( buf, sz, "%s",
    (dt>0L) ? TEXT_GREEN "    -" TEXT_NORMAL :
    (!dt)   ? TEXT_RED   " NONE" TEXT_NORMAL :
              TEXT_BLUE  "RESET" TEXT_NORMAL );
}

/* snprintf_sig will print the current and previous value of a cnc signal.
   to stdout.  Will be exactly 10 char wide and color coded. */

static char const *
sig_color( ulong sig ) {
  switch( sig ) {
  case FD_CNC_SIGNAL_BOOT: return TEXT_BLUE;   break; /* Blue -> waiting for tile to start */
  case FD_CNC_SIGNAL_HALT: return TEXT_YELLOW; break; /* Yellow -> waiting for tile to process */
  case FD_CNC_SIGNAL_RUN:  return TEXT_GREEN;  break; /* Green -> Normal */
  case FD_CNC_SIGNAL_FAIL: return TEXT_RED;    break; /* Red -> Definitely abnormal */
  default: break; /* Unknown, don't colorize */
  }
  return TEXT_NORMAL;
}

static int
snprintf_sig( char * buf, size_t sz, ulong sig_now, ulong sig_then ) {
  char buf0[ FD_CNC_SIGNAL_CSTR_BUF_MAX ];
  char buf1[ FD_CNC_SIGNAL_CSTR_BUF_MAX ];
  char const * c0 = sig_color( sig_now );
  char const * c1 = sig_color( sig_then );
  return snprintf( buf, sz, "%s%4s" TEXT_NORMAL "(%s%4s" TEXT_NORMAL ")",
                   c0, fd_cnc_signal_cstr( sig_now, buf0 ),
                   c1, fd_cnc_signal_cstr( sig_then, buf1 ) );
}

/* snprintf_err_bool will print to stdout a boolean flag that indicates
   if error condition was present now and then.  Will be exactly 12 char
   wide and color coded. */

static int
snprintf_err_bool( char * buf, size_t sz, ulong err_now, ulong err_then ) {
  return snprintf( buf, sz, "%5s(%5s)",
    err_now  ? TEXT_RED   "err" TEXT_NORMAL : TEXT_GREEN "  -" TEXT_NORMAL,
    err_then ? TEXT_RED   "err" TEXT_NORMAL : TEXT_GREEN "  -" TEXT_NORMAL );
}

/* snprintf_err_cnt will print to stdout a 64-bit counter holding the
   number of times an error condition has happened and how it has
   changed between now and then.  Will be exactly 19 char wide and color
   coded.  (The 64-bit counter will be truncated to 32-bit before pretty
   printing to make it more compact as cumulative value of such counters
   is often less important than how it is changed between now and then.) */

static int
snprintf_err_cnt( char * buf, size_t sz, ulong cnt_now, ulong cnt_then ) {
  long delta = (long)(cnt_now - cnt_then);
  char const * color = (!delta)   ? TEXT_GREEN  /* no new error counts */
                     : (delta>0L) ? TEXT_RED    /* new error counts */
                     : (cnt_now)  ? TEXT_YELLOW /* decrease of existing error counts?? */
                     :              TEXT_BLUE;  /* reset of the error counter */
  if(      delta >  99999L ) return snprintf( buf, sz, "%10u(%s>+99999" TEXT_NORMAL ")", (uint)cnt_now, color );
  else if (delta < -99999L ) return snprintf( buf, sz, "%10u(%s<-99999" TEXT_NORMAL ")", (uint)cnt_now, color );
  else                      return snprintf( buf, sz, "%10u(%s %+6li"  TEXT_NORMAL ")", (uint)cnt_now, color, delta );
}

/* snprintf_seq will print to stdout a 64-bit sequence number and how it
   has changed between now and then.  Will be exactly 25 char wide and
   color coded. */

static int
snprintf_seq( char * buf, size_t sz, ulong seq_now, ulong seq_then ) {
  long delta = (long)(seq_now - seq_then);
  char const * color = (!delta)   ? TEXT_YELLOW /* no sequence numbers published */
                     : (delta>0L) ? TEXT_GREEN  /* new sequence numbers published */
                     : (seq_now)  ? TEXT_RED    /* sequence number went backward */
                     :              TEXT_BLUE;  /* sequence number reset */
  if(      delta >  99999L ) return snprintf( buf, sz, "%16lx(%s>+99999" TEXT_NORMAL ")", seq_now, color );
  else if (delta < -99999L ) return snprintf( buf, sz, "%16lx(%s<-99999" TEXT_NORMAL ")", seq_now, color );
  else                      return snprintf( buf, sz, "%16lx(%s %+6li"  TEXT_NORMAL ")", seq_now, color, delta );
}


/**********************************************************************/

/* snap reads all the IPC diagnostics in a frank instance and stores
   them into the easy to process structure snap */

struct snap {
  ulong pmap; /* Bit {0,1,2} set <> {cnc,mcache,fseq} values are valid */

  long  cnc_heartbeat;
  ulong cnc_signal;

  ulong cnc_diag_in_backp;
  ulong cnc_diag_backp_cnt;
  ulong cnc_diag_ha_filt_cnt;
  ulong cnc_diag_ha_filt_sz;
  ulong cnc_diag_sv_filt_cnt;
  ulong cnc_diag_sv_filt_sz;

  ulong mcache_seq;

  ulong fseq_seq;

  ulong fseq_diag_tot_cnt;
  ulong fseq_diag_tot_sz;
  ulong fseq_diag_filt_cnt;
  ulong fseq_diag_filt_sz;
  ulong fseq_diag_ovrnp_cnt;
  ulong fseq_diag_ovrnr_cnt;
  ulong fseq_diag_slow_cnt;
};

typedef struct snap snap_t;

static void
snap( ulong             tile_cnt,     /* Number of tiles to snapshot */
      snap_t *          snap_cur,     /* Snaphot for each tile, indexed [0,tile_cnt) */
      fd_cnc_t **       tile_cnc,     /* Local cnc    joins for each tile, NULL if n/a, indexed [0,tile_cnt) */
      fd_frag_meta_t ** tile_mcache,  /* Local mcache joins for each tile, NULL if n/a, indexed [0,tile_cnt) */
      ulong **          tile_fseq ) { /* Local fseq   joins for each tile, NULL if n/a, indexed [0,tile_cnt) */

  for( ulong tile_idx=0UL; tile_idx<tile_cnt; tile_idx++ ) {

    snap_t * snap = &snap_cur[ tile_idx ];

    ulong pmap = 0UL;

    fd_cnc_t const * cnc = tile_cnc[ tile_idx ];
    if( FD_LIKELY( cnc ) ) {
      snap->cnc_heartbeat = fd_cnc_heartbeat_query( cnc );
      snap->cnc_signal    = fd_cnc_signal_query   ( cnc );
      ulong const * cnc_diag = (ulong const *)fd_cnc_app_laddr_const( cnc );
      FD_COMPILER_MFENCE();
      snap->cnc_diag_in_backp    = cnc_diag[ FD_FRANK_CNC_DIAG_IN_BACKP    ];
      snap->cnc_diag_backp_cnt   = cnc_diag[ FD_FRANK_CNC_DIAG_BACKP_CNT   ];
      snap->cnc_diag_ha_filt_cnt = cnc_diag[ FD_FRANK_CNC_DIAG_HA_FILT_CNT ];
      snap->cnc_diag_ha_filt_sz  = cnc_diag[ FD_FRANK_CNC_DIAG_HA_FILT_SZ  ];
      snap->cnc_diag_sv_filt_cnt = cnc_diag[ FD_FRANK_CNC_DIAG_SV_FILT_CNT ];
      snap->cnc_diag_sv_filt_sz  = cnc_diag[ FD_FRANK_CNC_DIAG_SV_FILT_SZ  ];
      FD_COMPILER_MFENCE();

      pmap |= 1UL;
    }

    fd_frag_meta_t const * mcache = tile_mcache[ tile_idx ];
    if( FD_LIKELY( mcache ) ) {
      ulong const * seq = (ulong const *)fd_mcache_seq_laddr_const( mcache );
      snap->mcache_seq = fd_mcache_seq_query( seq );

      pmap |= 2UL;
    }

    ulong const * fseq = tile_fseq[ tile_idx ];
    if( FD_LIKELY( fseq ) ) {
      snap->fseq_seq = fd_fseq_query( fseq );
      ulong const * fseq_diag = (ulong const *)fd_fseq_app_laddr_const( fseq );
      FD_COMPILER_MFENCE();
      snap->fseq_diag_tot_cnt   = fseq_diag[ FD_FSEQ_DIAG_PUB_CNT   ];
      snap->fseq_diag_tot_sz    = fseq_diag[ FD_FSEQ_DIAG_PUB_SZ    ];
      snap->fseq_diag_filt_cnt  = fseq_diag[ FD_FSEQ_DIAG_FILT_CNT  ];
      snap->fseq_diag_filt_sz   = fseq_diag[ FD_FSEQ_DIAG_FILT_SZ   ];
      snap->fseq_diag_ovrnp_cnt = fseq_diag[ FD_FSEQ_DIAG_OVRNP_CNT ];
      snap->fseq_diag_ovrnr_cnt = fseq_diag[ FD_FSEQ_DIAG_OVRNR_CNT ];
      snap->fseq_diag_slow_cnt  = fseq_diag[ FD_FSEQ_DIAG_SLOW_CNT  ];
      FD_COMPILER_MFENCE();
      snap->fseq_diag_tot_cnt += snap->fseq_diag_filt_cnt;
      snap->fseq_diag_tot_sz  += snap->fseq_diag_filt_sz;
      pmap |= 4UL;
    }

    snap->pmap = pmap;
  }
}

/**********************************************************************/

#define MAX_LINE_LEN 512

int
main( int     argc,
      char ** argv ) {

  fd_boot( &argc, &argv );

  /* Parse command line arguments */

  char const * pod_gaddr =       fd_env_strip_cmdline_cstr  ( &argc, &argv, "--pod",      NULL, NULL                 );
  char const * cfg_path  =       fd_env_strip_cmdline_cstr  ( &argc, &argv, "--cfg",      NULL, NULL                 );
  long         dt_min    = (long)fd_env_strip_cmdline_double( &argc, &argv, "--dt-min",   NULL,   66666667.          );
  long         dt_max    = (long)fd_env_strip_cmdline_double( &argc, &argv, "--dt-max",   NULL, 1333333333.          );
  long         duration  = (long)fd_env_strip_cmdline_double( &argc, &argv, "--duration", NULL,          0.          );
  uint         seed      =       fd_env_strip_cmdline_uint  ( &argc, &argv, "--seed",     NULL, (uint)fd_tickcount() );

  if( FD_UNLIKELY( !pod_gaddr   ) ) FD_LOG_ERR(( "--pod not specified"                  ));
  if( FD_UNLIKELY( !cfg_path    ) ) FD_LOG_ERR(( "--cfg not specified"                  ));
  if( FD_UNLIKELY( dt_min<0L    ) ) FD_LOG_ERR(( "--dt-min should be positive"          ));
  if( FD_UNLIKELY( dt_max<dt_min) ) FD_LOG_ERR(( "--dt-max should be at least --dt-min" ));
  if( FD_UNLIKELY( duration<0L  ) ) FD_LOG_ERR(( "--duration should be non-negative"    ));

  /* Load up the configuration for this frank instance */

  FD_LOG_INFO(( "using configuration in pod --pod %s at path --cfg %s", pod_gaddr, cfg_path ));

  uchar const * pod     = fd_wksp_pod_attach( pod_gaddr );
  uchar const * cfg_pod = fd_pod_query_subpod( pod, cfg_path );
  if( FD_UNLIKELY( !cfg_pod ) ) FD_LOG_ERR(( "path not found" ));

  uchar const * verifyin_pods = fd_pod_query_subpod( cfg_pod, "verifyin" );
  ulong verifyin_cnt = fd_pod_cnt_subpod( verifyin_pods );
  FD_LOG_INFO(( "%lu verifyin found", verifyin_cnt ));

  uchar const * verify_pods = fd_pod_query_subpod( cfg_pod, "verify" );
  ulong verify_cnt = fd_pod_cnt_subpod( verify_pods );
  FD_LOG_INFO(( "%lu verify found", verify_cnt ));

  ulong tile_cnt = 5UL + verify_cnt;

  /* Allocate buffers for double-buffered terminal rendering */
  /* Need 3 header rows + tile_cnt data rows + 1 extra row for safety */
  ulong max_rows = 3UL + tile_cnt + 1UL;
  char (*buffer_prev)[MAX_LINE_LEN] = fd_alloca( alignof(char[MAX_LINE_LEN]), sizeof(char[MAX_LINE_LEN]) * max_rows );
  char (*buffer_curr)[MAX_LINE_LEN] = fd_alloca( alignof(char[MAX_LINE_LEN]), sizeof(char[MAX_LINE_LEN]) * max_rows );
  if( FD_UNLIKELY( (!buffer_prev) | (!buffer_curr) ) ) FD_LOG_ERR(( "fd_alloca failed for buffers" ));
  
  /* Initialize buffers to zero */
  memset( buffer_prev, 0, sizeof(char[MAX_LINE_LEN]) * max_rows );
  memset( buffer_curr, 0, sizeof(char[MAX_LINE_LEN]) * max_rows );

  /* Join all IPC objects for this frank instance */

  char const **     tile_name   = fd_alloca( alignof(char const *    ), sizeof(char const *    )*tile_cnt );
  fd_cnc_t **       tile_cnc    = fd_alloca( alignof(fd_cnc_t *      ), sizeof(fd_cnc_t *      )*tile_cnt );
  fd_frag_meta_t ** tile_mcache = fd_alloca( alignof(fd_frag_meta_t *), sizeof(fd_frag_meta_t *)*tile_cnt );
  ulong **          tile_fseq   = fd_alloca( alignof(ulong *         ), sizeof(ulong *         )*tile_cnt );
  if( FD_UNLIKELY( (!tile_name) | (!tile_cnc) | (!tile_mcache) | (!tile_fseq) ) ) FD_LOG_ERR(( "fd_alloca failed" )); /* paranoia */

  do {
    ulong tile_idx = 0UL;

    tile_name[ tile_idx ] = "main";
    FD_LOG_INFO(( "joining %s.main.cnc", cfg_path ));
    tile_cnc[ tile_idx ] = fd_cnc_join( fd_wksp_pod_map( cfg_pod, "main.cnc" ) );
    if( FD_UNLIKELY( !tile_cnc[ tile_idx ] ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
    if( FD_UNLIKELY( fd_cnc_app_sz( tile_cnc[ tile_idx ] )<64UL ) ) FD_LOG_ERR(( "cnc app sz should be at least 64 bytes" ));
    tile_mcache[ tile_idx ] = NULL; /* main has no mcache */
    tile_fseq  [ tile_idx ] = NULL; /* main has no fseq */
    tile_idx++;

    tile_name[ tile_idx ] = "pack";
    FD_LOG_INFO(( "joining %s.pack.cnc", cfg_path ));
    tile_cnc[ tile_idx ] = fd_cnc_join( fd_wksp_pod_map( cfg_pod, "pack.cnc" ) );
    if( FD_UNLIKELY( !tile_cnc[ tile_idx ] ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
    if( FD_UNLIKELY( fd_cnc_app_sz( tile_cnc[ tile_idx ] )<64UL ) ) FD_LOG_ERR(( "cnc app sz should be at least 64 bytes" ));
    tile_mcache[ tile_idx ] = NULL;
    FD_LOG_INFO(( "joining %s.dedup.fseq", cfg_path ));
    tile_fseq[ tile_idx ] = fd_fseq_join( fd_wksp_pod_map( cfg_pod, "dedup.fseq" ) );
    if( FD_UNLIKELY( !tile_fseq[ tile_idx ] ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));
    tile_idx++;

    tile_name[ tile_idx ] = "dedup";
    FD_LOG_INFO(( "joining %s.dedup.cnc", cfg_path ));
    tile_cnc[ tile_idx ] = fd_cnc_join( fd_wksp_pod_map( cfg_pod, "dedup.cnc" ) );
    if( FD_UNLIKELY( !tile_cnc[ tile_idx ] ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
    if( FD_UNLIKELY( fd_cnc_app_sz( tile_cnc[ tile_idx ] )<64UL ) ) FD_LOG_ERR(( "cnc app sz should be at least 64 bytes" ));
    FD_LOG_INFO(( "joining %s.dedup.mcache", cfg_path ));
    tile_mcache[ tile_idx ] = fd_mcache_join( fd_wksp_pod_map( cfg_pod, "dedup.mcache" ) );
    if( FD_UNLIKELY( !tile_mcache[ tile_idx ] ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));
    /* FIXME using dedup.fseq instead of aggregating all verify.<verify_name>.fseq */
    FD_LOG_INFO(( "joining %s.dedup.fseq", cfg_path ));
    tile_fseq[ tile_idx ] = fd_fseq_join( fd_wksp_pod_map( cfg_pod, "dedup.fseq" ) );
    if( FD_UNLIKELY( !tile_fseq[ tile_idx ] ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));
    tile_idx++;

    for( fd_pod_iter_t iter = fd_pod_iter_init( verify_pods ); !fd_pod_iter_done( iter ); iter = fd_pod_iter_next( iter ) ) {
      fd_pod_info_t info = fd_pod_iter_info( iter );
      if( FD_UNLIKELY( info.val_type!=FD_POD_VAL_TYPE_SUBPOD ) ) continue;
      char const  * verify_name =                info.key;
      uchar const * verify_pod  = (uchar const *)info.val;

      FD_LOG_INFO(( "joining %s.verify.%s.cnc", cfg_path, verify_name ));
      tile_name[ tile_idx ] = verify_name;
      tile_cnc [ tile_idx ] = fd_cnc_join( fd_wksp_pod_map( verify_pod, "cnc" ) );
      if( FD_UNLIKELY( !tile_cnc[tile_idx] ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
      if( FD_UNLIKELY( fd_cnc_app_sz( tile_cnc[ tile_idx ] )<64UL ) ) FD_LOG_ERR(( "cnc app sz should be at least 64 bytes" ));
      FD_LOG_INFO(( "joining %s.verify.%s.mcache", cfg_path, verify_name ));
      tile_mcache[ tile_idx ] = fd_mcache_join( fd_wksp_pod_map( verify_pod, "mcache" ) );
      if( FD_UNLIKELY( !tile_mcache[ tile_idx ] ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));
      FD_LOG_INFO(( "joining %s.verify.%s.fseq", cfg_path, verify_name ));
      tile_fseq[ tile_idx ] = fd_fseq_join( fd_wksp_pod_map( verify_pod, "fseq" ) );
      if( FD_UNLIKELY( !tile_fseq[ tile_idx ] ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));
      tile_idx++;
    }

    tile_name[ tile_idx ] = "parser";
    FD_LOG_INFO(( "joining %s.parser.cnc", cfg_path ));
    tile_cnc[ tile_idx ] = fd_cnc_join( fd_wksp_pod_map( cfg_pod, "parser.cnc" ) );
    if( FD_UNLIKELY( !tile_cnc[ tile_idx ] ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
    if( FD_UNLIKELY( fd_cnc_app_sz( tile_cnc[ tile_idx ] )<64UL ) ) FD_LOG_ERR(( "cnc app sz should be at least 64 bytes" ));
    FD_LOG_INFO(( "joining %s.parser.sentinel_mcache", cfg_path ));
    tile_mcache[ tile_idx ] = fd_mcache_join( fd_wksp_pod_map( cfg_pod, "parser.sentinel_mcache" ) );
    if( FD_UNLIKELY( !tile_mcache[ tile_idx ] ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));
    FD_LOG_INFO(( "joining %s.replay.fseq", cfg_path ));
    tile_fseq[ tile_idx ] = fd_fseq_join( fd_wksp_pod_map( cfg_pod, "replay.fseq" ) );
    if( FD_UNLIKELY( !tile_fseq[ tile_idx ] ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));
    tile_idx++;

    tile_name[ tile_idx ] = "replay";
    FD_LOG_INFO(( "joining %s.replay.cnc", cfg_path ));
    tile_cnc[ tile_idx ] = fd_cnc_join( fd_wksp_pod_map( cfg_pod, "replay.cnc" ) );
    if( FD_UNLIKELY( !tile_cnc[ tile_idx ] ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
    if( FD_UNLIKELY( fd_cnc_app_sz( tile_cnc[ tile_idx ] )<64UL ) ) FD_LOG_ERR(( "cnc app sz should be at least 64 bytes" ));
    FD_LOG_INFO(( "joining %s.replay.mcache", cfg_path ));
    tile_mcache[ tile_idx ] = fd_mcache_join( fd_wksp_pod_map( cfg_pod, "replay.mcache" ) );
    if( FD_UNLIKELY( !tile_mcache[ tile_idx ] ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));
    tile_fseq[ tile_idx ] = NULL; /* replay has no fseq */
    tile_idx++;

    FD_TEST(tile_idx == tile_cnt);
  } while(0);

  /* Setup local objects used by this app */

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );

  snap_t * snap_prv = (snap_t *)fd_alloca( alignof(snap_t), sizeof(snap_t)*2UL*tile_cnt );
  if( FD_UNLIKELY( !snap_prv ) ) FD_LOG_ERR(( "fd_alloca failed" )); /* Paranoia */
  snap_t * snap_cur = snap_prv + tile_cnt;

  /* Get the inital reference diagnostic snapshot */

  snap( tile_cnt, snap_prv, tile_cnc, tile_mcache, tile_fseq );
  long then; long tic; fd_tempo_observe_pair( &then, &tic );

  /* Monitor for duration ns.  Note that for duration==0, this
     will still do exactly one pretty print. */

  FD_LOG_NOTICE(( "monitoring --dt-min %li ns, --dt-max %li ns, --duration %li ns, --seed %u", dt_min, dt_max, duration, seed ));

  double ns_per_tic = 1./fd_tempo_tick_per_ns( NULL ); /* calibrate during first wait */

  /* Setup TTY */

  printf( TEXT_CUP_HOME );

  /* put monitor on its own clean alternate screen */
  printf( TEXT_ALTBUF_ENABLE TEXT_ED TEXT_CUP_HOME );

  long stop = then + duration;
  for(;;) {

    /* Wait a somewhat randomized amount and then make a diagnostic
       snapshot */

    fd_log_wait_until( then + dt_min + (long)fd_rng_ulong_roll( rng, 1UL+(ulong)(dt_max-dt_min) ) );


    snap( tile_cnt, snap_cur, tile_cnc, tile_mcache, tile_fseq );
    long now; long toc; fd_tempo_observe_pair( &now, &toc );

    /* Pretty print a comparison between this diagnostic snapshot and
       the previous one. */

    /* FIXME: CONSIDER DOING CNC ACKS AND INCL IN SNAPSHOT */
    /* FIXME: CONSIDER INCLUDING TILE UPTIME */
    /* FIXME: CONSIDER ADDING INFO LIKE PID OF INSTANCE */

    uint row = 0;

    char now_cstr[ FD_LOG_WALLCLOCK_CSTR_BUF_SZ ];
    snprintf(buffer_curr[row++], MAX_LINE_LEN, "snapshot for %s" TEXT_NEWLINE, fd_log_wallclock_cstr( now, now_cstr ));

    snprintf(buffer_curr[row++], MAX_LINE_LEN,
        "  tile  |      stale | heart |        sig | in backp |           backp cnt |         sv_filt cnt |                    tx seq |                    rx seq" TEXT_NEWLINE);

    snprintf(buffer_curr[row++], MAX_LINE_LEN,
        "--------+------------+-------+------------+----------+---------------------+---------------------+---------------------------+---------------------------" TEXT_NEWLINE);

    for( ulong tile_idx=0UL; tile_idx<tile_cnt; tile_idx++ ) {
      snap_t * prv = &snap_prv[ tile_idx ];
      snap_t * cur = &snap_cur[ tile_idx ];

      char * out = buffer_curr[row];
      int pos = 0;

      pos += snprintf(out + pos, (size_t)(MAX_LINE_LEN - pos), " %6s", tile_name[ tile_idx ]);

      if( FD_LIKELY( cur->pmap & 1UL ) ) {
        pos += snprintf(out + pos, (size_t)(MAX_LINE_LEN - pos), " | ");
        pos += snprintf_stale(out + pos, (size_t)(MAX_LINE_LEN - pos),
                              (long)(0.5 + ns_per_tic * (double)(toc - cur->cnc_heartbeat)),
                              dt_min);

        pos += snprintf(out + pos, (size_t)(MAX_LINE_LEN - pos), " | ");
        pos += snprintf_heart(out + pos, (size_t)(MAX_LINE_LEN - pos),
                              cur->cnc_heartbeat, prv->cnc_heartbeat);

        pos += snprintf(out + pos, (size_t)(MAX_LINE_LEN - pos), " | ");
        pos += snprintf_sig(out + pos, (size_t)(MAX_LINE_LEN - pos),
                            cur->cnc_signal, prv->cnc_signal);

        pos += snprintf(out + pos, (size_t)(MAX_LINE_LEN - pos), " | ");
        pos += snprintf_err_bool(out + pos, (size_t)(MAX_LINE_LEN - pos),
                                 cur->cnc_diag_in_backp, prv->cnc_diag_in_backp);

        pos += snprintf(out + pos, (size_t)(MAX_LINE_LEN - pos), " | ");
        pos += snprintf_err_cnt(out + pos, (size_t)(MAX_LINE_LEN - pos),
                                cur->cnc_diag_backp_cnt, prv->cnc_diag_backp_cnt);

        pos += snprintf(out + pos, (size_t)(MAX_LINE_LEN - pos), " | ");
        pos += snprintf_err_cnt(out + pos, (size_t)(MAX_LINE_LEN - pos),
                                cur->cnc_diag_sv_filt_cnt, prv->cnc_diag_sv_filt_cnt);
      } else {
        pos += snprintf(out + pos, (size_t)(MAX_LINE_LEN - pos),
                        " |          - |     - |          - |        - |                   - |                   -");
      }

      if( FD_LIKELY( cur->pmap & 2UL ) ) {
        pos += snprintf(out + pos, (size_t)(MAX_LINE_LEN - pos), " | ");
        pos += snprintf_seq(out + pos, (size_t)(MAX_LINE_LEN - pos),
                            cur->mcache_seq, prv->mcache_seq);
      } else {
        pos += snprintf(out + pos, (size_t)(MAX_LINE_LEN - pos), " |                         -");
      }

      if( FD_LIKELY( cur->pmap & 4UL ) ) {
        pos += snprintf(out + pos, (size_t)(MAX_LINE_LEN - pos), " | ");
        pos += snprintf_seq(out + pos, (size_t)(MAX_LINE_LEN - pos),
                            cur->fseq_seq, prv->fseq_seq);
      } else {
        pos += snprintf(out + pos, (size_t)(MAX_LINE_LEN - pos), " |                         -");
      }

      pos += snprintf(out + pos, (size_t)(MAX_LINE_LEN - pos), TEXT_NEWLINE);
      row++;
    }

    /* Add blank line after table (original behavior) */
    snprintf(buffer_curr[row], MAX_LINE_LEN, TEXT_NEWLINE);
    row++;

    /* Switch to alternate screen and erase junk below
       TODO ideally we'd have the last iteration on the main buffer and only the rest on ALTBUF */

    for (uint i = 0; i < row; i++) {
      if (strcmp(buffer_prev[i], buffer_curr[i]) != 0) {
        printf("\033[%d;1H%s", i + 1, buffer_curr[i]);
        memcpy(buffer_prev[i], buffer_curr[i], MAX_LINE_LEN);
      }
    }

    /* Stop once we've been monitoring for duration ns */

    if( FD_UNLIKELY( (now-stop)>=0L ) ) break;

    /* Still more monitoring to do ... wind up for the next iteration by
       swaping the two snap arrays. */

    then = now; tic = toc;
    snap_t * tmp = snap_prv; snap_prv = snap_cur; snap_cur = tmp;
  }

  /* Monitoring done ... clean up */

  printf( TEXT_ALTBUF_DISABLE );

  FD_LOG_NOTICE(( "cleaning up" ));
  fd_rng_delete( fd_rng_leave( rng ) );
  for( ulong tile_idx=tile_cnt; tile_idx; tile_idx-- ) {
    if( FD_LIKELY( tile_fseq  [ tile_idx-1UL ] ) ) fd_wksp_pod_unmap( fd_fseq_leave  ( tile_fseq  [ tile_idx-1UL ] ) );
    if( FD_LIKELY( tile_mcache[ tile_idx-1UL ] ) ) fd_wksp_pod_unmap( fd_mcache_leave( tile_mcache[ tile_idx-1UL ] ) );
    if( FD_LIKELY( tile_cnc   [ tile_idx-1UL ] ) ) fd_wksp_pod_unmap( fd_cnc_leave   ( tile_cnc   [ tile_idx-1UL ] ) );
  }
  fd_wksp_pod_detach( pod );
  fd_halt();
  return 0;
}

#else

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_LOG_ERR(( "unsupported for this build target" ));
  fd_halt();
  return 0;
}

#endif

