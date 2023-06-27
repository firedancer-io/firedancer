#include "fd_frank.h"
#include "../../tango/fd_tango.h"
#include "../../wiredancer/c/wd_f1.h"
#include "wd_frank_f1_mon.h"
#include <pthread.h>

#if FD_HAS_HOSTED && FD_HAS_X86 && FD_HAS_WIREDANCER

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  
  char const * pod_gaddr  = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--pod",     NULL, NULL         );
  char const * cfg_path   = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--cfg",     NULL, NULL         );
  long         duration   = fd_env_strip_cmdline_long  ( &argc, &argv, "--duration", NULL, (long)10e9  );

  if( FD_UNLIKELY( !pod_gaddr ) ) FD_LOG_ERR(( "--pod not specified" ));
  if( FD_UNLIKELY( !cfg_path  ) ) FD_LOG_ERR(( "--cfg not specified" ));

  FD_LOG_NOTICE(( "duration: %ld", duration ));
  FD_LOG_NOTICE(( "using configuration in pod --pod %s at path --cfg %s", pod_gaddr, cfg_path ));

  uchar const * pod     = fd_wksp_pod_attach( pod_gaddr );
  uchar const * cfg_pod = fd_pod_query_subpod( pod, cfg_path );
  if( FD_UNLIKELY( !cfg_pod ) ) FD_LOG_ERR(( "path not found" ));

  /* wiredancer */
  ulong wd_enabled = fd_pod_query_ulong( cfg_pod, "wd.enabled", 0UL );
  ulong wd_slots = 0UL;
  if( !!wd_enabled ) {
    /* extract how many wd_slots have been configured */
    char const * wd_slots_str = fd_pod_query_cstr(  cfg_pod, "wd.slots", 0UL );
    ulong wd_slots_idx [ sizeof(ulong) ]; /* max number of slots (size of ulong) */
    ulong wd_slots_cnt        = fd_cstr_to_ulong_seq( wd_slots_str, wd_slots_idx, sizeof(ulong) );
    if( FD_UNLIKELY( !wd_slots_cnt ) ) FD_LOG_ERR(( "wiredancer no slots found" ));
    /* convert to wiredancer 1-hot encoding */
    for( ulong s_i=0; s_i<wd_slots_cnt; s_i++) { wd_slots |= ( 1UL<<wd_slots_idx[s_i] ); }
    FD_LOG_NOTICE(("wd_slots 0x%lx", wd_slots));
  }
  if( !!wd_enabled ) { FD_LOG_NOTICE(("running with wiredancer wd_slots 0x%lx", wd_slots)); } else { FD_LOG_NOTICE(("running on x86")); }

  /* replay_cnc */
  FD_LOG_INFO(( "joining %s.replay.cnc", cfg_path ));
  fd_cnc_t * replay_cnc = fd_cnc_join( fd_wksp_pod_map( cfg_pod, "replay.cnc" ) );
  if( FD_UNLIKELY( !replay_cnc ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
  ulong * replay_cnc_diag = (ulong *)fd_cnc_app_laddr( replay_cnc );

  /* parser_cnc */
  FD_LOG_INFO(( "joining %s.parser.cnc", cfg_path ));
  fd_cnc_t * parser_cnc = fd_cnc_join( fd_wksp_pod_map( cfg_pod, "parser.cnc" ) );
  if( FD_UNLIKELY( !parser_cnc ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
  ulong * parser_cnc_diag = (ulong *)fd_cnc_app_laddr( parser_cnc );

  /* dedup_fseq */
  FD_LOG_INFO(( "joining %s.dedup.fseq", cfg_path ));
  ulong * dedup_fseq = fd_fseq_join( fd_wksp_pod_map( cfg_pod, "dedup.fseq" ) );
  if( FD_UNLIKELY( !dedup_fseq ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));
  ulong const * dedup_fseq_diag = (ulong const *)fd_fseq_app_laddr_const( dedup_fseq );

  uchar const * verify_pods = fd_pod_query_subpod( cfg_pod, "verify" );
  ulong verify_cnt = fd_pod_cnt_subpod( verify_pods );
  ulong wd_cnt = 0;
  if( !!fd_pod_query_ulong( cfg_pod, "wd.enabled", 0UL ) ) {
    wd_cnt = verify_cnt;
  }


  uchar const * vin_pods = fd_pod_query_subpod( cfg_pod, "verifyin" );
  if( FD_UNLIKELY( !vin_pods ) ) FD_LOG_ERR(( "%s.verifyin path not found", cfg_path ));

  ulong const ** sigv_fseq_diag = fd_alloca(32, verify_cnt * sizeof(ulong const *));
  for (ulong vi = 0; vi < verify_cnt; vi ++)
  {
    #define MAX_POD_NAME (128)
    char vin_name[MAX_POD_NAME];
    sprintf(vin_name, "v%luin", vi);

    uchar const * vin_pod = fd_pod_query_subpod( vin_pods, vin_name );
    if( FD_UNLIKELY( !vin_pod ) ) FD_LOG_ERR(( "%s.verifyin.%s path not found", cfg_path, vin_name ));

    ulong const * vin_fseq = fd_fseq_join( fd_wksp_pod_map( vin_pod, "fseq" ) );
    if( FD_UNLIKELY( !vin_fseq ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));
    ulong const * vin_fseq_diag = (ulong const *)fd_fseq_app_laddr_const( vin_fseq );
    if( FD_UNLIKELY( !vin_fseq_diag ) ) FD_LOG_ERR(( "fd_fseq_app_laddr failed" ));

    sigv_fseq_diag[vi] = vin_fseq_diag;
  }

  /* Wiredancer Monitor */
  wd_mon_state_t wd_mon_state;
  wd_mon_state.recv_cnt[0] = 0UL;
  wd_mon_state.recv_cnt[1] = 0UL;
  wd_mon_state.send_cnt    = 0UL;
  wd_mon_state.cnt_pkt_sz  = 0UL;
  wd_mon_state.cnt_replay  = 0UL;
  wd_mon_state.cnt_parser  = 0UL;
  wd_mon_state.cnt_dedup   = 0UL;
  wd_mon_state.cnt_sigv    = 0UL;
  wd_mon_state.cnt_sw_sigv = 0UL;
  wd_mon_state.rate_pkt_sz = 0UL;
  wd_mon_state.rate_replay = 0UL;
  wd_mon_state.rate_parser = 0UL;
  wd_mon_state.rate_dedup  = 0UL;
  wd_mon_state.running     = 1;
  wd_mon_state.stopped     = 0;
  FD_TEST( !wd_init_pci( &wd_mon_state.wd, wd_slots ) );
  pthread_t wd_mon_thread;
  FD_TEST( !pthread_create( &wd_mon_thread, NULL, mon_thread, &wd_mon_state)  );

  /* main loop */
  long now  = fd_log_wallclock();
  long next = now;
  long done = (!!duration)? now + duration : (long)((~(ulong)0UL)>>1);
  for(;;) {
    long now = fd_log_wallclock();
    if( FD_UNLIKELY( (now-done) >= 0L ) ) {
      break;
    }
    if( FD_UNLIKELY( (now-next) >= 0L ) ) {
      FD_COMPILER_MFENCE();
      ulong pkt_sz_cnt = replay_cnc_diag[  FD_FRANK_REPLAY_CNC_DIAG_PCAP_PUB_SZ ]; /* bytes */
      ulong replay_cnt = replay_cnc_diag[ FD_FRANK_REPLAY_CNC_DIAG_PCAP_PUB_CNT ];
      ulong parser_cnt = parser_cnc_diag[      FD_FRANK_PARSER_CNC_DIAG_PUB_CNT ];
      ulong dedup_cnt  = dedup_fseq_diag[                  FD_FSEQ_DIAG_PUB_CNT ];
      ulong sigv_cnt   = 0;
      ulong sw_sigv_cnt= 0;
      for (ulong vi = 0; vi < verify_cnt; vi ++)
        sigv_cnt += sigv_fseq_diag[vi][FD_FSEQ_DIAG_PUB_CNT];
      for (ulong vi = wd_cnt; vi < verify_cnt; vi ++)
        sw_sigv_cnt += sigv_fseq_diag[vi][FD_FSEQ_DIAG_PUB_CNT];
      FD_COMPILER_MFENCE();
      /* compute the rates first */
      wd_mon_state.rate_pkt_sz = pkt_sz_cnt - wd_mon_state.cnt_pkt_sz; /* per second */
      wd_mon_state.rate_replay = replay_cnt - wd_mon_state.cnt_replay; /* per second */
      wd_mon_state.rate_parser = parser_cnt - wd_mon_state.cnt_parser; /* per second */
      wd_mon_state.rate_dedup  = dedup_cnt  - wd_mon_state.cnt_dedup;  /* per second */
      wd_mon_state.rate_sigv   = sigv_cnt   - wd_mon_state.cnt_sigv;   /* per second */
      wd_mon_state.rate_sw_sigv= sw_sigv_cnt- wd_mon_state.cnt_sw_sigv;/* per second */
      FD_COMPILER_MFENCE();
      /* update the counts second */
      wd_mon_state.cnt_pkt_sz = pkt_sz_cnt;  /* bytes */
      wd_mon_state.cnt_replay = replay_cnt;
      wd_mon_state.cnt_parser = parser_cnt;
      wd_mon_state.cnt_dedup  = dedup_cnt;
      wd_mon_state.cnt_sigv   = sigv_cnt;
      wd_mon_state.cnt_sw_sigv= sw_sigv_cnt;
      FD_COMPILER_MFENCE();
      /* time increment must be 1 second (for the above rates to be computed easily) */
      next += (long)1e9; /* 1 second */
    }
    FD_YIELD();
  }
  /* halt: monitor */
  wd_mon_state.running = 0;
  pthread_join( wd_mon_thread, NULL);
  while(!wd_mon_state.stopped) { FD_YIELD(); }
  FD_LOG_NOTICE(( "Cleaning up" ));
  
  FD_LOG_NOTICE(( "done" ));
  fd_halt();
  return 0;
}

#else

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_LOG_WARNING(( "skip: unit test requires FD_HAS_HOSTED, FD_HAS_X86 and FD_HAS_WIREDANCER capabilities" ));
  fd_halt();
  return 0;
}

#endif
