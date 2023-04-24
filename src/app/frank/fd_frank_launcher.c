/* fd_frank_launcher is pointed to a `grp` and launches all of the tasks that
 * are mentioned for it in the cfg.
 */

#include "fd_frank.h"

#if FD_HAS_FRANK

// todo(marcus-jump): add sandboxing once it lands in main

#include <stdio.h>
#include <signal.h>

static fd_cnc_t * fd_frank_main_cnc = NULL;

static void
fd_frank_sigaction( int         sig,
                    siginfo_t * info,
                    void *      context ) {
  (void)info;
  (void)context;
  /* FIXME: add support to fd_log for robust logging inside a signal
     handler (i.e. make sure that behavior of calling a log when the
     interrupted thread might be in the middle of preparing a log
     message is well defined) */
  FD_LOG_NOTICE(( "received POSIX signal %i; sending halt to main", sig ));
  if( FD_UNLIKELY( fd_cnc_open( fd_frank_main_cnc ) ) ) { /* logs details */
    FD_LOG_WARNING(( "unable to send halt (fd_cnc_open failed); shutdown will be unclean" ));
    raise( sig ); /* fall back on default handler so thread still terminates */
  }
  fd_cnc_signal( fd_frank_main_cnc, FD_CNC_SIGNAL_HALT );
  fd_cnc_close ( fd_frank_main_cnc );
}

static void
fd_frank_signal_trap( int sig ) {
  struct sigaction act[1];
  act->sa_sigaction = fd_frank_sigaction;
  if( FD_UNLIKELY( sigemptyset( &act->sa_mask ) ) ) FD_LOG_ERR(( "sigempty set failed" ));
  act->sa_flags = (int)(SA_SIGINFO | SA_RESETHAND);
  if( FD_UNLIKELY( sigaction( sig, act, NULL ) ) ) FD_LOG_ERR(( "unable to override signal %i", sig ));
}

static void
list_groups( const uchar * groups_pod ) {
  for( fd_pod_iter_t iter = fd_pod_iter_init( groups_pod ); !fd_pod_iter_done( iter ); iter = fd_pod_iter_next( iter ) ) {
    fd_pod_info_t info = fd_pod_iter_info( iter );
    if( FD_UNLIKELY( info.val_type!=FD_POD_VAL_TYPE_SUBPOD ) ) continue;
    FD_LOG_WARNING(( "\t- %s", info.key ));
  }
}

uint
min_tile_cnt( const uchar * grp_path, uint task_count ) {
  uint min_tile = fd_pod_query_uint( grp_path, "additional-tiles", 0);
  return task_count + min_tile;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_tempo_tick_per_ns( NULL ); /* eat calibration cost at deterministic place */

  char const * pod_gaddr = fd_env_strip_cmdline_cstr( &argc, &argv, "--pod", NULL, NULL );
  char const * cfg_path  = fd_env_strip_cmdline_cstr( &argc, &argv, "--cfg", NULL, NULL );
  char const * grp_name  = fd_env_strip_cmdline_cstr( &argc, &argv, "--grp", NULL, NULL );

  if( FD_UNLIKELY( !pod_gaddr ) ) FD_LOG_ERR(( "--pod not specified" ));
  if( FD_UNLIKELY( !cfg_path  ) ) FD_LOG_ERR(( "--cfg not specified" ));
  if( FD_UNLIKELY( !grp_name  ) ) FD_LOG_ERR(( "--grp not specified" ));

  /* Load up the configuration for this frank instance */

  FD_LOG_NOTICE(( "using configuration in pod --pod %s at path --cfg %s", pod_gaddr, cfg_path ));
  uchar const * pod     = fd_wksp_pod_attach( pod_gaddr );
  uchar const * cfg_pod = fd_pod_query_subpod( pod, cfg_path );
  if( FD_UNLIKELY( !cfg_pod ) ) FD_LOG_ERR(( "path not found" ));

  uchar const * all_groups_pod = fd_pod_query_subpod( cfg_pod, "grp" );
  if( FD_UNLIKELY( !all_groups_pod ) ) FD_LOG_ERR(( "path not found" ));
  ulong group_cnt = fd_pod_cnt_subpod( all_groups_pod );
  FD_LOG_NOTICE(( "found %lu group(s)", group_cnt ));

  /* Find the the pod for the group we are attempting to launch. */
  uchar const * group_pod = fd_pod_query_subpod( all_groups_pod, grp_name );
  if( FD_UNLIKELY( !group_pod ) ) {
    FD_LOG_WARNING(( "valid groups are:" ));
    list_groups( all_groups_pod );
    FD_LOG_ERR(( "'%s' is an invalid group", grp_name ));
  };
  
  // /* Todo(marcus-jump) find the minimum tile count for this group. */
  // uint tile_req_cnt = min_tile_cnt( "group_pod", );
  // if ( fd_tile_cnt() < tile_req_cnt ) {
  //   FD_LOG_ERR(( "not enough tiles available - available=%lu min_required=%lu", fd_tile_cnt(), tile_req_cnt ));
  // }
  // fd_tile_cnt()

  /* Find the tasks pod. */
  uchar const * all_tasks_pod = fd_pod_query_subpod( group_pod, "task" );
  if( FD_UNLIKELY( !all_tasks_pod ) ) FD_LOG_ERR(( "path not found" ));

  ulong next_tile_idx = 1UL;
  (void) next_tile_idx;

  /* For each type fo task, launch all of the specified tasks. */
  for( fd_pod_iter_t task_type_iter = fd_pod_iter_init( all_tasks_pod ); !fd_pod_iter_done( task_type_iter ); task_type_iter = fd_pod_iter_next( task_type_iter ) ) {
    fd_pod_info_t task_type_info = fd_pod_iter_info( task_type_iter );
    if( FD_UNLIKELY( task_type_info.val_type!=FD_POD_VAL_TYPE_SUBPOD ) ) continue;
    char const * task_type = task_type_info.key;

    /* Find the tasks pod. */
    uchar const * task_type_pod = fd_pod_query_subpod( all_tasks_pod, task_type );
    if( FD_UNLIKELY( !task_type_pod ) ) FD_LOG_ERR(( "path not found" ));

    for( fd_pod_iter_t iter = fd_pod_iter_init( task_type_pod ); !fd_pod_iter_done( iter ); iter = fd_pod_iter_next( iter ) ) {
      fd_pod_info_t task_info = fd_pod_iter_info( iter );
      if( FD_UNLIKELY( task_info.val_type!=FD_POD_VAL_TYPE_SUBPOD ) ) continue;
      FD_LOG_NOTICE(( "launching task: %s:%s", task_type, task_info.key ));

      // Prepare all
    }
    // 
  }

  /* Configure normal kill and ctrl-c to do a clean shutdown */

  // FD_VOLATILE( fd_frank_main_cnc ) = cnc;
  fd_frank_signal_trap( SIGTERM );
  fd_frank_signal_trap( SIGINT  );


  fd_halt();
  return 0;
}

#else

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_LOG_WARNING(( "unsupported for this build target" ));
  fd_halt();
  return 1;
}

#endif /* FD_HAS_FRANK */