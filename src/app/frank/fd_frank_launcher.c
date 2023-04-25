/* fd_frank_launcher is pointed to a `grp` and launches all of the tasks that
 * are mentioned for it in the cfg.
 */

#include "fd_frank.h"

#if FD_HAS_FRANK

// todo(marcus-jump): add sandboxing once it lands in main

#include <stdio.h>
#include <signal.h>

#define MAX_TASK_POD_KEY_LEN 1024

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

static ulong
find_task_count( const uchar * group_tasks_pod ) {
  ulong sum = 0;

  for( fd_pod_iter_t task_iter = fd_pod_iter_init( group_tasks_pod );
       !fd_pod_iter_done( task_iter ); 
       task_iter = fd_pod_iter_next( task_iter ) ) {
        fd_pod_info_t task_type_info = fd_pod_iter_info( task_iter );
        /* Skip if node is not a subpod */
        if( FD_UNLIKELY( task_type_info.val_type!=FD_POD_VAL_TYPE_SUBPOD ) ) continue;

        /* Find how many tasks there are for this task type */
        uchar const * tasks_pod = fd_pod_query_subpod(group_tasks_pod, task_type_info.key);
        sum += fd_pod_cnt_subpod( tasks_pod );
  } /* all groups */  

  return sum;
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
  FD_LOG_NOTICE(( "found %lu task group(s) in config", group_cnt ));

  /* Find the the pod for the group we are attempting to launch. */
  uchar const * group_pod = fd_pod_query_subpod( all_groups_pod, grp_name );
  if( FD_UNLIKELY( !group_pod ) ) {
    FD_LOG_WARNING(( "valid groups are:" ));
    list_groups( all_groups_pod );
    FD_LOG_ERR(( "'%s' is an invalid group", grp_name ));
  };

  /* Find out how many tasks are going to be launched */
  
  /* Todo(marcus-jump): ensure that the required shmem is mapped */

  // /* Todo(marcus-jump): find the minimum tile count for this group. */
  // uint tile_req_cnt = min_tile_cnt( "group_pod", );
  // if ( fd_tile_cnt() < tile_req_cnt ) {
  //   FD_LOG_ERR(( "not enough tiles available - available=%lu min_required=%lu", fd_tile_cnt(), tile_req_cnt ));
  // }
  // fd_tile_cnt()

  /* Find the tasks pod. */
  uchar const * all_tasks_pod = fd_pod_query_subpod( group_pod, "task" );
  if( FD_UNLIKELY( !all_tasks_pod ) ) FD_LOG_ERR(( "path not found" ));

  ulong tasks_cnt = find_task_count(all_tasks_pod);

  // Todo: Can store fewer entries
  char * task_type_paths = fd_alloca( alignof(char *), MAX_TASK_POD_KEY_LEN * tasks_cnt );
  if( FD_UNLIKELY( !task_type_paths ) ) FD_LOG_ERR(( "fd_alloca failed" ));

  /* Have a referance handy to all tasks's CNC */
  fd_cnc_t ** tile_cnc = fd_alloca( alignof(fd_cnc_t *), sizeof(fd_cnc_t *)*tasks_cnt );
  if( FD_UNLIKELY( !tile_cnc ) ) FD_LOG_ERR(( "fd_alloca failed" ));  

  /* The main tile's (this thread) CNC will be the first in this list */
  fd_cnc_t * cnc = tile_cnc[ 0 ] = fd_cnc_join( fd_wksp_pod_map( group_pod, "main.cnc" ) );
  if( FD_UNLIKELY( !cnc ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
  if( FD_UNLIKELY( fd_cnc_app_sz( cnc ) < 64UL ) ) FD_LOG_ERR(( "cnc app sz should be at least 64 bytes" ));


  ulong tile_idx = 1UL;
  (void) tile_idx;

  /* For each type fo task, launch all of the specified tasks. */
  for( fd_pod_iter_t task_type_iter = fd_pod_iter_init( all_tasks_pod ); !fd_pod_iter_done( task_type_iter ); task_type_iter = fd_pod_iter_next( task_type_iter ) ) {
    fd_pod_info_t task_type_info = fd_pod_iter_info( task_type_iter );
    if( FD_UNLIKELY( task_type_info.val_type!=FD_POD_VAL_TYPE_SUBPOD ) ) continue;
    char const * task_type = task_type_info.key;

    /* Find the tasks pod. */
    uchar const * task_type_pod = fd_pod_query_subpod( all_tasks_pod, task_type );
    if( FD_UNLIKELY( !task_type_pod ) ) FD_LOG_ERR(( "path not found" ));

    fd_tile_task_t task;

    if      ( FD_UNLIKELY( !strcmp(task_type, "pack"   ) ) )
      task = fd_frank_pack_task;
    else if ( FD_UNLIKELY( !strcmp(task_type, "dedup"  ) ) )
      task = fd_frank_dedup_task;
    else if ( FD_UNLIKELY( !strcmp(task_type, "verify" ) ) )
      task = fd_frank_verify_task;
    else {
      FD_LOG_ERR(( "unknown task type '%s'", task_type ));
    }

    /* Todo: Sandbox the process */

    /* Launch each instance of that pod. */
    for( fd_pod_iter_t instance_iter = fd_pod_iter_init( task_type_pod ); !fd_pod_iter_done( instance_iter ); instance_iter = fd_pod_iter_next( instance_iter ) ) {
      fd_pod_info_t task_info = fd_pod_iter_info( instance_iter );
      if( FD_UNLIKELY( task_info.val_type!=FD_POD_VAL_TYPE_SUBPOD ) ) continue;
      FD_LOG_NOTICE(( "launching task: %s:%s", task_type, task_info.key ));

      uchar const * task_instance = fd_pod_query_subpod( task_type_pod, task_info.key );
      if( FD_UNLIKELY( !task_instance ) ) FD_LOG_ERR(( "path not found" ));

      tile_cnc[ tile_idx ] = fd_cnc_join( fd_wksp_pod_map( task_instance, "cnc" ) );


      char * task_type_path = task_type_paths + (tile_idx * MAX_TASK_POD_KEY_LEN);

      int written = snprintf(task_type_path, MAX_TASK_POD_KEY_LEN, "%s.grp.%s.task.%s", cfg_path, grp_name, task_type_info.key);
      if (written+1 > MAX_TASK_POD_KEY_LEN) {
        FD_LOG_ERR(( "would have overran task type path" ));
      }


      
      char * task_argv[4];
      task_argv[0] = (char *)task_type_path;
      task_argv[1] = (char *)task_info.key;
      task_argv[2] = (char *)pod_gaddr;
      task_argv[3] = (char *)cfg_path;

      if( FD_UNLIKELY( !fd_tile_exec_new( tile_idx, task, 0, task_argv ) ) )
        FD_LOG_ERR(( "fd_tile_exec_new failed" ));
      
      if( FD_UNLIKELY( fd_cnc_wait( tile_cnc[ tile_idx ], FD_CNC_SIGNAL_BOOT, (long)5e9, NULL )!=FD_CNC_SIGNAL_RUN ) )
        FD_LOG_ERR(( "tile failed to boot in a timely fashion" ));

      tile_idx++;
    }
  }

  /* Configure normal kill and ctrl-c to do a clean shutdown */

  // FD_VOLATILE( fd_frank_main_cnc ) = cnc;
  fd_frank_signal_trap( SIGTERM );
  fd_frank_signal_trap( SIGINT  );

  FD_LOG_INFO(( "main run" ));
  fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
  for(;;) {
    /* Send diagnostic info */
    fd_cnc_heartbeat( cnc, fd_tickcount() );
    /* Receive command-and-control signals */
    if( FD_UNLIKELY( fd_cnc_signal_query( cnc )==FD_CNC_SIGNAL_HALT ) ) break;
    FD_YIELD(); /* not SPIN_PAUSE as this tile is meant to float and be low resource utilization */
  }

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
