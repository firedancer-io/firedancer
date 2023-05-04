/* fd_frank_launcher is pointed to a `grp` and launches all of the tasks that
 * are mentioned for it in the cfg.
 */

#include "fd_frank.h"

#if FD_HAS_FRANK

#define MAX_CMDLINE_LEN 1024UL
#define MAX_TASK_GROUP_NAME_LEN 1024UL

#define MAX_STALE_NS (long)10e9
#define SHUTDOWN_GRACE_NS (long)5e9

#include <stdio.h>
#include <signal.h>

#ifdef FD_HAS_SANDBOX
#include "../../util/sandbox/fd_sandbox.h"
#endif /* FD_HAS_SANDBOX */

#define MAX_TASK_POD_KEY_LEN 1024

static fd_cnc_t * fd_frank_main_cnc = NULL;

static void
fd_frank_sigaction( int         sig,
                    siginfo_t * info,
                    void *      context ) {
  (void)info;
  (void)context;
  printf("trap!\n");
  /* FIXME: add support to fd_log for robust logging inside a signal
     handler (i.e. make sure that behavior of calling a log when the
     interrupted thread might be in the middle of preparing a log
     message is well defined) */
  FD_LOG_NOTICE(( "received POSIX signal %i; sending halt to main @ %p", sig, (void*)fd_frank_main_cnc ));
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
launch_group( int     argc,
              char ** argv ) {

  char const * pod_gaddr = fd_env_strip_cmdline_cstr( &argc, &argv, "--pod", NULL, NULL );
  char const * cfg_path  = fd_env_strip_cmdline_cstr( &argc, &argv, "--cfg", NULL, NULL );
  char const * grp_name  = fd_env_strip_cmdline_cstr( &argc, &argv, "--task-group", NULL, NULL );

  if( FD_UNLIKELY( !pod_gaddr ) ) FD_LOG_ERR(( "--pod not specified" ));
  if( FD_UNLIKELY( !cfg_path  ) ) FD_LOG_ERR(( "--cfg not specified" ));
  if( FD_UNLIKELY( !grp_name  ) ) FD_LOG_ERR(( "--task-group not specified" ));

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
  char * task_type_paths = fd_alloca(
    alignof(char *), 
    MAX_TASK_POD_KEY_LEN * (tasks_cnt+1) );

  if( FD_UNLIKELY( !task_type_paths ) ) FD_LOG_ERR(( "fd_alloca failed" ));

  /* Have a reference handy to all tasks's CNC */
  fd_cnc_t ** tile_cnc = fd_alloca( alignof(fd_cnc_t *), sizeof(fd_cnc_t *)*tasks_cnt );
  if( FD_UNLIKELY( !tile_cnc ) ) FD_LOG_ERR(( "fd_alloca failed" ));  

  /* The main tile's (this thread) CNC will be the first in this list */
  fd_cnc_t * cnc = tile_cnc[ 0 ] = fd_cnc_join( fd_wksp_pod_map( group_pod, "cnc" ) );
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

    #ifdef FD_HAS_SANDBOX
    fd_sandbox_profile_t profile;
    fd_sandbox_profile_init( &profile );
    #endif /* FD_HAS_SANDBOX */

    if      ( FD_UNLIKELY( !strcmp( task_type, "pack"   ) ) )
      task = fd_frank_pack_task;
    else if ( FD_UNLIKELY( !strcmp( task_type, "dedup"  ) ) )
      task = fd_frank_dedup_task;
    else if ( FD_UNLIKELY( !strcmp( task_type, "verify" ) ) )
      task = fd_frank_verify_task;
    else {
      FD_LOG_ERR(( "unknown task type '%s'", task_type ));
    }

    #ifdef FD_HAS_SANDBOX
    fd_sandbox(&profile);
    #endif /* FD_HAS_SANDBOX */

    FD_LOG_NOTICE(( "attempting to launch %lu task(s) of type %s", fd_pod_cnt_subpod( task_type_pod ), task_type ));

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
      if ( written+1 > MAX_TASK_POD_KEY_LEN ) {
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

  FD_VOLATILE( fd_frank_main_cnc ) = cnc;
  fd_frank_signal_trap( SIGTERM );
  fd_frank_signal_trap( SIGINT  );

  FD_LOG_INFO(( "main run" ));
  fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
  pid_t pid = getpid();

  //double ns_per_tic = 1./fd_tempo_tick_per_ns( NULL );
//  long then = fd_tickcount();
  for (;;) { /* shutdown loop */
    // long now = fd_tickcount();

    // if ( (double)(now - then) * ns_per_tic < 1e9 ) {
    //   FD_YIELD();
    //   continue;
    // }
    // then = now;

    /* Check on top level tasks */
    for(ulong task_id=0UL; task_id <tasks_cnt; task_id++) {

    }

    /* Send diagnostic info */
    fd_cnc_heartbeat( cnc, fd_tickcount(), pid );
    /* Receive command-and-control signals */
    if( FD_UNLIKELY( fd_cnc_signal_query( cnc )==FD_CNC_SIGNAL_HALT ) ) {
      FD_LOG_NOTICE(( "CNC entered HALT state" ));
      break;
    }
    FD_YIELD(); /* not SPIN_PAUSE as this tile is meant to float and be low resource utilization */
  }

  fd_cnc_signal( cnc, FD_CNC_SIGNAL_BOOT );
  FD_LOG_INFO(( "main fini" ));

  FD_LOG_NOTICE(( "app fini" ));

  FD_LOG_NOTICE(( "shutting down %lu task(s)", tasks_cnt ));
  for( ulong tile_idx=tasks_cnt; tile_idx>=1UL; tile_idx-- ) {
    /* Note: could do this in parallel too but doing reverse
       one-at-a-time for symmetry with boot */

    FD_LOG_WARNING(( "about to end tile %lu", tile_idx ));
    if( FD_UNLIKELY( fd_cnc_open( tile_cnc[ tile_idx ] ) ) ) FD_LOG_ERR(( "fd_cnc_open failed for tile %lu", tile_idx ));
    fd_cnc_signal( tile_cnc[ tile_idx ], FD_CNC_SIGNAL_HALT );
    fd_cnc_close ( tile_cnc[ tile_idx ] );

    int ret;
    if( FD_UNLIKELY( fd_tile_exec_delete( fd_tile_exec( tile_idx ), &ret ) ) ) FD_LOG_ERR(( "fd_tile_exec_delete failed" ));
    if( FD_UNLIKELY( ret ) ) FD_LOG_ERR(( "unexpected ret (%i)", ret ));
  }

  /* Clean up */
  
  for( ulong tile_idx=tasks_cnt+1; tile_idx; tile_idx-- ) fd_wksp_pod_unmap( fd_cnc_leave( tile_cnc[ tile_idx-1UL ] ) );
  fd_wksp_pod_detach( pod );
  fd_halt();
  return 0;
}

#include <unistd.h> // fork
#include <sys/wait.h> // waitpid
#include <errno.h>

ulong fd_join_char_arrays( char *  dst, 
                                    ulong   dst_sz, 
                                    char    sep, 
                                    int     argc, 
                                    char ** argv ) {
  char * head = dst;

  for (uint i = 0; i < (uint) argc; i++) {
    ulong written = (ulong) (head - dst);
    /* ensure it does not overflow */
    ulong arglen = strnlen( argv[i], 1024 );
    if ( FD_UNLIKELY( ( arglen == 1024 ) ) )                FD_LOG_ERR(( "argument too long (>1024)" ));
    if ( FD_UNLIKELY( ( written + arglen + 1 ) > dst_sz ) ) FD_LOG_ERR(( "buffer would overrun"      )); /* `+ 1` to account for the separator */
    printf("arg: %s\n", argv[i]);
    fd_memcpy( head, argv[i], arglen );
    head[ arglen ] = sep;
    head += arglen + 1; /* `+ 1` to skip over the separator */
  }

  /* replace the last sep by \00 */
  head = 0;
  return (ulong) (head - dst);
}

// /* fd_cstr_to_table takes a cstr `line` and turns naively replaces spaces with line terminators.
//    While doing so, it adds a pointer to the string heads into `dst_table`.
//    It returns the number of words found or -1 on error.
// */
// long fd_cstr_to_table( char ** dst_table,
//                         long dst_max_sz,
//                         char * line, 
//                         long n ) {
//   char * head = line;
//   long words_found = 0;
//   for ( uint i=0; i<n; i++ ) {
//     switch ( line[ i ] ) {
//     case ' ': /* found space */
//       line[ i ] = 0;
//       dst_table[ words_found++ ] = head;
//       head = line + i + 1;
//       if ( FD_UNLIKELY( words_found >= dst_max_sz ) ) {
//         /* the next entry won't fit the dst_table */
//         goto fail;
//       }
//       break;

//     case 0: /* line is terminated */
//       dst_table[ words_found++ ] = head;
//       dst_table[words_found] = 0; /* null-terminate the table */
//       return words_found;
//     }
//   }

//   /* reaching here means that there was no null in line
//      proactively invalidate the destination buffer. */

//   fail:
//   fd_memcpy(line, '\00', (ulong)n);
//   dst_table[0] = NULL;
//   return -1;
// }

int
main( int   argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_tempo_tick_per_ns( NULL ); /* eat calibration cost at deterministic place */

  char const * task_group_name = fd_env_cmdline_cstr( &argc, &argv, "--task-group", NULL, NULL );
  if( FD_LIKELY( task_group_name ) ) {
    /* run the task group */
    printf("launching group\n");
    return launch_group(argc, argv);
  }
  fd_log_thread_set( "launcher" );
    
  /* since there's no task group group specified, run the launcher */

  char const * pod_gaddr = fd_env_cmdline_cstr( &argc, &argv, "--pod", NULL, NULL );
  char const * cfg_path  = fd_env_cmdline_cstr( &argc, &argv, "--cfg", NULL, NULL );

  if( FD_UNLIKELY( !pod_gaddr ) ) FD_LOG_ERR(( "--pod not specified" ));
  if( FD_UNLIKELY( !cfg_path  ) ) FD_LOG_ERR(( "--cfg not specified" ));

  uchar const * pod     = fd_wksp_pod_attach( pod_gaddr );
  uchar const * cfg_pod = fd_pod_query_subpod( pod, cfg_path );
  if( FD_UNLIKELY( !cfg_pod ) ) FD_LOG_ERR(( "path not found" ));

  uchar const * all_groups_pod = fd_pod_query_subpod( cfg_pod, "grp" );
  if( FD_UNLIKELY( !all_groups_pod ) ) FD_LOG_ERR(( "path not found" ));

  /* reference to CNCs
     [0] is this thread's CNC
     [n] is group n-1's CNC */
  const ulong group_cnt = fd_pod_cnt_subpod( all_groups_pod );
  char const ** tg_names = fd_alloca( alignof(char const *), sizeof(char const *)*group_cnt );
  fd_cnc_t **   tg_cnc =    fd_alloca( alignof(fd_cnc_t *), sizeof(fd_cnc_t *)*group_cnt );

  if( FD_UNLIKELY( !tg_cnc ) ) FD_LOG_ERR(( "fd_alloca failed" ));
  if( FD_UNLIKELY( !tg_names ) ) FD_LOG_ERR(( "fd_alloca failed" ));

  /* The main tile's (this thread) CNC will be the first in this list */
  fd_cnc_t * cnc = tg_cnc[ 0 ] = fd_cnc_join( fd_wksp_pod_map( cfg_pod, "main.cnc" ) );
  if( FD_UNLIKELY( !cnc ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
  if( FD_UNLIKELY( fd_cnc_app_sz( cnc ) < 64UL ) ) FD_LOG_ERR(( "cnc app sz should be at least 64 bytes" ));

  /* make sure that the launcher can boot */
  if( FD_UNLIKELY( fd_cnc_signal_query( cnc )!=FD_CNC_SIGNAL_BOOT ) ) {
    FD_LOG_ERR(( "launcher CNC is not in BOOT state... aborting." ));
  }

  FD_LOG_NOTICE(( "attempting to launch the following groups..." ));
  list_groups(all_groups_pod);

  char * child_arg_buf = fd_alloca( alignof( char* ), MAX_CMDLINE_LEN );
  const char ** child_argv = fd_alloca( alignof( char** ), 1024UL );

  pid_t * tg_pids = fd_alloca( alignof( pid_t ), group_cnt );

  uint group_no = 0;
  for( fd_pod_iter_t tg_iter = fd_pod_iter_init( all_groups_pod ); !fd_pod_iter_done( tg_iter ); tg_iter = fd_pod_iter_next( tg_iter ) ) {
    fd_pod_info_t group_info = fd_pod_iter_info( tg_iter );
    if( FD_UNLIKELY( group_info.val_type!=FD_POD_VAL_TYPE_SUBPOD ) ) continue;

    char const * tg_name = tg_names[group_no] = group_info.key;

    int this_tg_pid = fork();

    if ( !this_tg_pid ) {
      /* running child */

      /* Leave the parent's process group to prevent signals destined to it from making it
         to the child. This has the advantage of letting us control the leaving order. */
      setpgid( 0, 0 );

      /* find cmdline */
      char const * cmdline = fd_pod_query_cstr( group_info.val, "cmdline", NULL );

      if ( FD_UNLIKELY( !cmdline ) ) {
        FD_LOG_WARNING(( "cmdline for task group '%s' is not set in config",  tg_name ));
      } else if ( FD_UNLIKELY( !cmdline ) ) {
        FD_LOG_WARNING(( "cmdline for task group '%s' is set and empty",  tg_name ));
      }

      /* turn cmdline in a structure suitable for execv* */
      ulong cmdlinelen = strlen( cmdline );
      if ( MAX_CMDLINE_LEN < cmdlinelen+1 ) {
        FD_LOG_ERR(( "cmdline longer than %lu", MAX_CMDLINE_LEN ));
      }
      fd_memcpy(child_arg_buf, cmdline, cmdlinelen+1 );

      /* reserve the first entry for the invocation name */
      child_argv[0] = argv[0];
      /* reserve the 2nd and 3rd entres for the tg name */
      child_argv[1] = "--task-group";
      child_argv[2] = tg_name;

      ulong c_argc = fd_cstr_tokenize (
        (char **)child_argv + 3, /* accounting for the reserved argv[0:2] */
        1023UL - 3, /* accounting for array null terminator */
        child_arg_buf,
        ' '
      );

      c_argc += 3; /* accounting for the reselved slots */
      child_argv[c_argc] = NULL;

      // clean up parent's resources
      fd_wksp_pod_detach( pod );
      fd_halt();

      execv(argv[0], (char**)child_argv);
      FD_LOG_ERR(( "execv: %s", strerror( errno ) ));
    }

    fd_cnc_t * child_cnc = tg_cnc[group_no+1] = fd_cnc_join( fd_wksp_pod_map( group_info.val, "cnc" ) );
    if( FD_UNLIKELY( !child_cnc ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
    if( FD_UNLIKELY( fd_cnc_app_sz( child_cnc ) < 64UL ) ) FD_LOG_ERR(( "cnc app sz should be at least 64 bytes" ));

    
    /* wait for this tg to be successfully started before moving forward 
       If it times-out: fail. */

    if( FD_UNLIKELY( fd_cnc_wait( child_cnc, FD_CNC_SIGNAL_BOOT, (long)5e9, NULL )!=FD_CNC_SIGNAL_RUN ) )
      FD_LOG_ERR(( "task group failed to boot in a timely fashion name=%s", tg_name ));
    else
      FD_LOG_NOTICE(( "task group started name=%s pid=%d", tg_name, this_tg_pid ));
    // todo: cleanup
    
    /* track the child pid */
    tg_pids[group_no] = this_tg_pid;
    group_no++;
  }

  /* all tgs have been launched */
  fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
  FD_LOG_NOTICE(( "launched %lu task(s)", group_cnt ));

  // todo: sandbox

  /* Configure normal kill and ctrl-c to do a clean shutdown */
  FD_VOLATILE( fd_frank_main_cnc ) = cnc;
  fd_frank_signal_trap( SIGTERM );
  fd_frank_signal_trap( SIGINT  );

  double ns_per_tic = 1./fd_tempo_tick_per_ns( NULL );
  pid_t pid = getpid();
  for(;;) {

    /* Send diagnostic info */
    fd_cnc_heartbeat( cnc, fd_tickcount(), pid );
    /* Receive command-and-control signals */
    if( FD_UNLIKELY( fd_cnc_signal_query( cnc )==FD_CNC_SIGNAL_HALT ) ) {
      FD_LOG_NOTICE(( "CNC entered HALT state" ));
      break;
    }

    /* Check that all task groups haven't timed out */
    fd_cnc_t * ccnc;

    int done = 0;
    long now; long tic; fd_tempo_observe_pair( &now, &tic );
    for ( ulong tg_idx = 1UL; tg_idx < group_cnt; tg_idx++ ) {
      ccnc = tg_cnc[tg_idx];
      long last_heartbeat = fd_cnc_heartbeat_query( ccnc );

      double stale_ns = (double)(tic - last_heartbeat) * ns_per_tic;

      if (stale_ns > MAX_STALE_NS) {
        FD_LOG_NOTICE(( "CNC @ %lu is stale", tg_idx ));
        done = 1;
        break;
      }
    }
    if ( done ) break;

    FD_YIELD(); /* not SPIN_PAUSE as this tile is meant to float and be low resource utilization */
  }
  FD_LOG_NOTICE(( "leaving launcher main loop" ));
  fd_cnc_signal( cnc, FD_CNC_SIGNAL_BOOT );

  for( ulong tg_idx=0UL; tg_idx< group_cnt; tg_idx++ ) {
    FD_LOG_NOTICE(( "halting task group %s", tg_names[tg_idx] ));

    /* Note: could do this in parallel too but doing reverse
       one-at-a-time for symmetry with boot */

    fd_cnc_t * ccnc = (tg_cnc+1)[ tg_idx ];
    if( FD_UNLIKELY( fd_cnc_open( ccnc ) ) ) FD_LOG_ERR(( "fd_cnc_open failed for task %s", tg_names[tg_idx] ));

    ulong tg_sig = fd_cnc_signal_query( ccnc );
    if ( tg_sig == FD_CNC_SIGNAL_RUN ) 
      fd_cnc_signal( ccnc, FD_CNC_SIGNAL_HALT );
    else {
      char signamebuf[ FD_CNC_SIGNAL_CSTR_BUF_MAX ];
      fd_cnc_signal_cstr ( tg_sig, signamebuf );
      FD_LOG_WARNING(( "attempting to halt task not in run state task=%s state=%s", tg_names[tg_idx], signamebuf ));
    }
    fd_cnc_close ( ccnc );
  }

  // Improvement: could wait for all children to quit

  long then = fd_tickcount();
  for (;;) { /* shutdown loop */
    long now = fd_tickcount();

    /* call waitpid WNOHANG on each children
       - if they all have exited, launcher can exit too
       - if there remains one alive beyond the shutdown grace, it needs to die
     */

    ulong remaining = group_cnt;
    for (ulong i = 0; i < group_cnt; i++) {
      pid_t target = tg_pids[i];

      if ( !target ) { // already observed as exited
        remaining--;
        continue;
      }

      int status;
      pid_t res = waitpid(target, &status, WNOHANG);

      if (res) {
        remaining--;
        tg_pids[i] = 0;
      }
    }

    if ( !remaining ) {
      break;
    }

    if ( (double)(now - then) * ns_per_tic > SHUTDOWN_GRACE_NS ) {
      FD_LOG_WARNING(( "sending SIGKILL to %lu task groups", remaining ));
      for (ulong i = 0; i < group_cnt; i++) {
        pid_t target = tg_pids[i];

        if ( !target ) { // already observed as exited
          remaining--;
          continue;
        }

        FD_LOG_WARNING(( "killing pid=%d group=%s", target, tg_names[i] ));
        kill(target, SIGKILL);
        break;
      }
    }

    FD_YIELD();
  } /* shutdown loop */
  
  /* Clean up */
  
  for( ulong cnc_idx=group_cnt+1; cnc_idx; cnc_idx-- ) fd_wksp_pod_unmap( fd_cnc_leave( tg_cnc[ cnc_idx-1UL ] ) );
  fd_wksp_pod_detach( pod );
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
