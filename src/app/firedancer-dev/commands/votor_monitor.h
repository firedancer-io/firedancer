#ifndef HEADER_fd_src_app_firedancer_dev_commands_votor_monitor_h
#define HEADER_fd_src_app_firedancer_dev_commands_votor_monitor_h

/* The Alpenglow consensus view: a terminal rendering of what the votor
   tile is doing, read off its votor_out link.

   Two ways in.  `firedancer-dev votor` stands up a minimal ingest
   topology and calls votor_monitor_run directly.  `firedancer-dev votor-monitor`
   attaches to an ALREADY RUNNING validator the way `monitor` does --
   join its workspaces, poll the link, draw -- which is also what
   `firedancer-dev dev --votor-monitor` forks.

   Either way the view only ever reads.  It is not a topology consumer,
   so a slow terminal can never backpressure consensus; it just misses
   frags and says so. */

#include "../../shared/fd_config.h"
#include "../../shared/fd_action.h"

FD_PROTOTYPES_BEGIN

/* votor_monitor_args strips the view's flags (--fps, --frames, --rows,
   --cols, --ascii, --no-color) off the command line. */

void
votor_monitor_args( int *    pargc,
               char *** pargv );

/* votor_monitor_run draws until interrupted (or until --frames frames have
   been rendered).  config->topo must already be joined. */

void
votor_monitor_run( config_t * config );

/* votor_monitor_child is the `dev --votor-monitor` entry point: join the running
   validator's workspaces read-only, then draw.  Never returns. */

void
votor_monitor_child( args_t *   args,
                     config_t * config );

/* votor_monitor_attach joins AND fills the topology, then draws.  Use it
   from a process that has not already set the topology up. */

void
votor_monitor_attach( config_t * config );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_firedancer_dev_commands_votor_monitor_h */
