#ifndef HEADER_fd_src_app_fdctl_fdctl_h
#define HEADER_fd_src_app_fdctl_fdctl_h

#include "../shared/fd_config.h"
#include "../shared/fd_cap_chk.h"
#include "../../disco/topo/fd_topo.h"

#include <unistd.h>
#include <errno.h>

extern fd_topo_run_tile_t * TILES[];

struct configure_stage;

ulong
fdctl_obj_align( fd_topo_t const *     topo,
                 fd_topo_obj_t const * obj );

ulong
fdctl_obj_footprint( fd_topo_t const *     topo,
                     fd_topo_obj_t const * obj );

ulong
fdctl_obj_loose( fd_topo_t const *     topo,
                 fd_topo_obj_t const * obj );

fd_topo_run_tile_t
fdctl_tile_run( fd_topo_tile_t const * tile );

extern action_t ACTIONS[];

void fdctl_boot( int *        pargc,
                 char ***     pargv,
                 config_t   * config,
                 char const * log_path);

int
main1( int     argc,
       char ** _argv );

void FD_FN_SENSITIVE
generate_keypair( char const *     keyfile,
                  config_t const * config,
                  int              use_grnd_random );

void run1_cmd_args        ( int * pargc, char *** pargv, args_t * args );
void keys_cmd_args        ( int * pargc, char *** pargv, args_t * args );
void set_identity_cmd_args( int * pargc, char *** pargv, args_t * args );

void set_identity_cmd_perm( args_t * args, fd_cap_chk_t * chk, config_t const * config );

void run1_cmd_fn        ( args_t * args, config_t * config );
void keys_cmd_fn        ( args_t * args, config_t * config );
void set_identity_cmd_fn( args_t * args, config_t * config );
void ready_cmd_fn       ( args_t * args, config_t * config );
void mem_cmd_fn         ( args_t * args, config_t * config );
void netconf_cmd_fn     ( args_t * args, config_t * config );
void help_cmd_fn        ( args_t * args, config_t * config );
void version_cmd_fn     ( args_t * args, config_t * config );

#if !FD_HAS_NO_AGAVE
void run_agave_cmd_fn( args_t * args, config_t * config );
#endif

#endif /* HEADER_fd_src_app_fdctl_fdctl_h */
