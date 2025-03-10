#ifndef HEADER_fd_src_app_fdctl_fdctl_h
#define HEADER_fd_src_app_fdctl_fdctl_h

#include "config.h"

#include "../../disco/topo/fd_topo.h"
#include "../shared/fd_cap_chk.h"

#include <unistd.h>
#include <errno.h>

extern fd_topo_run_tile_t * TILES[];


#define CONFIGURE_STAGE_COUNT 12
struct configure_stage;

union fdctl_args {
  struct {
    char  tile_name[ 7UL ];
    ulong kind_id;
    int   pipe_fd;
  } run1;

  struct {
    long dt_min;
    long dt_max;
    long duration;
    uint seed;
    double ns_per_tic;
    int drain_output_fd;
    int with_bench;
    int with_sankey;
  } monitor;

  struct {
    int                      command;
    struct configure_stage * stages[ CONFIGURE_STAGE_COUNT ];
  } configure;

  struct {
    int     require_tower;
    int     force;
    uchar * keypair;
  } set_identity;

  struct {
    int  parent_pipefd;
    int  monitor;
    int  no_configure;
    int  no_init_workspaces;
    int  no_agave;
    char debug_tile[ 32 ];
  } dev;

  struct {
    char tile_name[ 7UL ];
    int  no_configure;
  } dev1;

  struct {
    ulong cmd;
    char  file_path[ 256 ];
  } keys;

  struct {
    const char * payload_base64;
    ulong  count;
    const char * dst_ip;
    ushort dst_port;
  } txn;

  struct {
    char link_name[ 64UL ];
    char pcap_path[ 256UL ];
  } dump;

  struct {
    char name[ 13UL ];
  } flame;

  struct {
    char    affinity[ AFFINITY_SZ ];
    uint    tpu_ip;
    uint    rpc_ip;
    ushort  tpu_port;
    ushort  rpc_port;
    ulong   accounts;
    ulong   connections;
    ulong   benchg;
    ulong   benchs;
    int     no_quic;
    int     transaction_mode;
    float   contending_fraction;
    float   cu_price_spread;
  } load;

  struct {
    int event;
    int dump; /* whether the user requested --dump */
  } quic_trace;
};

typedef union fdctl_args args_t;

typedef struct {
  const char * name;
  const char * description;
  uchar        is_diagnostic;  /* 1 implies action should be allowed for prod debugging */

  void       (*args)( int * pargc, char *** pargv, args_t * args );
  void       (*perm)( args_t * args, fd_cap_chk_t * chk, config_t const * config );
  void       (*fn  )( args_t * args, config_t * config );
} action_t;

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
fdctl_tile_run( fd_topo_tile_t * tile );

extern action_t ACTIONS[];

void fdctl_boot( int *        pargc,
                 char ***     pargv,
                 config_t   * config,
                 char const * log_path);

int
main1( int     argc,
       char ** _argv );

void FD_FN_SENSITIVE
generate_keypair( char const * keyfile,
                  config_t *   config,
                  int          use_grnd_random );

void configure_cmd_args   ( int * pargc, char *** pargv, args_t * args );
void run1_cmd_args        ( int * pargc, char *** pargv, args_t * args );
void monitor_cmd_args     ( int * pargc, char *** pargv, args_t * args );
void keys_cmd_args        ( int * pargc, char *** pargv, args_t * args );
void set_identity_cmd_args( int * pargc, char *** pargv, args_t * args );

void configure_cmd_perm   ( args_t * args, fd_cap_chk_t * chk, config_t const * config );
void run_cmd_perm         ( args_t * args, fd_cap_chk_t * chk, config_t const * config );
void monitor_cmd_perm     ( args_t * args, fd_cap_chk_t * chk, config_t const * config );
void set_identity_cmd_perm( args_t * args, fd_cap_chk_t * chk, config_t const * config );

void configure_cmd_fn   ( args_t * args, config_t * config );
void run_cmd_fn         ( args_t * args, config_t * config );
void run1_cmd_fn        ( args_t * args, config_t * config );
void run_agave_cmd_fn   ( args_t * args, config_t * config );
void monitor_cmd_fn     ( args_t * args, config_t * config );
void keys_cmd_fn        ( args_t * args, config_t * config );
void set_identity_cmd_fn( args_t * args, config_t * config );
void ready_cmd_fn       ( args_t * args, config_t * config );
void mem_cmd_fn         ( args_t * args, config_t * config );
void netconf_cmd_fn     ( args_t * args, config_t * config );
void help_cmd_fn        ( args_t * args, config_t * config );
void version_cmd_fn     ( args_t * args, config_t * config );

#endif /* HEADER_fd_src_app_fdctl_fdctl_h */
