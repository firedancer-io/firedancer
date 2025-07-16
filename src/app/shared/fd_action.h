#ifndef HEADER_fd_src_app_shared_fd_action_h
#define HEADER_fd_src_app_shared_fd_action_h

#include "../platform/fd_cap_chk.h"

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
  } load; /* also used by bench */

  struct {
    int event;
    int dump; /* whether the user requested --dump */
    int dump_config; /* whether the user requested to dump the quic config */
    int dump_conns;  /* whether the user requested to dump the quic connections */
  } quic_trace;

  struct {
    char tile_cpus[ 256UL ];
  } snapshot_load;

  struct {
    ushort listen_port;
  } udpecho;

};

typedef union fdctl_args args_t;

struct fd_action {
  char const * name;
  char const * description;
  char const * permission_err;

  int          is_help;
  int          is_immediate;
  int          require_config;   /* halt if the user tries to use the default config */
  int          is_local_cluster; /* If a command is one which runs a local cluster, certain information in
                                    the configuration file will be changed. */
  uchar        is_diagnostic;  /* 1 implies action should be allowed for prod debugging */

  void       (*args)( int * pargc, char *** pargv, args_t * args );
  void       (*perm)( args_t * args, fd_cap_chk_t * chk, config_t const * config );
  void       (*fn  )( args_t * args, config_t * config );
};

typedef struct fd_action action_t;

#endif /* HEADER_fd_src_app_shared_fd_action_h */
