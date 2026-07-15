#ifndef HEADER_fd_src_app_shared_fd_action_h
#define HEADER_fd_src_app_shared_fd_action_h

#include "../platform/fd_cap_chk.h"

/* FD_APP_NAME and FD_BINARY_NAME identify the control binary at run time
   (e.g. "Firedancer"/"firedancer", "Frankendancer"/"fddev").  They are
   defined once per binary in its main translation unit.  Commands
   shared across binaries should reference these instead of hard-coding
   a binary name in help text or usage messages. */

extern char const * FD_APP_NAME;
extern char const * FD_BINARY_NAME;

union fdctl_args {
  struct {
    char  tile_name[ 7UL ];
    ulong kind_id;
    int   pipe_fd;
  } run1;

  struct {
    char topo[ 64 ];
    long dt_min;
    long dt_max;
    long duration;
    uint seed;
    int drain_output_fd;
    int with_bench;
    int with_sankey;
  } monitor;

  struct {
    int drain_output_fd;
    int full;
  } watch;

  struct {
    int                      command;
    struct configure_stage * stages[ CONFIGURE_STAGE_COUNT ];
  } configure;

  struct {
    int     require_tower;
    int     require_vote_history;
    int     force;
    uchar const * keypair;
    char    name[ 64UL ];
  } set_identity;

  struct {
    uchar const * keypair;
    char    name[ 64UL ];
  } add_authorized_voter;

  struct {
    char name[ 64UL ];
  } remove_all_authorized_voters;

  struct {
    char name[ 64UL ];
  } get_identity;

  struct {
    int clean;
  } ps;

  struct {
    int  parent_pipefd;
    int  no_watch;
    int  full_watch;
    int  no_configure;
    int  no_init_workspaces;
    int  no_agave;
  } dev;

  struct {
    int no_watch;
  } backtest;

  struct {
    int no_watch;
  } forktest;

  struct {
    char tile_name[ 7UL ];
    int  no_configure;
  } dev1;

  struct {
    ulong cmd;
    char  file_path[ PATH_MAX ];
  } keys;

  struct {
    const char * payload_base64;
    ulong  count;
    const char * dst_ip;
    ushort dst_port;
  } txn;

  struct {
    char link_name[ 128UL ];
    char pcap_path[ 256UL ];
    int  once;
  } dump;

  struct {
    char name[ 13UL ];
    uint freq;
  } flame;

  struct {
    char const * pos_arg;
    int          help;

    /* options */

    char         manifest_path[256UL];
    char         iptable_path[256UL];
    ulong        slot;
    int          sort_by_slot;
  } repair;

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
    int     no_watch;
    int     transaction_mode;
    float   contending_fraction;
    float   cu_price_spread;
  } load; /* also used by bench */

  struct {
    int event;
    int dump; /* whether the user requested --dump */
    int dump_config; /* whether the user requested to dump the quic config */
    int dump_conns;  /* whether the user requested to dump the quic connections */
    int trace_send;  /* whether the user requested tracing send tile (1) or quic tile (0) */
  } quic_trace;

  struct {
    ushort listen_port;
  } udpecho;

  struct {
    char topo[ 64 ];
  } metrics;

  struct {
    char topo[ 64 ];
    int  sort;
  } mem;

  struct {
    char  topo[ 64 ];
    ulong interval_ns;

    ulong selectors_cnt;
    struct fd_action_metrics_record_selector {
      char  name[ 32 ];
      char  kind[ 16 ];
      ulong kind_id;
    } selectors[ 128 ];
  } metrics_record;

  struct {
    int accounts_hist;
    int offline;
    int no_incremental;
    int no_watch;

    char snapshot_dir[ PATH_MAX ];

    ulong db_rec_max;
    ulong cache_sz;
  } snapshot_load;

  struct {
    ulong max_entries;
    ulong max_contact;
    int   compact_mode;
  } gossip;

  struct {
    char topo[ 64 ];
    int  compact_mode;
  } monitor_gossip;

  struct {
    char const * pos_arg;
    int          help;
  } tower;

  struct {
    ulong ready_slot;
  } ready;
};

typedef union fdctl_args args_t;

struct fd_action_help;
typedef struct fd_action_help fd_action_help_t;

/* fd_action_help_arg emits one argument into the help builder.  name is
   the flag or positional placeholder (e.g. "--topo" or "<keypair>").
   value is the value placeholder for flags taking an argument (e.g.
   "<name>"), or NULL.  description is the human readable description,
   which may contain embedded newlines to wrap onto continuation lines. */

void
fd_action_help_arg( fd_action_help_t * help,
                    char const *       name,
                    char const *       value,
                    char const *       description );

struct fd_action {
  char const * name;
  char const * description;     /* one-line summary shown in the subcommand list */
  char const * permission_err;

  char const * usage;     /* usage synopsis line (e.g. "keys <new|pubkey> <path>"), or NULL to derive from name */
  char const * detail;    /* multi-line long-form description, or NULL */

  /* args_help, if non-NULL, emits the accepted flags / positional
     arguments for `--help`. */
  void (*args_help)( fd_action_help_t * help );

  int          is_help;
  int          is_immediate;
  int          require_config;   /* halt if the user tries to use the default config */
  int          is_local_cluster; /* If a command is one which runs a local cluster, certain information in
                                    the configuration file will be changed. */
  uchar        is_diagnostic;  /* 1 implies action should be allowed for prod debugging */

  void       (*args)( int * pargc, char *** pargv, args_t * args );
  void       (*topo)( config_t * config );
  void       (*perm)( args_t * args, fd_cap_chk_t * chk, config_t const * config );
  void       (*fn  )( args_t * args, config_t * config );
};

typedef struct fd_action action_t;

/* fd_action_help_print prints the help message for a single subcommand
   to stdout. */

void
fd_action_help_print( action_t const * action );

/* fd_global_options_help emits the global command-line options accepted
   by every subcommand of the binary.  These differ depending on how the
   binary boots: fd_boot.c provides a weak default, and fd_dev_boot.c
   provides a strong override listing additional development flags. */

void
fd_global_options_help( fd_action_help_t * help );

#endif /* HEADER_fd_src_app_shared_fd_action_h */
