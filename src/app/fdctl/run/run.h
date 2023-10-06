#ifndef HEADER_fd_src_app_fdctl_run_h
#define HEADER_fd_src_app_fdctl_run_h

#include "../fdctl.h"

#include "../../../tango/xdp/fd_xsk.h"
#include "../../../util/sandbox/fd_sandbox.h"

typedef struct {
   int                pid;
   char *             app_name;
   char *             tile_name;
   ulong              tile_idx;
   ulong              idx;
   const uchar *      wksp_pod[ 16 ];
   fd_xsk_t *         xsk;
   fd_xsk_t *         lo_xsk;
} fd_tile_args_t;

typedef struct {
   char *             name;
   ushort             allow_workspaces_cnt;
   workspace_kind_t * allow_workspaces;
   ushort             allow_syscalls_cnt;
   long *             allow_syscalls;
   ulong (*allow_fds)( fd_tile_args_t * args, ulong out_fds_sz, int * out_fds );
   void  (*init)( fd_tile_args_t * args );
   void  (*run )( fd_tile_args_t * args );
   sandbox_mode_t sandbox_mode;
} fd_tile_config_t;

extern fd_tile_config_t net;
extern fd_tile_config_t netmux;
extern fd_tile_config_t quic;
extern fd_tile_config_t verify;
extern fd_tile_config_t dedup;
extern fd_tile_config_t pack;
extern fd_tile_config_t metrics;
extern fd_tile_config_t bank;

typedef struct {
  fd_tile_config_t * tile;
  ulong tile_idx;
  ulong idx;
  int sandbox;
  uid_t uid;
  gid_t gid;
  char * app_name;
} tile_main_args_t;

const uchar *
workspace_pod_join( char * app_name,
                    char * workspace_name );

int
solana_labs_main( void * args );

int
tile_main( void * _args );

void
run_firedancer( config_t * const config );

#endif /* HEADER_fd_src_app_fdctl_run_h */
