#ifndef HEADER_fd_src_app_fdctl_run_h
#define HEADER_fd_src_app_fdctl_run_h

#include "../fdctl.h"

#include "../../../tango/xdp/fd_xsk.h"

typedef struct {
   int           pid;
   char *        app_name;
   char *        tile_name;
   ulong         tile_idx;
   ulong         idx;
   uchar const * tile_pod;
   uchar const * in_pod;
   uchar const * out_pod;
   fd_xsk_t    * xsk;
   fd_xsk_t    * lo_xsk;
} fd_tile_args_t;

typedef struct {
   char *  name;
   char *  in_wksp;
   char *  out_wksp;
   ushort  allow_syscalls_sz;
   long *  allow_syscalls;
   ulong (*allow_fds)( fd_tile_args_t * args, ulong out_fds_sz, int * out_fds );
   void  (*init)( fd_tile_args_t * args );
   void  (*run )( fd_tile_args_t * args );
} fd_tile_config_t;

extern fd_tile_config_t verify;
extern fd_tile_config_t dedup;
extern fd_tile_config_t serve;
extern fd_tile_config_t pack;

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
                    char * tile_name,
                    ulong tile_idx );

int
solana_labs_main( void * args );

int
tile_main( void * _args );

void
run_firedancer( config_t * const config );

#endif /* HEADER_fd_src_app_fdctl_run_h */
