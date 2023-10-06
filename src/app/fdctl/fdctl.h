#ifndef HEADER_fd_src_app_fdctl_fdctl_h
#define HEADER_fd_src_app_fdctl_fdctl_h

#include "../../util/fd_util.h"
#include "../../util/net/fd_ip4.h"

#include "config.h"
#include "caps.h"
#include "utility.h"

#include <unistd.h>
#include <errno.h>

#define CONFIGURE_STAGE_COUNT 12
struct configure_stage;

typedef union {
  struct {
    long dt_min;
    long dt_max;
    long duration;
    uint seed;
    double ns_per_tic;
    int drain_output_fd;
  } monitor;
  struct {
    int                      command;
    struct configure_stage * stages[ CONFIGURE_STAGE_COUNT ];
  } configure;
  struct {
    int tile;
  } run1;
  struct {
    int monitor;
    int no_configure;
  } dev;
  struct {
    const char * payload_base64;
    ulong  count;
    const char * dst_ip;
    ushort dst_port;
  } txn;
} args_t;

typedef struct fd_caps_ctx fd_caps_ctx_t;

typedef struct {
    const char * name;
    void       (*args)( int * pargc, char *** pargv, args_t * args );
    void       (*perm)( args_t * args, fd_caps_ctx_t * caps, config_t * const config );
    void       (*fn  )( args_t * args, config_t * const config );
} action_t;

extern action_t ACTIONS[ 5 ];

int
main1( int     argc,
      char ** _argv );

void
generate_keypair( const char * keyfile,
                  config_t * const config );

void
configure_cmd_args( int *    pargc,
                    char *** pargv,
                    args_t * args );
void
configure_cmd_perm( args_t *         args,
                    fd_caps_ctx_t *  caps,
                    config_t * const config );
void
configure_cmd_fn( args_t *         args,
                  config_t * const config );

void
run_cmd_perm( args_t *         args,
              fd_caps_ctx_t *  caps,
              config_t * const config );

void
run_cmd_fn( args_t *         args,
            config_t * const config );

void
monitor_cmd_args( int *    pargc,
                  char *** pargv,
                  args_t * args );
void
monitor_cmd_perm( args_t *         args,
                  fd_caps_ctx_t *  caps,
                  config_t * const config );
void
monitor_cmd_fn( args_t *         args,
                config_t * const config );

void
keygen_cmd_fn( args_t *         args,
               config_t * const config );

void
ready_cmd_fn( args_t *         args,
              config_t * const config );

#endif /* HEADER_fd_src_app_fdctl_fdctl_h */
