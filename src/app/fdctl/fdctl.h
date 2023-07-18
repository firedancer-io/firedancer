#ifndef HEADER_fd_src_app_fdctl_fdctl_h
#define HEADER_fd_src_app_fdctl_fdctl_h

#include "../../util/fd_util.h"

#include "config.h"
#include "security.h"
#include "utility.h"

#include <errno.h>

#define CONFIGURE_STAGE_COUNT 10
struct configure_stage;

typedef union {
  struct {
    int configure;
  } run;
  struct {
    long dt_min;
    long dt_max;
    long duration;
    uint seed;
  } monitor;
  struct {
    int                      command;
    struct configure_stage * stages[ CONFIGURE_STAGE_COUNT ];
  } configure;
} args_t;

typedef struct security security_t;

void
configure_cmd_args( int *    pargc,
                    char *** pargv,
                    args_t * args );
void
configure_cmd_perm( args_t *         args,
                    security_t *     security,
                    config_t * const config );
void
configure_cmd_fn( args_t *         args,
                  config_t * const config );

void
run_cmd_args( int *    pargc,
              char *** pargv,
              args_t * args );

void
run_cmd_perm( args_t *         args,
              security_t *     security,
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
                  security_t *     security,
                  config_t * const config );
void
monitor_cmd_fn( args_t *         args,
                config_t * const config );

#endif /* HEADER_fd_src_app_fdctl_fdctl_h */
