#ifndef HEADER_fd_src_app_fddev_fddev_h
#define HEADER_fd_src_app_fddev_fddev_h

#include "../fdctl/fdctl.h"

void
dev_cmd_args( int *    pargc,
              char *** pargv,
              args_t * args );

void
dev_cmd_perm( args_t *         args,
              security_t *     security,
              config_t * const config );

void
dev_cmd_fn( args_t *         args,
            config_t * const config );

void
dev1_cmd_args( int *    pargc,
               char *** pargv,
               args_t * args );

void
dev1_cmd_fn( args_t *         args,
             config_t * const config );

void
txn_cmd_perm( args_t *         args,
              security_t *     security,
              config_t * const config );

void
txn_cmd_args( int *    pargc,
              char *** pargv,
              args_t * args);

void
txn_cmd_fn( args_t *         args,
            config_t * const config );

#endif /* HEADER_fd_src_app_fddev_fddev_h */
