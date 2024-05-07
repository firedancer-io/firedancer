#ifndef HEADER_fd_src_app_fddev_fddev_h
#define HEADER_fd_src_app_fddev_fddev_h

#include "../fdctl/fdctl.h"

int fddev_main( int     argc,
                char ** argv );

void
update_config_for_dev( config_t * const config );

void
add_bench_topo( fd_topo_t  * topo,
                char const * affinity,
                ulong        benchg_tile_cnt,
                ulong        benchs_tile_cnt,
                ulong        accounts_cnt,
                ulong        conn_cnt,
                ushort       send_to_port,
                uint         send_to_ip_addr,
                ushort       rpc_port,
                uint         rpc_ip_addr,
                int          no_quic );

void
dev_cmd_args( int *    pargc,
              char *** pargv,
              args_t * args );

void
dev_cmd_perm( args_t *         args,
              fd_caps_ctx_t *  caps,
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
              fd_caps_ctx_t *  caps,
              config_t * const config );

void
txn_cmd_args( int *    pargc,
              char *** pargv,
              args_t * args );

void
txn_cmd_fn( args_t *         args,
            config_t * const config );

void
bench_cmd_perm( args_t *         args,
                fd_caps_ctx_t *  caps,
                config_t * const config );

void
bench_cmd_args( int *    pargc,
                char *** pargv,
                args_t * args );

void
bench_cmd_fn( args_t *         args,
              config_t * const config );

void
hiit_cmd_args( int *    pargc,
               char *** pargv,
               args_t * args );

void
hiit_cmd_perm( args_t *         args,
               fd_caps_ctx_t *  caps,
               config_t * const config );

void
hiit_cmd_fn( args_t *         args,
             config_t * const config );

void
dump_cmd_args( int      * argc,
               char * * * argv,
               args_t   * args );

void
dump_cmd_fn( args_t *         args,
             config_t * const config );

void
flame_cmd_perm( args_t *         args,
                fd_caps_ctx_t *  caps,
                config_t * const config );

void
flame_cmd_args( int *    pargc,
                char *** pargv,
                args_t * args );

void
flame_cmd_fn( args_t *         args,
              config_t * const config );

#endif /* HEADER_fd_src_app_fddev_fddev_h */
