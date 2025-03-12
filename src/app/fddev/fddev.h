#ifndef HEADER_fd_src_app_fddev_fddev_h
#define HEADER_fd_src_app_fddev_fddev_h

#include "../fdctl/fdctl.h"

extern action_t DEV_ACTIONS[];

int
fddev_main( int     argc,
            char ** argv );

void
add_bench_topo( fd_topo_t  * topo,
                char const * affinity,
                ulong        benchg_tile_cnt,
                ulong        benchs_tile_cnt,
                ulong        accounts_cnt,
                int          transaction_mode,
                float        contending_fraction,
                float        cu_price_spread,
                ulong        conn_cnt,
                ushort       send_to_port,
                uint         send_to_ip_addr,
                ushort       rpc_port,
                uint         rpc_ip_addr,
                int          no_quic );

void flame_cmd_perm( args_t * args, fd_cap_chk_t * chk, config_t const * config );
void dev_cmd_perm  ( args_t * args, fd_cap_chk_t * chk, config_t const * config );
void load_cmd_perm ( args_t * args, fd_cap_chk_t * chk, config_t const * config );
void txn_cmd_perm  ( args_t * args, fd_cap_chk_t * chk, config_t const * config );
void wksp_cmd_perm ( args_t * args, fd_cap_chk_t * chk, config_t const * config );

void bench_cmd_args     ( int * pargc, char *** pargv, args_t * args );
void dev_cmd_args       ( int * pargc, char *** pargv, args_t * args );
void dev1_cmd_args      ( int * pargc, char *** pargv, args_t * args );
void dump_cmd_args      ( int * pargc, char *** pargv, args_t * args );
void flame_cmd_args     ( int * pargc, char *** pargv, args_t * args );
void load_cmd_args      ( int * pargc, char *** pargv, args_t * args );
void pktgen_cmd_args    ( int * pargc, char *** pargv, args_t * args );
void quic_trace_cmd_args( int * pargc, char *** pargv, args_t * args );
void txn_cmd_args       ( int * pargc, char *** pargv, args_t * args );

void bench_cmd_fn     ( args_t * args, config_t * config );
void dev_cmd_fn       ( args_t * args, config_t * config );
void dev1_cmd_fn      ( args_t * args, config_t * config );
void dev_help_cmd_fn  ( args_t * args, config_t * config );
void dump_cmd_fn      ( args_t * args, config_t * config );
void flame_cmd_fn     ( args_t * args, config_t * config );
void load_cmd_fn      ( args_t * args, config_t * config );
void pktgen_cmd_fn    ( args_t * args, config_t * config );
void quic_trace_cmd_fn( args_t * args, config_t * config );
void txn_cmd_fn       ( args_t * args, config_t * config );
void wksp_cmd_fn      ( args_t * args, config_t * config );

#if FD_HAS_NO_AGAVE

void gossip_cmd_args( int * pargc, char *** pargv, args_t * args );

void gossip_cmd_fn( args_t * args, config_t * config );

void gossip_cmd_perm( args_t * args, fd_cap_chk_t * chk, config_t const * config );

#endif /* FD_HAS_NO_AGAVE */

#endif /* HEADER_fd_src_app_fddev_fddev_h */
