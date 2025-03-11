#ifndef HEADER_fd_src_app_shared_dev_commands_bench_bench_h
#define HEADER_fd_src_app_shared_dev_commands_bench_bench_h

#include "../../../shared/fd_config.h"

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

#endif /* HEADER_fd_src_app_shared_dev_commands_bench_bench_h */
