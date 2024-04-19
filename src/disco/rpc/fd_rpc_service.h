#ifndef HEADER_fd_src_flamenco_rpc_fd_rpc_service_h
#define HEADER_fd_src_flamenco_rpc_fd_rpc_service_h

#include "../../util/fd_util.h"
#include "../../funk/fd_funk.h"
#include "../../util/valloc/fd_valloc.h"
#include "../tvu/fd_replay.h"

typedef struct fd_rpc_ctx fd_rpc_ctx_t;
typedef struct fd_exec_slot_ctx fd_exec_slot_ctx_t;

fd_rpc_ctx_t * fd_rpc_alloc_ctx(fd_replay_t * replay, fd_pubkey_t * identity);

void fd_rpc_start_service(ushort portno, fd_rpc_ctx_t * ctx);
  
void fd_rpc_stop_service(fd_rpc_ctx_t * ctx);

#endif /* HEADER_fd_src_flamenco_rpc_fd_rpc_service_h */
