#ifndef HEADER_fd_src_flamenco_rpc_fd_rpc_service_h
#define HEADER_fd_src_flamenco_rpc_fd_rpc_service_h

#include "../../util/fd_util.h"
#include "../../funk/fd_funk.h"
#include "../../util/valloc/fd_valloc.h"
#include "../runtime/fd_blockstore.h"

typedef struct fd_rpc_ctx fd_rpc_ctx_t;

fd_rpc_ctx_t * fd_rpc_alloc_ctx(fd_funk_t * funk, fd_blockstore_t * blks, fd_pubkey_t * identity, fd_valloc_t valloc);

void fd_rpc_set_slot(fd_rpc_ctx_t * ctx, ulong slot);

void fd_rpc_start_service(ushort portno, fd_rpc_ctx_t * ctx);
  
void fd_rpc_stop_service(fd_rpc_ctx_t * ctx);

#endif /* HEADER_fd_src_flamenco_rpc_fd_rpc_service_h */
