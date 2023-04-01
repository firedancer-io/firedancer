#ifndef HEADER_fd_src_ballet_runtime_fd_runtime_h
#define HEADER_fd_src_ballet_runtime_fd_runtime_h

#include "fd_executor.h"
#include "fd_rocksdb.h"

#define FD_RUNTIME_EXECUTE_SUCCESS                               ( 0 )  /* Slot executed successfully */
#define FD_RUNTIME_EXECUTE_GENERIC_ERR                       ( -1 ) /* The Slot execute returned an error */

FD_PROTOTYPES_BEGIN

void fd_runtime_boot_slot_zero( global_ctx_t *global );
int fd_runtime_block_execute( global_ctx_t *global, fd_slot_blocks_t *slot_data );
int fd_runtime_block_verify( global_ctx_t *global, fd_slot_blocks_t *slot_data );
int fd_runtime_block_eval( global_ctx_t *global, fd_slot_blocks_t *slot_data );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_runtime_fd_runtime_h */
