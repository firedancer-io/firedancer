#ifndef HEADER_fd_src_flamenco_runtime_info_fd_microblock_info_h
#define HEADER_fd_src_flamenco_runtime_info_fd_microblock_info_h

#include "../../fd_flamenco_base.h"
#include "../../../ballet/block/fd_microblock.h"
#include "../../../ballet/txn/fd_txn.h"
#include "../../../ballet/pack/fd_microblock.h"

struct fd_microblock_info {
  fd_microblock_hdr_t microblock_hdr;
  ulong signature_cnt;
  ulong account_cnt;

  fd_txn_p_t * txns;

  void const * raw_microblock;
  ulong raw_microblock_sz;
};
typedef struct fd_microblock_info fd_microblock_info_t;

FD_PROTOTYPES_BEGIN

void *
fd_microblock_info_new( void * mem );

fd_microblock_info_t *
fd_microblock_info_join( void * mem );

void *
fd_microblock_info_leave( fd_microblock_info_t * info );

void *
fd_microblock_info_delete( void * mem );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_info_fd_microblock_info_h */
