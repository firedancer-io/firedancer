#ifndef HEADER_fd_src_ballet_block_fd_microblock_h
#define HEADER_fd_src_ballet_block_fd_microblock_h

#include "../fd_ballet_base.h"
#include "../sha256/fd_sha256.h"

struct __attribute__((packed)) fd_microblock_hdr {
  /* Number of PoH hashes between this and last microblock */
  /* 0x00 */ ulong hash_cnt;

  /* PoH state after evaluating this microblock (including all
     appends and mixin). The input to the poh calculation of the first
     microblock is the last hash of the parent block, otherwise it is the
     hash of the previous microblock. */
  /* 0x08 */ uchar hash[ FD_SHA256_HASH_SZ ];

  /* Number of transactions in this microblock */
  /* 0x28 */ ulong txn_cnt;
};
typedef struct fd_microblock_hdr fd_microblock_hdr_t;

#endif /* HEADER_fd_src_ballet_block_fd_microblock_h */
