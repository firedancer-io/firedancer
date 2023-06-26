#ifndef HEADER_fd_src_ballet_block_fd_microblock_h
#define HEADER_fd_src_ballet_block_fd_microblock_h

#include "../fd_ballet_base.h"
#include "../sha256/fd_sha256.h"

struct __attribute__((packed)) fd_microblock_hdr {
  /* Number of PoH hashes between this and last microblock */
  /* 0x00 */ ulong hash_cnt;

  /* PoH state after evaluating parent microblock (including previous
     appends and mixin).

     For the first microblock within the slot, this is equal to the
     parent block hash, i.e. the PoH state after evaluating the last
     microblock or the parent block.  Otherwise, this is the PoH state
     after evaluating the immediate predecessor microblock within the
     same slot. */
  /* 0x08 */ uchar hash[ FD_SHA256_HASH_SZ ];

  /* Number of transactions in this microblock */
  /* 0x28 */ ulong txn_cnt;
};
typedef struct fd_microblock_hdr fd_microblock_hdr_t;

#endif /* HEADER_fd_src_ballet_block_fd_microblock_h */
