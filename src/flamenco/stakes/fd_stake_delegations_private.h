#ifndef HEADER_fd_src_flamenco_stakes_fd_stake_delegations_private_h
#define HEADER_fd_src_flamenco_stakes_fd_stake_delegations_private_h

#include "fd_stake_delegations.h"

#define PAGE_FREE    (0)
#define PAGE_ROOT    (1)
#define PAGE_DELTA   (2)
#define PAGE_DIRTY   ((uchar)1)
#define PAGE_WRITTEN ((uchar)2)

struct page {
  ulong  used[2];
  uint   frame;
  uint   prev;
  uint   next;
  ushort cnt;
  uchar  role;
  uchar  flags;
};
typedef struct page page_t;

struct frame {
  uint page;
  uint referenced;
  uint next;
  uint pad;
};
typedef struct frame frame_t;

struct fork {
  uint   delta_head;
  uint   views;
  ushort parent;
  uchar  in_use;
};
typedef struct fork fork_t;

struct __attribute__((aligned(64))) stripe {
  uint  lock;
  uchar pad[60];
};
typedef struct stripe stripe_t;

FD_STATIC_ASSERT( sizeof(page_t)  ==32UL, page_size );
FD_STATIC_ASSERT( sizeof(frame_t) ==16UL, frame_size );
FD_STATIC_ASSERT( sizeof(fork_t)  ==12UL, fork_size );
FD_STATIC_ASSERT( sizeof(stripe_t)==64UL, stripe_size );

#endif /* HEADER_fd_src_flamenco_stakes_fd_stake_delegations_private_h */
