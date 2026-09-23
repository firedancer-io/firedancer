#ifndef HEADER_fd_src_flamenco_stakes_fd_stake_delegations_private_h
#define HEADER_fd_src_flamenco_stakes_fd_stake_delegations_private_h

#include "fd_stake_delegations.h"

#define PAGE_FREE    (0)
#define PAGE_ROOT    (1)
#define PAGE_DELTA   (2)
#define PAGE_DIRTY   ((uchar)1)
#define PAGE_WRITTEN ((uchar)2)

struct page {
  ulong  used[2]; /* allocated slots; free record contents are unspecified */
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
  uint next;
};
typedef struct frame frame_t;

struct fork {
  uint   delta_head;
  ushort parent; /* pool next when free */
  uchar  in_use;
};
typedef struct fork fork_t;

FD_STATIC_ASSERT( sizeof(page_t)  ==32UL, page_size );
FD_STATIC_ASSERT( sizeof(frame_t) == 8UL, frame_size );
FD_STATIC_ASSERT( sizeof(fork_t)  == 8UL, fork_size );

struct fd_stake_delegations {
  /* Identity and immutable configuration */
  ulong magic;
  ulong seed;
  ulong max_live_slots;
  uint  page_max;
  uint  frame_max;
  int   disk_fd;

  /* Packed shared-memory layout */
  ulong pages_offset;
  ulong frames_offset;
  ulong forks_offset;
  ulong descends_offset;
  ulong data_offset;

  /* Record allocator and page cache */
  uint        page_wmk; /* one past the highest page index ever acquired */
  uint        next_victim; /* frame evicted next when every frame is in use */

  /* Linked lists of partly used pages, split by role and by whether the
     page is resident in a cache frame or evicted to disk.  Each head is
     the page index of the first page in the list, or UINT_MAX if the
     list is empty.  The rest of a list is linked through page_t
     prev/next. */
  uint        partial_root_resident_head;
  uint        partial_root_evicted_head;
  uint        partial_delta_resident_head;
  uint        partial_delta_evicted_head;
  fd_rwlock_t lock;

  /* Fork lifecycle */
  ushort      root_fork;
  uchar       boot;

  /* Rooted aggregate state */
  ulong root_cnt;
  ulong effective_stake;
  ulong activating_stake;
  ulong deactivating_stake;
  uchar fp_warmed_awarded;

  /* Rooted aggregate calculation context */
  uchar                    context_valid;
  int                      root_fixed_point;
  ulong                    root_epoch;
  ulong                    root_rate_epoch;
  ulong                    root_history_len;
  fd_stake_history_entry_t root_history[ FD_SYSVAR_STAKE_HISTORY_CAP ];
};

#endif /* HEADER_fd_src_flamenco_stakes_fd_stake_delegations_private_h */
