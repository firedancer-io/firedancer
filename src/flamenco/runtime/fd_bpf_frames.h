#ifndef HEADER_fd_src_flamenco_runtime_fd_bpf_frames_h
#define HEADER_fd_src_flamenco_runtime_fd_bpf_frames_h

/* fd_bpf_frames holds the BPF loader input serialization frames for the
   exec{rp,le} tiles.  A BPF instruction serializes its input into a
   frame and holds it until it returns, and a CPI takes another frame
   while its caller keeps its own, so a tile holds up to one frame per
   instruction stack level.  This object allows for shared and
   tile-local frames for both tiles.  Each tile can keep some number of
   frames local to itself for performance reasons.  The last shared
   frames are held back so the pool cannot deadlock.  This is sized so
   that contending transactions cannot starve each other for bpf frames.

   fd_bpf_frames_shmem_t is the pool and fd_bpf_frames_t is one user's
   local join to it. */

#include "fd_runtime_const.h"

/* FD_BPF_FRAMES_HELD_CNT is the number of shared frames held back when
   each join has local_cnt local frames, and so the fewest shared frames
   a pool can have. */

#define FD_BPF_FRAMES_HELD_CNT( local_cnt ) (2UL*(FD_MAX_INSTRUCTION_STACK_DEPTH-(local_cnt)))
#define FD_BPF_FRAMES_CNT_MAX               (1UL<<16)

/* FD_BPF_FRAMES_ALIGN is the alignment of every frame. */

#define FD_BPF_FRAMES_ALIGN (4096UL)

struct fd_bpf_frames_shmem;
typedef struct fd_bpf_frames_shmem fd_bpf_frames_shmem_t;

struct fd_bpf_frames;
typedef struct fd_bpf_frames fd_bpf_frames_t;

FD_PROTOTYPES_BEGIN

/* fd_bpf_frames_shmem_{align,footprint,new} size and format a pool of
   frame_cnt shared frames, plus local_cnt local frames reserved for
   each of up to joiner_cnt_max joins.  footprint returns 0 if local_cnt
   is more than FD_MAX_INSTRUCTION_STACK_DEPTH, frame_cnt is less than
   FD_BPF_FRAMES_HELD_CNT( local_cnt ), or the pool would have more than
   FD_BPF_FRAMES_CNT_MAX frames.  new returns shmem on success, NULL on
   failure (logs details). */

FD_FN_CONST ulong
fd_bpf_frames_shmem_align( void );

FD_FN_CONST ulong
fd_bpf_frames_shmem_footprint( ulong frame_cnt,
                               ulong joiner_cnt_max,
                               ulong local_cnt );

void *
fd_bpf_frames_shmem_new( void * shmem,
                         ulong  frame_cnt,
                         ulong  joiner_cnt_max,
                         ulong  local_cnt );

/* fd_bpf_frames_{align,footprint,join} size and create a local join to
   the pool at shframes in the memory at ljoin, taking the next joiner's
   local frames.  Each user needs its own join.  join returns NULL (logs
   details) if joiner_cnt_max users already joined. */

FD_FN_CONST ulong
fd_bpf_frames_align( void );

FD_FN_CONST ulong
fd_bpf_frames_footprint( void );

fd_bpf_frames_t *
fd_bpf_frames_join( void * ljoin,
                    void * shframes );

/* fd_bpf_frames_acquire takes a frame, spinning until one is
   available.  priority is whether the caller is the priority caller. */

uchar *
fd_bpf_frames_acquire( fd_bpf_frames_t * join,
                       int               priority );

/* fd_bpf_frames_release returns a frame acquired through join.  A
   join's frames must be released in the reverse order they were
   acquired. */

void
fd_bpf_frames_release( fd_bpf_frames_t * join,
                       uchar *           frame );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_bpf_frames_h */
