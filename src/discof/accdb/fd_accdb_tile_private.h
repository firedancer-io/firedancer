#ifndef HEADER_fd_src_discof_accdb_fd_accdb_tile_private_h
#define HEADER_fd_src_discof_accdb_fd_accdb_tile_private_h

#include "../../vinyl/fd_vinyl.h"
#include "../../funk/fd_funk.h"
#include "../../util/io_uring/fd_io_uring.h"

#define FD_VINYL_CLIENT_MAX (1024UL)
#define FD_VINYL_REQ_MAX    (1024UL)

struct fd_vinyl_client {
  fd_vinyl_rq_t * rq;        /* Channel for requests from this client (could be shared by multiple vinyl instances) */
  fd_vinyl_cq_t * cq;        /* Channel for completions from this client to this vinyl instance
                                (could be shared by multiple receivers of completions from this vinyl instance). */
  ulong           burst_max; /* Max requests receive from this client at a time */
  ulong           seq;       /* Sequence number of the next request to receive in the rq */
  ulong           link_id;   /* Identifies requests from this client to this vinyl instance in the rq */
  ulong           laddr0;    /* A valid non-zero gaddr from this client maps to the vinyl instance's laddr laddr0 + gaddr ... */
  ulong           laddr1;    /* ... and thus is in (laddr0,laddr1).  A zero gaddr maps to laddr NULL. */
  ulong           quota_rem; /* Num of remaining acquisitions this client is allowed on this vinyl instance */
  ulong           quota_max; /* Max quota */
};

typedef struct fd_vinyl_client fd_vinyl_client_t;

struct fd_accdb_tile {

  fd_funk_t funk[1];

  /* Vinyl objects */

  fd_vinyl_t vinyl[1];
  void * io_mem;

  /* Tile architecture */

  uint booted : 1;
  uint shutdown : 1;
  struct {
    ulong                  state_expected;
    ulong volatile const * state;
    ulong volatile const * pair_cnt;
    /* When booting from genesis only */
    struct {
      ulong                io_seed;
    } from_genesis;
  } boot;

  /* I/O */

  int   bstream_fd;
  ulong bstream_file_sz;

  /* io_uring */

  fd_io_uring_t ring[1];
  void * ioring_shmem; /* shared between kernel and user */

  /* Clients */

  fd_vinyl_client_t _client[ FD_VINYL_CLIENT_MAX ];
  ulong             client_cnt;
  ulong             client_idx;

  /* Received requests */

  fd_vinyl_req_t _req[ FD_VINYL_REQ_MAX ];
  ulong          req_head;                 /* Requests [0,req_head)         have been processed */
  ulong          req_tail;                 /* Requests [req_head,req_tail)  are pending */
                                           /* Requests [req_tail,ULONG_MAX) have not been received */
  ulong exec_max;

  /* accum_dead_cnt is the number of dead blocks that have been
     written since the last partition block.

     accum_move_cnt is the number of move blocks that have been
     written since this last partition block.

     accum_garbage_cnt / sz is the number of items / bytes garbage in
     the bstream that have accumulated since the last time we compacted
     the bstream.  We use this to estimate the number of rounds of
     compaction to do in async handling. */

  ulong accum_dead_cnt;
  ulong accum_garbage_cnt;
  ulong accum_garbage_sz;

  /* Run loop state */

  ulong seq_part;

  /* Periodic syncing */

  long sync_next_ns;

  /* Vinyl limit on the number of pairs the meta map will accept.
     Exceeding this limit will trigger a LOG_ERR. */
  ulong pair_cnt_limit;

  uint clock_hand; /* CLOCK sweep position, in [0,line_cnt) */
};

typedef struct fd_accdb_tile fd_accdb_tile_t;

FD_PROTOTYPES_BEGIN

/* fd_accdb_clock_evict uses a CLOCK sweep to select and evict a
   cache line.  Scans from clock_hand (mod line_cnt), giving each
   unreferenced line with chance==1 a "second chance" (clearing chance
   to 0) and spinning until it finds an unreferenced line with
   chance==0 that it can claim via CAS.  Frees the data obj,
   disconnects meta, and bumps the version inline.  Returns the
   evicted line_idx. */

static inline ulong
fd_accdb_clock_evict( fd_accdb_tile_t *     ctx,
                      fd_vinyl_line_t *     line,
                      ulong                 line_cnt,
                      fd_vinyl_meta_ele_t * ele0,
                      ulong                 ele_max,
                      fd_vinyl_data_t *     data ) {
  uint hand = ctx->clock_hand;

  for(;;) {

    ulong hand_ctl = line[ hand ].ctl;

    if( FD_LIKELY( !fd_vinyl_line_ctl_ref( hand_ctl ) ) ) {

      uint src = FD_VOLATILE_CONST( line[ hand ].specread_ctl );

      /* Skip lines pinned by specreaders */
      if( FD_UNLIKELY( src & FD_VINYL_LINE_SRC_REF_MASK ) ) {
        hand = (uint)((hand+1U<(uint)line_cnt) ? hand+1U : 0U);
        continue;
      }

      /* Second chance: if chance set, clear it and advance */
      if( FD_UNLIKELY( src & FD_VINYL_LINE_SRC_CHANCE ) ) {
        FD_ATOMIC_FETCH_AND_AND( &line[ hand ].specread_ctl,
                                 ~FD_VINYL_LINE_SRC_CHANCE );
        hand = (uint)((hand+1U<(uint)line_cnt) ? hand+1U : 0U);
        continue;
      }

      /* Try to claim for eviction via CAS */
      if( FD_LIKELY( !FD_ATOMIC_CAS( &line[ hand ].specread_ctl,
                                      0U, FD_VINYL_LINE_SRC_EVICTING ) ) ) {
        break;  /* CAS succeeded: specread_ctl was 0, now EVICTING */
      }

      /* CAS failed: a reader pinned between our read and the CAS */
    }

    hand = (uint)((hand+1U<(uint)line_cnt) ? hand+1U : 0U);
  }

  ctx->clock_hand = (uint)((hand+1U<(uint)line_cnt) ? hand+1U : 0U);

  /* Evict: free data obj, disconnect meta, bump version */

  fd_vinyl_data_obj_t * obj     = line[ hand ].obj;
  ulong                 ele_idx = line[ hand ].ele_idx;

  if( FD_LIKELY( obj ) ) {
    FD_CRIT( obj->line_idx==(ulong)hand, "corruption detected" );
    FD_CRIT( !obj->rd_active,            "corruption detected" );
    fd_vinyl_data_free( data, obj );
    line[ hand ].obj = NULL;
  }

  if( FD_LIKELY( ele_idx<ele_max ) ) {
    FD_CRIT( ele0[ ele_idx ].line_idx==(ulong)hand, "corruption detected" );
    ele0[ ele_idx ].line_idx = ULONG_MAX;
  } else {
    FD_CRIT( ele_idx==ULONG_MAX, "corruption detected" );
  }

  ulong ver = fd_vinyl_line_ctl_ver( line[ hand ].ctl );
  line[ hand ].ctl = fd_vinyl_line_ctl( ver+1UL, 0L );

  return (ulong)hand;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_accdb_fd_accdb_tile_private_h */
