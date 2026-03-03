#ifndef HEADER_fd_src_discof_accdb_fd_accdb_tile_private_h
#define HEADER_fd_src_discof_accdb_fd_accdb_tile_private_h

#include "../../vinyl/fd_vinyl.h"
#include "../../funk/fd_funk.h"
#include "../../util/io_uring/fd_io_uring.h"
#include "fd_accdb_line_ctl.h"

/* fd_accdb_line_ctl_clear atomically bumps the version, clears
   EVICTING and CHANCE, and sets ref to new_ref.  Uses a CAS loop
   to handle concurrent specreader pin/unpin safely.  Any in-flight
   specreader ADD/SUBs that race with the CAS simply cause a retry
   (the specreader bails on EVICTING and SUBs back immediately). */

static inline void
fd_accdb_line_ctl_clear( fd_vinyl_line_t * line,
                         ulong             line_idx,
                         long              new_ref ) {
  for(;;) {
    ulong cur = FD_VOLATILE_CONST( line[ line_idx ].ctl );
    ulong new = fd_accdb_line_ctl( fd_accdb_line_ctl_ver( cur )+1UL, new_ref );
    if( FD_LIKELY( FD_ATOMIC_CAS( &line[ line_idx ].ctl, cur, new )==cur ) ) return;
    FD_SPIN_PAUSE();
  }
}

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

  uint clock_hand;          /* CLOCK sweep position, in [0,line_cnt) */
  int  root_populate_cache; /* If non-zero, root_batch copies rooted pairs into cache with least priority */

  /* Rooting — the replay tile sends root target xids via stem link.
     The accdb tile consumes them immediately (after_frag) and walks
     funk's child list in during_housekeeping to find the oldest unrooted
     txn, publishing it to vinyl subject to write_delay_slots. */

  fd_funk_txn_t * root_txn;       /* txn being rooted, NULL if idle */
  fd_funk_rec_t * root_rec;       /* next rec head for root_batch, NULL if done */
  ulong           root_txn_idx;   /* index of root_txn in txn_pool */

  fd_funk_txn_xid_t root_target_xid; /* newest root xid from replay; ul[0]==ULONG_MAX means none received yet */
  ulong write_delay_slots;

  /* Stem input link for root messages from replay */

  fd_wksp_t * root_in_mem;
  ulong       root_in_chunk0;
  ulong       root_in_wmark;

  /* Scratch for during_frag → after_frag handoff */

  fd_funk_txn_xid_t pending_xid;
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

    if( FD_LIKELY( !fd_accdb_line_ctl_ref( hand_ctl ) ) ) {

      if( FD_UNLIKELY( hand_ctl & FD_ACCDB_LINE_CTL_CHANCE ) ) {
        FD_ATOMIC_FETCH_AND_AND( &line[ hand ].ctl,
                                 ~FD_ACCDB_LINE_CTL_CHANCE );
        hand = (uint)((hand+1U<(uint)line_cnt) ? hand+1U : 0U);
        continue;
      }

      /* Try to claim for eviction via CAS.  CAS proves ref==0 at
         this instant. */
      if( FD_LIKELY( FD_ATOMIC_CAS( &line[ hand ].ctl,
                                     hand_ctl,
                                     hand_ctl | FD_ACCDB_LINE_CTL_EVICTING )==hand_ctl ) ) {

        /* Drain any specread pins that raced with the EVICTING CAS.
           A specread that did FETCH_AND_ADD after our CAS will see
           EVICTING in old_ctl and immediately FETCH_AND_SUB back.
           We must wait for that SUB to land before ctl_clear, which
           would otherwise capture the transient +1 ref in its own
           CAS and leave ref at -1 after the specread's SUB. */
        while( FD_UNLIKELY( fd_accdb_line_ctl_ref(
                   FD_VOLATILE_CONST( line[ hand ].ctl ) ) > 0L ) ) {
          FD_SPIN_PAUSE();
        }

        break;
      }
    }

    hand = (uint)((hand+1U<(uint)line_cnt) ? hand+1U : 0U);
  }

  ctx->clock_hand = (uint)((hand+1U<(uint)line_cnt) ? hand+1U : 0U);

  /* Evict: free data obj, disconnect meta */

  void *                data_laddr0 = data->laddr0;
  ulong                 obj_gaddr   = line[ hand ].obj_gaddr;
  ulong                 ele_idx     = line[ hand ].ele_idx;

  if( FD_LIKELY( obj_gaddr ) ) {
    FD_LOG_ERR(( "evicting obj_gaddr=%lu", obj_gaddr ));
    fd_vinyl_data_obj_t * obj = fd_vinyl_data_laddr( obj_gaddr, data_laddr0 );
    FD_CRIT( obj->line_idx==(ulong)hand, "corruption detected" );
    FD_CRIT( !obj->rd_active,            "corruption detected" );
    fd_vinyl_data_free( data, obj );
    line[ hand ].obj_gaddr = 0UL;
  }

  if( FD_LIKELY( ele_idx<ele_max ) ) {
    FD_CRIT( ele0[ ele_idx ].line_idx==(ulong)hand, "corruption detected" );
    ele0[ ele_idx ].line_idx = ULONG_MAX;
  } else {
    FD_CRIT( ele_idx==ULONG_MAX, "corruption detected" );
  }

  /* Bump version, clear EVICTING via CAS (handles in-flight specread
     ADD/SUBs that race with eviction).  Sets ref=0. */
  fd_accdb_line_ctl_clear( line, (ulong)hand, 0L );

  return (ulong)hand;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_accdb_fd_accdb_tile_private_h */
