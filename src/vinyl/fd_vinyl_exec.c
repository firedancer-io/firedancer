#include "fd_vinyl.h"
#include "../util/pod/fd_pod.h"
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <lz4.h>

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

/* MAP_REQ_GADDR maps a request global address req_gaddr to an array of
   cnt T's into the local address space as a T * pointer.  If the result
   is not properly aligned or the entire range does not completely fall
   within the shared region with the client, returns NULL.  Likewise,
   gaadr 0 maps to NULL.  Assumes sizeof(T)*(n) does not overflow (which
   is true where as n is at most batch_cnt which is at most 2^32 and
   sizeof(T) is at most 40. */

#define MAP_REQ_GADDR( gaddr, T, n ) ((T *)fd_vinyl_laddr( (gaddr), alignof(T), sizeof(T)*(n), client_laddr0, client_laddr1 ))

FD_FN_CONST static inline void *
fd_vinyl_laddr( ulong req_gaddr,
                ulong align,
                ulong footprint,
                ulong client_laddr0,
                ulong client_laddr1 ) {
  ulong req_laddr0 = client_laddr0 + req_gaddr;
  ulong req_laddr1 = req_laddr0    + footprint;
  return (void *)fd_ulong_if( (!!req_gaddr) & fd_ulong_is_aligned( req_laddr0, align ) &
                              (client_laddr0<=req_laddr0) & (req_laddr0<=req_laddr1) & (req_laddr1<=client_laddr1),
                              req_laddr0, 0UL );
}

/* FIXME: STASH THESE IN THE VINYL TOO? */
#define FD_VINYL_CLIENT_MAX (1024UL)
#define FD_VINYL_REQ_MAX    (1024UL)

void
fd_vinyl_exec( fd_vinyl_t * vinyl ) {

  /* Unpack shared objects */

  fd_cnc_t *        cnc  = vinyl->cnc;
  fd_vinyl_io_t *   io   = vinyl->io;
  fd_vinyl_line_t * line = vinyl->line;
  fd_vinyl_meta_t * meta = vinyl->meta;
  fd_vinyl_data_t * data = vinyl->data;

  /* Unpack config */

  ulong line_cnt  = vinyl->line_cnt;
  ulong pair_max  = vinyl->pair_max;
  ulong async_min = vinyl->async_min;
  ulong async_max = vinyl->async_max;

  /* Unpack cnc */

  if( FD_UNLIKELY( fd_cnc_signal_query( cnc )!=FD_VINYL_CNC_SIGNAL_BOOT ) ) {
    FD_LOG_WARNING(( "cnc not booting (restarting after an unclean termination?); forcing to boot and attempting to continue" ));
    fd_cnc_signal( cnc, FD_VINYL_CNC_SIGNAL_BOOT );
  }

  fd_vinyl_cmd_t * cmd  = (fd_vinyl_cmd_t *)fd_cnc_app_laddr( cnc );
  ulong *          diag = (ulong *)(cmd+1);

  /* Unpack io */

  ulong io_seed = fd_vinyl_io_seed( io );

  /* Unpack meta */

  fd_vinyl_meta_ele_t * ele0       =  meta->ele;
  ulong                 ele_max    =  meta->ele_max;
  ulong                 meta_seed  =  meta->seed;
  ulong *               lock       =  meta->lock;
  int                   lock_shift =  meta->lock_shift;

  /* Unpack data */

  ulong                       data_laddr0 = (ulong)data->laddr0;
  fd_vinyl_data_vol_t const * vol         =        data->vol;
  ulong                       vol_cnt     =        data->vol_cnt;

  /* Connected clients */

  fd_vinyl_client_t _client[ FD_VINYL_CLIENT_MAX ];
  ulong             client_cnt = 0UL;               /* In [0,client_max) */
  ulong             client_idx = 0UL;               /* If client_cnt>0, next client to poll for requests, d/c otherwise */

  ulong quota_free = line_cnt - 1UL;

  /* Received requests */

  fd_vinyl_req_t _req[ FD_VINYL_REQ_MAX ];
  ulong          req_head = 0UL;           /* Requests [0,req_head)         have been processed */
  ulong          req_tail = 0UL;           /* Requests [req_head,req_tail)  are pending */
                                           /* Requests [req_tail,ULONG_MAX) have not been received */
  ulong burst_free = FD_VINYL_REQ_MAX;
  ulong exec_max   = 0UL;

  /* accum_dead_cnt is the number of dead blocks that have been
     written since the last partition block.

     accum_move_cnt is the number of move blocks that have been
     written since this last partition block.

     accum_garbage_cnt / sz is the number of items / bytes garbage in
     the bstream that have accumulated since the last time we compacted
     the bstream.  We use this to estimate the number of rounds of
     compaction to do in async handling.

     accum_drop_link is the number of requests that were silently
     dropped because the request link_id did not match the client's
     link_id.

     accum_drop_comp is the number of requests that were silently
     dropped because an out-of-band completion was requested to be sent
     to an unmappable client address.

     accumt_req_full is the number of times we detected the pending
     request queue being completely full. */

  ulong accum_dead_cnt    = 0UL;
  ulong accum_move_cnt    = 0UL;
  ulong accum_garbage_cnt = 0UL;
  ulong accum_garbage_sz  = 0UL;
  ulong accum_drop_link   = 0UL;
  ulong accum_drop_comp   = 0UL;

  ulong seq_part = fd_vinyl_io_seq_present( io );

  /* Run */

  fd_cnc_signal( cnc, FD_VINYL_CNC_SIGNAL_RUN );

  ulong async_rem = 1UL;

  for(;;) {

    /* Process background tasks this iteration if necessary */

    if( FD_UNLIKELY( !(--async_rem) ) ) {
      long now  = fd_log_wallclock();
      async_rem = async_min + (fd_ulong_hash( (ulong)now ) % (async_max-async_min+1UL)); /* FIXME: FASTER ALGO */

      fd_cnc_heartbeat( cnc, now );

      /* If we've written enough to justify appending a parallel
         recovery partition, append one. */

      ulong seq_future = fd_vinyl_io_seq_future( io );
      if( FD_UNLIKELY( (seq_future - seq_part) > vinyl->part_thresh ) ) {

        ulong seq = fd_vinyl_io_append_part( io, seq_part, accum_dead_cnt, accum_move_cnt, NULL, 0UL );
        FD_CRIT( fd_vinyl_seq_eq( seq, seq_future ), "corruption detected" );
        seq_part = seq + FD_VINYL_BSTREAM_BLOCK_SZ;

        accum_dead_cnt = 0UL;
        accum_move_cnt = 0UL;

        accum_garbage_cnt++;
        accum_garbage_sz += FD_VINYL_BSTREAM_BLOCK_SZ;

        fd_vinyl_io_commit( io, FD_VINYL_IO_FLAG_BLOCKING );

      }

      diag[ FD_VINYL_DIAG_DROP_LINK ] += accum_drop_link; accum_drop_link = 0UL;
      diag[ FD_VINYL_DIAG_DROP_COMP ] += accum_drop_comp; accum_drop_comp = 0UL;

      /* Let the number of items of garbage generated since the last
         compaction be accum_garbage_cnt and let the steady steady
         average number of live / garbage items in the bstream's past be
         L / G (i.e. L is the average value of pair_cnt).  The average
         number pieces of garbage collected per garbage collection round
         is thus G / (L + G).  If we do compact_max rounds garbage
         collection this async handling, we expect to collect

              compact_max G / (L + G)

         items of garbage on average.  To make sure we collect garbage
         faster than we generate it on average, we then require:

              accum_garbage_cnt <~ compact_max G / (L + G)
           -> compact_max >~ (L + G) accum_garbage_cnt / G

         Let the be 2^-gc_eager be the maximum fraction of items in the
         bstream's past we are willing tolerate as garbage on average.
         We then have G = 2^-gc_eager (L + G).  This implies:

           -> compact_max >~ accum_garbage_cnt 2^gc_eager

         When accum_garbage_cnt is 0, we use a compact_max of 1 to do
         compaction rounds at a minimum rate all the time.  This allows
         transients (e.g. a sudden change to new steady state
         equilibrium, temporary disabling of garbage collection at key
         times for highest performance, etc) and unaccounted zero
         padding garbage to be absorbed when nothing else is going on. */

      int gc_eager = vinyl->gc_eager;
      if( FD_LIKELY( gc_eager>=0 ) ) {

        /* Saturating wide left shift */
        ulong overflow    = (accum_garbage_cnt >> (63-gc_eager) >> 1); /* sigh ... avoid wide shift UB */
        ulong compact_max = fd_ulong_max( fd_ulong_if( !overflow, accum_garbage_cnt << gc_eager, ULONG_MAX ), 1UL );

        /**/                                   accum_garbage_cnt = 0UL;
        vinyl->garbage_sz += accum_garbage_sz; accum_garbage_sz  = 0UL;

        fd_vinyl_compact( vinyl, compact_max );

      }

      ulong signal = fd_cnc_signal_query( cnc );
      if( FD_UNLIKELY( signal!=FD_VINYL_CNC_SIGNAL_RUN ) ) {
        if( FD_UNLIKELY( signal==FD_VINYL_CNC_SIGNAL_HALT ) ) break;

        switch( signal ) {

        case FD_VINYL_CNC_SIGNAL_SYNC: {
          fd_vinyl_io_sync( io, FD_VINYL_IO_FLAG_BLOCKING );
          break;
        }

        case FD_VINYL_CNC_SIGNAL_GET: {
          ulong old;
          int   err = FD_VINYL_SUCCESS;
          switch( cmd->get.opt ) {
          case FD_VINYL_OPT_PART_THRESH: old = vinyl->part_thresh;            break;
          case FD_VINYL_OPT_GC_THRESH:   old = vinyl->gc_thresh;              break;
          case FD_VINYL_OPT_GC_EAGER:    old = (ulong)(long)vinyl->gc_eager;  break;
          case FD_VINYL_OPT_STYLE:       old = (ulong)(uint)vinyl->style;     break;
          default:                       old = 0UL; err = FD_VINYL_ERR_INVAL; break;
          }
          cmd->get.val = old;
          cmd->get.err = err;
          break;
        }

        case FD_VINYL_CNC_SIGNAL_SET: { /* FIXME: ADD VALIDATION TO SET VALUES FOR OPT_GC_EAGER AND OPT_STYLE */
          ulong new = cmd->set.val;
          ulong old;
          int   err = FD_VINYL_SUCCESS;
          switch( cmd->set.opt ) {
          case FD_VINYL_OPT_PART_THRESH: old = vinyl->part_thresh;            vinyl->part_thresh =      new; break;
          case FD_VINYL_OPT_GC_THRESH:   old = vinyl->gc_thresh;              vinyl->gc_thresh   =      new; break;
          case FD_VINYL_OPT_GC_EAGER:    old = (ulong)(long)vinyl->gc_eager;  vinyl->gc_eager    = (int)new; break;
          case FD_VINYL_OPT_STYLE:       old = (ulong)(uint)vinyl->style;     vinyl->style       = (int)new; break;
          default:                       old = 0UL;                           err = FD_VINYL_ERR_INVAL;      break;
          }
          cmd->set.val = old;
          cmd->set.err = err;
          break;
        }

        case FD_VINYL_CNC_SIGNAL_CLIENT_JOIN: {
          int err;

          ulong        link_id   = cmd->join.link_id;
          ulong        burst_max = cmd->join.burst_max;
          ulong        quota_max = cmd->join.quota_max;
          char const * _rq       = cmd->join.rq;
          char const * _cq       = cmd->join.cq;
          char const * _wksp     = cmd->join.wksp;

          if( FD_UNLIKELY( client_cnt>=FD_VINYL_CLIENT_MAX ) ) {
            FD_LOG_WARNING(( "Too many clients (increase FD_VINYL_CLIENT_MAX)" ));
            err = FD_VINYL_ERR_FULL;
            goto join_done;
          }

          if( FD_UNLIKELY( burst_max > burst_free ) ) {
            FD_LOG_WARNING(( "Too large burst_max (increase FD_VINYL_RECV_MAX or decrease burst_max)" ));
            err = FD_VINYL_ERR_FULL;
            goto join_done;
          }

          if( FD_UNLIKELY( quota_max > fd_ulong_min( quota_free, FD_VINYL_COMP_QUOTA_MAX ) ) ) {
            FD_LOG_WARNING(( "Too large quota_max (increase line_cnt or decrease quota_max)" ));
            err = FD_VINYL_ERR_FULL;
            goto join_done;
          }

          for( ulong client_idx=0UL; client_idx<client_cnt; client_idx++ ) {
            if( FD_UNLIKELY( _client[ client_idx ].link_id==link_id ) ) {
              FD_LOG_WARNING(( "Client already joined with this link_id" ));
              err = FD_VINYL_ERR_FULL;
              goto join_done;
            }
          }

          fd_vinyl_rq_t * rq = fd_vinyl_rq_join( fd_wksp_map( _rq ) );
          if( FD_UNLIKELY( !rq ) ) {
            FD_LOG_WARNING(( "Unable to join client rq" ));
            err = FD_VINYL_ERR_INVAL;
            goto join_done;
          }

          fd_vinyl_cq_t * cq = fd_vinyl_cq_join( fd_wksp_map( _cq ) );
          if( FD_UNLIKELY( !cq ) ) {
            FD_LOG_WARNING(( "Unable to join client cq" ));
            err = FD_VINYL_ERR_INVAL;
            goto join_done;
          }

          fd_wksp_t * wksp = fd_wksp_attach( _wksp );
          if( FD_UNLIKELY( !wksp ) ) {
            FD_LOG_WARNING(( "Unable to attach to client request workspace" ));
            err = FD_VINYL_ERR_INVAL;
            goto join_done;
          }

          _client[ client_cnt ].rq        = rq;
          _client[ client_cnt ].cq        = cq;
          _client[ client_cnt ].burst_max = burst_max;
          _client[ client_cnt ].seq       = 0UL;
          _client[ client_cnt ].link_id   = link_id;
          _client[ client_cnt ].laddr0    = (ulong)wksp;
          _client[ client_cnt ].laddr1    = ULONG_MAX; //wksp->gaddr_hi; /* FIXME: HOW TO GET THIS CLEANLY */
          _client[ client_cnt ].quota_rem = quota_max;
          _client[ client_cnt ].quota_max = quota_max;
          client_cnt++;

          quota_free -= quota_max;
          burst_free -= burst_max;

          /* Every client_cnt run loop iterations we receive at most:

               sum_clients recv_max = FD_VINYL_RECV_MAX - burst_free

             requests.  To guarantee we processe requests fast enough
             that we never overrun our receive queue, under maximum
             client load, we need to process:

               sum_clients recv_max / client_cnt

             requests per run loop iteration.  We thus set exec_max
             to the ceil sum_clients recv_max / client_cnt. */

          exec_max = (FD_VINYL_REQ_MAX - burst_free + client_cnt - 1UL) / client_cnt;

          err = FD_VINYL_SUCCESS;

        join_done:
          cmd->join.err = err;
          break;
        }

        case FD_VINYL_CNC_SIGNAL_CLIENT_LEAVE: {
          int err;

          ulong link_id = cmd->leave.link_id;

          for( ulong client_idx=0UL; client_idx<client_cnt; client_idx++ ) {
            if( _client[ client_idx ].link_id==link_id ) {

              if( FD_UNLIKELY( _client[ client_idx ].quota_rem != _client[ client_idx ].quota_max ) ) {
                FD_LOG_WARNING(( "client still has outstanding acquires" ));
                err = FD_VINYL_ERR_INVAL;
                goto leave_done;
              }

              /* discard pending requests from this client */

              ulong req_tail_new = req_head;

              for( ulong req_id=req_head; req_id<req_tail; req_id++ ) {
                ulong req_idx = req_id & (FD_VINYL_REQ_MAX-1UL);
                int   discard = (_req[ req_idx ].link_id == client_idx); /* Note: link_id remapped while pending */
                _req[ req_tail_new & (FD_VINYL_REQ_MAX-1UL) ] = _req[ req_idx ];
                req_tail_new += (ulong)discard;
              }

              ulong discard_cnt = req_tail - req_tail_new;
              if( discard_cnt ) FD_LOG_WARNING(( "discard %lu pending requests from leaving client", discard_cnt ));

              req_tail = req_tail_new;

              fd_wksp_unmap( fd_vinyl_rq_leave( _client[ client_idx ].rq ) );
              fd_wksp_unmap( fd_vinyl_cq_leave( _client[ client_idx ].cq ) );
              fd_wksp_detach( (fd_wksp_t *)_client[ client_idx ].laddr0 );

              quota_free += _client[ client_idx ].quota_max;
              burst_free += _client[ client_idx ].burst_max;

              _client[ client_idx ] = _client[ --client_cnt ];

              exec_max = client_cnt ? ((FD_VINYL_REQ_MAX - burst_free + client_cnt - 1UL) / client_cnt) : 0UL;

              err = FD_VINYL_SUCCESS;
              goto leave_done;
            }
          }

          FD_LOG_WARNING(( "client not joined" ));
          err = FD_VINYL_ERR_EMPTY;

        leave_done:
          cmd->leave.err = err;
          break;
        }

        default: {
          FD_LOG_WARNING(( "unknown signal received (%lu); ignoring", signal ));
          break;
        }

        }

        fd_cnc_signal( cnc, FD_VINYL_CNC_SIGNAL_RUN );
      }
    }

    /* Receive requests from clients */

    if( FD_LIKELY( client_cnt ) ) {

      /* Select client to poll this run loop iteration */

      client_idx = fd_ulong_if( client_idx+1UL<client_cnt, client_idx+1UL, 0UL );

      fd_vinyl_client_t * client = _client + client_idx;

      fd_vinyl_rq_t * rq        = client->rq;
      ulong           seq       = client->seq;
      ulong           burst_max = client->burst_max;
      ulong           link_id   = client->link_id;

      /* Enqueue up to burst_max requests from this client into the
         local request queue.  Using burst_max << FD_VINYL_REQ_MAX
         allows applications to prevent a bursty client from starving
         other clients of resources while preserving the spatial and
         temporal locality of reasonably sized O(burst_max) bursts from
         an individual client in processing below.  Each run loop
         iteration can enqueue up to burst_max requests per iterations. */

      for( ulong recv_rem=fd_ulong_min( FD_VINYL_REQ_MAX-(req_tail-req_head), burst_max ); recv_rem; recv_rem-- ) {
        fd_vinyl_req_t * req = _req + (req_tail & (FD_VINYL_REQ_MAX-1UL));

        long diff = fd_vinyl_rq_recv( rq, seq, req );

        if( FD_LIKELY( diff>0L ) ) break; /* No requests waiting in rq at this time */

        if( FD_UNLIKELY( diff ) ) FD_LOG_CRIT(( "client overran request queue" ));

        seq++;

        /* We got the next request.  Decide if we should accept it.

           Specifically, we ignore requests whose link_id don't match
           link_id (e.g. an unknown link_id or matches a different
           client's link_id ... don't know if it is where or even if it
           is safe to the completion).  Even if the request provided an
           out-of-band location to send the completion (comp_gaddr!=0),
           we have no reason to trust it given the mismatch.

           This also gives a mechanism for a client use a single rq to
           send requests to multiple vinyl instances ... the client
           should use a different link_id for each vinyl instance.  Each
           vinyl instance will quickly filter out the requests not
           addressed to it.

           Since we know the client_idx at this point, given a matching
           link_id, we stash the client_idx in the pending req link_id
           to eliminate the need to maintain a link_id<>client_idx map
           in the execution loop below. */

        if( FD_UNLIKELY( req->link_id!=link_id ) ) {
          accum_drop_link++;
          continue;
        }

        req->link_id = client_idx;

        req_tail++;
      }

      client->seq = seq;
    }

    /* Execute received requests */

    for( ulong exec_rem=fd_ulong_min( req_tail-req_head, exec_max ); exec_rem; exec_rem-- ) {
      fd_vinyl_req_t * req = _req + ((req_head++) & (FD_VINYL_REQ_MAX-1UL));

      /* Determine the client that sent this request and unpack the
         completion fields.  We ignore requests with non-NULL but
         unmappable out-of-band completion because we can't send the
         completion in the expected manner and, in lieu of that, the
         receivers aren't expecting any completion to come via the cq
         (if any).  Note that this implies requests that don't produce a
         completion (e.g. FETCH and FLUSH) need to either provide NULL
         or a valid non-NULL location for comp_gaddr to pass this
         validation (this is not a burden practically). */

      ulong  req_id     =        req->req_id;
      ulong  client_idx =        req->link_id; /* See note above about link_id / client_idx conversion */
      ulong  batch_cnt  = (ulong)req->batch_cnt;
      ulong  comp_gaddr =        req->comp_gaddr;

      fd_vinyl_client_t * client = _client + client_idx;

      fd_vinyl_cq_t * cq            = client->cq;
      ulong           link_id       = client->link_id;
      ulong           client_laddr0 = client->laddr0;
      ulong           client_laddr1 = client->laddr1;
      ulong           quota_rem     = client->quota_rem;

      FD_CRIT( quota_rem<=client->quota_max, "corruption detected" );

      fd_vinyl_comp_t * comp = MAP_REQ_GADDR( comp_gaddr, fd_vinyl_comp_t, 1UL );
      if( FD_UNLIKELY( (!comp) & (!!comp_gaddr) ) ) {
        accum_drop_comp++;
        continue;
      }

      int   comp_err   = 1;
      ulong fail_cnt   = 0UL;

      ulong read_cnt   = 0UL;
      ulong append_cnt = 0UL;

      switch( req->type ) {

#     include "fd_vinyl_case_acquire.c"
#     include "fd_vinyl_case_release.c"
#     include "fd_vinyl_case_erase.c"
#     include "fd_vinyl_case_move.c"
#     include "fd_vinyl_case_fetch.c"
#     include "fd_vinyl_case_flush.c"
#     include "fd_vinyl_case_try.c"
#     include "fd_vinyl_case_test.c"

      default:
        comp_err = FD_VINYL_ERR_INVAL;
        break;
      }

      for( ; read_cnt; read_cnt-- ) {
        fd_vinyl_io_rd_t * _rd; /* avoid pointer escape */
        fd_vinyl_io_poll( io, &_rd, FD_VINYL_IO_FLAG_BLOCKING );
        fd_vinyl_io_rd_t * rd = _rd;

        fd_vinyl_data_obj_t *     obj      = (fd_vinyl_data_obj_t *)    rd->ctx;
        ulong                     seq      =                            rd->seq; (void)seq;
        fd_vinyl_bstream_phdr_t * cphdr    = (fd_vinyl_bstream_phdr_t *)rd->dst;
        ulong                     cpair_sz =                            rd->sz;  (void)cpair_sz;

        fd_vinyl_data_obj_t * cobj = (fd_vinyl_data_obj_t *)fd_ulong_align_dn( (ulong)rd, FD_VINYL_BSTREAM_BLOCK_SZ );

        FD_CRIT( cphdr==fd_vinyl_data_obj_phdr( cobj ), "corruption detected" );

        ulong cpair_ctl = cphdr->ctl;

        int   cpair_type    = fd_vinyl_bstream_ctl_type ( cpair_ctl );
        int   cpair_style   = fd_vinyl_bstream_ctl_style( cpair_ctl );
        ulong cpair_val_esz = fd_vinyl_bstream_ctl_sz   ( cpair_ctl );

        FD_CRIT( cpair_type==FD_VINYL_BSTREAM_CTL_TYPE_PAIR,            "corruption detected" );
        FD_CRIT( cpair_sz  ==fd_vinyl_bstream_pair_sz( cpair_val_esz ), "corruption detected" );

        schar * rd_err = cobj->rd_err;

        FD_CRIT ( rd_err,                                          "corruption detected" );
        FD_ALERT( fd_vinyl_data_is_valid_obj( obj, vol, vol_cnt ), "corruption detected" );

        ulong line_idx = obj->line_idx;

        FD_CRIT( line_idx<line_cnt,                 "corruption detected" );
        FD_CRIT( line[ line_idx ].obj==obj,         "corruption detected" );

        ulong ele_idx = line[ line_idx ].ele_idx;

        FD_CRIT ( ele_idx<ele_max,                                                          "corruption detected" );
        FD_ALERT( !memcmp( &ele0[ ele_idx ].phdr, cphdr, sizeof(fd_vinyl_bstream_phdr_t) ), "corruption detected" );
        FD_CRIT ( ele0[ ele_idx ].seq     ==seq,                                            "corruption detected" );
        FD_CRIT ( ele0[ ele_idx ].line_idx==line_idx,                                       "corruption detected" );

        /* Verify data integrity */

        FD_ALERT( !fd_vinyl_bstream_pair_test( io_seed, seq, (fd_vinyl_bstream_block_t *)cphdr, cpair_sz ), "corruption detected" );

        /* Decode the pair */

        char * val    = (char *)fd_vinyl_data_obj_val( obj );
        ulong  val_sz = (ulong)cphdr->info.val_sz;

        FD_CRIT( val_sz <= FD_VINYL_VAL_MAX,                 "corruption detected" );
        FD_CRIT( fd_vinyl_data_obj_val_max( obj ) >= val_sz, "corruption detected" );

        if( FD_LIKELY( cpair_style==FD_VINYL_BSTREAM_CTL_STYLE_RAW ) ) {

          FD_CRIT( obj==cobj,             "corruption detected" );
          FD_CRIT( cpair_val_esz==val_sz, "corruption detected" );

        } else {

          char const * cval    = (char const *)fd_vinyl_data_obj_val( cobj );
          ulong        cval_sz = fd_vinyl_bstream_ctl_sz( cpair_ctl );

          ulong _val_sz = (ulong)LZ4_decompress_safe( cval, val, (int)cval_sz, (int)val_sz );
          if( FD_UNLIKELY( _val_sz!=val_sz ) ) FD_LOG_CRIT(( "LZ4_decompress_safe failed" ));

          fd_vinyl_data_free( data, cobj );

          fd_vinyl_bstream_phdr_t * phdr = fd_vinyl_data_obj_phdr( obj );

          phdr->ctl  = fd_vinyl_bstream_ctl( FD_VINYL_BSTREAM_CTL_TYPE_PAIR, FD_VINYL_BSTREAM_CTL_STYLE_RAW, val_sz );
          phdr->key  = cphdr->key;
          phdr->info = cphdr->info;

        }

        obj->rd_active = (short)0;

        /* Fill any trailing region with zeros (there is at least
           FD_VINYL_BSTREAM_FTR_SZ) and tell the client the item was
           successfully processed. */

        memset( val + val_sz, 0, fd_vinyl_data_szc_obj_footprint( (ulong)obj->szc )
                                 - (sizeof(fd_vinyl_data_obj_t) + sizeof(fd_vinyl_bstream_phdr_t) + val_sz) );

        FD_COMPILER_MFENCE();
        *rd_err = (schar)FD_VINYL_SUCCESS;
        FD_COMPILER_MFENCE();

      }

      if( FD_UNLIKELY( append_cnt ) ) fd_vinyl_io_commit( io, FD_VINYL_IO_FLAG_BLOCKING );

      if( FD_LIKELY( comp_err<=0 ) ) fd_vinyl_cq_send( cq, comp, req_id, link_id, comp_err, batch_cnt, fail_cnt, quota_rem );

      client->quota_rem = quota_rem;

    }

  } /* run loop */

  ulong discard_cnt = req_tail - req_head;

  /* Append the final partition and sync so we can resume with a fast
     parallel recovery */

  fd_vinyl_io_append_part( io, seq_part, accum_dead_cnt, accum_move_cnt, NULL, 0UL );

  accum_dead_cnt = 0UL;
  accum_move_cnt = 0UL;

  accum_garbage_cnt++;
  accum_garbage_sz += FD_VINYL_BSTREAM_BLOCK_SZ;

  fd_vinyl_io_commit( io, FD_VINYL_IO_FLAG_BLOCKING );

  fd_vinyl_io_sync( io, FD_VINYL_IO_FLAG_BLOCKING );

  /* Drain outstanding accumulators */

  /**/                                   accum_garbage_cnt = 0UL;
  vinyl->garbage_sz += accum_garbage_sz; accum_garbage_sz  = 0UL;

  diag[ FD_VINYL_DIAG_DROP_LINK ] += accum_drop_link; accum_drop_link   = 0UL;
  diag[ FD_VINYL_DIAG_DROP_COMP ] += accum_drop_comp; accum_drop_comp   = 0UL;

  /* Disconnect from the clients */

  ulong released_cnt = 0UL;
  for( ulong client_idx=0UL; client_idx<client_cnt; client_idx++ ) {
    released_cnt += (_client[ client_idx ].quota_max - _client[ client_idx ].quota_rem);
    fd_wksp_unmap( fd_vinyl_rq_leave( _client[ client_idx ].rq ) );
    fd_wksp_unmap( fd_vinyl_cq_leave( _client[ client_idx ].cq ) );
    fd_wksp_detach( (fd_wksp_t *)_client[ client_idx ].laddr0 );
  }

  if( FD_UNLIKELY( discard_cnt  ) ) FD_LOG_WARNING(( "halt discarded %lu received requests",   discard_cnt  ));
  if( FD_UNLIKELY( released_cnt ) ) FD_LOG_WARNING(( "halt released %lu outstanding acquires", released_cnt ));
  if( FD_UNLIKELY( client_cnt   ) ) FD_LOG_WARNING(( "halt disconneced %lu clients",           client_cnt   ));

  /* Return to boot state */

  fd_cnc_signal( cnc, FD_VINYL_CNC_SIGNAL_BOOT );
}
