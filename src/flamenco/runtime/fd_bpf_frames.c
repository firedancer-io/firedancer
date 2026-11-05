#include "fd_bpf_frames.h"
#include "../fd_rwlock.h"

union __attribute__((aligned(FD_BPF_FRAMES_ALIGN))) fd_bpf_frame {
  ulong next; /* pool link while free */
  uchar data[ BPF_LOADER_SERIALIZATION_FOOTPRINT ];
};
typedef union fd_bpf_frame fd_bpf_frame_t;

#define POOL_NAME frame_pool
#define POOL_T    fd_bpf_frame_t
#include "../../util/tmpl/fd_pool.c"

#define FD_BPF_FRAMES_MAGIC (0xf17eda2c3bf2a3e0UL) /* FIREDANCE BPF FRAMES V0 */

struct __attribute__((aligned(FD_BPF_FRAMES_ALIGN))) fd_bpf_frames_shmem {
  ulong       magic;
  fd_rwlock_t lock;
  ulong       has_owner;      /* 1 while some join is the owner, the one
                                 tile allowed into the owner's reserve */
  ulong       joiner_cnt;
  ulong       joiner_cnt_max;
  ulong       local_cnt;

  /* local_cnt local frames for each of joiner_cnt_max joins follow,
     then frame_pool */
};

struct fd_bpf_frames {
  fd_bpf_frames_shmem_t * shmem;
  fd_bpf_frame_t *        pool;
  fd_bpf_frame_t *        local;
  ulong                   local_cnt;
  ulong                   local_used;  /* local[ 0, local_used ) are in use */
  ulong                   reserve_cnt; /* frames held back for each of the owner and
                                          the priority caller, the most shared
                                          frames one stack can need */
  int                     is_owner;
  ulong                   held_cnt;    /* shared frames */
};

FD_FN_CONST ulong
fd_bpf_frames_shmem_align( void ) {
  return fd_ulong_max( alignof(fd_bpf_frames_shmem_t), frame_pool_align() );
}

FD_FN_CONST ulong
fd_bpf_frames_shmem_footprint( ulong frame_cnt,
                               ulong joiner_cnt_max,
                               ulong local_cnt ) {
  if( FD_UNLIKELY( local_cnt>FD_MAX_INSTRUCTION_STACK_DEPTH                 ) ) return 0UL;
  if( FD_UNLIKELY( frame_cnt<FD_BPF_FRAMES_HELD_CNT( local_cnt )            ) ) return 0UL;
  if( FD_UNLIKELY( frame_cnt>FD_BPF_FRAMES_CNT_MAX                          ) ) return 0UL;
  if( FD_UNLIKELY( joiner_cnt_max>FD_BPF_FRAMES_CNT_MAX                     ) ) return 0UL;
  if( FD_UNLIKELY( frame_cnt+joiner_cnt_max*local_cnt>FD_BPF_FRAMES_CNT_MAX ) ) return 0UL;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_bpf_frames_shmem_t), sizeof(fd_bpf_frames_shmem_t)                   );
  l = FD_LAYOUT_APPEND( l, alignof(fd_bpf_frame_t),        joiner_cnt_max*local_cnt*sizeof(fd_bpf_frame_t) );
  l = FD_LAYOUT_APPEND( l, frame_pool_align(),             frame_pool_footprint( frame_cnt )               );
  return FD_LAYOUT_FINI( l, fd_bpf_frames_shmem_align() );
}

static fd_bpf_frame_t *
local_frames( fd_bpf_frames_shmem_t * shmem ) {
  return (fd_bpf_frame_t *)( shmem+1 );
}

static void *
pool_mem( fd_bpf_frames_shmem_t * shmem ) {
  return (void *)fd_ulong_align_up( (ulong)( local_frames( shmem )+shmem->joiner_cnt_max*shmem->local_cnt ), frame_pool_align() );
}

void *
fd_bpf_frames_shmem_new( void * shmem,
                         ulong  frame_cnt,
                         ulong  joiner_cnt_max,
                         ulong  local_cnt ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_bpf_frames_shmem_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_bpf_frames_shmem_footprint( frame_cnt, joiner_cnt_max, local_cnt ) ) ) {
    FD_LOG_WARNING(( "invalid frame_cnt %lu, joiner_cnt_max %lu or local_cnt %lu", frame_cnt, joiner_cnt_max, local_cnt ));
    return NULL;
  }

  fd_bpf_frames_shmem_t * frames = (fd_bpf_frames_shmem_t *)shmem;
  fd_rwlock_new( &frames->lock );
  frames->has_owner      = 0UL;
  frames->joiner_cnt     = 0UL;
  frames->joiner_cnt_max = joiner_cnt_max;
  frames->local_cnt      = local_cnt;
  FD_TEST( frame_pool_new( pool_mem( frames ), frame_cnt ) );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( frames->magic ) = FD_BPF_FRAMES_MAGIC;
  FD_COMPILER_MFENCE();
  return shmem;
}

FD_FN_CONST ulong
fd_bpf_frames_align( void ) {
  return alignof(fd_bpf_frames_t);
}

FD_FN_CONST ulong
fd_bpf_frames_footprint( void ) {
  return sizeof(fd_bpf_frames_t);
}

fd_bpf_frames_t *
fd_bpf_frames_join( void * ljoin,
                    void * shframes ) {
  fd_bpf_frames_t *       join  = (fd_bpf_frames_t *)ljoin;
  fd_bpf_frames_shmem_t * shmem = (fd_bpf_frames_shmem_t *)shframes;
  if( FD_UNLIKELY( !join || !fd_ulong_is_aligned( (ulong)join, fd_bpf_frames_align() ) ) ) {
    FD_LOG_WARNING(( "NULL or misaligned ljoin" ));
    return NULL;
  }
  if( FD_UNLIKELY( !shmem || !fd_ulong_is_aligned( (ulong)shmem, fd_bpf_frames_shmem_align() ) ) ) {
    FD_LOG_WARNING(( "NULL or misaligned shframes" ));
    return NULL;
  }
  if( FD_UNLIKELY( shmem->magic!=FD_BPF_FRAMES_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }
  ulong idx = FD_ATOMIC_FETCH_AND_ADD( &shmem->joiner_cnt, 1UL );
  if( FD_UNLIKELY( idx>=shmem->joiner_cnt_max ) ) {
    FD_LOG_WARNING(( "too many joins (max %lu)", shmem->joiner_cnt_max ));
    return NULL;
  }

  join->shmem       = shmem;
  join->pool        = frame_pool_join( pool_mem( shmem ) );
  join->local       = local_frames( shmem )+idx*shmem->local_cnt;
  join->local_cnt   = shmem->local_cnt;
  join->reserve_cnt = FD_MAX_INSTRUCTION_STACK_DEPTH-shmem->local_cnt;
  join->local_used  = 0UL;
  join->is_owner    = 0;
  join->held_cnt    = 0UL;
  FD_TEST( join->pool );
  return join;
}

static uchar *
fd_bpf_frames_try_acquire( fd_bpf_frames_t * join,
                           int               priority ) {
  if( FD_LIKELY( join->local_used<join->local_cnt ) ) {
    return (uchar *)( join->local+join->local_used++ );
  }

  /* Take the lock, and give up right away if no frames are free. */
  fd_bpf_frames_shmem_t * shmem = join->shmem;
  fd_rwlock_write( &shmem->lock );
  ulong free_cnt = frame_pool_free( join->pool );
  if( FD_UNLIKELY( !free_cnt ) ) {
    fd_rwlock_unwrite( &shmem->lock );
    return NULL;
  }

  /* Become owner if you can. */
  if( !shmem->has_owner ) {
    shmem->has_owner = 1UL;
    join->is_owner   = 1;
  }

  /* keep is how many free frames this call must leave for others.  The
     owner never needs more than reserve_cnt frames, so it cannot run
     into the priority caller's reserve. */
  ulong keep;
  if( priority || join->is_owner ) {
    keep = 0UL;
  } else {
    keep = 2UL*join->reserve_cnt; /* leave both reserves */
  }

  uchar * frame = NULL;
  if( FD_LIKELY( free_cnt>keep ) ) {
    frame = (uchar *)frame_pool_ele_acquire( join->pool );
    join->held_cnt++;
  }

  fd_rwlock_unwrite( &shmem->lock );
  return frame;
}

uchar *
fd_bpf_frames_acquire( fd_bpf_frames_t * join,
                       int               priority ) {
  for(;;) {
    uchar * frame = fd_bpf_frames_try_acquire( join, priority );
    if( FD_LIKELY( frame ) ) return frame;
    FD_SPIN_PAUSE();
  }
}

void
fd_bpf_frames_release( fd_bpf_frames_t * join,
                       uchar *           frame ) {
  if( FD_LIKELY( !join->held_cnt ) ) {
    FD_TEST( join->local_used && frame==(uchar *)( join->local+join->local_used-1UL ) );
    join->local_used--;
    return;
  }

  fd_bpf_frames_shmem_t * shmem = join->shmem;
  fd_rwlock_write( &shmem->lock );
  frame_pool_ele_release( join->pool, (fd_bpf_frame_t *)frame );
  join->held_cnt--;
  if( !join->held_cnt && join->is_owner ) {
    shmem->has_owner = 0UL;
    join->is_owner   = 0;
  }
  fd_rwlock_unwrite( &shmem->lock );
}
