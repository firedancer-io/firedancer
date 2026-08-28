#include "fd_bpf_ser_arena.h"

static inline uchar *
bundle_laddr( fd_bpf_ser_arena_t * arena,
              ulong                idx ) {
  return (uchar *)arena + sizeof(fd_bpf_ser_arena_t) + idx*FD_BPF_SER_ARENA_BUNDLE_FOOTPRINT( arena->frame_cnt );
}

void *
fd_bpf_ser_arena_new( void * shmem,
                      ulong  bundle_cnt,
                      ulong  frame_cnt ) {
  if( FD_UNLIKELY( !shmem ) ) { FD_LOG_WARNING(( "NULL shmem" )); return NULL; }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, FD_BPF_SER_ARENA_ALIGN ) ) ) { FD_LOG_WARNING(( "misaligned shmem" )); return NULL; }
  if( FD_UNLIKELY( !bundle_cnt || bundle_cnt>FD_BPF_SER_ARENA_BUNDLE_MAX ) ) { FD_LOG_WARNING(( "bad bundle_cnt" )); return NULL; }
  if( FD_UNLIKELY( !frame_cnt || frame_cnt>FD_MAX_INSTRUCTION_STACK_DEPTH ) ) { FD_LOG_WARNING(( "bad frame_cnt" )); return NULL; }

  fd_bpf_ser_arena_t * arena = (fd_bpf_ser_arena_t *)shmem;
  memset( arena, 0, sizeof(fd_bpf_ser_arena_t) );
  arena->bundle_cnt = bundle_cnt;
  arena->frame_cnt  = frame_cnt;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( arena->magic ) = FD_BPF_SER_ARENA_MAGIC;
  FD_COMPILER_MFENCE();
  return shmem;
}

fd_bpf_ser_arena_t *
fd_bpf_ser_arena_join( void * shmem ) {
  fd_bpf_ser_arena_t * arena = (fd_bpf_ser_arena_t *)shmem;
  if( FD_UNLIKELY( !arena ) ) { FD_LOG_WARNING(( "NULL shmem" )); return NULL; }
  if( FD_UNLIKELY( arena->magic!=FD_BPF_SER_ARENA_MAGIC ) ) { FD_LOG_WARNING(( "bad magic" )); return NULL; }
  return arena;
}

ulong
fd_bpf_ser_arena_ticket( fd_bpf_ser_arena_t * arena ) {
  return FD_ATOMIC_FETCH_AND_ADD( &arena->next_ticket, 1UL );
}

int
fd_bpf_ser_arena_ready( fd_bpf_ser_arena_t const * arena,
                        ulong                      ticket ) {
  /* Tickets [done_cnt, done_cnt+bundle_cnt) may hold concurrently */
  return (ticket - FD_VOLATILE_CONST( arena->done_cnt ))<arena->bundle_cnt;
}

uchar *
fd_bpf_ser_arena_wait( fd_bpf_ser_arena_t * arena,
                       ulong                ticket ) {
  while( FD_UNLIKELY( !fd_bpf_ser_arena_ready( arena, ticket ) ) ) FD_SPIN_PAUSE();

  /* Past the gate at most bundle_cnt tickets are unreleased, so a free
     slot exists; CAS races with other gate passers only. */
  for(;;) {
    for( ulong i=0UL; i<arena->bundle_cnt; i++ ) {
      if( FD_VOLATILE_CONST( arena->slot[ i ].used ) ) continue;
      if( FD_LIKELY( !FD_ATOMIC_CAS( &arena->slot[ i ].used, 0UL, 1UL ) ) ) return bundle_laddr( arena, i );
    }
    FD_SPIN_PAUSE();
  }
}

void
fd_bpf_ser_arena_release( fd_bpf_ser_arena_t * arena,
                          uchar *              bundle ) {
  ulong off = (ulong)(bundle - bundle_laddr( arena, 0UL ));
  ulong idx = off/FD_BPF_SER_ARENA_BUNDLE_FOOTPRINT( arena->frame_cnt );
  if( FD_UNLIKELY( (off%FD_BPF_SER_ARENA_BUNDLE_FOOTPRINT( arena->frame_cnt )) || idx>=arena->bundle_cnt ) ) FD_LOG_CRIT(( "bad bundle" ));
  if( FD_UNLIKELY( !FD_VOLATILE_CONST( arena->slot[ idx ].used ) ) ) FD_LOG_CRIT(( "double release" ));

  /* Free the slot before counting the release so a woken waiter always
     finds a free slot (x86 TSO keeps the store order) */
  FD_COMPILER_MFENCE();
  FD_VOLATILE( arena->slot[ idx ].used ) = 0UL;
  FD_COMPILER_MFENCE();
  FD_ATOMIC_FETCH_AND_ADD( &arena->done_cnt, 1UL );
}
