#include "fd_gui_gossip_bw.h"
#include "../../tango/tempo/fd_tempo.h"

FD_FN_CONST ulong
fd_gui_gossip_bw_align( void ) {
  return FD_GUI_GOSSIP_BW_ALIGN;
}

FD_FN_CONST ulong
fd_gui_gossip_bw_footprint( void ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_GUI_GOSSIP_BW_ALIGN,         sizeof(fd_gui_gossip_bw_t)                                     );
  l = FD_LAYOUT_APPEND( l, fd_gui_gossip_bw_map_align(), fd_gui_gossip_bw_map_footprint( FD_GUI_GOSSIP_BW_LG_SLOT_CNT ) );
  return FD_LAYOUT_FINI( l, FD_GUI_GOSSIP_BW_ALIGN );
}

void *
fd_gui_gossip_bw_new( void * shmem,
                      ulong  seed ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_gui_gossip_bw_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_gui_gossip_bw_t * bw   = FD_SCRATCH_ALLOC_APPEND( l, FD_GUI_GOSSIP_BW_ALIGN,         sizeof(fd_gui_gossip_bw_t)                                     );
  void *               _map = FD_SCRATCH_ALLOC_APPEND( l, fd_gui_gossip_bw_map_align(), fd_gui_gossip_bw_map_footprint( FD_GUI_GOSSIP_BW_LG_SLOT_CNT ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, FD_GUI_GOSSIP_BW_ALIGN )==(ulong)shmem+fd_gui_gossip_bw_footprint() );

  bw->flush_ticks = (long)((double)FD_GUI_GOSSIP_BW_FLUSH_NS*fd_tempo_tick_per_ns( NULL ));
  bw->deadline    = LONG_MAX;
  bw->map         = fd_gui_gossip_bw_map_join( fd_gui_gossip_bw_map_new( _map, FD_GUI_GOSSIP_BW_LG_SLOT_CNT, seed ) );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( bw->magic ) = FD_GUI_GOSSIP_BW_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

fd_gui_gossip_bw_t *
fd_gui_gossip_bw_join( void * shbw ) {

  if( FD_UNLIKELY( !shbw ) ) {
    FD_LOG_WARNING(( "NULL shbw" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shbw, fd_gui_gossip_bw_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shbw" ));
    return NULL;
  }

  fd_gui_gossip_bw_t * bw = (fd_gui_gossip_bw_t *)shbw;
  if( FD_UNLIKELY( bw->magic!=FD_GUI_GOSSIP_BW_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return bw;
}

void *
fd_gui_gossip_bw_leave( fd_gui_gossip_bw_t const * bw ) {

  if( FD_UNLIKELY( !bw ) ) {
    FD_LOG_WARNING(( "NULL bw" ));
    return NULL;
  }

  return (void *)bw;
}

void *
fd_gui_gossip_bw_delete( void * shbw ) {

  if( FD_UNLIKELY( !shbw ) ) {
    FD_LOG_WARNING(( "NULL shbw" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shbw, fd_gui_gossip_bw_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shbw" ));
    return NULL;
  }

  fd_gui_gossip_bw_t * bw = (fd_gui_gossip_bw_t *)shbw;
  if( FD_UNLIKELY( bw->magic!=FD_GUI_GOSSIP_BW_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( bw->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return shbw;
}
