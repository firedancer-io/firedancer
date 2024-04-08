#ifndef HEADER_fd_src_app_run_topos_topo_util_h
#define HEADER_fd_src_app_run_topos_topo_util_h

#define TILE( cnt, kind1, wksp, out_link_id_primary1 ) do {                                    \
    ulong wksp_id = fd_topo_find_wksp( topo, wksp );                                           \
    if( FD_UNLIKELY( wksp_id==ULONG_MAX ) )                                                    \
      FD_LOG_ERR(( "could not find workspace %s", fd_topo_wksp_kind_str( wksp ) ));            \
    for( ulong i=0; i<cnt; i++ ) {                                                             \
      topo->tiles[ tile_cnt ] = (fd_topo_tile_t){ .id                  = tile_cnt,             \
                                                  .kind                = kind1,                \
                                                  .kind_id             = i,                    \
                                                  .wksp_id             = wksp_id,              \
                                                  .in_cnt              = 0,                    \
                                                  .out_link_id_primary = out_link_id_primary1, \
                                                  .out_cnt             = 0 };                  \
      tile_cnt++;                                                                              \
    }                                                                                          \
  } while(0)

#define LINK( cnt, kind1, wksp, depth1, mtu1, burst1 ) do {                                   \
    for( ulong i=0; i<cnt; i++ ) {                                                            \
      topo->links[ link_cnt ] = (fd_topo_link_t){ .id      = link_cnt,                        \
                                                  .kind    = kind1,                           \
                                                  .kind_id = i,                               \
                                                  .wksp_id = fd_topo_find_wksp( topo, wksp ), \
                                                  .depth   = depth1,                          \
                                                  .mtu     = mtu1,                            \
                                                  .burst   = burst1 };                        \
      link_cnt++;                                                                             \
    }                                                                                         \
  } while(0)

#define TILE_IN( kind, kind_id, link, link_id, reliable, poll ) do {                        \
    ulong tile_id = fd_topo_find_tile( topo, kind, kind_id );                               \
    if( FD_UNLIKELY( tile_id == ULONG_MAX ) )                                               \
      FD_LOG_ERR(( "could not find tile %s %lu", fd_topo_tile_kind_str( kind ), kind_id )); \
    fd_topo_tile_t * tile = &topo->tiles[ tile_id ];                                        \
    tile->in_link_id      [ tile->in_cnt ] = fd_topo_find_link( topo, link, link_id );      \
    tile->in_link_reliable[ tile->in_cnt ] = reliable;                                      \
    tile->in_link_poll    [ tile->in_cnt ] = poll;                                          \
    tile->in_cnt++;                                                                         \
  } while(0)

  /* TILE_OUT is used for specifying additional, non-primary outs for
     the tile.  The primary output link is specified with the TILE macro
     above and will not appear as a TILE_OUT. */
#define TILE_OUT( kind, kind_id, link, link_id ) do {                                       \
    ulong tile_id = fd_topo_find_tile( topo, kind, kind_id );                               \
    if( FD_UNLIKELY( tile_id == ULONG_MAX ) )                                               \
      FD_LOG_ERR(( "could not find tile %s %lu", fd_topo_tile_kind_str( kind ), kind_id )); \
    fd_topo_tile_t * tile = &topo->tiles[ tile_id ];                                        \
    tile->out_link_id[ tile->out_cnt ] = fd_topo_find_link( topo, link, link_id );          \
    tile->out_cnt++;                                                                        \
  } while(0)

#endif /* HEADER_fd_src_app_run_topos_topo_util_h */
