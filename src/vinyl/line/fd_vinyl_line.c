#include "fd_vinyl_line.h"

void
fd_vinyl_line_evict_prio( uint *            _line_idx_lru,
                          fd_vinyl_line_t * line,
                          ulong             _line_cnt,
                          ulong             _line_idx,
                          int               evict_prio ) {

  if( FD_UNLIKELY( evict_prio>=FD_VINYL_LINE_EVICT_PRIO_UNC ) ) return; /* no-op */

  uint line_cnt = (uint)_line_cnt;
  uint line_idx = (uint)_line_idx;

  /* Remove line_idx from its current position in the eviction sequence */

  uint line_idx_lru   = *_line_idx_lru;
  uint line_idx_newer = line[ line_idx ].line_idx_newer; uint line_idx_older = line[ line_idx ].line_idx_older;

  FD_CRIT( line_idx_lru  <line_cnt, "corruption detected" );
  FD_CRIT( line_idx_newer<line_cnt, "corruption detected" );
  FD_CRIT( line_idx_older<line_cnt, "corruption detected" );

  line[ line_idx_newer ].line_idx_older = line_idx_older;
  line[ line_idx_older ].line_idx_newer = line_idx_newer;

  line_idx_lru = fd_uint_if( line_idx_lru!=line_idx, line_idx_lru, line_idx_newer );

  /* Insert line_idx between the LRU and MRU in the eviction sequence */

  line_idx_newer =       line_idx_lru;
  line_idx_older = line[ line_idx_lru ].line_idx_older;

  FD_CRIT( line_idx_older<line_cnt, "corruption detected" );

  line[ line_idx_newer ].line_idx_older = line_idx; line[ line_idx ].line_idx_newer = line_idx_newer;
  line[ line_idx_older ].line_idx_newer = line_idx; line[ line_idx ].line_idx_older = line_idx_older;

  /* Update the LRU */

  *_line_idx_lru = fd_uint_if( evict_prio==FD_VINYL_LINE_EVICT_PRIO_LRU, line_idx, line_idx_lru );
}

ulong
fd_vinyl_line_evict_lru( uint *                _line_idx_lru,
                         fd_vinyl_line_t *     line,
                         ulong                 line_cnt,
                         fd_vinyl_meta_ele_t * ele0,
                         ulong                 ele_max,
                         fd_vinyl_data_t *     data ) {

  ulong line_idx = (ulong)*_line_idx_lru;

  ulong rem;

  for( rem=line_cnt; rem; rem-- ) {

    FD_CRIT( line_idx<line_cnt, "corruption detected" );

    ulong line_ctl = line[ line_idx ].ctl;

    if( FD_LIKELY( !fd_vinyl_line_ctl_ref( line_ctl ) ) ) {

      fd_vinyl_data_obj_t * obj     = line[ line_idx ].obj;
      ulong                 ele_idx = line[ line_idx ].ele_idx;

      if( FD_LIKELY( obj ) ) {
        FD_CRIT( obj->line_idx==line_idx, "corruption detected" );
        FD_CRIT( !obj->rd_active,         "corruption detected" );
        fd_vinyl_data_free( data, obj );
        line[ line_idx ].obj = NULL;
      }

      if( FD_LIKELY( ele_idx<ele_max ) ) {
        FD_CRIT( ele0[ ele_idx ].line_idx==line_idx, "corruption detected" );
        ele0[ ele_idx ].line_idx = ULONG_MAX;
      } else {
        FD_CRIT( ele_idx==ULONG_MAX, "corruption detected" );
      }

      ulong ver = fd_vinyl_line_ctl_ver( line_ctl );
      line[ line_idx ].ctl = fd_vinyl_line_ctl( ver+1UL, 0L ); /* bump ver */

      break;
    }

    line_idx = (ulong)line[ line_idx ].line_idx_newer;

  }

  FD_CRIT( rem, "corruption detected" );

  return line_idx;
}
