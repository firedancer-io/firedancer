#include "fd_vinyl_meta.h"

#define MAP_NAME                  fd_vinyl_meta
#define MAP_ELE_T                 fd_vinyl_meta_ele_t
#define MAP_KEY_T                 fd_vinyl_key_t
#define MAP_KEY                   phdr.key
#define MAP_KEY_EQ(k0,k1)         fd_vinyl_key_eq( (k0), (k1) )
#define MAP_KEY_HASH(key,seed)    fd_vinyl_key_memo( (seed), (key) )
#define MAP_MEMOIZE               1
#define MAP_MEMO                  memo
#define MAP_KEY_EQ_IS_SLOW        1
#define MAP_ELE_IS_FREE(ctx,ele)  (!(ele)->phdr.ctl)
#define MAP_ELE_FREE(ctx,ele)     do { (ele)->phdr.ctl = 0UL; } while(0)
#define MAP_ELE_MOVE(ctx,dst,src) do { fd_vinyl_meta_ele_t * _src = (src); *(dst) = *_src; _src->phdr.ctl = 0UL; } while(0)
#define MAP_IMPL_STYLE            2
#include "../../util/tmpl/fd_map_slot_para.c"

int
fd_vinyl_meta_query_fast( fd_vinyl_meta_ele_t const * ele0,
                          ulong                       ele_max,
                          fd_vinyl_key_t const *      key,
                          ulong                       memo,
                          ulong *                     _ele_idx ) {

  ulong ele_idx = memo & (ele_max-1UL);

  int err = FD_VINYL_ERR_CORRUPT;

  ulong rem;

  for( rem=ele_max; rem; rem-- ) { /* guarantee finite termination in face of corruption */
    fd_vinyl_meta_ele_t const * ele = ele0 + ele_idx;

    if( FD_UNLIKELY( !ele->phdr.ctl ) ) { /* not found */
      *_ele_idx = ele_idx;
      err       = FD_VINYL_ERR_KEY;
      break;
    }

    if( FD_LIKELY( ele->memo==memo ) && FD_LIKELY( fd_vinyl_key_eq( &ele->phdr.key, key ) ) ) { /* found */
      *_ele_idx = ele_idx;
      err       = FD_VINYL_SUCCESS;
      break;
   }

    ele_idx = (ele_idx+1UL) & (ele_max-1UL); /* collision, try next slot */
  }

  FD_CRIT( rem, "corruption detected" );

  return err;
}

#include "../line/fd_vinyl_line.h" /* FIXME: gross (maybe make line below meta in the API hierarchy?) */

void
fd_vinyl_meta_remove_fast( fd_vinyl_meta_ele_t * ele0,
                           ulong                 ele_max,
                           ulong *               lock,
                           int                   lock_shift,
                           fd_vinyl_line_t *     line,
                           ulong                 line_cnt,
                           ulong                 ele_idx ) {

  /* At this point, we know:

     - nobody will lock any elements behind our back (single writer)
     - no elements are locked (not in a prepare)
     - there is at least one unoccupied element in the meta (pair_max < ele_max)
     - there is at least one   occupied element in the meta (ele_idx)
     - (thus ele_max is at least 2)

     When we remove element ele_idx, we might need to move elements in
     the cyclic contiguously occupied range starting at ele_idx toward
     ele_idx (but not before ele_idx) to keep their probe sequences
     intact.  This can interfere with lockfree non-blocking concurrent
     reads whose probe sequences overlap this range.

     Thus, we determine the set of contiguously occupied elements
     starting at ele_idx, determine the range of corresponding locks and
     lock them before we remove ele_idx to protect concurrent readers.
     If the map is not overfilled, contig_cnt is O(1) elements.

     If the ele is currently cached, we also need to update the
     underlying line to it points to the moved location. */

  ulong contig_cnt;

  for( contig_cnt=1UL; contig_cnt<ele_max; contig_cnt++ )
    if( FD_LIKELY( !ele0[ (ele_idx + contig_cnt) & (ele_max-1UL) ].phdr.ctl ) ) break;

  FD_CRIT( contig_cnt<ele_max, "corruption detected" );

  /* At this point, contig_cnt is in [1,ele_max) and meta elements
     [ele_idx,ele_idx+contig_cnt) (cyclic) are the contiguously occupied
     elements starting at ele_idx.  Determine the set of locks that
     cover this set. */

  ulong lock_lo  =  ele_idx                     >> lock_shift;        /* lock that covers first element (wrapped) */
  ulong lock_hi  = (ele_idx + contig_cnt - 1UL) >> lock_shift;        /* lock that covers last  element (unwrapped) */
  ulong lock_max =  ele_max                     >> lock_shift;        /* max locks */
  ulong lock_cnt = fd_ulong_min( lock_hi - lock_lo + 1UL, lock_max ); /* num locks required */

  /* Lock the range */

  for( ulong idx=0UL; idx<lock_cnt; idx++ ) fd_vinyl_meta_lock_update_fast( lock + ((lock_lo + idx) & (lock_max-1UL)), 1L );

  /* At this point, we are clear to remove ele_idx.  Make a hole at
     ele_idx and then iterate over the contig_cnt-1 remaining cyclically
     contiguously occupied elements, repairing broken probe sequences as
     we go.  Since we already learned how many contiguous elements there
     are (from the above locking), we can simplify the iteration
     slightly over a standard remove. */

  ele0[ ele_idx ].phdr.ctl = 0UL;

  ulong hole_idx = ele_idx;

  for( ulong rem=contig_cnt-1UL; rem; rem-- ) {
    ele_idx = (ele_idx+1UL) & (ele_max-1UL);

    /* At this point, meta elements before hole_idx (cyclic) have intact
       probe sequences, meta element hole_idx is unoccupied, meta
       elements (hole_idx,ele_idx) (cyclic) are occupied with intact
       probe sequences and meta elements [ele_idx,ele_idx+rem) (cyclic)
       are occupied but might have broken probe sequences due to the
       hole.

       If a probe looking for the key at ele_idx does not start its
       probe in (hole_idx,ele_idx] (cyclic), probing will fail
       erroneously due to the hole.  In this case, we move ele_idx to
       hole_idx to restore the probe sequence for the key at ele_idx,
       making a new hole at ele_idx.  As the probe sequences following
       the new hole could still be broken, we continue repairing probe
       sequences for elements following the new hole. */

    ulong start_idx = ele0[ ele_idx ].memo & (ele_max-1UL);

    if( !( ((hole_idx<start_idx) & (start_idx<=ele_idx)                       ) |
           ((hole_idx>ele_idx) & ((hole_idx<start_idx) | (start_idx<=ele_idx))) ) ) {

      ulong line_idx = ele0[ ele_idx ].line_idx;
      if( FD_LIKELY( line_idx<line_cnt ) ) {
        FD_CRIT( line[ line_idx ].ele_idx==ele_idx, "corruption detected" );
        line[ line_idx ].ele_idx = hole_idx;
      } else {
        FD_CRIT( line_idx==ULONG_MAX, "corruption detected" );
      }

      ele0[ hole_idx ] = ele0[ ele_idx ];
      ele0[ ele_idx ].phdr.ctl = 0UL;

      hole_idx = ele_idx;

    }
  }

  /* Unlock the range */

  for( ulong idx=0UL; idx<lock_cnt; idx++ ) fd_vinyl_meta_lock_update_fast( lock + ((lock_lo + idx) & (lock_max-1UL)), 1L );
}
