#include "fd_slow_inflight.h"

static fd_slow_inflight_page_t *
tail_page_with_space( fd_slow_inflight_list_t * list,
                      fd_slow_inflight_page_t * pool ) {

  if( fd_slow_inflight_list_is_empty( list, pool ) ) {
    return NULL;
  }
  fd_slow_inflight_page_t * tail =
      fd_slow_inflight_list_ele_peek_tail( list, pool );
  if( fd_ulong_popcnt( tail->live_set )==FD_SLOW_INFLIGHT_PAGE_ELE_CNT ) {
    return NULL;
  }
  FD_DCHECK_CRIT( fd_ulong_popcnt( tail->live_set )<=FD_SLOW_INFLIGHT_PAGE_ELE_CNT, "inflight page bit set corrupt" );

  return tail;
}

fd_slow_inflight_t *
fd_slow_inflight_insert( fd_slow_inflight_list_t * list,
                         fd_slow_inflight_page_t * pool,
                         ulong                     pktnum,
                         uint                      type ) {

  fd_slow_inflight_page_t * tail = tail_page_with_space( list, pool );
  if( FD_UNLIKELY( !tail ) ) {
    if( FD_UNLIKELY( !fd_slow_inflight_pool_free( pool ) ) ) return NULL;
    tail = fd_slow_inflight_pool_ele_acquire( pool );
    *tail = (fd_slow_inflight_page_t) {
      .pktnum_base  = pktnum,
      .pktnum_range = 0U
    };
  }

  int free_idx = fd_ulong_find_lsb( ~tail->live_set );
  FD_DCHECK_CRIT( free_idx<FD_SLOW_INFLIGHT_PAGE_ELE_CNT, "inflight page bit set corrupt" );
  tail->live_set |= (1UL<<free_idx);

  FD_CHECK_CRIT( pktnum >= tail->pktnum_base, "pktnum moved backwards" );
  FD_DCHECK_CRIT( pktnum - tail->pktnum_base <= UINT_MAX, "giant pktnum skip" );
  tail->pktnum_range = (uint)( pktnum - tail->pktnum_base );

  fd_slow_inflight_t * ele = &tail->ele[ free_idx ];
  *ele = (fd_slow_inflight_t) {
    .pktnum = pktnum,
    .type   = type
  };
  return ele;
}

void
fd_slow_inflight_remove( fd_slow_inflight_list_t * list,
                         fd_slow_inflight_page_t * pool,
                         ulong                     pktnum0,
                         ulong                     pktnum1 ) {

  /* seek to pktnum0 */
  /* FIXME DoS resistance for high ACKs (bound iter) */

  uint page_idx;
  for( page_idx = list->head; page_idx!=UINT_MAX; ) {
    fd_slow_inflight_page_t * page = &pool[ page_idx ];
    ulong page_pktnum0 = page->pktnum_base;
    if( FD_LIKELY( pktnum0 <= page_pktnum0 ) ) break;
    page_idx = page->next;
  }

  /* remove full pages */

  while( page_idx!=UINT_MAX ) {
    fd_slow_inflight_page_t * page = &pool[ page_idx ];
    ulong page_pktnum0 = page->pktnum_base;
    ulong page_pktnum1 = page_pktnum0 + page->pktnum_range;
    if( pktnum0 > page_pktnum0 || page_pktnum1 > pktnum1 ) break;
    /* remove page */
    page_idx = page->next;
    fd_slow_inflight_list_ele_remove( list, pool, page );
  }

  /* remove individual elements */

  fd_slow_inflight_iter_t iter[1]; /* TODO */
  while( !fd_slow_inflight_iter_done( iter ) ) {
    fd_slow_inflight_t * ele = fd_slow_inflight_iter_ele( iter );
    if( pktnum0 > ele->pktnum || ele->pktnum > pktnum1 ) break;
    fd_slow_inflight_iter_remove( iter );
  }
}

void
fd_slow_inflight_remove_all( fd_slow_inflight_list_t * list,
                             fd_slow_inflight_page_t * pool ) {
  uint page_idx = list->head;
  /* assume internal linkage does not get destroyed */
  fd_slow_inflight_list_remove_all( list, pool );
  while( page_idx!=UINT_MAX ) {
    uint next = pool[ page_idx ].next;
    fd_slow_inflight_pool_idx_release( pool, next );
    page_idx = next;
  }
}
