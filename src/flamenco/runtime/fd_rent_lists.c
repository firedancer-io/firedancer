#include <malloc.h>
#include "../../util/fd_util.h"
#include "../../funk/fd_funk.h"
#include "fd_rent_lists.h"
#include "fd_acc_mgr.h"

#define FD_RENT_LIST_MAX_UNSORTED 32
#define FD_RENT_LIST_INC_SORTED 64

struct fd_rent_list {
    ulong num_unsorted;
    ulong num_sorted;
    ulong max_sorted;
    fd_funk_rec_t const * unsorted[FD_RENT_LIST_MAX_UNSORTED];
    fd_funk_rec_t const * sorted[1]; /* Dynamically expanded */
};
typedef struct fd_rent_list fd_rent_list_t;

struct fd_rent_pause_line {
    fd_funk_rec_t const * updated;
    fd_funk_rec_t const * removed;
    void *                arg;
};
typedef struct fd_rent_pause_line fd_rent_pause_line_t;

struct fd_rent_lists {
    int startup;
    int paused;
    ulong slots_per_epoch;
    ulong part_width;
    ulong pause_len;
    ulong pause_max;
    fd_rent_pause_line_t * pause_queue;
    fd_rent_list_t * lists[1]; /* Dynamically expanded */
};

fd_rent_lists_t *
fd_rent_lists_new( ulong slots_per_epoch ) {
  fd_rent_lists_t * lists = (fd_rent_lists_t *)malloc(sizeof(fd_rent_lists_t) + sizeof(fd_rent_list_t *)*(slots_per_epoch - 1UL));
  lists->startup = 1;
  lists->slots_per_epoch = slots_per_epoch;
  lists->part_width      = fd_rent_partition_width( slots_per_epoch );
  fd_rent_list_t ** end = lists->lists + slots_per_epoch;
  for ( fd_rent_list_t ** i = lists->lists; i != end; ++i )
    *i = NULL;
  lists->paused = 0;
  lists->pause_len = 0;
  lists->pause_max = 1024;
  lists->pause_queue = (fd_rent_pause_line_t *)malloc(sizeof(fd_rent_pause_line_t) * lists->pause_max);
  return lists;
}

void
fd_rent_lists_delete( fd_rent_lists_t * lists ) {
  fd_rent_list_t ** end = lists->lists + lists->slots_per_epoch;
  for ( fd_rent_list_t ** i = lists->lists; i != end; ++i ) {
    if ( NULL != *i )
      free(*i);
  }
  free(lists->pause_queue);
  free(lists);
}

ulong
fd_rent_lists_get_slots_per_epoch( fd_rent_lists_t * lists ) {
  return lists->slots_per_epoch;
}

static int
fd_rent_lists_compare(fd_funk_rec_t const * a, fd_funk_rec_t const * b) {
  if ( a == b )
    return 0;
  fd_funk_xid_key_pair_t const * const ap = &a->pair;
  fd_funk_xid_key_pair_t const * const bp = &b->pair;
  for ( ulong i = 0; i < FD_FUNK_REC_KEY_FOOTPRINT / sizeof(ulong); ++i ) {
    if ( ap->key[0].ul[i] != bp->key[0].ul[i] )
      return ( ap->key[0].ul[i] < bp->key[0].ul[i] ? -1 : 1 );
  }
  for ( ulong i = 0; i < FD_FUNK_TXN_XID_FOOTPRINT / sizeof(ulong); ++i ) {
    if ( ap->xid[0].ul[i] != bp->xid[0].ul[i] )
      return ( ap->xid[0].ul[i] < bp->xid[0].ul[i] ? -1 : 1 );
  }
  return 0;
}

static fd_funk_rec_t const **
fd_rent_lists_search_sorted( fd_rent_list_t * list, fd_funk_rec_t const * rec ) {
  ulong low = 0;
  ulong high = list->num_sorted;
  while ( low < high ) {
    ulong i = (low + high)>>1;
    if ( FD_UNLIKELY( NULL == list->sorted[i] )) {
      /* Oops! We hit a null. Do it the slow way */
      if ( NULL == list->sorted[low] ) {
        low++;
        continue;
      }
      int r = fd_rent_lists_compare( list->sorted[low], rec );
      if ( !r )
        return &list->sorted[low];
      else if ( r > 0 )
        high = low;
      else
        low++;
      continue;
    }

    /* Good case */
    int r = fd_rent_lists_compare( list->sorted[i], rec );
    if ( !r )
      return &list->sorted[i];
    else if ( r > 0 )
      high = i;
    else
      low = i+1U;
  }
  return NULL;
}

static void
fd_rent_lists_swap(fd_funk_rec_t const ** a, fd_funk_rec_t const ** b) {
  fd_funk_rec_t const * t = *a;
  *a = *b;
  *b = t;
}

static ulong
fd_rent_lists_partition(fd_funk_rec_t const ** arr, ulong low, ulong high)
{
  // Choosing the pivot
  ulong i = (low + high)>>1;
  if ( i != high )
    fd_rent_lists_swap(&arr[i], &arr[high]);
  fd_funk_rec_t const * pivot = arr[high];

  // Index of smaller element and indicates
  // the right position of pivot found so far
  i = (low - 1U);
  for (ulong j = low; j <= high - 1U; j++) {
    // If current element is smaller than the pivot
    if (fd_rent_lists_compare(arr[j], pivot) < 0) {
      // Increment index of smaller element
      i++;
      fd_rent_lists_swap(&arr[i], &arr[j]);
    }
  }
  fd_rent_lists_swap(&arr[i + 1U], &arr[high]);
  return (i + 1U);
}

static void
fd_rent_lists_quickSort(fd_funk_rec_t const ** arr, ulong low, ulong high) {
  if (low < high) {
    // pi is partitioning index, arr[p]
    // is now at right place
    ulong pi = fd_rent_lists_partition(arr, low, high);
    // Separately sort elements before
    // partition and after partition

    if (pi - low > 1)
      fd_rent_lists_quickSort(arr, low, pi - 1U);
    if (high - pi > 1)
      fd_rent_lists_quickSort(arr, pi + 1U, high);
  }
}

void
fd_rent_lists_startup_done( fd_rent_lists_t * lists ) {
  FD_TEST( lists->startup );
  fd_rent_list_t ** end = lists->lists + lists->slots_per_epoch;
  for ( fd_rent_list_t ** i = lists->lists; i != end; ++i ) {
    fd_rent_list_t * j = *i;
    if ( j && j->num_sorted > 1 )
      fd_rent_lists_quickSort(j->sorted, 0, j->num_sorted - 1U);
  }
  lists->startup = 0;
}

static void fd_rent_lists_sort_tpool( void * tpool,
                                      ulong  t0,     ulong t1,
                                      void * args,
                                      void * reduce, ulong stride,
                                      ulong  l0,     ulong l1,
                                      ulong  m0,     ulong m1,
                                      ulong  n0,     ulong n1 ) {

  (void)t0;
  (void)t1;
  (void)args;
  (void)reduce;
  (void)stride;
  (void)l0;
  (void)l1;
  (void)n0;
  (void)n1;
  
  fd_rent_lists_t * lists = (fd_rent_lists_t*)tpool;
  fd_rent_list_t ** i = lists->lists + m0;
  while ( i != lists->lists + m1) {
    if ( i == lists->lists + lists->slots_per_epoch)
    return;

    fd_rent_list_t * j = *i;
    if ( j && j->num_sorted > 1 ) {
      fd_rent_lists_quickSort(j->sorted, 0, j->num_sorted - 1U);
    }
    ++i;
  }
}

void fd_rent_lists_startup_done_tpool( fd_rent_lists_t * lists, fd_tpool_t * tpool, ulong max_workers ) {
  fd_tpool_exec_all_taskq( tpool, 0, max_workers, fd_rent_lists_sort_tpool, lists, NULL, NULL, 4, 0, lists->slots_per_epoch);
  lists->startup = 0;
}

static void
fd_rent_lists_compact_and_sort( fd_rent_list_t ** listp ) {
  fd_rent_list_t * list = *listp;

  /* Eliminate nulls first */
  fd_funk_rec_t const ** end = list->sorted + list->num_sorted;
  fd_funk_rec_t const ** j = list->sorted;
  for ( fd_funk_rec_t const ** i = list->sorted; i != end; ++i )
    if ( *i ) *(j++) = *i;
  list->num_sorted = (ulong)(j - list->sorted);

  if ( list->num_unsorted == 0 )
    return;

  /* See if we need to grow the list */
  if ( list->num_sorted + list->num_unsorted > list->max_sorted ) {
    list->max_sorted += FD_RENT_LIST_INC_SORTED;
    list = *listp = (fd_rent_list_t *)realloc(list, sizeof(fd_rent_list_t) + sizeof(fd_funk_rec_t const *)*(list->max_sorted - 1UL));
  }
  /* Move the unsorted to the sorted */
  while ( list->num_unsorted ) {
    list->sorted[(list->num_sorted)++] = list->unsorted[--(list->num_unsorted)];
  }

  /* Actually do the sort */
  fd_rent_lists_quickSort(list->sorted, 0, list->num_sorted - 1U);
}

static fd_rent_list_t **
fd_rent_lists_key_to_bucket( fd_rent_lists_t * lists,
                             fd_funk_rec_t const * rec ) {
  fd_pubkey_t const * key = fd_type_pun_const( &rec->pair.key[0].uc );
  ulong prefixX_be = key->ul[0];
  ulong prefixX    = fd_ulong_bswap( prefixX_be );
  return lists->lists + fd_rent_key_to_partition( prefixX, lists->part_width, lists->slots_per_epoch );
}

/* Hook into funky */
void
fd_rent_lists_cb( fd_funk_rec_t const * updated,
                  fd_funk_rec_t const * removed,
                  void *                arg ) { /* fd_rent_lists_t */
  fd_rent_lists_t * lists = (fd_rent_lists_t *)arg;

  if ( lists->startup ) {
    /* Assume all updates are unique and we can sort later */
    FD_TEST( updated && !removed );

    fd_rent_list_t ** listp = fd_rent_lists_key_to_bucket( lists, updated );
    fd_rent_list_t * list = *listp;
    if ( list == NULL ) {
      /* Allocate a fresh list */
      list = *listp = (fd_rent_list_t *)malloc(sizeof(fd_rent_list_t) + sizeof(fd_funk_rec_t const *)*(FD_RENT_LIST_INC_SORTED - 1UL));
      list->num_unsorted = 0;
      list->num_sorted = 0;
      list->max_sorted = FD_RENT_LIST_INC_SORTED;
    } else if ( list->num_sorted == list->max_sorted ) {
      list->max_sorted += FD_RENT_LIST_INC_SORTED;
      list = *listp = (fd_rent_list_t *)realloc(list, sizeof(fd_rent_list_t) + sizeof(fd_funk_rec_t const *)*(list->max_sorted - 1UL));
    }
    list->sorted[list->num_sorted ++] = updated;
    return;
  }

  if ( lists->paused ) {
    /* We are currently walking a list. Just hold onto the callback
       for now to prevent crazy corruption and recursion. */
    if ( lists->pause_len == lists->pause_max ) {
      lists->pause_max *= 2;
      lists->pause_queue = (fd_rent_pause_line_t *)realloc(lists->pause_queue, sizeof(fd_rent_pause_line_t) * lists->pause_max);
    }
    fd_rent_pause_line_t line = {
      .updated = updated,
      .removed = removed,
      .arg = arg
    };
    lists->pause_queue[lists->pause_len++] = line;
    return;
  }

  do {
    if ( removed && fd_acc_mgr_is_key( removed->pair.key ) ) {
      fd_rent_list_t ** listp = fd_rent_lists_key_to_bucket( lists, removed );
      fd_rent_list_t * list = *listp;
      if ( list == NULL )
        break;
      fd_funk_rec_t const ** p = fd_rent_lists_search_sorted( list, removed );
      if ( p ) {
        /* Replace with NULL for speed, compact later */
        *p = NULL;
        break;
      }
      fd_funk_rec_t const ** end = list->unsorted + list->num_unsorted;
      for ( fd_funk_rec_t const ** i = list->unsorted; i != end; ++i )
        if ( *i == removed ) {
          *i = end[-1];
          list->num_unsorted--;
          break;
        }
    }
  } while (0);

  if ( updated && fd_acc_mgr_is_key( updated->pair.key ) ) {
    fd_rent_list_t ** listp = fd_rent_lists_key_to_bucket( lists, updated );
    fd_rent_list_t * list = *listp;
    if ( list == NULL ) {
      /* Allocate a fresh list */
      list = *listp = (fd_rent_list_t *)malloc(sizeof(fd_rent_list_t) + sizeof(fd_funk_rec_t const *)*(FD_RENT_LIST_INC_SORTED - 1UL));
      list->num_unsorted = 0;
      list->num_sorted = 0;
      list->max_sorted = FD_RENT_LIST_INC_SORTED;
    }
    fd_funk_rec_t const ** p = fd_rent_lists_search_sorted( list, updated );
    if ( p ) {
      /* Already in the list */
      return;
    }
    fd_funk_rec_t const ** end = list->unsorted + list->num_unsorted;
    for ( fd_funk_rec_t const ** i = list->unsorted; i != end; ++i )
      if ( *i == updated ) {
        /* Already in the list */
        return;
      }
    if ( list->num_unsorted == FD_RENT_LIST_MAX_UNSORTED ) {
      fd_rent_lists_compact_and_sort(listp);
      list = *listp;
    }
    list->unsorted[list->num_unsorted++] = updated;
  }
}

void
fd_rent_lists_walk( fd_rent_lists_t * lists,
                    ulong offset,
                    fd_rent_lists_walk_cb cb,
                    void * cb_arg ) {
  FD_TEST( offset < lists->slots_per_epoch );
  FD_TEST( ! lists->paused );

  /* Prevent changes to this list while I'm walking it */
  lists->paused = 1;
  lists->pause_len = 0;

  fd_rent_list_t ** listp = &lists->lists[offset];
  if (NULL == *listp) {
    lists->paused = 0;
    return;
  }
  fd_rent_lists_compact_and_sort(listp);
  fd_rent_list_t * list = *listp;
  for ( ulong i = 0; i < list->num_sorted; ++i )
    if ( ! (*cb)( list->sorted[i], cb_arg ) )
      list->sorted[i] = NULL; /* Ignore in future */

  lists->paused = 0;
  fd_rent_pause_line_t * end = lists->pause_queue + lists->pause_len;
  for ( fd_rent_pause_line_t * i = lists->pause_queue; i != end; ++i )
    fd_rent_lists_cb( i->updated, i->removed, i->arg );
  lists->pause_len = 0;
}
