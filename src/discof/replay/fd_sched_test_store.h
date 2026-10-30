#ifndef HEADER_fd_src_discof_replay_fd_sched_test_store_h
#define HEADER_fd_src_discof_replay_fd_sched_test_store_h

/* Test-only helper that backs fd_sched_fec_t read handles with a small
   real store.  A FEC is staged in an fd_sched_test_fec_t (payload size
   and tracked shred sizes), pinned with fd_sched_test_fec_pin
   (insert_begin, fill, insert_commit, query_acquire), and unpinned
   with fd_sched_test_fec_unpin, which releases the view and publishes
   past the FEC's slot so the store never fills.  Like replay, at most
   one FEC may be pinned at a time per thread.

   Each thread in a translation unit including this header gets its own
   store, created on first use in an anonymous normal page workspace.
   Solfuzz runs shred fixtures concurrently on multiple tile threads. */

#include "fd_sched.h"

#define FD_SCHED_TEST_STORE_FEC_MAX (4UL)

struct fd_sched_test_fec {
  uint   data_sz;                       /* total payload bytes */
  ushort shred_sz[ FD_FEC_SHRED_CNT ];  /* tracked shred sizes */
};
typedef struct fd_sched_test_fec fd_sched_test_fec_t;

static FD_TL fd_store_t * fd_sched_test_store;
static FD_TL ulong        fd_sched_test_store_slot;

static inline fd_store_t *
fd_sched_test_store_get( void ) {
  if( FD_LIKELY( fd_sched_test_store ) ) return fd_sched_test_store;

  ulong fec_max   = FD_SCHED_TEST_STORE_FEC_MAX;
  ulong footprint = fd_store_footprint( fec_max, FD_STORE_MAX_FEC_DATA_SZ, 0UL, 0UL, 0UL, 1UL, fec_max );
  FD_TEST( footprint );
  ulong page_cnt  = footprint/FD_SHMEM_NORMAL_PAGE_SZ + 64UL;
  char  name[ 64 ];
  fd_cstr_printf( name, sizeof(name), NULL, "sched_test_store_%lu", fd_tile_idx() );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( FD_SHMEM_NORMAL_PAGE_SZ, page_cnt, fd_shmem_cpu_idx( 0UL ), name, 0UL );
  FD_TEST( wksp );
  void * mem = fd_wksp_alloc_laddr( wksp, fd_store_align(), footprint, 1UL );
  FD_TEST( mem );
  fd_sched_test_store = fd_store_join( fd_store_new( mem, fec_max, FD_STORE_MAX_FEC_DATA_SZ, 0UL, 0UL, 0UL,
                                                     FD_SHRED_BLK_MAX, 0UL, 1UL, fec_max ) );
  FD_TEST( fd_sched_test_store );
  return fd_sched_test_store;
}

/* fd_sched_test_fec_pin inserts fec with payload data (data_sz bytes,
   may be NULL if 0) under a fresh slot and pins it.  Returns the read
   handle to put in fd_sched_fec_t. */

static inline fd_sched_fec_read_t
fd_sched_test_fec_pin( fd_sched_test_fec_t const * fec,
                       uchar const *               data ) {
  fd_store_t * store = fd_sched_test_store_get();
  ulong        slot  = ++fd_sched_test_store_slot;
  fd_hash_t    mr    = { .ul = { slot, 0x5c4ed7e57UL } };

  fd_store_insert_t ins;
  FD_TEST( fd_store_insert_begin( store, -1, &mr, slot, 0UL, NULL, &ins )==FD_STORE_SUCCESS );
  fd_store_fec_t * rec = fd_store_insert_data( store, ins );
  fd_memcpy( rec->shred_sz, fec->shred_sz, sizeof(rec->shred_sz) );
  if( FD_LIKELY( data ) ) fd_memcpy( rec->payload, data, fec->data_sz );
  else FD_TEST( !fec->data_sz );
  FD_TEST( fd_store_insert_commit( store, ins, fec->data_sz )==FD_STORE_SUCCESS );

  fd_store_view_t view = fd_store_query_acquire( store, &mr, NULL );
  FD_TEST( view!=FD_STORE_VIEW_NULL );
  return (fd_sched_fec_read_t){ .store = store, .disk_fd = -1, .view = view };
}

/* fd_sched_test_fec_unpin releases read's view and frees its FEC. */

static inline void
fd_sched_test_fec_unpin( fd_sched_fec_read_t * read ) {
  FD_TEST( read->view!=FD_STORE_VIEW_NULL );
  fd_store_query_release( read->store, read->view );
  read->view = FD_STORE_VIEW_NULL;
  fd_store_publish( read->store, fd_sched_test_store_slot+1UL, NULL );
}

/* fd_sched_test_fec_ingest ingests fec, then unpins it.  Returns
   fd_sched_fec_ingest's verdict. */

static inline int
fd_sched_test_fec_ingest( fd_sched_t *     sched,
                          fd_sched_fec_t * fec ) {
  int ok = fd_sched_fec_ingest( sched, fec );
  fd_sched_test_fec_unpin( &fec->read );
  return ok;
}

#endif /* HEADER_fd_src_discof_replay_fd_sched_test_store_h */
