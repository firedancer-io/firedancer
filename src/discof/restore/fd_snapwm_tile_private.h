#ifndef HEADER_fd_discof_restore_fd_snapwm_tile_private_h
#define HEADER_fd_discof_restore_fd_snapwm_tile_private_h

/* fd_snapwm_tile_private.h contains private APIs for the "snapwm" tile,
   which is the tile responsible for directing vinyl database writes. */

#include "utils/fd_slot_delta_parser.h"
#include "../../disco/stem/fd_stem.h"
#include "../../disco/topo/fd_topo.h"
#include "../../vinyl/io/fd_vinyl_io.h"
#include "../../vinyl/meta/fd_vinyl_meta.h"

struct fd_snapwm_out_link {
  ulong       idx;
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
  ulong       mtu;
};
typedef struct fd_snapwm_out_link fd_snapwm_out_link_t;

struct fd_snapwm_tile {
  int  state;
  uint full      : 1;       /* loading a full snapshot? */
  uint lthash_disabled : 1; /* disable lthash checking? */

  ulong seed;
  long boot_timestamp;

  fd_stem_context_t *      stem;

  fd_sstxncache_entry_t * txncache_entries;
  ulong *                 txncache_entries_len_ptr;

  struct {
    ulong full_bytes_read;
    ulong incremental_bytes_read;
    ulong accounts_inserted;
  } metrics;

  struct {
    fd_wksp_t * wksp;
    ulong       chunk0;
    ulong       wmark;
    ulong       mtu;
    ulong       pos;
  } in;

  ulong                out_ct_idx;
  fd_snapwm_out_link_t hash_out;

  struct {
    uchar * bstream_mem;
    ulong   bstream_sz;

    /* Vinyl in either io_wd or io_mm mode */
    fd_vinyl_io_t * io;
    fd_vinyl_io_t * io_wd;
    fd_vinyl_io_t * io_mm;
    ulong           io_seed;

    fd_vinyl_meta_t map[1];

    ulong txn_seq;  /* bstream seq of first txn record (in [seq_past,seq_present]) */
    uint  txn_active : 1;
  } vinyl;
};

typedef struct fd_snapwm_tile fd_snapwm_tile_t;

/* Vinyl APIs *********************************************************/

FD_PROTOTYPES_BEGIN

#define FD_SNAPWM_IO_SPAD_MAX (64UL<<20) /* 64 MiB of I/O scratch space */

/* fd_snapwm_vinyl_privileged_init performs administrative tasks, such
   as opening and mapping the bstream file descriptor. */

void
fd_snapwm_vinyl_privileged_init( fd_snapwm_tile_t * ctx,
                                 fd_topo_t *        topo,
                                 fd_topo_tile_t *   tile );

/* fd_snapwm_vinyl_unprivileged_init performs setup tasks after being
   sandboxed.  (anything that might be exposed to untrusted data) */

void
fd_snapwm_vinyl_unprivileged_init( fd_snapwm_tile_t * ctx,
                                   fd_topo_t *        topo,
                                   fd_topo_tile_t *   tile,
                                   void *             io_mm_mem,
                                   void *             io_wd_mem );

/* fd_snapwm_vinyl_seccomp returns a seccomp sandbox policy suitable
   for vinyl operation. */

ulong
fd_snapwm_vinyl_seccomp( ulong                out_cnt,
                         struct sock_filter * out );

/* fd_snapwm_vinyl_reset pauses the snapwr tile (waits for the snapwr
   tile to ack) and formats a bstream file to be empty.  THIS IS A
   DESTRUCTIVE ACTION. */

void
fd_snapwm_vinyl_reset( fd_snapwm_tile_t * ctx );

/* fd_snapwm_vinyl_txn_begin starts a transactional burst write.
   Assumes vinyl uses the io_mm backend.  The write can then either be
   committed or cancelled.  There is no practical limit on the size of
   this burst. */

void
fd_snapwm_vinyl_txn_begin( fd_snapwm_tile_t * ctx );

/* fd_snapwm_vinyl_txn_commit finishes a transactional burst write.
   Assumes vinyl uses the io_mm backend.  Reads through bstream records
   written since txn_begin was called and updates the vinyl_meta index. */

void
fd_snapwm_vinyl_txn_commit( fd_snapwm_tile_t * ctx );

/* fd_snapwm_vinyl_txn_cancel abandons a transactional burst write.
   Assumes vinyl uses the io_mm backend.  Reverts the bstream state to
   when txn_begin was called. */

void
fd_snapwm_vinyl_txn_cancel( fd_snapwm_tile_t * ctx );

/* fd_snapwm_vinyl_wd_init transitions the vinyl backend from generic
   vinyl accessor (io_mm) to fast dumb direct account insertion (io_wd).
   This must be called before calling fd_snapwm_process_account_*.
   Starts the snapwr tile (waits for the snapwr tile to ack). */

void
fd_snapwm_vinyl_wd_init( fd_snapwm_tile_t * ctx );

/* fd_snapwm_vinyl_wd_fini transitions the vinyl backend from fast dumb
   direct account insertion (io_wd) back to generic mode (io_mm).
   Pauses the snapwr tile (waits for the snapwr to ack). */

void
fd_snapwm_vinyl_wd_fini( fd_snapwm_tile_t * ctx );

/* fd_snapwm_vinyl_shutdown instructs vinyl-related tiles of the loader
   to shut down.  Blocks until all affected tiles have acknowledged the
   shutdown signal. */

void
fd_snapwm_vinyl_shutdown( fd_snapwm_tile_t * ctx );

/* Internal APIs for inserting accounts */

void
fd_snapwm_process_account_vinyl( fd_snapwm_tile_t * ctx,
                                 ulong              chunk,
                                 ulong              acc_cnt );

void
fd_snapwm_read_account_vinyl( fd_snapwm_tile_t *  ctx,
                              void const *        acct_addr,
                              fd_account_meta_t * meta,
                              uchar *             data,
                              ulong               data_max );

FD_PROTOTYPES_END

/* Generic APIs *******************************************************/

FD_PROTOTYPES_BEGIN

static inline int
fd_snapwm_process_account( fd_snapwm_tile_t * ctx,
                           ulong              chunk,
                           ulong              acc_cnt ) {
  fd_snapwm_process_account_vinyl( ctx, chunk, acc_cnt );
  return 0;
}

static inline void
fd_snapwm_read_account( fd_snapwm_tile_t *  ctx,
                        void const *        acct_addr,
                        fd_account_meta_t * meta,
                        uchar *             data,
                        ulong               data_max ) {
  fd_snapwm_read_account_vinyl( ctx, acct_addr, meta, data, data_max );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_discof_restore_fd_snapwm_tile_private_h */
