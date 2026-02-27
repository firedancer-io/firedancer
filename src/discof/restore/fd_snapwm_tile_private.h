#ifndef HEADER_fd_discof_restore_fd_snapwm_tile_private_h
#define HEADER_fd_discof_restore_fd_snapwm_tile_private_h

/* fd_snapwm_tile_private.h contains private APIs for the "snapwm" tile,
   which is the tile responsible for directing vinyl database writes. */

#include "utils/fd_slot_delta_parser.h"
#include "utils/fd_ssparse.h"
#include "utils/fd_vinyl_admin.h"
#include "../../ballet/lthash/fd_lthash.h"
#include "../../ballet/lthash/fd_lthash_adder.h"
#include "../../disco/stem/fd_stem.h"
#include "../../disco/topo/fd_topo.h"
#include "../../vinyl/io/fd_vinyl_io.h"
#include "../../vinyl/meta/fd_vinyl_meta.h"

#define FD_SNAPWM_WR_MTU             (16UL<<20)
#define FD_SNAPWM_PAIR_BATCH_CNT_MAX (FD_SSPARSE_ACC_BATCH_MAX)
#define FD_SNAPWM_PAIR_SZ_MAX        (fd_vinyl_bstream_pair_sz(FD_RUNTIME_ACC_SZ_MAX))
#define FD_SNAPWM_PAIR_BATCH_SZ_MAX  (FD_SNAPWM_PAIR_BATCH_CNT_MAX*FD_SNAPWM_PAIR_SZ_MAX)

#define FD_SNAPWM_DUP_META_BATCH_CNT_MAX  (FD_SNAPWM_PAIR_BATCH_CNT_MAX)
#define FD_SNAPWM_DUP_META_SZ             (sizeof(ulong)+sizeof(fd_vinyl_bstream_phdr_t))
#define FD_SNAPWM_DUP_META_BATCH_SZ       (FD_SNAPWM_DUP_META_BATCH_CNT_MAX*FD_SNAPWM_DUP_META_SZ)

#define FD_SNAPWM_DUP_BATCH_CREDIT_MIN  (1UL)
#define FD_SNAPWM_DUP_LTHASH_CREDIT_MIN ((FD_LTHASH_LEN_BYTES+(ctx->hash_out.mtu-1))/ctx->hash_out.mtu)

struct fd_snapwm_out_link {
  ulong         idx;
  fd_wksp_t *   mem;
  ulong         chunk0;
  ulong         wmark;
  ulong         chunk;
  ulong         mtu;
  ulong         depth;
  ulong const * consumer_fseq;
};
typedef struct fd_snapwm_out_link fd_snapwm_out_link_t;

struct fd_snapwm_tile {
  int  state;
  uint full      : 1;       /* loading a full snapshot? */
  uint lthash_disabled : 1; /* disable lthash checking? */

  ulong seed;
  long boot_timestamp;

  fd_sstxncache_entry_t * txncache_entries;
  ulong const *           txncache_entries_len_ptr;

  struct {
    /* Account counters (full + incremental) */
    ulong accounts_loaded;
    ulong accounts_replaced;
    ulong accounts_ignored;

    /* Account counters (snapshot taken for full snapshot only) */
    ulong full_accounts_loaded;
    ulong full_accounts_replaced;
    ulong full_accounts_ignored;
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

    ulong pair_cnt;
    ulong full_pair_cnt;
    ulong pair_cnt_max;

    /* Vinyl in either io_wd or io_mm mode */
    fd_vinyl_io_t * io;
    fd_vinyl_io_t * io_wd;
    fd_vinyl_io_t * io_mm;
    ulong           io_seed;

    fd_vinyl_meta_t map[1];

    ulong txn_seq;  /* bstream seq of first txn record (in [seq_past,seq_present]) */
    uint  txn_active : 1;
    uint  txn_commit : 1;

    ulong   duplicate_accounts_batch_sz;
    ulong   duplicate_accounts_batch_cnt;

    fd_lthash_adder_t adder;
    fd_lthash_value_t running_lthash;

    ulong              wr_cnt;
    fd_vinyl_admin_t * admin;

   struct {
      ulong seq_ancient;
      ulong seq_past;
      ulong seq_present;
      ulong seq_future;
   } recovery;
  } vinyl;
};

typedef struct fd_snapwm_tile fd_snapwm_tile_t;

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
fd_snapwm_vinyl_txn_commit( fd_snapwm_tile_t * ctx, fd_stem_context_t * stem );

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

/* fd_snapwm_vinyl_process_account reads a set of pre-generated bstream
   pairs and decides whether to actually add then to the vinyl database.
   It supports batch mode as well as single account (pair). */

void
fd_snapwm_vinyl_process_account( fd_snapwm_tile_t *  ctx,
                                 ulong               chunk,
                                 ulong               acc_cnt,
                                 fd_stem_context_t * stem );

/* fd_snapwm_vinyl_read_account retrieves an account from the vinyl
   database. */

void
fd_snapwm_vinyl_read_account( fd_snapwm_tile_t *  ctx,
                              void const *        acct_addr,
                              fd_account_meta_t * meta,
                              uchar *             data,
                              ulong               data_max );

/* fd_snapwm_vinyl_duplicate_accounts_batch_{init,append,fini} handle
   duplicate accounts batching when lthash computation is enabled.
   The batch is needed to minimize the STEM_BURST, and make the stem
   credit handling possible.  _fini is responsible for sending the
   message downstream.

   Typical usage:
     fd_snapwm_vinyl_duplicate_accounts_batch_init( ctx, stem );
     for(...) {
       ...
       fd_snapwm_vinyl_duplicate_accounts_batch_append( ctx, phdr, seq );
     }
     fd_snapwm_vinyl_duplicate_accounts_batch_fini( ctx, stem );

   They all return 1 on success, and 0 otherwise.

   IMPORTANT: there is an fseq check inside init, since every append
   modifies the output link's dcache directly.  However, there is no
   fseq check inside fini.  This is a performance optimization, which
   requires no fd_stem_publish between init and fini. */
int
fd_snapwm_vinyl_duplicate_accounts_batch_init( fd_snapwm_tile_t *  ctx,
                                               fd_stem_context_t * stem );
int
fd_snapwm_vinyl_duplicate_accounts_batch_append( fd_snapwm_tile_t *        ctx,
                                                 fd_vinyl_bstream_phdr_t * phdr,
                                                 ulong                     seq );
int
fd_snapwm_vinyl_duplicate_accounts_batch_fini( fd_snapwm_tile_t *  ctx,
                                               fd_stem_context_t * stem );

/* fd_snapwm_vinyl_duplicate_accounts_lthash_{init,append,fini} handle
   duplicate accounts lthash local calculation when lthash computation
   is enabled.  This is typically only needed when the account is an
   "old" duplicate (meaning that it corresponds to an older slot than
   what is currently in the database).  _fini is responsible for
   sending the message downstream.

   Typical usage:
     fd_snapwm_vinyl_duplicate_accounts_lthash_init( ctx, stem );
     for(...) {
       ...
       fd_snapwm_vinyl_duplicate_accounts_lthash_append( ctx, pair );
     }
     fd_snapwm_vinyl_duplicate_accounts_lthash_fini( ctx, stem );

   They all return 1 on success, and 0 otherwise.

   IMPORTANT: the fseq check happens only inside fini, since append
   only operates on internal variables.  Therefore, it is safe to have
   fd_stem_publish in between init and fini. */
int
fd_snapwm_vinyl_duplicate_accounts_lthash_init( fd_snapwm_tile_t *  ctx,
                                                fd_stem_context_t * stem );
int
fd_snapwm_vinyl_duplicate_accounts_lthash_append( fd_snapwm_tile_t * ctx,
                                                  uchar *            pair );
int
fd_snapwm_vinyl_duplicate_accounts_lthash_fini( fd_snapwm_tile_t *  ctx,
                                                fd_stem_context_t * stem );

/* fd_snapwm_vinyl_{init,update}_admin provide init and update helper
   functions on the vinyl admin object.  do_rwlock is a flag indicating
   whether the lock is required or not.  They return 1 on success and
   0 otherwise. */
int
fd_snapwm_vinyl_init_admin( fd_snapwm_tile_t * ctx,
                            int                do_rwlock );

int
fd_snapwm_vinyl_update_admin( fd_snapwm_tile_t * ctx,
                              int                do_rwlock );

/* fd_snapwm_vinyl_recovery_seq_{backup,apply} are helper functions
   that handle vinyl io bstream seq backup and apply (for recovery).
   Both operate on vinyl io_mm seq values, since this is the io that
   keeps track of those values.  That means that backup must happen
   after io init, and apply must happen before io sync.  */

void
fd_snapwm_vinyl_recovery_seq_backup( fd_snapwm_tile_t * ctx );

void
fd_snapwm_vinyl_recovery_seq_apply( fd_snapwm_tile_t * ctx );

/* fd_snapwm_vinyl_revert_full provides the mechanism to revert any
   changes that happened during a full snapshot load that has been
   cancelled.  It frees all elements of the vinyl meta map.  Finally,
   it reverts the bstream seq(s) in vinyl io and syncs the bstream. */

void
fd_snapwm_vinyl_revert_full( fd_snapwm_tile_t * ctx );

/* fd_snapwm_vinyl_revert_incr provides the mechanism to revert any
   changes that happened during an incr snapshot load that has been
   cancelled.  To do this, every bstream pair's phdr info, as well
   as the corresponding meta map element's phdr info, is modified to
   include val_sz (32 bits), recovery_seq (48 bits) and slot (48 bits)
   in the info length of 16 bytes (128 bits).  When a new account is
   written to the bstream, recovery_seq=0UL is assigned (which works
   as a sentinel value).  When an account is a duplicate update of an
   existing account, the update's recovery_seq corresponds to the seq
   value of the existing account in the bstream.  This is essentially
   a reference to the account that is being superseded.

      bstream:  [     full     |  incr  |   free  )
      revert:                 (*)->......)

   To revert the incremental snapshot, the function walks the bstream
   from recovery seq_present (*) towards the future, until all pairs
   are processed.  If the recovery_seq (in the pair's phdr info) is
   0UL (the sentinel) this account was a new account, and the meta map
   entry needs to be freed.  If the recovery_seq is less than the
   recovery seq_present, the phdr of the pair at recovery_seq is read,
   and used to update the meta map element.  If the recovery_seq is
   greater or equal to the recovery seq_present, this means that the
   update was a duplicate on the incr snapshot itself, and it can
   be discarded altogether.
   Note that as the recovery process moves forward, the meta map entry
   and an account update on the incr side of the bstream may see
   different revovery_seq values (e.g. consider what happens with
   chained duplicate updates).  This means that the true recovery_seq
   is the one in the phdr info of the bstream pair.
   Finally, it reverts the bstream seq(s) in vinyl io and syncs the
   bstream. */

void
fd_snapwm_vinyl_revert_incr( fd_snapwm_tile_t * ctx );

/* fd_snapin_vinyl_pair_info_{from_parts,update_recovery_seq} are
   helper functions to update the pair's info.
   fd_snapin_vinyl_pair_info_{val_sz,recovery_seq,slot} are helper
   functions to retrieve the corresponding values.
   In order to facilitate a recovery process, in particular when an
   incr snapshot is cancelled, every bstream pair's phdr info, as well
   as the corresponding meta map element's phdr info, is modified to
   include val_sz (32 bits), recovery_seq (48 bits) and slot (48 bits)
   in the info length of 16 bytes (128 bits). */

void
fd_snapin_vinyl_pair_info_from_parts( fd_vinyl_info_t * info,
                                      ulong             val_sz,
                                      ulong             recovery_seq,
                                      ulong             slot );
void
fd_snapin_vinyl_pair_info_update_recovery_seq( fd_vinyl_info_t * info,
                                               ulong             recovery_seq );
ulong fd_snapin_vinyl_pair_info_val_sz      ( fd_vinyl_info_t const * info );
ulong fd_snapin_vinyl_pair_info_recovery_seq( fd_vinyl_info_t const * info );
ulong fd_snapin_vinyl_pair_info_slot        ( fd_vinyl_info_t const * info );

FD_PROTOTYPES_END

#endif /* HEADER_fd_discof_restore_fd_snapwm_tile_private_h */
