#ifndef HEADER_fd_src_discof_backup_fd_snapmk_h
#define HEADER_fd_src_discof_backup_fd_snapmk_h

/* fd_snapmk.h provides APIs for Firedancer's snapshot creator.

   Tiles:
   - snapmk: lay out account data
   - snapzp (multiple): compress data and write the content to disk

   Limitations:
   - requires support for FALLOC_FL_INSERT_RANGE (ext4 or XFS)
     (Why? Because the snapshot manifest must precede accounts, but it
     is more convenient to produce it after compressing all accounts,
     which could take a while. The FALLOC_FL_INSERT_RANGE trick allows
     prepending data to a file efficiently.)
   - requires rooting to stop (until new accdb v7 ships)

   Administrative flow:
   - snapmk/snapzp mostly sleep, periodically checking for new jobs
   - User runs 'firedancer snapshot-create', notifying replay tile
   - Replay tile wakes up snapmk, which propagates a wakeup message
   - ... pipeline does its thing ...
   - snapmk tells snapzp tiles to shut down
   - snapmk notifies replay tile
   - snapmk shuts itself down

   Data flow (accounts):
   - snapmk scans the funk index for rooted accounts (vinyl not
     supported)
   - snapmk reads each account, copies it to an in-memory queue
   - snapzp compresses accounts
   - snapzp writes compressed accounts to disk (using O_DIRECT)

   Data flow (manifest):
   - snapmk streams manifest data to an in-memory queue
   - snapzp copies and compresses manifest data */

#include "../../util/archive/fd_tar.h"

#define FUNK_SCAN_PARA 64
#define SNAPZP_TILE_MAX (64UL)

/* snapmk state machine */

#define SNAPMK_STATE_IDLE           0 /* clean, waiting for job */
#define SNAPMK_STATE_TAR_HEADERS    1
#define SNAPMK_STATE_MANIFEST       2 /* writing manifest */
#define SNAPMK_STATE_ACCOUNTS       3 /* writing accounts */
#define SNAPMK_STATE_ACCOUNTS_FLUSH 4 /* done writing accounts, flush pipeline */
#define SNAPMK_STATE_DONE           5 /* done, notify replay tile */
#define SNAPMK_STATE_FAIL           6 /* error state, doing cleanup */

/* snapmk message types (frag_meta orig field) */

#define SNAPMK_ORIG_BATCH       1 /* account batch */
#define SNAPMK_ORIG_FLUSH       2 /* flush pending batch */
#define SNAPMK_ORIG_RESET       3 /* reset state */
#define SNAPMK_ORIG_DONE        4

struct __attribute__((aligned(64))) fd_snapmk_batch {
  ulong val_gaddr[ FUNK_SCAN_PARA ];
  uint  rec_idx  [ FUNK_SCAN_PARA ];
  uint  data_sz  [ FUNK_SCAN_PARA ];
};
typedef struct fd_snapmk_batch fd_snapmk_batch_t;

/* Instruction-level parallel funk index scanner.

   ### Why does this exist?

   map_chain_para has horrible pointer-chasing characteristics.
   Naively iterating through a giant map_chain_para map on a Zen 5
   DDR5-4800 box results in about 6.5 million element/second throughput.
   That is about 150 ns or 450 cycles per element.

   ### What do we do about it?

   Read-ahead & memory gather optimizations to amortize DRAM latency by
   keeping the CPU's load queue busy. */

#include "../../funk/fd_funk.h"
#include "../../flamenco/fd_flamenco_base.h"

typedef fd_funk_rec_map_shmem_private_chain_t fd_funk_rec_chain_t;

#define FUNK_SCAN_PARA 64

static fd_funk_rec_chain_t const rec_chain_sentinel = {
  .ver_cnt   = 0UL,
  .head_cidx = UINT_MAX
};

static fd_funk_rec_t const rec_sentinel = {
  .val_gaddr = ULONG_MAX
};

struct fd_funk_scan {
  /* Source */
  fd_funk_rec_chain_t const * chain_tbl;
  fd_funk_rec_t const *       rec_tbl;
  fd_snapmk_batch_t *         batch;
  ulong                       cnt;
};
typedef struct fd_funk_scan fd_funk_scan_t;

fd_funk_scan_t *
fd_funk_scan_init( fd_funk_scan_t *  scan,
                   fd_funk_t const * funk );

void
fd_funk_scan_refill( fd_funk_scan_t * scan,
                     ulong            chain );

FD_FN_UNUSED static fd_tar_meta_t *
fd_snapmk_tar_file_hdr( fd_tar_meta_t * tar_meta,
                        ulong           sz ) {
  *tar_meta = (fd_tar_meta_t){
    .magic    = "ustar ",
    .mode     = "644",
    .uid      = "0",
    .gid      = "0",
    .typeflag = FD_TAR_TYPE_REGULAR,
    .chksum   = "        "
  };
  (void)fd_tar_meta_set_size( tar_meta, sz );
  return tar_meta;
}

FD_FN_UNUSED static fd_tar_meta_t *
fd_snapmk_tar_dir_hdr( fd_tar_meta_t * tar_meta ) {
  *tar_meta = (fd_tar_meta_t){
    .magic    = "ustar ",
    .mode     = "755",
    .uid      = "0",
    .gid      = "0",
    .typeflag = FD_TAR_TYPE_DIR,
    .chksum   = "        "
  };
  (void)fd_tar_meta_set_size( tar_meta, 0UL );
  return tar_meta;
}

#endif /* HEADER_fd_src_discof_backup_fd_snapmk_h */
