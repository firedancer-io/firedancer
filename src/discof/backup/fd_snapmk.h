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

#include "../../util/fd_util_base.h"

#define SNAPZP_TILE_MAX (64UL)

/* snapmk state machine */

#define SNAPMK_STATE_IDLE           0 /* clean, waiting for job */
#define SNAPMK_STATE_ACCOUNTS       1 /* writing accounts */
#define SNAPMK_STATE_ACCOUNTS_FLUSH 2 /* done writing accounts, flush pipeline */
#define SNAPMK_STATE_MANIFEST       3 /* writing manifest */
#define SNAPMK_STATE_FAIL           4 /* error state, doing cleanup */

/* snapmk message types (frag_meta orig field) */

#define SNAPMK_ORIG_DATA        0 /* data frag */
#define SNAPMK_ORIG_CREATE_FULL 1 /* create a full snapshot */
#define SNAPMK_ORIG_DONE        2 /* done */
#define SNAPMK_ORIG_ERROR       3 /* error */

#endif /* HEADER_fd_src_discof_backup_fd_snapmk_h */
