#ifndef HEADER_fd_src_choreo_tower_fd_tower_file_h
#define HEADER_fd_src_choreo_tower_fd_tower_file_h

/* fd_tower_file writes and reads the tower file in Agave's on-disk
   format, bincode of SavedTowerVersions::Current wrapping a signed
   Tower1_14_11.  Agave signs the payload with the node identity and
   verifies the signature on load, so serialization takes a signing
   callback and deserialization verifies everything before trusting it. */

#include "fd_tower.h"
#include "fd_tower_serdes.h"

/* FD_TOWER_FILE_MAX bounds the file image.  A full tower with 31
   votes is about 2.3 KiB. */
#define FD_TOWER_FILE_MAX (4096UL)

/* fd_tower_sign_fn produces a 64-byte Ed25519 signature of msg under
   the node identity.  ctx is the caller's closure. */
typedef void (fd_tower_sign_fn)( void *        ctx,
                                 uchar         sig[ 64 ],
                                 uchar const * msg,
                                 ulong         msg_sz );

FD_PROTOTYPES_BEGIN

/* fd_tower_file_ser serializes the votes deque and root into a
   complete signed tower file image in buf.  bank_hash and block_id
   are the values of the vote being persisted,
   now_secs is a file timestamp.
   Returns the image size, or -1 for invalid input or insufficient
   buffer space. */
long
fd_tower_file_ser( fd_tower_vote_t const * votes,
                   ulong                   root,
                   fd_hash_t const *       bank_hash,
                   fd_hash_t const *       block_id,
                   long                    now_secs,
                   fd_pubkey_t const *     identity,
                   fd_tower_sign_fn *      sign_fn,
                   void *                  sign_ctx,
                   uchar *                 buf,
                   ulong                   buf_max );

/* fd_tower_file_de verifies and reads a tower file image.  The
   signature must verify under identity and the embedded node pubkey
   must equal it, mirroring Agave's load checks.  On success fills
   out_votes (room for FD_TOWER_VOTE_MAX), *out_votes_cnt, *out_root
   (ULONG_MAX when the file has none), and *out_ts, and returns 0.
   Returns -1 on any structural or authenticity failure. */
int
fd_tower_file_de( uchar const *       buf,
                  ulong               buf_sz,
                  fd_pubkey_t const * identity,
                  fd_tower_vote_t *   out_votes,
                  ulong *             out_votes_cnt,
                  ulong *             out_root,
                  long *              out_ts );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_tower_fd_tower_file_h */
