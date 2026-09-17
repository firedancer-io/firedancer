#ifndef HEADER_fd_src_choreo_tower_fd_tower_file_h
#define HEADER_fd_src_choreo_tower_fd_tower_file_h

/* fd_tower_file writes and reads the tower file.  The layout is
   Agave's, bincode of SavedTowerVersions::Current holding a signed
   Tower1_14_11.  The signature is different.  Agave signs the body
   directly, we sign sha256(sha256(body)) so the sign tile only ever
   sees a 32 byte digest.  Agave cannot verify our file.  It lives under
   paths.base/tower where Agave does not look. */

#include "fd_tower.h"
#include "fd_tower_serdes.h"

/* FD_TOWER_FILE_MAX is the largest file we write or read.  A full
   tower of 31 votes is about 2.3 KiB. */
#define FD_TOWER_FILE_MAX (4096UL)

/* A decoded and verified tower file.  bank_hash and block_id belong
   to the last vote, votes[votes_cnt-1], and come from the embedded
   CompactTowerSync.  timestamp_slot and timestamp are Agave's
   last_timestamp pair. */
struct fd_tower_file {
  fd_tower_vote_t votes[ FD_TOWER_VOTE_MAX ];
  ulong           votes_cnt;
  ulong           root;
  fd_hash_t       bank_hash;
  fd_hash_t       block_id;
  ulong           timestamp_slot;
  long            timestamp;
};
typedef struct fd_tower_file fd_tower_file_t;

/* fd_tower_sign_fn is the signing callback for fd_tower_file_ser.  It
   gets the file body in msg and must write the 64 byte Ed25519
   signature of fd_tower_file_sign_msg( msg ) with the node identity.
   ctx is passed through from sign_ctx. */
typedef void (fd_tower_sign_fn)( void *        ctx,
                                 uchar         sig[ 64 ],
                                 uchar const * msg,
                                 ulong         msg_sz );

FD_PROTOTYPES_BEGIN

/* fd_tower_file_sign_msg computes the 32 byte message the file
   signature covers, sha256(sha256(body)), into out. */

void
fd_tower_file_sign_msg( uchar const * body,
                        ulong         body_sz,
                        uchar         out[ static 32 ] );

/* fd_tower_file_ser writes a complete signed tower file for votes and
   root into buf.  bank_hash and block_id belong to the last vote,
   now_secs is the file timestamp, identity is the node pubkey stored in
   the file and used by sign_fn.  Returns the file size, or -1 if the
   input is invalid or buf_max is too small. */
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

/* fd_tower_file_de checks a tower file and decodes it into out.  The
   signature must verify under identity and the node pubkey stored in
   the file must equal identity, the same checks Agave makes.  Returns 0
   on success with out filled in, root is ULONG_MAX if the file has no
   root.  Returns -1 if anything is malformed or the signature fails,
   and out is left untouched. */
int
fd_tower_file_de( uchar const *       buf,
                  ulong               buf_sz,
                  fd_pubkey_t const * identity,
                  fd_tower_file_t *   out );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_tower_fd_tower_file_h */
