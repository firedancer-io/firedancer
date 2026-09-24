#ifndef HEADER_fd_src_choreo_votor_ag_hist_file_h
#define HEADER_fd_src_choreo_votor_ag_hist_file_h

/* Reads and writes the votor's saved vote history.  The layout is our
   own, not Agave's vote_history-<pubkey>.bin, which is a wincode dump
   of hash maps and signed vote payloads that does not map onto the
   votor's slot state flags, and Agave could not check our signature
   anyway.  The body is magic, version, node pubkey and timestamp
   followed by the ag_hist wire form, then a 64 byte Ed25519 signature
   over FD_KEYGUARD_VOTOR_HIST_PREFIX plus sha256(body), so the sign
   tile sees a short fixed message no other role can produce. */

#include "ag_hist.h"
#include "../../disco/keyguard/fd_keyguard.h"

#define AG_HIST_FILE_MAGIC   (0x48414446U) /* the bytes 'F','D','A','H' read as a little endian uint */
#define AG_HIST_FILE_VERSION (1U)
#define AG_HIST_FILE_HDR_SZ  (48UL)        /* u32 magic, u32 version, 32 byte pubkey, i64 timestamp */

/* AG_HIST_FILE_MAX is the largest file we write or read.  A full
   history of AG_HIST_MAX notar records is 5378 bytes. */
#define AG_HIST_FILE_MAX (8192UL)

FD_STATIC_ASSERT( AG_HIST_FILE_MAX>=AG_HIST_FILE_HDR_SZ+AG_HIST_SER_MAX+64UL, ag_hist_file_max );

/* ag_hist_sign_fn is the signing callback for ag_hist_file_ser.  It
   gets the file body in msg and must write the 64 byte Ed25519
   signature of ag_hist_file_sign_msg( msg ) with the node identity.
   ctx is passed through from sign_ctx. */
typedef void (ag_hist_sign_fn)( void *        ctx,
                                uchar         sig[ 64 ],
                                uchar const * msg,
                                ulong         msg_sz );

FD_PROTOTYPES_BEGIN

/* ag_hist_file_sign_msg computes the message the file signature
   covers, FD_KEYGUARD_VOTOR_HIST_PREFIX followed by sha256(body), into
   out. */

void
ag_hist_file_sign_msg( uchar const * body,
                       ulong         body_sz,
                       uchar         out[ static FD_KEYGUARD_VOTOR_HIST_MSG_SZ ] );

/* ag_hist_file_ser writes a complete signed history file for hist into
   buf.  identity is the node pubkey stored in the file and used by
   sign_fn, now_secs is the file timestamp.  Returns the file size, or
   -1 if hist is invalid or buf_max is too small, in which case nothing
   is written. */
long
ag_hist_file_ser( ag_hist_t const *   hist,
                  fd_pubkey_t const * identity,
                  long                now_secs,
                  ag_hist_sign_fn *   sign_fn,
                  void *              sign_ctx,
                  uchar *             buf,
                  ulong               buf_max );

/* ag_hist_file_de checks a history file and decodes it into out.  The
   node pubkey stored in the file must equal identity and the signature
   must verify under it.  Returns 0 on success with out filled in and
   the file timestamp in opt_timestamp when it is non-NULL.  Returns -1
   if anything is malformed or the signature fails, and out is left
   untouched. */
int
ag_hist_file_de( uchar const *       buf,
                 ulong               buf_sz,
                 fd_pubkey_t const * identity,
                 ag_hist_t *         out,
                 long *              opt_timestamp );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_votor_ag_hist_file_h */
