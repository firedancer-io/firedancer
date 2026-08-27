#ifndef HEADER_fd_src_discof_votor_fd_votor_notif_h
#define HEADER_fd_src_discof_votor_fd_votor_notif_h

#include "../../disco/fd_disco_base.h"

/* Votor notifications are informational state updates for consumers
   which do not participate in consensus.  The fragment signature
   identifies the payload stored in fd_votor_notif_t.

   The link is unreliable, so a consumer may miss fragments.  Every
   notification is therefore idempotent and describes a state rather
   than a transition, and consumers merge them monotonically: a regular
   notarization supersedes a fallback one, and fast finalization
   supersedes slow, which supersedes implicit.  Nothing here is
   consensus critical, and votor must never block on a consumer of it.

   Two consequences of "unreliable" are worth stating, because they are
   what keeps this feed simple.  A dropped notification is recovered by
   the next one for the same slot, because each carries the whole state
   rather than a delta.  And the terminal states - a block is final, a
   slot has no block - do not depend on this feed at all: they are
   already delivered reliably as a root, and every slot in a gap of the
   rooted chain is skipped.  So this feed only ever enriches; losing it
   degrades detail, never correctness.

   Types here are deliberately plain (fd_hash_t, ulong) rather than the
   ag_* consensus types.  ag_event.h reserves those for use inside
   votor, and a wire type must not change shape when the algorithm's
   internal representation does. */

#define FD_VOTOR_NOTIF_FINALIZED_SLOT (0UL) /* ulong                         */
#define FD_VOTOR_NOTIF_CERT           (1UL) /* fd_votor_notif_cert_t         */
#define FD_VOTOR_NOTIF_PARENT_READY   (2UL) /* fd_votor_notif_parent_ready_t */

/* Certificate kinds.  A skip certificate proves the cluster agreed the
   slot has no block, so it names a slot and never a block. */

#define FD_VOTOR_NOTIF_CERT_NOTAR          ((uchar)0) /* >=60% notarize                       */
#define FD_VOTOR_NOTIF_CERT_NOTAR_FALLBACK ((uchar)1) /* >=60% notarize and notarize-fallback */
#define FD_VOTOR_NOTIF_CERT_SKIP           ((uchar)2) /* >=60% skip and skip-fallback         */
#define FD_VOTOR_NOTIF_CERT_FAST_FINAL     ((uchar)3) /* >=80% notarize, finalizes directly   */
#define FD_VOTOR_NOTIF_CERT_FINAL          ((uchar)4) /* >=60% finalize, finalizes directly   */

struct fd_votor_notif_cert {
  ulong     slot;
  fd_hash_t block_id;     /* the certified block, valid iff has_block_id */
  uchar     kind;         /* one of FD_VOTOR_NOTIF_CERT_* */
  uchar     has_block_id; /* zero for a skip certificate, which has no
                             block by construction, and for a slow
                             finalization whose notarization certificate
                             has not landed yet, in which case the block
                             is not knowable.  A later notification for
                             the slot carries it once it is. */
};

typedef struct fd_votor_notif_cert fd_votor_notif_cert_t;

/* Parent ready is Votor's fork choice: the block that the next leader
   window may be built on.  It is only ever emitted for the first slot
   of a window, so it advances in window sized steps and is not a
   per-slot frontier. */

struct fd_votor_notif_parent_ready {
  ulong     slot;            /* first slot of the ready leader window */
  ulong     parent_slot;
  fd_hash_t parent_block_id;
};

typedef struct fd_votor_notif_parent_ready fd_votor_notif_parent_ready_t;

union fd_votor_notif {
  ulong                         finalized_slot;
  fd_votor_notif_cert_t         cert;
  fd_votor_notif_parent_ready_t parent_ready;
};

typedef union fd_votor_notif fd_votor_notif_t;

#endif /* HEADER_fd_src_discof_votor_fd_votor_notif_h */
