
#include "../tiles.h"

#define FD_ARCHIVER_HEADER_VERSION (1U)

#define FD_ARCHIVER_TILE_ID_SHRED  (0U)
#define FD_ARCHIVER_TILE_ID_GOSSIP (1U)
#define FD_ARCHIVER_TILE_ID_REPAIR (2U)
#define FD_ARCHIVER_TILE_ID_QUIC   (3U)

#define FD_ARCHIVER_HEADER_MAGIC (0xF17EDA2CE5A4B321) /* FIREDANCE ARCHIVER */

/* Header written out to the archive for each fragment */
struct __attribute__((aligned(1UL))) fd_archiver_frag_header {
  ulong magic;
  /* Version */
  uint version;
  /* The identifier of the tile that the frag was received from */
  uint tile_id;
  /* Number of ns since the previous fragment */
  ulong ns_since_prev_fragment;
  /* Size of the fragment data portion, immediately following this header */
  ulong sz;
  /* Signature of the fragment */
  ulong sig;
  /* Sequence number of the fragment */
  ulong seq;
};
typedef struct fd_archiver_frag_header fd_archiver_frag_header_t;
#define FD_ARCHIVER_FRAG_HEADER_FOOTPRINT (48UL)
#define FD_ARCHIVER_FRAG_HEADER_ALIGN     (1UL)
