#include "../../../../disco/tiles.h"

#define FD_ARCHIVER_HEADER_VERSION (1U)

#define FD_ARCHIVER_TILE_ID_SHRED  (0U)
#define FD_ARCHIVER_TILE_ID_VERIFY (1U)
#define FD_ARCHIVER_TILE_ID_GOSSIP (2U)
#define FD_ARCHIVER_TILE_ID_REPAIR (3U)

#define FD_ARCHIVER_HEADER_MAGIC (0xF17EDA2CE5A4B321) /* FIREDANCE ARCHIVER */

/* Header written out to the archive for each fragment */
struct fd_archiver_frag_header {
  ulong magic;
  /* Version */
  uint version;
  /* The identifier of the tile that the frag was received from */
  uint tile_id;
  /* The timestamp when the frag was created, compressed */
  ulong tspub_comp;
  /* Size of the fragment data portion, immediately following this header */
  ulong sz;
};
typedef struct fd_archiver_frag_header fd_archiver_frag_header_t;
#define FD_ARCHIVER_FRAG_HEADER_FOOTPRINT (32UL)
#define FD_ARCHIVER_FRAG_HEADER_ALIGN     (8UL)
