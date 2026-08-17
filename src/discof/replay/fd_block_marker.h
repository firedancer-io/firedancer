#ifndef HEADER_fd_src_discof_replay_fd_block_marker_h
#define HEADER_fd_src_discof_replay_fd_block_marker_h

/* fd_block_marker deserializes Alpenglow block markers. */

#include "../../flamenco/fd_flamenco_base.h"
#include "../../flamenco/rewards/fd_reward_cert.h"
#include "../../choreo/votor/ag_cert.h"

#define FD_BLOCK_MARKER_DE_SUCCESS         ( 0)
#define FD_BLOCK_MARKER_DE_ERR_TRUNCATED   (-1) /* input ended short of the encoding */
#define FD_BLOCK_MARKER_DE_ERR_MALFORMED   (-2) /* not a valid encoding */
#define FD_BLOCK_MARKER_DE_ERR_UNSUPPORTED (-3) /* valid, but a version/variant we don't handle */

/* Size of the fixed marker preamble: marker_flag (8) + version (2) +
   variant (1) + length (2). */
#define FD_BLOCK_MARKER_PREAMBLE_SZ (13UL)

/* https://github.com/anza-xyz/agave/blob/v4.3.0-beta.0/entry/src/block_component.rs#L381 */
enum fd_block_marker_variant {
   FOOTER = 0,
   HEADER = 1,
   UPDATE_PARENT = 2,
   GENESIS_CERTIFICATE = 3,
};
struct fd_block_header {
   ulong     parent_slot;
   fd_hash_t parent_block_id;
};
typedef struct fd_block_header fd_block_header_t;

/* https://github.com/anza-xyz/agave/blob/v4.3.0-beta.0/entry/src/block_component.rs#L436 */
struct fd_update_parent {
   ulong     new_parent_slot;
   fd_hash_t new_parent_block_id;
};
typedef struct fd_update_parent fd_update_parent_t;

#define FD_BLOCK_FOOTER_USER_AGENT_MAX (255UL)

struct fd_block_footer {
   fd_hash_t bank_hash;
   ulong     block_producer_time_nanos;
   ulong     user_agent_len;
   uchar     user_agent[ FD_BLOCK_FOOTER_USER_AGENT_MAX ];

   /* Optional finalization certa, shape validated and agg
      signatures decompressed, but not verified. A fast finalization
      cert fills fast_final_cert; a slow one fills final_cert +
      notar_cert. */
   int                  has_fast_final_cert;
   int                  has_final_cert;
   ag_fast_final_cert_t fast_final_cert;
   ag_final_cert_t      final_cert;
   ag_notar_cert_t      notar_cert;

   /* Optional reward certs. Shapes are validated but signatures are
      not verified. */
   int              has_skip_reward_cert;
   fd_reward_cert_t skip_reward_cert;
   int              has_notar_reward_cert;
   fd_reward_cert_t notar_reward_cert;
};
typedef struct fd_block_footer fd_block_footer_t;

struct fd_block_marker {
   uchar variant; /* enum fd_block_marker_variant */
   union {
    fd_block_header_t  header;
    fd_block_footer_t  footer;
    fd_update_parent_t update_parent;
   };
};
typedef struct fd_block_marker fd_block_marker_t;

FD_PROTOTYPES_BEGIN

/* The deserializers below decode a versioned block marker payload,
   with buf pointing at the payload byte (FD_BLOCK_MARKER_PREAMBLE_SZ
   into the marker). returns FD_BLOCK_MARKER_DE_SUCCESS and write
   the number of bytes consumed to buf_sz (if non-NULL) on success, and
   return FD_BLOCK_MARKER_DE_ERR_* on failure. */

int
fd_block_header_de( fd_block_header_t * header,
                    uchar const *       buf,
                    ulong               buf_max,
                    ulong *             buf_sz );

int
fd_block_footer_de( fd_block_footer_t * footer,
                    uchar const *       buf,
                    ulong               buf_max,
                    ulong *             buf_sz );

int
fd_update_parent_de( fd_update_parent_t * update_parent,
                     uchar const *        buf,
                     ulong                buf_max,
                     ulong *              buf_sz );

/* fd_block_marker_de deserializes a whole block marker, with buf
   pointing at the marker flag (the start of the entry batch). Trailing
   bytes past buf_max are not consumed.  buf_sz set to
   FD_BLOCK_MARKER_PREAMBLE_SZ + length on success, and returns
   FD_BLOCK_MARKER_DE_SUCCESS or FD_BLOCK_MARKER_DE_ERR_* on failure */
int
fd_block_marker_de( fd_block_marker_t * marker,
                    uchar const *       buf,
                    ulong               buf_max,
                    ulong *             buf_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_replay_fd_block_marker_h */
