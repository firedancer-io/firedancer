#ifndef HEADER_fd_src_disco_shred_fd_shredcap_h
#define HEADER_fd_src_disco_shred_fd_shredcap_h

#include "../../util/fd_util_base.h"
#include "../../disco/store/fd_store.h"
#include "../../ballet/shred/fd_shred.h"

#define FD_SHRED_CAP_OK    0
#define FD_SHRED_CAP_ERR   -1

// TODO: Could we add a ushort magic number here?  Could we also add a ushort sizeof(fd_shred_cap_hdr) here as well?
//       this will let us add things into the header without invalidating all previous packet captures
#define FD_SHRED_CAP_MAGIC 0xFDCB
struct __attribute__((packed)) fd_shred_cap_file_hdr {
  ushort magic;
  ushort shred_cap_hdr_sz;
};
typedef struct fd_shred_cap_file_hdr fd_shred_cap_file_hdr_t;

struct __attribute__((packed)) fd_shred_cap_hdr {
  ulong sz;
  uchar flags;
};
typedef struct fd_shred_cap_hdr fd_shred_cap_hdr_t;

struct fd_shred_cap_ctx {
  int   is_archive;
  int   shred_cap_fileno;
  ulong stable_slot_end;
  ulong stable_slot_start;
};
typedef struct fd_shred_cap_ctx fd_shred_cap_ctx_t;

#define FD_SHRED_CAP_FLAG_MARK_TURBINE(x) fd_uchar_set_bit(x, 1)      /* xxxxxxx1 */
#define FD_SHRED_CAP_FLAG_MARK_REPAIR(x)  fd_uchar_clear_bit(x, 1)    /* xxxxxxx0 */

#define FD_SHRED_CAP_FLAG_IS_TURBINE(x)   fd_uchar_extract_bit(x, 1)  /* xxxxxxx1 */
#define FD_SHRED_CAP_FLAG_IS_REPAIR(x)    !fd_uchar_extract_bit(x, 1) /* xxxxxxx0 */

// TODO: Lets properly document these on documentation day

int
fd_shred_cap_archive( fd_shred_cap_ctx_t * ctx,
                      fd_shred_t const *   shred,
                      uchar                flags);
int
fd_shred_cap_replay( const char *      shred_cap_fpath,
                     fd_store_t *      store );
#endif
