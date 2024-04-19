#ifndef HEADER_fd_src_disco_shred_fd_shredcap_h
#define HEADER_fd_src_disco_shred_fd_shredcap_h

/* Header include for fd_replay_t, fd_shred_t and fd_blockstoe_t */
#include "../tvu/fd_replay.h"
#include "../../ballet/shred/fd_fec_set.h"
#include "../../flamenco/runtime/fd_blockstore.h"

#define FD_SHRED_CAP_OK  0
#define FD_SHRED_CAP_ERR -1

// TODO: Could we add a ushort magic number here?  Could we also add a ushort sizeof(fd_shred_cap_hdr) here as well?
//       this will let us add things into the header without invalidating all previous packet captures

struct __attribute__((packed)) fd_shred_cap_hdr {

    ulong size;
    uchar flags;
};
typedef struct fd_shred_cap_hdr fd_shred_cap_hdr_t;

#define FD_SHRED_CAP_FLAG_MARK_TURBINE(x) fd_uchar_set_bit(x, 1)      /* xxxxxxx1 */
#define FD_SHRED_CAP_FLAG_MARK_REPAIR(x)  fd_uchar_clear_bit(x, 1)    /* xxxxxxx0 */

#define FD_SHRED_CAP_FLAG_IS_TURBINE(x)   fd_uchar_extract_bit(x, 1)  /* xxxxxxx1 */
#define FD_SHRED_CAP_FLAG_IS_REPAIR(x)    !fd_uchar_extract_bit(x, 1) /* xxxxxxx0 */

// TODO: Lets properly document these on documentation day

int fd_shred_cap_mark_stable( fd_replay_t * replay, ulong slot );
int fd_shred_cap_archive( fd_replay_t * replay, fd_shred_t const * shred , uchar flags);
int fd_shred_cap_replay( const char * shred_pcap, fd_replay_t * replay );

#endif
