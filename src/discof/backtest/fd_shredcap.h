#ifndef HEADER_fd_src_discof_backtest_fd_shredcap_h
#define HEADER_fd_src_discof_backtest_fd_shredcap_h

/* fd_shredcap.h provides C definitions for shredcap v0.2 file format
   bits. */

#include "../../util/net/fd_pcapng.h"

#define FD_SHREDCAP_V0_IFNAME "shredcap0"

#define FD_SHREDCAP_TYPE_BANK_HASH_V0 (0x1u)
#define FD_SHREDCAP_TYPE_ROOT_SLOT_V0 (0x2u)

struct __attribute__((packed)) fd_shredcap_bank_hash_v0 {
  ulong slot;
  uchar bank_hash[32];
  ulong data_shred_cnt;
};
typedef struct fd_shredcap_bank_hash_v0 fd_shredcap_bank_hash_v0_t;

struct __attribute__((packed)) fd_shredcap_root_slot_v0 {
  ulong slot;
};
typedef struct fd_shredcap_root_slot_v0 fd_shredcap_root_slot_v0_t;

/* fd_shredcap_fwrite_hdr writes the pcapng section header and the two
   interfaces of a shredcap: IPv4 "lo" (index 0) for the shreds and
   USER0 "shredcap0" (index 1) for the records.  Returns 1 on success
   and 0 on failure, like fwrite. */

static inline ulong
fd_shredcap_fwrite_hdr( void * file ) {
  fd_pcapng_shb_opts_t shb_opts  = {0};
  fd_pcapng_idb_opts_t net_opts  = { .name="lo", .ip4_addr={ 127, 0, 0, 1 } };
  fd_pcapng_idb_opts_t meta_opts = { .name=FD_SHREDCAP_V0_IFNAME };
  fd_pcapng_shb_defaults( &shb_opts );
  ulong ok = fd_pcapng_fwrite_shb( &shb_opts, file );
  ok &= fd_pcapng_fwrite_idb( FD_PCAPNG_LINKTYPE_IPV4,  &net_opts,  file );
  ok &= fd_pcapng_fwrite_idb( FD_PCAPNG_LINKTYPE_USER0, &meta_opts, file );
  return ok;
}

#endif /* HEADER_fd_src_discof_backtest_fd_shredcap_h */
