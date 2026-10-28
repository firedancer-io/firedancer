#ifndef HEADER_fd_src_discof_backtest_fd_shredcap_trim_h
#define HEADER_fd_src_discof_backtest_fd_shredcap_trim_h

/* fd_shredcap_trim.h provides an API that copies the frames of a range
   of slots from one shredcap file into a new one. */

#include "../../util/fd_util_base.h"

/* fd_shredcap_trim_stats_t describes what fd_shredcap_trim saw and
   wrote: the first slot with shreds in the input (ULONG_MAX when none
   was read), the highest slot written, and the shreds and bank hash
   records written. */

struct fd_shredcap_trim_stats {
  ulong first_slot;
  ulong last_slot;
  ulong shred_cnt;
  ulong bank_hash_cnt;
};
typedef struct fd_shredcap_trim_stats fd_shredcap_trim_stats_t;

FD_PROTOTYPES_BEGIN

/* fd_shredcap_trim writes the frames of slots start_slot to end_slot
   from the shredcap at in_path to a new zstd compressed shredcap at
   out_path.  The input may be plain or zstd compressed.  It must be
   laid out as blockstore2shredcap writes it: shreds in IPv4 frames,
   slots in increasing order, and each slot's records after its shreds.
   Reading stops at the first shred after end_slot.  Fills stats.
   Returns 0 on success.  Returns -1 and logs a warning when the input
   is not a pcapng shredcap, when start_slot has no shreds or no root
   record, when a slot in the range has shreds but no bank hash record,
   or when a shred frame is invalid.  Aborts when a file cannot be
   opened or written. */

int
fd_shredcap_trim( char const *               in_path,
                  char const *               out_path,
                  ulong                      start_slot,
                  ulong                      end_slot,
                  fd_shredcap_trim_stats_t * stats );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_backtest_fd_shredcap_trim_h */
