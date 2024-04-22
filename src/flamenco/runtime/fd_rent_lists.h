#ifndef HEADER_fd_src_flamenco_runtime_fd_rent_lists_h
#define HEADER_fd_src_flamenco_runtime_fd_rent_lists_h

/* fd_rent_lists.h provides APIs for managing rent partitions.  Rent
   partitions are sorted buckets containing the addresses of rent
   paying accounts.  Due to be removed when rent collection is
   disabled on Solana mainnet. */

#include "../fd_flamenco_base.h"

static inline ulong
fd_rent_partition_width( ulong slots_per_epoch ) {
  if( FD_UNLIKELY( slots_per_epoch==1UL ) ) return ULONG_MAX;
  return (ULONG_MAX - slots_per_epoch + 1UL) / slots_per_epoch + 1UL;
}

/* fd_rent_key_to_partition returns the partition index that a pubkey
   falls into.  Returns ULONG_MAX if this key is not part of any
   partition.  Loosely corresponds to Bank::partition_from_pubkey @*/

static inline ulong
fd_rent_key_to_partition( ulong key,
                          ulong part_width,
                          ulong part_cnt ) {

  if( part_cnt==1UL ) return 0UL;
  if( key==0UL      ) return 0UL;

  ulong  part = key / part_width;
         part = fd_ulong_if( part>=part_cnt, part_cnt-1UL, part );
  return part;
}

/* fd_rent_partition_to_key returns the lower bound (inclusive) of the
   pubkey range that this rent partition spans.  Loosely corresponds to
   Bank::pubkey_range_from_partition.  if opt_last_key!=NULL then
   *opt_last_key is the last key of this partition.  This is not
   necessarily (return_value + part_width). */

static inline ulong
fd_rent_partition_to_key( ulong   partition_idx,
                          ulong   part_width,
                          ulong   part_cnt,
                          ulong * opt_last_key ) {

  ulong key0;
  ulong key1;

  if( part_cnt<=1UL ) {
    key0 = 0UL;
    key1 = ULONG_MAX;
  } else {
    key0 = partition_idx * part_width;
    key1 = fd_ulong_if( partition_idx==part_cnt-1UL,
                        ULONG_MAX,
                        key0 + part_width - 1UL );
  }

  if( opt_last_key ) *opt_last_key = key1;
  return key0;
}

#endif /* HEADER_fd_src_flamenco_runtime_fd_rent_lists_h */
