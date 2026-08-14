#ifndef HEADER_fd_src_ballet_txn_fd_txn_v1_h
#define HEADER_fd_src_ballet_txn_fd_txn_v1_h

#include "../fd_ballet_base.h"

/* FD_TXN_V1_DEFAULT_HEAP_SZ: V1 transactions that do not explicitly
   set their requested heap size using the config mask
   use a default 32 KiB requested heap size as per SIMD 385. */
#define FD_TXN_V1_DEFAULT_HEAP_SZ (32UL*1024UL)

/* Max/min bounds and the allowed granularity for the requested heap
   size as per SIMD 385. */
#define FD_TXN_V1_MIN_HEAP_SZ      (32UL *1024UL)
#define FD_TXN_V1_MAX_HEAP_SZ      (256UL*1024UL)
#define FD_TXN_V1_HEAP_GRANULARITY (1024UL)

FD_PROTOTYPES_BEGIN

/* fd_txn_parse_v1_config decodes the four compute-budget fields
   V1 transactions specify using the given config mask and config
   values.

   config_mask is the transaction config mask. Only bits 0-4 will be
   set.

   config_values is a pointer to the start of the config values
   region.  This contains only the config values that the config mask
   indicates are present, packed in little-endian, in ascending bit
   order.

   The results of the parsing are written to the
   out_priority_fee_lamports, out_compute_unit_limit,
   out_loaded_accounts_data_sz_limit and out_heap_size fields.  If a
   field is not specified by the config mask the defaults as per
   SIMD 385 are used.

   https://github.com/anza-xyz/agave/blob/v4.2.0-beta.1/runtime-transaction/src/runtime_transaction/transaction_view.rs#L98-L107 */
static inline void
fd_txn_parse_v1_config( uint           config_mask,
                        uchar const *  config_values,
                        ulong *        out_priority_fee_lamports,
                        ulong *        out_compute_unit_limit,
                        ulong *        out_loaded_accounts_data_sz_limit,
                        ulong *        out_heap_size ) {

  /* Default values as per SIMD 385 */
  ulong priority_fee = 0UL;
  ulong cu_limit     = 0UL;
  ulong lads_limit   = 0UL;
  ulong heap         = FD_TXN_V1_DEFAULT_HEAP_SZ;

  uchar const * v = config_values;
  /* Priority fee is a ulong, the rest are uint */
  if(  config_mask    & 1U ) { priority_fee = FD_LOAD( ulong, v ); v += 8UL; }
  if( (config_mask>>2)& 1U ) { cu_limit     = FD_LOAD( uint,  v ); v += 4UL; }
  if( (config_mask>>3)& 1U ) { lads_limit   = FD_LOAD( uint,  v ); v += 4UL; }
  if( (config_mask>>4)& 1U ) { heap         = FD_LOAD( uint,  v );           }

  *out_priority_fee_lamports         = priority_fee;
  *out_compute_unit_limit            = cu_limit;
  *out_loaded_accounts_data_sz_limit = lads_limit;
  *out_heap_size                     = heap;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_txn_fd_txn_v1_h */
