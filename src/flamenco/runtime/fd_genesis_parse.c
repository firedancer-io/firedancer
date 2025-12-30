#include "fd_genesis_parse.h"
#include "fd_runtime_const.h"
#include "../../util/bits/fd_bits.h"

/* Adapted from fd_txn_parse.c */
#define CHECK_INIT( payload, payload_sz, offset )   \
  uchar const * _payload        = (payload);        \
  ulong const   _payload_sz     = (payload_sz);     \
  ulong const   _offset         = (offset);         \
  ulong         _i              = (offset);         \
  (void)        _payload;                           \
  (void)        _offset;                            \

#define CHECK( cond ) do {              \
  if( FD_UNLIKELY( !(cond) ) ) {        \
    return 0;                           \
  }                                     \
} while( 0 )

#define CHECK_LEFT( n ) CHECK( (n)<=(_payload_sz-_i) )

#define INC( n )   (_i += (ulong)(n))
#define CUR_OFFSET ((ushort)_i)
#define CURSOR     (_payload+_i)


fd_genesis_t *
fd_genesis_parse( void *        genesis_mem,
                  uchar const * bin,
                  ulong         bin_sz ) {
  FD_SCRATCH_ALLOC_INIT( l, genesis_mem );
  fd_genesis_t * genesis = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_genesis_t), sizeof(fd_genesis_t) );

  CHECK_INIT( bin, bin_sz, 0U );

  CHECK_LEFT( 8U ); genesis->creation_time = FD_LOAD( ulong, CURSOR ); INC( 8U );

  CHECK_LEFT( 8U ); genesis->accounts_len  = FD_LOAD( ulong, CURSOR ); INC( 8U );
  if( FD_UNLIKELY( genesis->accounts_len>FD_GENESIS_ACCOUNT_MAX_COUNT ) ) {
    FD_LOG_WARNING(( "genesis accounts length %lu exceeds supported max count %lu", genesis->accounts_len, FD_GENESIS_ACCOUNT_MAX_COUNT ));
    return NULL;
  }
  for( ulong i=0UL; i<genesis->accounts_len; i++ ) {
    fd_genesis_account_t * account = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_genesis_account_t), sizeof(fd_genesis_account_t) );
    genesis->accounts_off[ i ] = (uint)((ulong)account-(ulong)genesis);
    if( FD_UNLIKELY( genesis->accounts_off[ i ] + sizeof(fd_genesis_account_t) > FD_GENESIS_MAX_MESSAGE_SIZE ) ) {
      FD_LOG_WARNING(( "genesis accounts offset %u exceeds supported max size %lu", genesis->accounts_off[ i ], FD_GENESIS_MAX_MESSAGE_SIZE ));
      return NULL;
    }
    CHECK_LEFT( 32U ); fd_memcpy( account->pubkey, CURSOR, 32U );           INC( 32U );
    CHECK_LEFT( 8U );  account->meta.lamports = FD_LOAD( ulong, CURSOR );   INC( 8U );
    CHECK_LEFT( 8U );  account->meta.dlen = (uint)FD_LOAD( ulong, CURSOR ); INC( 8U );
    if( FD_UNLIKELY( account->meta.dlen>FD_RUNTIME_ACC_SZ_MAX ) ) {
      FD_LOG_WARNING(( "genesis builtin account data length %u exceeds supported max size %lu", account->meta.dlen, FD_RUNTIME_ACC_SZ_MAX ));
      return NULL;
    }
    if( FD_UNLIKELY( genesis->accounts_off[ i ] + sizeof(fd_genesis_account_t) + account->meta.dlen > FD_GENESIS_MAX_MESSAGE_SIZE ) ) {
      FD_LOG_WARNING(( "genesis builtin account data length %lu exceeds supported max size %lu", genesis->accounts_off[ i ] + sizeof(fd_genesis_account_t) + account->meta.dlen, FD_GENESIS_MAX_MESSAGE_SIZE ));
      return NULL;
    }
    CHECK_LEFT( account->meta.dlen );
    uchar * data = FD_SCRATCH_ALLOC_APPEND( l, alignof(uchar), account->meta.dlen );
    fd_memcpy( data, CURSOR, account->meta.dlen );                          INC( account->meta.dlen );
    CHECK_LEFT( 32U ); fd_memcpy( account->meta.owner, CURSOR, 32U );       INC( 32U );
    CHECK_LEFT( 1U );  account->meta.executable = FD_LOAD( uchar, CURSOR ); INC( 1U );
    CHECK_LEFT( 8U );                                                       INC( 8U ); /* don't care about rent epoch */
  }

  CHECK_LEFT( 8U ); genesis->builtin_len  = FD_LOAD( ulong, CURSOR ); INC( 8U );
  if( FD_UNLIKELY( genesis->builtin_len>FD_GENESIS_BUILTIN_MAX_COUNT ) ) {
    FD_LOG_WARNING(( "genesis builtin length %lu exceeds supported max count %lu", genesis->builtin_len, FD_GENESIS_BUILTIN_MAX_COUNT ));
    return NULL;
  }
  for( ulong i=0UL; i<genesis->builtin_len; i++ ) {
    /* The built in accounts are laid out with the data first followed
       by the pubkey. */
    fd_genesis_builtin_t * account = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_genesis_builtin_t), sizeof(fd_genesis_builtin_t) );
    genesis->builtin_off[ i ] = (uint)((ulong)account-(ulong)genesis);
    if( FD_UNLIKELY( genesis->builtin_off[ i ] + sizeof(fd_genesis_builtin_t) > FD_GENESIS_MAX_MESSAGE_SIZE ) ) {
      FD_LOG_WARNING(( "genesis builtin offset %lu exceeds supported max size %lu", genesis->builtin_off[ i ] + sizeof(fd_genesis_builtin_t), FD_GENESIS_MAX_MESSAGE_SIZE ));
      return NULL;
    }
    CHECK_LEFT( 8U );  account->data_len = FD_LOAD( ulong, CURSOR ); INC( 8U );
    if( FD_UNLIKELY( account->data_len>FD_RUNTIME_ACC_SZ_MAX ) ) {
      FD_LOG_WARNING(( "genesis builtin account data length %lu exceeds supported max size %lu", account->data_len, FD_RUNTIME_ACC_SZ_MAX ));
      return NULL;
    }
    if( FD_UNLIKELY( genesis->builtin_off[ i ] + sizeof(fd_genesis_builtin_t) + account->data_len > FD_GENESIS_MAX_MESSAGE_SIZE ) ) {
      FD_LOG_WARNING(( "genesis builtin account data length %lu exceeds supported max size %lu", genesis->builtin_off[ i ] + sizeof(fd_genesis_builtin_t) + account->data_len, FD_GENESIS_MAX_MESSAGE_SIZE ));
      return NULL;
    }
    CHECK_LEFT( account->data_len );
    uchar * data = FD_SCRATCH_ALLOC_APPEND( l, alignof(uchar), account->data_len );
    fd_memcpy( data, CURSOR, account->data_len ); INC( account->data_len );

    CHECK_LEFT( 32U ); fd_memcpy( account->pubkey, CURSOR, 32U ); INC( 32U );
  }

  genesis->total_sz = (ulong)(FD_SCRATCH_ALLOC_FINI( l, alignof(fd_genesis_t) )) - (ulong)genesis_mem;

  CHECK_LEFT( 8U ); ulong rewards_len = FD_LOAD( ulong, CURSOR ); INC( 8U );
  for( ulong i=0UL; i<rewards_len; i++ ) {
    CHECK_LEFT( 32U );                                       INC( 32U ); /* pubkey */
    CHECK_LEFT( 8U );                                        INC( 8U ); /* lamports */
    CHECK_LEFT( 8U ); ulong dlen = FD_LOAD( ulong, CURSOR ); INC( 8U ); /* dlen */
    CHECK_LEFT( dlen );                                      INC( dlen ); /* data */
    CHECK_LEFT( 32U );                                       INC( 32U ); /* owner */
    CHECK_LEFT( 1U );                                        INC( 1U ); /* executable */
    CHECK_LEFT( 8U );                                        INC( 8U ); /* rent epoch */
  }

  CHECK_LEFT( 8U ); genesis->poh.ticks_per_slot = FD_LOAD( ulong, CURSOR ); INC( 8U );

  CHECK_LEFT( sizeof(ulong) ); INC( sizeof(ulong) ); /* unused */

  CHECK_LEFT( 8U ); genesis->poh.tick_duration_secs = FD_LOAD( ulong, CURSOR ); INC( 8U );
  CHECK_LEFT( 4U ); genesis->poh.tick_duration_ns   = FD_LOAD( uint,  CURSOR ); INC( 4U );
  CHECK_LEFT( 1U ); int has_target_tick_count       = FD_LOAD( uchar, CURSOR ); INC( 1U );
  if( has_target_tick_count ) { CHECK_LEFT( 8U ); genesis->poh.target_tick_count = FD_LOAD( ulong, CURSOR ); INC( 8U ); }
  else                                            genesis->poh.target_tick_count = 0UL;
  CHECK_LEFT( 1U ); int has_hashes_per_tick       = FD_LOAD( uchar, CURSOR ); INC( 1U );
  if( has_hashes_per_tick ) { CHECK_LEFT( 8U ); genesis->poh.hashes_per_tick = FD_LOAD( ulong, CURSOR ); INC( 8U ); }
  else                                          genesis->poh.hashes_per_tick = 0UL;

  CHECK_LEFT( sizeof(ulong) ); INC( sizeof(ulong) ); /* bakcward compat v23 */

  CHECK_LEFT( 8U ); genesis->fee_rate_governor.target_lamports_per_signature = FD_LOAD( ulong, CURSOR ); INC( 8U );
  CHECK_LEFT( 8U ); genesis->fee_rate_governor.target_signatures_per_slot    = FD_LOAD( ulong, CURSOR ); INC( 8U );
  CHECK_LEFT( 8U ); genesis->fee_rate_governor.min_lamports_per_signature    = FD_LOAD( ulong, CURSOR ); INC( 8U );
  CHECK_LEFT( 8U ); genesis->fee_rate_governor.max_lamports_per_signature    = FD_LOAD( ulong, CURSOR ); INC( 8U );
  CHECK_LEFT( 1U ); genesis->fee_rate_governor.burn_percent                  = FD_LOAD( uchar, CURSOR ); INC( 1U );

  CHECK_LEFT( 8U ); genesis->rent.lamports_per_uint8_year = FD_LOAD( ulong, CURSOR );  INC( 8U );
  CHECK_LEFT( 8U ); genesis->rent.exemption_threshold     = FD_LOAD( double, CURSOR ); INC( 8U );
  CHECK_LEFT( 1U ); genesis->rent.burn_percent            = FD_LOAD( uchar, CURSOR );  INC( 1U );

  CHECK_LEFT( 8U ); genesis->inflation.initial         = FD_LOAD( double, CURSOR ); INC( 8U );
  CHECK_LEFT( 8U ); genesis->inflation.terminal        = FD_LOAD( double, CURSOR ); INC( 8U );
  CHECK_LEFT( 8U ); genesis->inflation.taper           = FD_LOAD( double, CURSOR ); INC( 8U );
  CHECK_LEFT( 8U ); genesis->inflation.foundation      = FD_LOAD( double, CURSOR ); INC( 8U );
  CHECK_LEFT( 8U ); genesis->inflation.foundation_term = FD_LOAD( double, CURSOR ); INC( 8U );
  CHECK_LEFT( 8U );                                                                 INC( 8U ); /* unused */

  CHECK_LEFT( 8U ); genesis->epoch_schedule.slots_per_epoch             = FD_LOAD( ulong, CURSOR ); INC( 8U );
  CHECK_LEFT( 8U ); genesis->epoch_schedule.leader_schedule_slot_offset = FD_LOAD( ulong, CURSOR ); INC( 8U );
  CHECK_LEFT( 1U ); genesis->epoch_schedule.warmup                      = FD_LOAD( uchar, CURSOR ); INC( 1U );
  CHECK_LEFT( 8U ); genesis->epoch_schedule.first_normal_epoch          = FD_LOAD( ulong, CURSOR ); INC( 8U );
  CHECK_LEFT( 8U ); genesis->epoch_schedule.first_normal_slot           = FD_LOAD( ulong, CURSOR ); INC( 8U );

  CHECK_LEFT( 4U ); genesis->cluster_type = FD_LOAD( uint, CURSOR ); INC( 4U );

  return genesis;
}
