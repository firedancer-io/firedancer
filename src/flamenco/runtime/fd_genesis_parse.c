#include "fd_genesis_parse.h"
#include "fd_runtime_const.h"
#include "../../util/bits/fd_bits.h"

fd_genesis_t *
fd_genesis_parse( fd_genesis_t * genesis,
                  uchar const *  bin,
                  ulong          bin_sz ) {
  /* Zero out top part of descriptor which is sufficient to fully
     initialize fd_genesis_t (assuming no struct reordering). */
  memset( genesis, 0, offsetof(fd_genesis_t, builtin) );

  uchar const * _payload    = bin;
  ulong const   _payload_sz = bin_sz;
  ulong         _i          = 0UL;

# define CHECK( cond )   { if( FD_UNLIKELY( !(cond) ) ) { return NULL; } }
# define CHECK_LEFT( n ) CHECK( (n)<=(_payload_sz-_i) )
# define INC( n )        (_i += (ulong)(n))
# define CUR_OFFSET      ((ushort)_i)
# define CURSOR          (_payload+_i)

  CHECK_LEFT( 8UL ); genesis->creation_time = FD_LOAD( ulong, CURSOR ); INC( 8UL );

  CHECK_LEFT( 8UL ); genesis->account_cnt = FD_LOAD( ulong, CURSOR ); INC( 8UL );
  if( FD_UNLIKELY( genesis->account_cnt>FD_GENESIS_ACCOUNT_MAX_COUNT ) ) {
    FD_LOG_WARNING(( "genesis account count %lu exceeds max %lu (increase FD_GENESIS_ACCOUNT_MAX_COUNT?)", genesis->account_cnt, FD_GENESIS_ACCOUNT_MAX_COUNT ));
    return NULL;
  }
  for( ulong i=0UL; i<genesis->account_cnt; i++ ) {
    fd_genesis_account_off_t * account = &genesis->account[ i ];

    account->pubkey_off = _i;
    CHECK_LEFT( 32UL );                                            INC( 32UL ); /* pubkey */
    CHECK_LEFT(  8UL );                                            INC(  8UL ); /* lamports */
    CHECK_LEFT(  8UL ); ulong data_len = FD_LOAD( ulong, CURSOR ); INC(  8UL );
    if( FD_UNLIKELY( data_len>FD_RUNTIME_ACC_SZ_MAX ) ) {
      FD_LOG_WARNING(( "genesis builtin account data length %lu exceeds max size %lu", data_len, FD_RUNTIME_ACC_SZ_MAX ));
      return NULL;
    }
    CHECK_LEFT( data_len ); INC( data_len ); /* data */

    account->owner_off = _i;
    CHECK_LEFT( 32UL ); INC( 32UL ); /* owner */
    CHECK_LEFT(  1UL ); INC(  1UL ); /* executable */
    CHECK_LEFT(  8UL ); INC(  8UL ); /* rent epoch */
  }

  CHECK_LEFT( 8UL ); genesis->builtin_cnt = FD_LOAD( ulong, CURSOR ); INC( 8UL );
  if( FD_UNLIKELY( genesis->builtin_cnt>FD_GENESIS_BUILTIN_MAX_COUNT ) ) {
    FD_LOG_WARNING(( "genesis builtin count %lu exceeds max %lu", genesis->builtin_cnt, FD_GENESIS_BUILTIN_MAX_COUNT ));
    return NULL;
  }
  for( ulong i=0UL; i<genesis->builtin_cnt; i++ ) {
    fd_genesis_builtin_off_t * account = &genesis->builtin[ i ];

    account->data_len_off = _i;
    CHECK_LEFT( 8UL ); ulong data_len = FD_LOAD( ulong, CURSOR ); INC( 8UL );
    if( FD_UNLIKELY( data_len>FD_RUNTIME_ACC_SZ_MAX ) ) {
      FD_LOG_WARNING(( "genesis builtin account data length %lu exceeds supported max size %lu", data_len, FD_RUNTIME_ACC_SZ_MAX ));
      return NULL;
    }
    CHECK_LEFT( data_len ); INC( data_len ); /* data */

    account->pubkey_off = _i;
    CHECK_LEFT( 32UL ); INC( 32UL ); /* pubkey */
  }

  CHECK_LEFT( 8UL ); ulong rewards_len = FD_LOAD( ulong, CURSOR ); INC( 8UL );
  for( ulong i=0UL; i<rewards_len; i++ ) {
    CHECK_LEFT( 32UL );                                        INC( 32UL ); /* pubkey */
    CHECK_LEFT(  8UL );                                        INC(  8UL ); /* lamports */
    CHECK_LEFT(  8UL ); ulong dlen = FD_LOAD( ulong, CURSOR ); INC(  8UL ); /* dlen */
    CHECK_LEFT( dlen );                                        INC( dlen ); /* data */
    CHECK_LEFT( 32UL );                                        INC( 32UL ); /* owner */
    CHECK_LEFT(  1UL );                                        INC(  1UL ); /* executable */
    CHECK_LEFT(  8UL );                                        INC(  8UL ); /* rent epoch */
  }

  CHECK_LEFT( 8UL ); genesis->poh.ticks_per_slot = FD_LOAD( ulong, CURSOR ); INC( 8UL );

  CHECK_LEFT( sizeof(ulong) ); INC( sizeof(ulong) ); /* unused */

  CHECK_LEFT( 8UL ); genesis->poh.tick_duration_secs = FD_LOAD( ulong, CURSOR ); INC( 8UL );
  CHECK_LEFT( 4UL ); genesis->poh.tick_duration_ns   = FD_LOAD( uint,  CURSOR ); INC( 4UL );
  CHECK_LEFT( 1UL ); int has_target_tick_count       = FD_LOAD( uchar, CURSOR ); INC( 1UL );
  if( has_target_tick_count ) { CHECK_LEFT( 8UL ); genesis->poh.target_tick_count = FD_LOAD( ulong, CURSOR ); INC( 8UL ); }
  else                                            genesis->poh.target_tick_count = 0UL;
  CHECK_LEFT( 1UL ); int has_hashes_per_tick       = FD_LOAD( uchar, CURSOR ); INC( 1UL );
  if( has_hashes_per_tick ) { CHECK_LEFT( 8UL ); genesis->poh.hashes_per_tick = FD_LOAD( ulong, CURSOR ); INC( 8UL ); }
  else                                          genesis->poh.hashes_per_tick = 0UL;

  CHECK_LEFT( sizeof(ulong) ); INC( sizeof(ulong) ); /* backward compat v23 */

  CHECK_LEFT( 8UL ); genesis->fee_rate_governor.target_lamports_per_signature = FD_LOAD( ulong, CURSOR ); INC( 8UL );
  CHECK_LEFT( 8UL ); genesis->fee_rate_governor.target_signatures_per_slot    = FD_LOAD( ulong, CURSOR ); INC( 8UL );
  CHECK_LEFT( 8UL ); genesis->fee_rate_governor.min_lamports_per_signature    = FD_LOAD( ulong, CURSOR ); INC( 8UL );
  CHECK_LEFT( 8UL ); genesis->fee_rate_governor.max_lamports_per_signature    = FD_LOAD( ulong, CURSOR ); INC( 8UL );
  CHECK_LEFT( 1UL ); genesis->fee_rate_governor.burn_percent                  = FD_LOAD( uchar, CURSOR ); INC( 1UL );

  CHECK_LEFT( 8UL ); genesis->rent.lamports_per_uint8_year = FD_LOAD( ulong, CURSOR );  INC( 8UL );
  CHECK_LEFT( 8UL ); genesis->rent.exemption_threshold     = FD_LOAD( double, CURSOR ); INC( 8UL );
  CHECK_LEFT( 1UL ); genesis->rent.burn_percent            = FD_LOAD( uchar, CURSOR );  INC( 1UL );

  CHECK_LEFT( 8UL ); genesis->inflation.initial         = FD_LOAD( double, CURSOR ); INC( 8UL );
  CHECK_LEFT( 8UL ); genesis->inflation.terminal        = FD_LOAD( double, CURSOR ); INC( 8UL );
  CHECK_LEFT( 8UL ); genesis->inflation.taper           = FD_LOAD( double, CURSOR ); INC( 8UL );
  CHECK_LEFT( 8UL ); genesis->inflation.foundation      = FD_LOAD( double, CURSOR ); INC( 8UL );
  CHECK_LEFT( 8UL ); genesis->inflation.foundation_term = FD_LOAD( double, CURSOR ); INC( 8UL );
  CHECK_LEFT( 8UL );                                                                 INC( 8UL ); /* unused */

  CHECK_LEFT( 8UL ); genesis->epoch_schedule.slots_per_epoch             = FD_LOAD( ulong, CURSOR ); INC( 8UL );
  CHECK_LEFT( 8UL ); genesis->epoch_schedule.leader_schedule_slot_offset = FD_LOAD( ulong, CURSOR ); INC( 8UL );
  CHECK_LEFT( 1UL ); genesis->epoch_schedule.warmup                      = FD_LOAD( uchar, CURSOR ); INC( 1UL );
  CHECK_LEFT( 8UL ); genesis->epoch_schedule.first_normal_epoch          = FD_LOAD( ulong, CURSOR ); INC( 8UL );
  CHECK_LEFT( 8UL ); genesis->epoch_schedule.first_normal_slot           = FD_LOAD( ulong, CURSOR ); INC( 8UL );

  CHECK_LEFT( 4UL ); genesis->cluster_type = FD_LOAD( uint, CURSOR ); INC( 4UL );

# undef CHECK
# undef CHECK_LEFT
# undef INC
# undef CUR_OFFSET
# undef CURSOR

  if( _i!=_payload_sz ) {
    FD_LOG_WARNING(( "genesis blob has %lu trailing unrecognized bytes. Perhaps this Firedancer build is too old?", _payload_sz-_i ));
    return NULL;
  }

  return genesis;
}

fd_genesis_account_t *
fd_genesis_account( fd_genesis_t const *   genesis,
                    uchar const *          bin,
                    fd_genesis_account_t * out,
                    ulong                  idx ) {
  fd_genesis_account_off_t const * off = &genesis->account[ idx ];
  out->pubkey        = FD_LOAD( fd_pubkey_t, bin+off->pubkey_off      );
  out->meta.lamports = FD_LOAD( ulong,       bin+off->pubkey_off+32UL );
  out->meta.dlen     = (uint)FD_LOAD( ulong, bin+off->pubkey_off+40UL );
  out->data          = bin+off->pubkey_off+48UL;
  memcpy( out->meta.owner, bin+off->owner_off, sizeof(fd_pubkey_t) );
  out->meta.executable = !!bin[ off->owner_off+32UL ];
  out->meta.slot       = 0UL;
  return out;
}

fd_genesis_builtin_t *
fd_genesis_builtin( fd_genesis_t const *   genesis,
                    uchar const *          bin,
                    fd_genesis_builtin_t * out,
                    ulong                  idx ) {
  fd_genesis_builtin_off_t const * off = &genesis->builtin[ idx ];
  out->pubkey = FD_LOAD( fd_pubkey_t, bin+off->pubkey_off   );
  out->dlen   = FD_LOAD( ulong,       bin+off->data_len_off );
  out->data   = bin+off->data_len_off+8UL;
  return out;
}
