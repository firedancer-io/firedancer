#include "fd_sysvar_base.h"
#include "fd_sysvar_recent_hashes.h"
#include "test_sysvar_cache_util.h"
#include "../fd_system_ids.h"

FD_IMPORT_BINARY( example_recent_hashes, "src/flamenco/runtime/sysvar/test_sysvar_recent_hashes.bin" );

static int
fd_mem_iszero8( uchar const * mem,
                ulong         sz ) {
  /* FIXME ... add a fast & tested "is memzero" API */
  ulong xor = 0UL;
  FD_TEST( fd_ulong_is_aligned( sz, sizeof(ulong) ) );
  for( ulong i=0UL; i<sz; i+=8UL ) xor ^= FD_LOAD( ulong, mem+i );
  return xor==0UL;
}

static void
test_sysvar_recent_hashes_bounds( void ) {
  FD_TEST( FD_SYSVAR_RECENT_HASHES_BINCODE_SZ==6008 );
}

static void
test_sysvar_recent_hashes_init( fd_wksp_t * wksp ) {
  test_sysvar_cache_env_t env[1];
  FD_TEST( test_sysvar_cache_env_create( env, wksp ) );
  FD_TEST( fd_sysvar_cache_recent_hashes_is_valid( env->sysvar_cache )==0 );

  /* Cannot create any sysvar without the rent sysvar */
  fd_rent_t const rent = {
    .lamports_per_uint8_year = 3480UL,
    .exemption_threshold     = 2.0,
    .burn_percent            = 100
  };
  fd_bank_rent_set( env->slot_ctx->bank, rent );

  /* Create an empty recent hashes sysvar */
  fd_sysvar_recent_hashes_init( env->slot_ctx );
  fd_sysvar_cache_restore( env->slot_ctx );
  FD_TEST( fd_sysvar_cache_recent_hashes_is_valid( env->sysvar_cache )==1 );
  {
    fd_bank_poh_set( env->slot_ctx->bank, (fd_hash_t){0} );
    ulong sz = 0UL;
    uchar const * data = fd_sysvar_cache_data_query( env->sysvar_cache, &fd_sysvar_recent_block_hashes_id, &sz );
    FD_TEST( data && sz==FD_SYSVAR_RECENT_HASHES_BINCODE_SZ );
    FD_TEST( FD_LOAD( ulong, data )==0UL ); /* zero blockhashes */
    FD_TEST( fd_mem_iszero8( data+8, FD_SYSVAR_RECENT_HASHES_BINCODE_SZ-8 ) );
  }

  test_sysvar_cache_env_destroy( env );
}

static void
test_sysvar_recent_hashes_update( fd_wksp_t * wksp ) {
  test_sysvar_cache_env_t env[1];
  FD_TEST( test_sysvar_cache_env_create( env, wksp ) );
  FD_TEST( fd_sysvar_cache_recent_hashes_is_valid( env->sysvar_cache )==0 );

  /* Cannot create any sysvar without the rent sysvar */
  fd_rent_t const rent = {
    .lamports_per_uint8_year = 3480UL,
    .exemption_threshold     = 2.0,
    .burn_percent            = 100
  };
  fd_bank_rent_set( env->slot_ctx->bank, rent );

  /* The recent blockhashes sysvar is tied to the blockhash queue */
  fd_blockhashes_t * blockhashes = fd_blockhashes_init( fd_bank_block_hash_queue_modify( env->slot_ctx->bank ), 0UL );
  FD_TEST( blockhashes );

  /* Register a new blockhash (creating the sysvar) */
  FD_TEST( fd_sysvar_cache_recent_hashes_is_valid( env->sysvar_cache )==0 );
  fd_hash_t poh = { .ul={ 0x110b8a330ecf93c2UL, 0xb709306fbd53c744, 0xda66f7127781dd72, 0UL } };
  fd_bank_poh_set( env->slot_ctx->bank, poh );
  fd_bank_lamports_per_signature_set( env->slot_ctx->bank, 1000UL );
  fd_sysvar_recent_hashes_update( env->slot_ctx );
  fd_sysvar_cache_restore( env->slot_ctx );
  FD_TEST( fd_sysvar_cache_recent_hashes_is_valid( env->sysvar_cache )==1 );
  {
    ulong sz = 0UL;
    uchar const * data = fd_sysvar_cache_data_query( env->sysvar_cache, &fd_sysvar_recent_block_hashes_id, &sz );
    FD_TEST( data && sz==FD_SYSVAR_RECENT_HASHES_BINCODE_SZ );
    FD_TEST( FD_LOAD( ulong, data )==1UL );
    FD_TEST( fd_hash_eq1( FD_LOAD( fd_hash_t, data+8 ), poh ) );
    FD_TEST( FD_LOAD( ulong, data+40 )==1000UL ); /* fee calculator */
    FD_TEST( fd_mem_iszero8( data+48, FD_SYSVAR_RECENT_HASHES_BINCODE_SZ-48 ) );
  }

  /* Keep adding hashes */
  for( ulong i=0UL; i<149UL; i++ ) {
    poh.ul[3] = i+1UL;
    fd_bank_poh_set( env->slot_ctx->bank, poh );
    fd_bank_lamports_per_signature_set( env->slot_ctx->bank, 1001UL+i );
    fd_sysvar_recent_hashes_update( env->slot_ctx );
    fd_sysvar_cache_restore( env->slot_ctx );

    ulong sz = 0UL;
    uchar const * data = fd_sysvar_cache_data_query( env->sysvar_cache, &fd_sysvar_recent_block_hashes_id, &sz );
    FD_TEST( data && sz==FD_SYSVAR_RECENT_HASHES_BINCODE_SZ );
    FD_TEST( FD_LOAD( ulong, data )==i+2 ); /* count */
  }

  /* Verify queue content */
  {
    ulong sz = 0UL;
    uchar const * data = fd_sysvar_cache_data_query( env->sysvar_cache, &fd_sysvar_recent_block_hashes_id, &sz );
    FD_TEST( data && sz==FD_SYSVAR_RECENT_HASHES_BINCODE_SZ );
    FD_TEST( FD_LOAD( ulong, data )==150 ); /* count */
    for( ulong i=0UL; i<150UL; i++ ) {
      uchar const *   entry = data+8 + i*40;
      fd_hash_t const hash  = FD_LOAD( fd_hash_t, entry    );
      ulong     const lps   = FD_LOAD( ulong,     entry+32 );
      ulong     const idx   = 149UL-i;
      FD_TEST( hash.ul[3]==idx        );
      FD_TEST( lps       ==1000UL+idx );

      fd_blockhash_info_t * info = fd_blockhash_deq_peek_index( blockhashes->d.deque, idx );
      FD_TEST( lps==info->fee_calculator.lamports_per_signature );
      FD_TEST( fd_hash_eq1( hash, info->hash ) );
      FD_TEST( fd_blockhashes_check_age( blockhashes, &hash, i )==1 );
    }
  }

  test_sysvar_cache_env_destroy( env );
}

static void
test_sysvar_recent_hashes( fd_wksp_t * wksp ) {
  test_sysvar_recent_hashes_bounds();
  test_sysvar_recent_hashes_init( wksp );
  test_sysvar_recent_hashes_update( wksp );
}
