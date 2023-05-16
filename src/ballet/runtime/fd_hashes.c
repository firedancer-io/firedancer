#include "fd_hashes.h"
#include "../blake3/fd_blake3.h"
#include "../sha256/fd_sha256.h"
#include <assert.h>
#include <stdio.h>
#include "../base58/fd_base58.h"
#include "fd_runtime.h"

#define SORT_NAME sort_pubkey_hash_pair
#define SORT_KEY_T fd_pubkey_hash_pair_t
#define SORT_BEFORE(a,b) ((memcmp(&a, &b, 32) < 0))
#include "../../util/tmpl/fd_sort.c"

#define FD_ACCOUNT_DELTAS_MERKLE_FANOUT (16UL)
#define FD_ACCOUNT_DELTAS_MAX_MERKLE_HEIGHT (16UL)

void 
fd_hash_account_deltas(fd_global_ctx_t *global, fd_pubkey_hash_pair_t * pairs, ulong pairs_len, fd_hash_t * hash ) {
  fd_sha256_t shas[FD_ACCOUNT_DELTAS_MAX_MERKLE_HEIGHT];
  uchar num_hashes[FD_ACCOUNT_DELTAS_MAX_MERKLE_HEIGHT+1];

  // Init the number of hashes 
  fd_memset( num_hashes, 0, sizeof(num_hashes) );

  sort_pubkey_hash_pair_inplace( pairs, pairs_len );
  for( ulong j = 0; j < FD_ACCOUNT_DELTAS_MAX_MERKLE_HEIGHT; ++j ) {
    fd_sha256_init( &shas[j] );
  }

  if( pairs_len == 0 ) {
    fd_sha256_fini( &shas[0], hash->hash );
    if (FD_UNLIKELY(global->log_level > 5)) {
      FD_LOG_NOTICE(( "M"
        "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT,
        FD_LOG_HEX16_FMT_ARGS(     hash->hash    ), FD_LOG_HEX16_FMT_ARGS(     hash->hash+16 ))); 
    }
    return;
  }

  if (FD_UNLIKELY(global->log_level > 2)) 
    FD_LOG_NOTICE(( "W %ld", pairs_len));

  for( ulong i = 0; i < pairs_len; ++i ) {

    if (FD_UNLIKELY(global->log_level > 2)) {
      char encoded_pubkey[50];
      fd_base58_encode_32((uchar *) pairs[i].pubkey.key, 0, encoded_pubkey);

      char encoded_hash[50];
      fd_base58_encode_32((uchar *) pairs[i].hash.hash, 0, encoded_hash);
      FD_LOG_NOTICE(( "X { \"key\":%ld, \"pubkey\":\"%s\", \"hash\":\"%s\" },", i, encoded_pubkey, encoded_hash));
    }

    fd_sha256_append( &shas[0] , (uchar const *) pairs[i].hash.hash, sizeof( fd_hash_t ) );
    num_hashes[0]++;
    
    for( ulong j = 0; j < FD_ACCOUNT_DELTAS_MAX_MERKLE_HEIGHT; ++j ) {
      if (FD_UNLIKELY(global->log_level > 5)) { 
        FD_LOG_NOTICE(( "Z %lu %lu %lu", i, j, shas[j].buf_used ));
      }
      if (num_hashes[j] == FD_ACCOUNT_DELTAS_MERKLE_FANOUT) {
        if (FD_UNLIKELY(global->log_level > 5)) { 
          FD_LOG_NOTICE(( "Y %lu %lu %u %u", i, j, num_hashes[j], num_hashes[j+1] ));
        }
        num_hashes[j] = 0;
        num_hashes[j+1]++;
        fd_hash_t sub_hash;
        fd_sha256_fini( &shas[j], &sub_hash );
        fd_sha256_init( &shas[j] );
        if (FD_UNLIKELY(global->log_level > 5)) { 
          char encoded_hash[50];
          fd_base58_encode_32((uchar *) sub_hash.hash, 0, encoded_hash);
          FD_LOG_NOTICE(( "V %lu %lu %s", i, j, encoded_hash ));
        }
        fd_sha256_append( &shas[j+1], (uchar const *) sub_hash.hash, sizeof( fd_hash_t ) );
      } else {
        break;
      }
    }
  }

  // TODO: use CZT on pairs_len
  ulong height = 0;
  for( long i = FD_ACCOUNT_DELTAS_MAX_MERKLE_HEIGHT-1; i >= 0; --i ) {
    if( num_hashes[i] != 0 ) {
      height = (ulong) i + 1;
      break;
    }
  }

  for( ulong i = 0; i < height; ++i ) {
#ifdef _VERBOSE    
    FD_LOG_NOTICE(( "S %lu %u", i, num_hashes[i] ));
#endif
    if( num_hashes[i]==0 ) {
      continue;
    }
    // At level i, finalize and append to i + 1
    //fd_hash_t sub_hash;
    fd_sha256_fini( &shas[i], hash );
#ifdef _VERBOSE    
    FD_LOG_NOTICE(( "Q (%lu)"
      "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT,
      i,
      FD_LOG_HEX16_FMT_ARGS(     hash->hash    ), FD_LOG_HEX16_FMT_ARGS(     hash->hash+16 ))); 
#endif
    num_hashes[i] = 0;
    num_hashes[i+1]++;
      
    if (i == (height-1)) {
      ulong tot_num_hashes = 0;
      for (ulong k = 0; k < FD_ACCOUNT_DELTAS_MAX_MERKLE_HEIGHT; ++k ) {
        tot_num_hashes += num_hashes[k];
      }

      assert(tot_num_hashes == 1);
#ifdef _VERBOSE    
      FD_LOG_NOTICE(( "M"
        "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT,
        FD_LOG_HEX16_FMT_ARGS(     hash->hash    ), FD_LOG_HEX16_FMT_ARGS(     hash->hash+16 ))); 
#endif
      return;
    }
    fd_sha256_append( &shas[i+1], (uchar const *) hash->hash, sizeof( fd_hash_t ) );
  
    // There is now one more hash at level i+1

    // check, have we filled this level and ones above it.
    for( ulong j = i+1; j < height; ++j ) {
      // if the level is full, finalize and push into next level.
      if (num_hashes[j] == FD_ACCOUNT_DELTAS_MERKLE_FANOUT) {
        num_hashes[j] = 0;
        num_hashes[j+1]++;
        fd_hash_t sub_hash;
        fd_sha256_fini( &shas[j], &sub_hash );
        if (FD_UNLIKELY(global->log_level > 5)) { 
          char encoded_hash[50];
          fd_base58_encode_32((uchar *) sub_hash.hash, 0, encoded_hash);
          FD_LOG_NOTICE(( "L %lu %lu %s", i, j, encoded_hash ));
        }
        fd_sha256_append( &shas[j+1], (uchar const *) sub_hash.hash, sizeof( fd_hash_t ) );
      }
    }
  }

  // If the level at the `height' was rolled into, do something about it

}

void
fd_hash_bank( fd_global_ctx_t *global, fd_hash_t * hash ) {
  global->prev_banks_hash = global->banks_hash;

  fd_hash_account_deltas( global, global->acc_mgr->keys.elems, global->acc_mgr->keys.cnt, &global->account_delta_hash );

  fd_sha256_t sha;
  fd_sha256_init( &sha );
  fd_sha256_append( &sha, (uchar const *) global->banks_hash.hash, sizeof( fd_hash_t ) );
  fd_sha256_append( &sha, (uchar const *) global->account_delta_hash.hash, sizeof( fd_hash_t  ) );
  fd_sha256_append( &sha, (uchar const *) &global->signature_cnt, sizeof( ulong ) );
  fd_sha256_append( &sha, (uchar const *) global->block_hash, sizeof( fd_hash_t ) );

  fd_sha256_fini( &sha, hash->hash );

  if (global->log_level > 0) {
    char encoded_hash[50];
    fd_base58_encode_32((uchar *) hash->hash, 0, encoded_hash);

    char encoded_parent[50];
    fd_base58_encode_32((uchar *) global->prev_banks_hash.hash, 0, encoded_parent);

    char encoded_account_delta[50];
    fd_base58_encode_32((uchar *) global->account_delta_hash.hash, 0, encoded_account_delta);

    char encoded_last_block_hash[50];
    fd_base58_encode_32((uchar *) global->block_hash, 0, encoded_last_block_hash);

    FD_LOG_NOTICE(( "bank_hash slot: %lu,  hash: %s,  parent_hash: %s,  accounts_delta: %s,  signature_count: %ld,  last_blockhash: %s",
        global->bank.solana_bank.slot, encoded_hash, encoded_parent, encoded_account_delta, global->signature_cnt, encoded_last_block_hash));
  }
}

void
fd_hash_meta( fd_account_meta_t const * m, ulong slot, fd_pubkey_t const * pubkey, uchar *data, fd_hash_t * hash ) {
  if( m->info.lamports==0 ) {
    fd_memset(hash->hash, 0, sizeof(fd_hash_t));
    return;
  }

  fd_blake3_t sha;
  fd_blake3_init( &sha );
  fd_blake3_append( &sha, (uchar const *) &m->info.lamports, sizeof( ulong ) );
  // TODO: There is a feature flag where slot is gonna get removed from the hash...
  fd_blake3_append( &sha, (uchar const *) &slot, sizeof( ulong ) );
  fd_blake3_append( &sha, (uchar const *) &m->info.rent_epoch, sizeof( ulong ) );
  // TODO: convince solana that this should effectively be
  //   fd_blake3_append( &sha, hash_of(data, m->dlen) );
  // instead of
  fd_blake3_append( &sha, (uchar const *) data, m->dlen );
  //  This way,  if the data does not change, you can recompute the hash of
  //  the account without having to haul all the data in.  ie, sending 1 lamport 
  //  to a 10m account has exactly the same network cost as sending 1 lamport to
  //  a 100 byte account...

  uchar executable = m->info.executable & 0x1;
  fd_blake3_append( &sha, (uchar const *) &executable, sizeof( uchar ));

  fd_blake3_append( &sha, (uchar const *) m->info.owner, 32 );
  fd_blake3_append( &sha, (uchar const *) pubkey->key, 32 );

  fd_blake3_fini( &sha, hash->hash );
}
