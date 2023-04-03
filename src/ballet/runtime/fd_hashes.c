#include "fd_hashes.h"
#include "../blake3/fd_blake3.h"
#include "../sha256/fd_sha256.h"
#include <assert.h>

#define SORT_NAME sort_pubkey_hash_pair
#define SORT_KEY_T fd_pubkey_hash_pair_t
#define SORT_BEFORE(a,b) ((memcmp(&a, &b, 32) < 0))
#include "../../util/tmpl/fd_sort.c"

#define FD_ACCOUNT_DELTAS_MERKLE_FANOUT (16UL)
#define FD_ACCOUNT_DELTAS_MAX_MERKLE_HEIGHT (16UL)

void 
fd_hash_account_deltas( fd_pubkey_hash_pair_t * pairs, ulong pairs_len, FD_FN_UNUSED fd_hash_t * hash ) {
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
      FD_LOG_NOTICE(( "M"
        "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT,
        FD_LOG_HEX16_FMT_ARGS(     hash->hash    ), FD_LOG_HEX16_FMT_ARGS(     hash->hash+16 ))); 
    return;
  }

  for( ulong i = 0; i < pairs_len; ++i ) {
    
    for( ulong k = 0; k < 8; ++k ) {
      FD_LOG_NOTICE(( "X %lu %lu %u", i, k, num_hashes[k] ));
    }
    fd_sha256_append( &shas[0] , (uchar const *) pairs[i].hash.hash, sizeof( fd_hash_t ) );
    num_hashes[0]++;
    
    for( ulong j = 0; j < FD_ACCOUNT_DELTAS_MAX_MERKLE_HEIGHT; ++j ) {
      FD_LOG_NOTICE(( "Z %lu %lu %lu", i, j, shas[j].buf_used ));
      if (num_hashes[j] == FD_ACCOUNT_DELTAS_MERKLE_FANOUT) {
        FD_LOG_NOTICE(( "Y %lu %lu %u", i, j, num_hashes[j] ));
        num_hashes[j] = 0;
        num_hashes[j+1]++;
        fd_hash_t sub_hash;
        fd_sha256_fini( &shas[j], &sub_hash );
        fd_sha256_init( &shas[j] );
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
    FD_LOG_NOTICE(( "S %lu %u", i, num_hashes[i] ));
    // At level i, finalize and append to i + 1
    //fd_hash_t sub_hash;
    fd_sha256_fini( &shas[i], hash );
    FD_LOG_NOTICE(( "Q (%lu)"
      "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT,
      i,
      FD_LOG_HEX16_FMT_ARGS(     hash->hash    ), FD_LOG_HEX16_FMT_ARGS(     hash->hash+16 ))); 
    num_hashes[i] = 0;
    num_hashes[i+1]++;
      
    if (i == (height-1)) {
      ulong tot_num_hashes = 0;
      for (ulong k = 0; k < FD_ACCOUNT_DELTAS_MAX_MERKLE_HEIGHT; ++k ) {
        tot_num_hashes += num_hashes[k];
      }

      assert(tot_num_hashes == 1);
      FD_LOG_NOTICE(( "M"
        "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT,
        FD_LOG_HEX16_FMT_ARGS(     hash->hash    ), FD_LOG_HEX16_FMT_ARGS(     hash->hash+16 ))); 
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
        fd_sha256_append( &shas[j+1], (uchar const *) sub_hash.hash, sizeof( fd_hash_t ) );
      }
    }
  }
  
  // If the level at the `height' was rolled into, do something about it

}

void 
fd_hash_bank( fd_deserializable_versioned_bank_t const * bank, fd_pubkey_hash_pair_t * pairs, ulong pairs_len, fd_hash_t * hash ) {
  fd_hash_t account_deltas_hash;

  fd_hash_account_deltas( pairs, pairs_len, &account_deltas_hash );

  fd_sha256_t sha;
  fd_sha256_init( &sha );
  fd_sha256_append( &sha, (uchar const *) &bank->parent_hash, sizeof( fd_hash_t ) );
  fd_sha256_append( &sha, (uchar const *) account_deltas_hash.hash, sizeof( fd_hash_t  ) );
  fd_sha256_append( &sha, (uchar const *) &bank->signature_count, sizeof( ulong ) );
  fd_sha256_append( &sha, (uchar const *) bank->blockhash_queue.last_hash->hash, sizeof( fd_hash_t ) );
 
  fd_sha256_fini( &sha, hash->hash );
}

// NOTE: will not work on big endian platforms
void 
fd_hash_account( fd_solana_account_t const * account, ulong slot, fd_pubkey_t const * pubkey, fd_hash_t * hash ) {
  if( account->lamports==0 ) {
    fd_memset(hash->hash, 0, sizeof(fd_hash_t));
    return;
  }

  fd_blake3_t sha;
  fd_blake3_init( &sha );
  fd_blake3_append( &sha, (uchar const *) &account->lamports, sizeof( ulong ) );
  fd_blake3_append( &sha, (uchar const *) &slot, sizeof( ulong ) );
  fd_blake3_append( &sha, (uchar const *) &account->rent_epoch, sizeof( ulong ) );
  fd_blake3_append( &sha, (uchar const *) account->data, account->data_len );
 
  uchar executable = account->executable & 0x1;
  fd_blake3_append( &sha, (uchar const *) &executable, sizeof( uchar ));

  fd_blake3_append( &sha, (uchar const *) account->owner.key, 32 );
  fd_blake3_append( &sha, (uchar const *) pubkey->key, 32 );

  fd_blake3_fini( &sha, hash->hash );
}
