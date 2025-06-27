#include "fd_solana_manifest_streaming_decode.h"
#include "../../flamenco/fd_flamenco_base.h"

#define FD_STREAMING_DECODE_SKIP_PRIMITIVE( buf, bufsz, type ) \
  do {                                                         \
    uchar const * ptr = (uchar const *)buf;                    \
    if( ptr + sizeof(type) > buf + bufsz ) {                   \
        return -1;                                             \
    }                                                          \
    buf += sizeof(type);                                       \
  } while(0)

#define FD_STREAMING_DECODE_BOOL( buf, bufsz, dest ) \
  do {                                               \
    uchar const * ptr = (uchar const *)buf;          \
    if( ptr + sizeof(uchar) > buf + bufsz ) {         \
        return -1;                                   \
    }                                                \
    *(int *)dest = *(uchar const *)ptr;              \
    buf += sizeof(uchar);                            \
  } while(0)


#define FD_STREAMING_DECODE_PRIMITIVE( buf, bufsz, type, dest ) \
  do {                                                          \
    uchar const * ptr = (uchar const *)buf;                     \
    if( ptr + sizeof(type) > buf + bufsz ) {                    \
        return -1;                                              \
    }                                                           \
    *(type *)dest = *(type const *)ptr;                         \
    buf += sizeof(type);                                        \
  } while(0)

#define FD_STREAMING_DECODE_SKIP_SIZE( buf, bufsz, size ) \
  do {                                                      \
    uchar const * ptr = (uchar const *)buf;                 \
    if( ptr + size > buf + bufsz ) {                        \
        return -1;                                          \
    }                                                       \
    buf += size;                                            \
  } while(0)

#define FD_STREAMING_DECODE_SIZE( buf, bufsz, size, dest ) \
  do {                                                      \
    uchar const * ptr = (uchar const *)buf;                 \
    if( ptr + size > buf + bufsz ) {                        \
        return -1;                                          \
    }                                                       \
    uchar * dest_buf = (uchar *)dest;                       \
    fd_memcpy( dest_buf, ptr, size );                       \
    buf += size;                                            \
  } while(0)

#define FD_STREAMING_DECODE_SKIP_OPTION_PRIMITIVE( buf, bufsz, option_type ) \
do {                                                                         \
    uchar const * ptr = (uchar const *)buf;                                  \
    if( ptr + 1 > buf + bufsz ) {                                            \
        return -1;                                                           \
    }                                                                        \
    if( *ptr ) {                                                             \
      buf += 1;                                                              \
      FD_STREAMING_DECODE_SKIP_PRIMITIVE( buf, bufsz, option_type );         \
    } else {                                                                 \
      buf += 1;                                                              \
    }                                                                        \
  } while(0)

#define FD_STREAMING_DECODE_OPTION_PRIMITIVE( buf, bufsz, option_type, dest ) \
  do {                                                                        \
      uchar * dest_buf = (uchar *)dest;                                       \
      uchar const * ptr = (uchar const *)buf;                                 \
      if( ptr + 1 > buf + bufsz ) {                                           \
          return -1;                                                          \
      }                                                                       \
      if( *ptr ) {                                                            \
        *dest_buf = (int)1;                                                   \
        dest_buf += sizeof(int);                                              \
        buf += 1;                                                             \
        FD_STREAMING_DECODE_PRIMITIVE( buf, bufsz, option_type, dest_buf );   \
      } else {                                                                \
        buf += 1;                                                             \
      }                                                                       \
    } while(0)

#define FD_STREAMING_DECODE_SKIP_OPTION_STATIC_SIZE( buf, bufsz, option_size ) \
  do {                                                                         \
      if( buf + 1 > buf + bufsz ) {                                            \
          return -1;                                                           \
      }                                                                        \
      if( *buf ) {                                                             \
        buf += 1;                                                              \
        if( buf + option_size > buf + bufsz ) {                                \
          return -1;                                                           \
        }                                                                      \
        buf += option_size;                                                    \
      } else {                                                                 \
        buf += 1;                                                              \
      }                                                                        \
    } while(0)

#define FD_STREAMING_DECODE_SKIP_VECTOR_STATIC_SIZE( buf, bufsz, vec_elem_size ) \
  do {                                                                           \
    ulong vec_len = (ulong)*( (ulong const *)buf );                              \
    FD_LOG_WARNING(("I got vector length %lu", vec_len));                        \
    if( buf + sizeof(ulong) + vec_elem_size * vec_len > buf + bufsz ) {          \
      return -1;                                                                 \
    }                                                                            \
    buf += sizeof(ulong);                                                        \
    buf += vec_elem_size * vec_len;                                              \
  } while(0)

#define FD_STREAMING_DECODE_VECTOR_STATIC_SIZE( buf, bufsz, vec_elem_size, dest ) \
  do {                                                                           \
    ulong vec_len = (ulong)*( (ulong const *)buf );                              \
    FD_LOG_WARNING(("I got vector length %lu", vec_len));                        \
    if( buf + sizeof(ulong) + vec_elem_size * vec_len > buf + bufsz ) {          \
      return -1;                                                                 \
    }                                                                            \
    uchar * dest_buf = (uchar *)dest;                                            \
    fd_memcpy( dest_buf, &vec_len, sizeof(ulong) );                              \
    dest_buf += sizeof(ulong);                                                   \
    buf += sizeof(ulong);                                                        \
    for( ulong i=0UL; i<vec_len; i++ ) {                                         \
      fd_memcpy( dest_buf, buf, vec_elem_size );                                 \
      dest_buf += vec_elem_size;                                                 \
      buf      += vec_elem_size;                                                 \
    }                                                                            \
    dest = (uchar *)dest_buf;                                                    \
  } while(0)

int
fd_streaming_decode_unix_timestamp( uchar * buf,
                                    ulong   bufsz,
                                    long *  dest ) {
  uchar const * ptr = (uchar const *)buf;
  if( ptr + sizeof(ulong) > buf + bufsz ) {
    return -1;
  }
  long nanos = (long)*(ulong const *)ptr * 1000000000L;
  *dest = nanos;
  return 0;
}

int
fd_streaming_decode_vote_account_0_23_5( uchar * buf,
                                         ulong   bufsz,
                                         uchar * dest ) {
  /* skip node pubkey and authorized withdrawer */
  FD_STREAMING_DECODE_SKIP_SIZE( buf, bufsz, 2*sizeof(fd_pubkey_t) );

  /* skip authorized voter epoch */
  FD_STREAMING_DECODE_SKIP_PRIMITIVE( buf, bufsz, ulong );

  for( ulong i=0UL; i<32UL; i++ ) {
    FD_STREAMING_DECODE_SKIP_VECTOR_STATIC_SIZE( buf, bufsz, sizeof(fd_vote_prior_voter_0_23_5_t) );
  }

  /* skip idx */
  FD_STREAMING_DECODE_SKIP_PRIMITIVE( buf, bufsz, ulong );

  /* skip authorized withdrawer */
  FD_STREAMING_DECODE_SKIP_SIZE( buf, bufsz, sizeof(fd_pubkey_t) );

  /* get commission */
  FD_STREAMING_DECODE_PRIMITIVE( buf, bufsz, uchar, dest );
  dest += sizeof(uchar);

  /* skip landed votes */
  FD_STREAMING_DECODE_SKIP_VECTOR_STATIC_SIZE( buf, bufsz, sizeof(fd_landed_vote_t) );

  /* root slot option */
  FD_STREAMING_DECODE_SKIP_OPTION_PRIMITIVE( buf, bufsz, ulong );

  /* get vector of epoch vote credits */
  FD_STREAMING_DECODE_VECTOR_STATIC_SIZE( buf, bufsz, sizeof(fd_vote_epoch_credits_t), dest );

  /* skip vote block timestamp */
  FD_STREAMING_DECODE_SKIP_SIZE( buf, bufsz, sizeof(fd_vote_block_timestamp_t));

  return 0;
}

int
fd_streaming_decode_vote_account_1_14_11( uchar * buf,
                                         ulong   bufsz,
                                         uchar * dest ) {
  /* skip node pubkey and authorized withdrawer */
  FD_STREAMING_DECODE_SKIP_SIZE( buf, bufsz, 2*sizeof(fd_pubkey_t) );

  /* get commission */
  FD_STREAMING_DECODE_PRIMITIVE( buf, bufsz, uchar, dest );
  dest += sizeof(uchar);

  /* skip landed votes */
  FD_STREAMING_DECODE_SKIP_VECTOR_STATIC_SIZE( buf, bufsz, sizeof(fd_landed_vote_t) );

  /* root slot option */
  FD_STREAMING_DECODE_SKIP_OPTION_PRIMITIVE( buf, bufsz, ulong );

  /* skip authorized voters */
  FD_STREAMING_DECODE_SKIP_VECTOR_STATIC_SIZE( buf, bufsz, sizeof(ulong) + sizeof(fd_pubkey_t) );

   /* skip prior voters */
   for( ulong i=0UL; i<32UL; i++ ) {
    FD_STREAMING_DECODE_SKIP_VECTOR_STATIC_SIZE( buf, bufsz, sizeof(fd_vote_prior_voter_t) );
  }

  /* skip idx */
  FD_STREAMING_DECODE_SKIP_PRIMITIVE( buf, bufsz, ulong );

  /* skip is empty */
  FD_STREAMING_DECODE_SKIP_PRIMITIVE( buf, bufsz, uchar );

  /* get vector of epoch vote credits */
  FD_STREAMING_DECODE_VECTOR_STATIC_SIZE( buf, bufsz, sizeof(fd_vote_epoch_credits_t), dest );

  /* skip vote block timestamp */
  FD_STREAMING_DECODE_SKIP_SIZE( buf, bufsz, sizeof(fd_vote_block_timestamp_t));

  return 0;
}

int
fd_streaming_decode_vote_account_current( uchar * buf,
                                          ulong   bufsz,
                                          uchar * dest ) {
  /* skip node pubkey and authorized withdrawer */
  FD_STREAMING_DECODE_SKIP_SIZE( buf, bufsz, 2*sizeof(fd_pubkey_t) );

  /* get commission */
  FD_STREAMING_DECODE_PRIMITIVE( buf, bufsz, uchar, dest );
  dest += sizeof(uchar);

  /* skip landed votes */
  FD_STREAMING_DECODE_SKIP_VECTOR_STATIC_SIZE( buf, bufsz, sizeof(fd_landed_vote_t) );

  /* root slot option */
  FD_STREAMING_DECODE_SKIP_OPTION_PRIMITIVE( buf, bufsz, ulong );

  /* skip authorized voters */
  FD_STREAMING_DECODE_SKIP_VECTOR_STATIC_SIZE( buf, bufsz, sizeof(ulong) + sizeof(fd_pubkey_t) );

  /* skip prior voters */
  for( ulong i=0UL; i<32UL; i++ ) {
    FD_STREAMING_DECODE_SKIP_VECTOR_STATIC_SIZE( buf, bufsz, sizeof(fd_vote_prior_voter_t) );
  }

  /* skip idx */
  FD_STREAMING_DECODE_SKIP_PRIMITIVE( buf, bufsz, ulong );

  /* skip is empty */
  FD_STREAMING_DECODE_SKIP_PRIMITIVE( buf, bufsz, uchar );

  /* get vector of epoch vote credits */
  FD_STREAMING_DECODE_VECTOR_STATIC_SIZE( buf, bufsz, sizeof(fd_vote_epoch_credits_t), dest );

  /* skip vote block timestamp */
  FD_STREAMING_DECODE_SKIP_SIZE( buf, bufsz, sizeof(fd_vote_block_timestamp_t));

  return 0;
}

int
fd_streaming_decode_vote_account( uchar *             buf,
                                  ulong               bufsz,
                                  uchar *             dest ) {
  /* get vote account pubkey */
  FD_STREAMING_DECODE_SIZE( buf, bufsz, sizeof(fd_pubkey_t), dest );
  dest += sizeof(fd_pubkey_t);

  /* skip stake */
  FD_STREAMING_DECODE_SKIP_PRIMITIVE( buf, bufsz, ulong );

  /* decode vote account */

  /* skip lamports */
  FD_STREAMING_DECODE_SKIP_PRIMITIVE( buf, bufsz, ulong );

  /* skip data len */
  if( buf + sizeof(ulong) > buf + bufsz ) {
    return -1;
  }
  ulong data_len = *(ulong const *)buf;
  buf += sizeof(ulong);

  if( buf + data_len > buf + bufsz ) {
    return -1;
  }

  /* decode data bytes */
  uint discriminant = *(uint const *)buf;
  buf += sizeof(uint);

  switch (discriminant) {
    case 0: {
      fd_streaming_decode_vote_account_0_23_5( buf, bufsz, dest );
      break;
    }
    case 1: {
      fd_streaming_decode_vote_account_1_14_11( buf, bufsz, dest );
      break;
    }
    case 2: {
      fd_streaming_decode_vote_account_current( buf, bufsz, dest );
      break;
    }
    default: {
      FD_LOG_ERR(("fatal error: invalid vote account discriminant %u", discriminant));
    }
  }

  /* skip owner + executable + rent epoch */
  FD_STREAMING_DECODE_SKIP_SIZE( buf, sizeof(fd_vote_accounts_pair_t),
                                 sizeof(fd_pubkey_t) + sizeof(uchar) + sizeof(ulong) );
  return 0;
}

int
fd_streaming_decode_vote_accounts( uchar * buf,
                                   ulong   bufsz,
                                   uchar * dest,
                                   ulong   len ) {
  for( ulong i=0UL; i<len; i++ ) {
    int err = fd_streaming_decode_vote_account( buf, bufsz, dest );
    if( FD_UNLIKELY( err ) ) {
      return err;
    }
  }

  return 0;
}

int
fd_solana_manifest_streaming_decode( uchar * buf,
                                     ulong   bufsz,
                                     fd_snapshot_storages_t * storages,
                                     fd_snapshot_manifest_t * manifest ) {
  (void)storages;
  /* decode blockhash queue last hash index */
  FD_STREAMING_DECODE_SKIP_PRIMITIVE( buf, bufsz, ulong );
  FD_STREAMING_DECODE_SKIP_OPTION_STATIC_SIZE( buf, bufsz, sizeof(fd_hash_t) );
  /* decode blockhash queue */
  FD_STREAMING_DECODE_SKIP_VECTOR_STATIC_SIZE( buf, bufsz, sizeof(fd_hash_hash_age_pair_t) );
  FD_STREAMING_DECODE_SKIP_PRIMITIVE( buf, bufsz, ulong );

  /* decode ancestors_len */
  FD_STREAMING_DECODE_SKIP_VECTOR_STATIC_SIZE( buf, bufsz, sizeof(fd_slot_pair_t) );
  /* decode bank hash and parent hash */
  FD_STREAMING_DECODE_SIZE( buf, bufsz, sizeof(fd_hash_t), &manifest->bank_hash );
  FD_STREAMING_DECODE_SIZE( buf, bufsz, sizeof(fd_hash_t), &manifest->parent_bank_hash );

  /* decode parent slot */
  FD_STREAMING_DECODE_PRIMITIVE( buf, bufsz, ulong, &manifest->parent_slot );

  /* decode hard forks */
  FD_STREAMING_DECODE_SKIP_VECTOR_STATIC_SIZE( buf, bufsz, sizeof(fd_slot_pair_t) );

  /* skip 5 ulongs in the bank */
  FD_STREAMING_DECODE_SKIP_SIZE( buf, bufsz, 3*sizeof(ulong) );

  /* get capitalization */
  FD_STREAMING_DECODE_PRIMITIVE( buf, bufsz, ulong, &manifest->capitalization );

  /* skip max tick height */
  FD_STREAMING_DECODE_SKIP_PRIMITIVE( buf, bufsz, ulong );

  /* skip hashes per tick option */
  FD_STREAMING_DECODE_OPTION_PRIMITIVE( buf, bufsz, ulong, &manifest->has_hashes_per_tick );

  /* get ticks per slot */
  FD_STREAMING_DECODE_PRIMITIVE( buf, bufsz, ulong, &manifest->ticks_per_slot );

  /* skip ns per slot */
  FD_STREAMING_DECODE_SKIP_SIZE( buf, bufsz, 16UL );

  /* get creation time ns */
  int err = fd_streaming_decode_unix_timestamp( buf, bufsz, &manifest->creation_time_ns );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }
  buf += sizeof(ulong);

  /* skip slots per year */
  FD_STREAMING_DECODE_SKIP_PRIMITIVE( buf, bufsz, ulong );

  /* skip accounts data len */
  FD_STREAMING_DECODE_SKIP_PRIMITIVE( buf, bufsz, ulong );

  /* get slot */
  FD_STREAMING_DECODE_PRIMITIVE( buf, bufsz, ulong, &manifest->slot );

  /* skip epoch */
  FD_STREAMING_DECODE_SKIP_PRIMITIVE( buf, bufsz, ulong );

  /* get block height */
  FD_STREAMING_DECODE_PRIMITIVE( buf, bufsz, ulong, &manifest->block_height );

  /* skip collector id, collector fees */
  FD_STREAMING_DECODE_SKIP_SIZE( buf, bufsz, sizeof(fd_pubkey_t) + sizeof(ulong) );

  /* skip the fee rate calculator */
  FD_STREAMING_DECODE_SKIP_PRIMITIVE( buf, bufsz, ulong );

  /* get the fee rate governor */
  FD_STREAMING_DECODE_PRIMITIVE( buf, bufsz, ulong, &manifest->fee_rate_governor.target_lamports_per_signature );
  FD_STREAMING_DECODE_PRIMITIVE( buf, bufsz, ulong, &manifest->fee_rate_governor.target_signatures_per_slot );
  FD_STREAMING_DECODE_PRIMITIVE( buf, bufsz, ulong, &manifest->fee_rate_governor.min_lamports_per_signature );
  FD_STREAMING_DECODE_PRIMITIVE( buf, bufsz, ulong, &manifest->fee_rate_governor.max_lamports_per_signature );
  FD_STREAMING_DECODE_PRIMITIVE( buf, bufsz, uchar, &manifest->fee_rate_governor.burn_percent );

  /* collected rent */
  FD_STREAMING_DECODE_SKIP_PRIMITIVE( buf, bufsz, ulong );
  /* epoch */
  FD_STREAMING_DECODE_SKIP_PRIMITIVE( buf, bufsz, ulong );

  /* epoch schedule skip */
  FD_STREAMING_DECODE_SKIP_SIZE( buf, bufsz, 4*sizeof(ulong) + sizeof(uchar) );

  /* skip slots per year */
  FD_STREAMING_DECODE_SKIP_PRIMITIVE( buf, bufsz, double );

  /* skip rent */
  FD_STREAMING_DECODE_SKIP_SIZE( buf, bufsz, 2*sizeof(ulong) + sizeof(uchar) );

  /* get epoch schedule */
  FD_STREAMING_DECODE_PRIMITIVE( buf, bufsz, ulong, &manifest->epoch_schedule_params.slots_per_epoch );
  FD_STREAMING_DECODE_PRIMITIVE( buf, bufsz, ulong, &manifest->epoch_schedule_params.leader_schedule_slot_offset );
  FD_STREAMING_DECODE_BOOL( buf, bufsz, &manifest->epoch_schedule_params.warmup );
  FD_STREAMING_DECODE_SKIP_SIZE( buf, bufsz, 2*sizeof(ulong) );

  /* get inflation params */
  FD_STREAMING_DECODE_PRIMITIVE( buf, bufsz, double, &manifest->inflation_params.initial );
  FD_STREAMING_DECODE_PRIMITIVE( buf, bufsz, double, &manifest->inflation_params.terminal );
  FD_STREAMING_DECODE_PRIMITIVE( buf, bufsz, double, &manifest->inflation_params.taper );
  FD_STREAMING_DECODE_PRIMITIVE( buf, bufsz, double, &manifest->inflation_params.foundation );
  FD_STREAMING_DECODE_PRIMITIVE( buf, bufsz, double, &manifest->inflation_params.foundation_term );

  /* skip unused field in inflation */
  FD_STREAMING_DECODE_SKIP_PRIMITIVE( buf, bufsz, ulong );

  /* get vote accounts len */
  FD_STREAMING_DECODE_PRIMITIVE( buf, bufsz, ulong, &manifest->vote_accounts_len );

  fd_streaming_decode_vote_accounts( buf,
                                     bufsz,
                                     (uchar *)&manifest->vote_accounts,
                                     manifest->vote_accounts_len );

  // FD_STREAMING_DECODE_SKIP_VECTOR_STATIC_SIZE( buf, bufsz, sizeof(fd_delegation_pair_t) );
  // FD_STREAMING_DECODE_SKIP_SIZE( buf, bufsz, 2*sizeof(ulong) );
  // FD_STREAMING_DECODE_SKIP_VECTOR_STATIC_SIZE( buf, bufsz, sizeof(fd_epoch_stake_history_entry_pair_t) );

  // /* skip unused accounts */
  // FD_STREAMING_DECODE_SKIP_VECTOR_STATIC_SIZE( buf, bufsz, sizeof(fd_pubkey_t) );
  // FD_STREAMING_DECODE_SKIP_VECTOR_STATIC_SIZE( buf, bufsz, sizeof(fd_pubkey_t) );
  // FD_STREAMING_DECODE_SKIP_VECTOR_STATIC_SIZE( buf, bufsz, sizeof(fd_pubkey_t) + sizeof(ulong) );

  // /* get epoch stakes */

  // /* skip is_delta */
  // FD_STREAMING_DECODE_SKIP_PRIMITIVE( buf, bufsz, uchar );

  return 0;
}
