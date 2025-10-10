#ifndef HEADER_fd_src_flamenco_capture_fd_capture_tile_h
#define HEADER_fd_src_flamenco_capture_fd_capture_tile_h

#include "../fd_rwlock.h"
#include "../../util/fd_util_base.h"
#include "../../util/log/fd_log.h"
#include "fd_solcap_writer.h"
#include "../runtime/fd_runtime_const.h"
#include <sys/types.h>

/* Capctx buffer shared object - a large buffer with read-write lock for
   multi-tile access */

#define FD_CAPCTX_BUF_ALIGN (128UL)
#define FD_CAPCTX_BUF_CNT (64)
#define FD_CAPCTX_BUF_MTU (FD_RUNTIME_ACC_SZ_MAX + sizeof(fd_pubkey_t) + sizeof(fd_solana_account_meta_t) + sizeof(ulong))

/*
 Capture Context Shared Object
*/

struct fd_capctx_buf {
  fd_rwlock_t lock;     /* Read-write lock for concurrent access */
  uchar       buffer[FD_CAPCTX_BUF_MTU * FD_CAPCTX_BUF_CNT];
  uint        reserve_flags[FD_CAPCTX_BUF_CNT];
  ulong       writer_idx;
  ulong       reader_idx;
  char        path[PATH_MAX];
};
typedef struct fd_capctx_buf fd_capctx_buf_t;


/* fd_capctx_buf_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as capctx buffer. */

FD_FN_CONST static inline ulong
fd_capctx_buf_align( void ) {
  return alignof(fd_capctx_buf_t);
}

FD_FN_CONST static inline ulong
fd_capctx_buf_footprint( void ) {
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
      FD_LAYOUT_INIT,
      alignof(fd_capctx_buf_t), sizeof(fd_capctx_buf_t)
    ),
    fd_capctx_buf_align()
  );
}

/* Initialize a capctx buffer in the given memory region */
static inline fd_capctx_buf_t *
fd_capctx_buf_new( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) return NULL;

  // do the layout setup here

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_capctx_buf_t * buf = FD_SCRATCH_ALLOC_APPEND( l, fd_capctx_buf_align(), fd_capctx_buf_footprint() );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_capctx_buf_align() ) == (ulong)mem + fd_capctx_buf_footprint() );


  /* Clear entire structure first to ensure clean state */
  fd_memset( buf, 0, sizeof(fd_capctx_buf_t) );
  

  buf->writer_idx = 0UL;
  buf->reader_idx = -1UL;

  /* Initialize the lock and reserve flags */
  buf->lock.value = 0;
  for( ulong i = 0UL; i < FD_CAPCTX_BUF_CNT; i++ ) {
    buf->reserve_flags[i] = 0;
  }
  
  return buf;
}

/* Join an existing capctx buffer */
static inline fd_capctx_buf_t *
fd_capctx_buf_join( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) return NULL;
  return (fd_capctx_buf_t *)mem;
}

/* Leave a capctx buffer (no-op for now) */
static inline void
fd_capctx_buf_leave( fd_capctx_buf_t * buf ) {
  (void)buf;
}


/*
  Solcap Buffer Writeables
*/

ulong
fd_capctx_buf_reader_aquire_lock( fd_capctx_buf_t * capctx_buf );

void
fd_capctx_buf_reader_release_lock( fd_capctx_buf_t * capctx_buf,
                                   ulong buf_idx );

void
fd_capctx_buf_process_msg( fd_capture_ctx_t * capture_ctx,
                            ulong sig,
                            char * actual_data );


#define SIG_SOLCAP_SLOT (1UL)
#define SIG_SOLCAP_FLUSH (2UL)
#define SIG_SOLCAP_SET_SLOT (3UL)
#define SIG_SOLCAP_WRITE_ACCOUNT (4UL)
#define SIG_SOLCAP_STAKE_ACCOUNT_PAYOUT (5UL)
#define SIG_SOLCAP_STAKE_REWARDS_BEGIN (6UL)
#define SIG_SOLCAP_WRITE_BANK_PREIMAGE (7UL)
#define SIG_SOLCAP_WRITE_STAKE_REWARD_EVENT (8UL)
#define SIG_SOLCAP_WRITE_VOTE_ACCOUNT_PAYOUT (9UL)

struct fd_solcap_buf_msg {
  ushort sig;
  char * data;
};
typedef struct fd_solcap_buf_msg fd_solcap_buf_msg_t;

/* 
  +++++++++++++++++++++++++++++++++ fd_solcap_writer_write_account wrapper +++++++++++++++++++++++++++++++++
*/
struct fd_solcap_buf_msg_account_update {
  fd_pubkey_t key;
  fd_solana_account_meta_t info;
  ulong data_sz;
  uchar data[FD_RUNTIME_ACC_SZ_MAX];
};
typedef struct fd_solcap_buf_msg_account_update fd_solcap_buf_msg_account_update_t;

static inline void
fd_capctx_buf_translate_account_update( fd_capctx_buf_t * buf,
                                        fd_pubkey_t const * key,
                                        fd_solana_account_meta_t const * info,
                                        uchar const * data,
                                        ulong data_sz ) {
  /* Atomically claim the next buffer slot */
  ulong writer_seq = FD_ATOMIC_FETCH_AND_ADD( &buf->writer_idx, 1UL );
  ulong buf_idx = writer_seq % FD_CAPCTX_BUF_CNT;
  
  /* Wait for reader to catch up if buffer is full */
  while( FD_UNLIKELY( writer_seq >= FD_VOLATILE_CONST( buf->reader_idx ) + FD_CAPCTX_BUF_CNT ) ) {
    FD_SPIN_PAUSE();
  }
  
  /* Write directly to the claimed slot */
  char * slot_ptr = (char *)&buf->buffer[buf_idx * FD_CAPCTX_BUF_MTU];
  
  /* Write the signature */
  *(ushort*)slot_ptr = SIG_SOLCAP_WRITE_ACCOUNT;
  slot_ptr += sizeof(ushort);
  
  /* Write the account update data */
  fd_memcpy( slot_ptr, key, sizeof(fd_pubkey_t) );
  slot_ptr += sizeof(fd_pubkey_t);
  
  fd_memcpy( slot_ptr, info, sizeof(fd_solana_account_meta_t) );
  slot_ptr += sizeof(fd_solana_account_meta_t);
  
  fd_memcpy( slot_ptr, &data_sz, sizeof(ulong) );
  slot_ptr += sizeof(ulong);
  
  fd_memcpy( slot_ptr, data, data_sz );
  
  /* Mark slot as ready for reading */
  FD_ATOMIC_CAS( &buf->reserve_flags[buf_idx], 0U, 1U );
}

/*
  +++++++++++++++++++++++++++++++++ fd_solcap_writer_set_slot wrapper +++++++++++++++++++++++++++++++++
*/

struct fd_solcap_buf_msg_set_slot {
  ulong slot;
};
typedef struct fd_solcap_buf_msg_set_slot fd_solcap_buf_msg_set_slot_t;

static inline void
fd_capctx_buf_translate_set_slot( fd_capctx_buf_t * buf,
                                  ulong slot ) {
  /* Atomically claim the next buffer slot */
  ulong writer_seq = FD_ATOMIC_FETCH_AND_ADD( &buf->writer_idx, 1UL );
  ulong buf_idx = writer_seq % FD_CAPCTX_BUF_CNT;
  
  /* Wait for reader to catch up if buffer is full */
  while( FD_UNLIKELY( writer_seq >= FD_VOLATILE_CONST( buf->reader_idx ) + FD_CAPCTX_BUF_CNT ) ) {
    FD_SPIN_PAUSE();
  }
  /* Write directly to the claimed slot */
  char * slot_ptr = (char *)&buf->buffer[buf_idx * FD_CAPCTX_BUF_MTU];
  
  /* Write the signature */
  *(ushort*)slot_ptr = SIG_SOLCAP_SET_SLOT;
  slot_ptr += sizeof(ushort);
  
  /* Write the slot data */
  fd_memcpy( slot_ptr, &slot, sizeof(ulong) );
  
  /* Mark slot as ready for reading */
  FD_ATOMIC_CAS( &buf->reserve_flags[buf_idx], 0U, 1U );
}

/*
  +++++++++++++++++++++++++++++++++ fd_solcap_writer_flush wrapper +++++++++++++++++++++++++++++++++
*/


static inline void
fd_capctx_buf_translate_flush( fd_capctx_buf_t * buf ) {
  /* Atomically claim the next buffer slot */
  ulong writer_seq = FD_ATOMIC_FETCH_AND_ADD( &buf->writer_idx, 1UL );
  ulong buf_idx = writer_seq % FD_CAPCTX_BUF_CNT;
  
  /* Wait for reader to catch up if buffer is full */
  while( FD_UNLIKELY( writer_seq >= FD_VOLATILE_CONST( buf->reader_idx ) + FD_CAPCTX_BUF_CNT ) ) {
    FD_SPIN_PAUSE();
  }
  
  /* Write directly to the claimed slot */
  char * slot_ptr = (char *)&buf->buffer[buf_idx * FD_CAPCTX_BUF_MTU];
  
  /* Write the signature */
  *(ushort*)slot_ptr = SIG_SOLCAP_FLUSH;
  /* Mark slot as ready for reading */
  FD_ATOMIC_CAS( &buf->reserve_flags[buf_idx], 0U, 1U );
}


/*
  +++++++++++++++++++++++++++++++++ fd_solcap_writer_write_bank_preimage wrapper +++++++++++++++++++++++++++++++++
*/
struct fd_solcap_buf_msg_bank_preimage {
  uchar bank_hash[32];
  uchar prev_bank_hash[32];
  uchar account_delta_hash[32];
  uchar accounts_lt_hash_checksum[32];
  uchar poh_hash[32];
  ulong signature_cnt;
};
typedef struct fd_solcap_buf_msg_bank_preimage fd_solcap_buf_msg_bank_preimage_t;

static inline void
fd_capctx_buf_translate_bank_preimage( fd_capctx_buf_t * buf,
                                       void const * bank_hash,
                                       void const * prev_bank_hash,
                                       void const * account_delta_hash,
                                       void const * accounts_lt_hash_checksum,
                                       void const * poh_hash,
                                       ulong signature_cnt ) {
  /* Atomically claim the next buffer slot */
  ulong writer_seq = FD_ATOMIC_FETCH_AND_ADD( &buf->writer_idx, 1UL );
  ulong buf_idx = writer_seq % FD_CAPCTX_BUF_CNT;
  
  /* Wait for reader to catch up if buffer is full */
  while( FD_UNLIKELY( writer_seq >= FD_VOLATILE_CONST( buf->reader_idx ) + FD_CAPCTX_BUF_CNT ) ) {
    FD_SPIN_PAUSE();
  }
  
  /* Write directly to the claimed slot */
  char * slot_ptr = (char *)&buf->buffer[buf_idx * FD_CAPCTX_BUF_MTU];
  
  /* Write the signature */
  *(ushort*)slot_ptr = SIG_SOLCAP_WRITE_BANK_PREIMAGE;
  slot_ptr += sizeof(ushort);
  
  /* Write the bank preimage data */
  fd_memcpy( slot_ptr, bank_hash, 32 );
  slot_ptr += 32;
  
  fd_memcpy( slot_ptr, prev_bank_hash, 32 );
  slot_ptr += 32;


  if (account_delta_hash != NULL){
    fd_memcpy( slot_ptr, account_delta_hash, 32 );
  } else {
    fd_memset( slot_ptr, 0, 32 );
  }
  slot_ptr += 32;

  fd_memcpy( slot_ptr, accounts_lt_hash_checksum, 32 );
  slot_ptr += 32;
  
  fd_memcpy( slot_ptr, poh_hash, 32 );
  slot_ptr += 32;
  
  fd_memcpy( slot_ptr, &signature_cnt, sizeof(ulong) );
  
  /* Mark slot as ready for reading */
  FD_ATOMIC_CAS( &buf->reserve_flags[buf_idx], 0U, 1U );
}


/*
  +++++++++++++++++++++++++++++++++ fd_solcap_writer_stake_rewards_begin wrapper +++++++++++++++++++++++++++++++++
*/

struct fd_solcap_buf_msg_stake_rewards_begin {
  ulong payout_epoch;
  ulong reward_epoch;
  ulong inflation_lamports;
  uint128 total_points;
};
typedef struct fd_solcap_buf_msg_stake_rewards_begin fd_solcap_buf_msg_stake_rewards_begin_t;

static inline void
fd_capctx_buf_translate_stake_rewards_begin( fd_capctx_buf_t * buf,
                                             ulong payout_epoch,
                                             ulong reward_epoch,
                                             ulong inflation_lamports,
                                             uint128 total_points ) {
  /* Atomically claim the next buffer slot */
  ulong writer_seq = FD_ATOMIC_FETCH_AND_ADD( &buf->writer_idx, 1UL );
  ulong buf_idx = writer_seq % FD_CAPCTX_BUF_CNT;
  
  /* Wait for reader to catch up if buffer is full */
  while( FD_UNLIKELY( writer_seq >= FD_VOLATILE_CONST( buf->reader_idx ) + FD_CAPCTX_BUF_CNT ) ) {
    FD_SPIN_PAUSE();
  }
  
  /* Write directly to the claimed slot */
  char * slot_ptr = (char *)&buf->buffer[buf_idx * FD_CAPCTX_BUF_MTU];
  
  /* Write the signature */
  *(ushort*)slot_ptr = SIG_SOLCAP_STAKE_REWARDS_BEGIN;
  slot_ptr += sizeof(ushort);
  
  /* Write the stake rewards begin data */
  fd_memcpy( slot_ptr, &payout_epoch, sizeof(ulong) );
  slot_ptr += sizeof(ulong);
  
  fd_memcpy( slot_ptr, &reward_epoch, sizeof(ulong) );
  slot_ptr += sizeof(ulong);
  
  fd_memcpy( slot_ptr, &inflation_lamports, sizeof(ulong) );
  slot_ptr += sizeof(ulong);
  
  fd_memcpy( slot_ptr, &total_points, sizeof(uint128) );
  
  /* Mark slot as ready for reading */
  FD_ATOMIC_CAS( &buf->reserve_flags[buf_idx], 0U, 1U );
}


/*
  +++++++++++++++++++++++++++++++++ fd_solcap_writer_stake_reward_event wrapper +++++++++++++++++++++++++++++++++
*/


struct fd_solcap_buf_msg_stake_reward_event {
  fd_pubkey_t stake_acc_addr;
  fd_pubkey_t vote_acc_addr;
  uint commission;
  long vote_rewards;
  long stake_rewards;
  long new_credits_observed;
};
typedef struct fd_solcap_buf_msg_stake_reward_event fd_solcap_buf_msg_stake_reward_event_t;

static inline void
fd_capctx_buf_translate_stake_reward_event( fd_capctx_buf_t * buf,
                                            fd_pubkey_t const * stake_acc_addr,
                                            fd_pubkey_t const * vote_acc_addr,
                                            uint commission,
                                            long vote_rewards,
                                            long stake_rewards,
                                            long new_credits_observed ) {
  /* Atomically claim the next buffer slot */
  ulong writer_seq = FD_ATOMIC_FETCH_AND_ADD( &buf->writer_idx, 1UL );
  ulong buf_idx = writer_seq % FD_CAPCTX_BUF_CNT;
  
  /* Wait for reader to catch up if buffer is full */
  while( FD_UNLIKELY( writer_seq >= FD_VOLATILE_CONST( buf->reader_idx ) + FD_CAPCTX_BUF_CNT ) ) {
    FD_SPIN_PAUSE();
  }
  
  /* Write directly to the claimed slot */
  char * slot_ptr = (char *)&buf->buffer[buf_idx * FD_CAPCTX_BUF_MTU];
  
  /* Write the signature */
  *(ushort*)slot_ptr = SIG_SOLCAP_WRITE_STAKE_REWARD_EVENT;
  slot_ptr += sizeof(ushort);
  
  /* Write the stake reward event data */
  fd_memcpy( slot_ptr, stake_acc_addr, sizeof(fd_pubkey_t) );
  slot_ptr += sizeof(fd_pubkey_t);
  
  fd_memcpy( slot_ptr, vote_acc_addr, sizeof(fd_pubkey_t) );
  slot_ptr += sizeof(fd_pubkey_t);
  
  fd_memcpy( slot_ptr, &commission, sizeof(uint) );
  slot_ptr += sizeof(uint);
  
  fd_memcpy( slot_ptr, &vote_rewards, sizeof(long) );
  slot_ptr += sizeof(long);
  
  fd_memcpy( slot_ptr, &stake_rewards, sizeof(long) );
  slot_ptr += sizeof(long);
  
  fd_memcpy( slot_ptr, &new_credits_observed, sizeof(long) );
  
  /* Mark slot as ready for reading */
  FD_ATOMIC_CAS( &buf->reserve_flags[buf_idx], 0U, 1U );
}

/*
  +++++++++++++++++++++++++++++++++ fd_solcap_writer_vote_account_payout wrapper +++++++++++++++++++++++++++++++++
*/

struct fd_solcap_buf_msg_vote_account_payout {
  fd_pubkey_t vote_acc_addr;
  ulong update_slot;
  ulong lamports;
  long lamports_delta;
};
typedef struct fd_solcap_buf_msg_vote_account_payout fd_solcap_buf_msg_vote_account_payout_t;

static inline void
fd_capctx_buf_translate_vote_account_payout( fd_capctx_buf_t * buf,
                                             fd_pubkey_t const * vote_acc_addr,
                                             ulong update_slot,
                                             ulong lamports,
                                             long lamports_delta ) {
  /* Atomically claim the next buffer slot */
  ulong writer_seq = FD_ATOMIC_FETCH_AND_ADD( &buf->writer_idx, 1UL );
  ulong buf_idx = writer_seq % FD_CAPCTX_BUF_CNT;
  
  /* Wait for reader to catch up if buffer is full */
  while( FD_UNLIKELY( writer_seq >= FD_VOLATILE_CONST( buf->reader_idx ) + FD_CAPCTX_BUF_CNT ) ) {
    FD_SPIN_PAUSE();
  }
  
  /* Write directly to the claimed slot */
  char * slot_ptr = (char *)&buf->buffer[buf_idx * FD_CAPCTX_BUF_MTU];
  
  /* Write the signature */
  *(ushort*)slot_ptr = SIG_SOLCAP_WRITE_VOTE_ACCOUNT_PAYOUT;
  slot_ptr += sizeof(ushort);
  
  /* Write the vote account payout data */
  fd_memcpy( slot_ptr, vote_acc_addr, sizeof(fd_pubkey_t) );
  slot_ptr += sizeof(fd_pubkey_t);
  
  fd_memcpy( slot_ptr, &update_slot, sizeof(ulong) );
  slot_ptr += sizeof(ulong);
  
  fd_memcpy( slot_ptr, &lamports, sizeof(ulong) );
  slot_ptr += sizeof(ulong);
  
  fd_memcpy( slot_ptr, &lamports_delta, sizeof(long) );
  
  /* Mark slot as ready for reading */
  FD_ATOMIC_CAS( &buf->reserve_flags[buf_idx], 0U, 1U );
}

/*
  +++++++++++++++++++++++++++++++++ fd_solcap_writer_stake_account_payout wrapper +++++++++++++++++++++++++++++++++
*/

struct fd_solcap_buf_msg_stake_account_payout {
  fd_pubkey_t stake_acc_addr;
  ulong update_slot;
  ulong lamports;
  long lamports_delta;
  ulong credits_observed;
  long credits_observed_delta;
  ulong delegation_stake;
  long delegation_stake_delta;
};
typedef struct fd_solcap_buf_msg_stake_account_payout fd_solcap_buf_msg_stake_account_payout_t;

static inline void
fd_capctx_buf_translate_stake_account_payout( fd_capctx_buf_t * buf,
                                              fd_pubkey_t const * stake_acc_addr,
                                              ulong update_slot,
                                              ulong lamports,
                                              long lamports_delta,
                                              ulong credits_observed,
                                              long credits_observed_delta,
                                              ulong delegation_stake,
                                              long delegation_stake_delta ) {
  /* Atomically claim the next buffer slot */
  ulong writer_seq = FD_ATOMIC_FETCH_AND_ADD( &buf->writer_idx, 1UL );
  ulong buf_idx = writer_seq % FD_CAPCTX_BUF_CNT;
  
  /* Wait for reader to catch up if buffer is full */
  while( FD_UNLIKELY( writer_seq >= FD_VOLATILE_CONST( buf->reader_idx ) + FD_CAPCTX_BUF_CNT ) ) {
    FD_SPIN_PAUSE();
  }
  
  /* Write directly to the claimed slot */
  char * slot_ptr = (char *)&buf->buffer[buf_idx * FD_CAPCTX_BUF_MTU];
  
  /* Write the signature */
  *(ushort*)slot_ptr = SIG_SOLCAP_STAKE_ACCOUNT_PAYOUT;
  slot_ptr += sizeof(ushort);
  
  /* Write the stake account payout data */
  fd_memcpy( slot_ptr, stake_acc_addr, sizeof(fd_pubkey_t) );
  slot_ptr += sizeof(fd_pubkey_t);
  
  fd_memcpy( slot_ptr, &update_slot, sizeof(ulong) );
  slot_ptr += sizeof(ulong);
  
  fd_memcpy( slot_ptr, &lamports, sizeof(ulong) );
  slot_ptr += sizeof(ulong);
  
  fd_memcpy( slot_ptr, &lamports_delta, sizeof(long) );
  slot_ptr += sizeof(long);
  
  fd_memcpy( slot_ptr, &credits_observed, sizeof(ulong) );
  slot_ptr += sizeof(ulong);
  
  fd_memcpy( slot_ptr, &credits_observed_delta, sizeof(long) );
  slot_ptr += sizeof(long);
  
  fd_memcpy( slot_ptr, &delegation_stake, sizeof(ulong) );
  slot_ptr += sizeof(ulong);
  
  fd_memcpy( slot_ptr, &delegation_stake_delta, sizeof(long) );
  
  /* Mark slot as ready for reading */
  FD_ATOMIC_CAS( &buf->reserve_flags[buf_idx], 0U, 1U );
}


#endif /* HEADER_fd_src_flamenco_capture_fd_capture_tile_h */
