#include "fd_ssmanifest_writer.h"

#define STATE_BLOCKHASH_QUEUE        1
#define STATE_HASHES                 2
#define STATE_HARD_FORKS             3
#define STATE_COUNTERS               4
#define STATE_VOTE_ACCOUNTS          5
#define STATE_STAKE_DELEGATION       6
#define STATE_STAKE_EPOCH            7
#define STATE_STAKE_HISTORY          8
#define STATE_BANK_TRAILER           9
#define STATE_ACCOUNT_STORAGE_ENTRY 10
#define STATE_BANK_HASH_INFO        11
#define STATE_EXTRA_FIELDS          12
#define STATE_EPOCH_STAKES          13
#define STATE_EPOCH_STAKES_STAKES   14
#define STATE_EPOCH_STAKES_EPOCH    15
#define STATE_EPOCH_STAKE_HISTORY   16
#define STATE_EPOCH_TOTAL_STAKE     17
#define STATE_NODE_VOTE_ACCOUNTS    18
#define STATE_AUTH_VOTER            19
#define STATE_LTHASH                20

fd_ssmanifest_writer_t *
fd_ssmanifest_writer_init( fd_ssmanifest_writer_t * enc,
                           fd_bank_t const *        bank ) {
  enc->state = STATE_BLOCKHASH_QUEUE;
  enc->bank = bank;
  return enc;
}

__attribute__((noreturn))
static inline void fail( void ) { FD_LOG_ERR(( "buffer overflow" )); }

ulong
fd_snap_manifest_serialize( fd_ssmanifest_writer_t * enc,
                            uchar out_buf[ FD_SSMANIFEST_BUF_MIN ],
                            ulong buf_sz ) {
  fd_bank_t const * bank = enc->bank;

  uchar * p  = out_buf;
  uchar * p1 = out_buf+buf_sz;
# define PUSH( n ) __extension__({ \
    ulong n_ = n; \
    if( FD_UNLIKELY( p+n_ > p1 ) ) fail(); \
    uchar * ret = p; \
    p += n_; \
    ret; \
  })

  switch( enc->state ) {
  case STATE_BLOCKHASH_QUEUE: {
    FD_STORE( ulong, PUSH( sizeof(ulong) ), 0UL ); /* last hash */
    break;
  }
  }
}
