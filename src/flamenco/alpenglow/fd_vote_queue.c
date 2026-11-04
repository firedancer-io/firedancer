#include "fd_vote_queue.h"
#include "../runtime/fd_hashes.h"

/* Images kept by a memo slot (memo[i]!=NULL) are read from and hashed
   into the slot; others point into the account being stored (acc_cnt
   counts them). */

struct __attribute__((aligned(FD_VOTE_QUEUE_ALIGN))) fd_vote_queue {
  fd_lthash_value_t        delta[ 1 ];
  fd_lthash_value_t        tmp  [ FD_BLAKE3_XN_MAX ];
  ulong                    cnt;
  ulong                    acc_cnt;
  fd_footer_cache_memo_t * memo [ FD_BLAKE3_XN_MAX ];
  int                      sub  [ FD_BLAKE3_XN_MAX ];
  uchar const *            pk   [ FD_BLAKE3_XN_MAX ];
  uchar const *            ow   [ FD_BLAKE3_XN_MAX ];
  ulong                    la   [ FD_BLAKE3_XN_MAX ];
  int                      ex   [ FD_BLAKE3_XN_MAX ];
  uchar const *            da   [ FD_BLAKE3_XN_MAX ];
  ulong                    dl   [ FD_BLAKE3_XN_MAX ];
  fd_lthash_value_t *      out  [ FD_BLAKE3_XN_MAX ];
};

FD_STATIC_ASSERT( sizeof (fd_vote_queue_t)==FD_VOTE_QUEUE_FOOTPRINT, vote_queue_footprint );
FD_STATIC_ASSERT( alignof(fd_vote_queue_t)==FD_VOTE_QUEUE_ALIGN,     vote_queue_align     );

fd_vote_queue_t *
fd_vote_queue_init( void * mem ) {
  fd_vote_queue_t * q = (fd_vote_queue_t *)mem;
  q->cnt     = 0UL;
  q->acc_cnt = 0UL;
  fd_lthash_zero( q->delta );
  return q;
}

static void
hash( fd_vote_queue_t * q ) {
  fd_hashes_account_lthash_xn( q->cnt, q->pk, q->ow, q->la, q->ex, q->da, q->dl, q->out );
  for( ulong i=0UL; i<q->cnt; i++ ) {
    if( q->sub[ i ] ) fd_lthash_sub( q->delta, q->out[ i ] );
    else              fd_lthash_add( q->delta, q->out[ i ] );
  }
  q->cnt     = 0UL;
  q->acc_cnt = 0UL;
}

static void
push( fd_vote_queue_t *        q,
      fd_footer_cache_memo_t * memo,
      int                      sub,
      uchar const *            pubkey,
      uchar const *            owner,
      ulong                    lamports,
      int                      executable,
      uchar const *            data,
      ulong                    data_len ) {
  ulong i = q->cnt++;
  q->memo[ i ] = memo;
  q->sub [ i ] = sub;
  q->pk  [ i ] = pubkey;     q->ow[ i ] = owner; q->la[ i ] = lamports;
  q->ex  [ i ] = executable; q->da[ i ] = data;  q->dl[ i ] = data_len;
  q->out [ i ] = memo ? &memo->lthash : q->tmp+i;
  q->acc_cnt  += !memo;
  if( q->cnt==FD_BLAKE3_XN_MAX ) hash( q );
}

void
fd_vote_queue_store( fd_vote_queue_t *        q,
                     fd_acc_t const *         acc,
                     fd_footer_cache_memo_t * memo ) {
  for( ulong i=0UL; memo && i<q->cnt; i++ ) {
    if( FD_UNLIKELY( q->memo[ i ]==memo ) ) { hash( q ); break; } /* memo's waiting image */
  }

  fd_lthash_value_t const * pre = memo ? fd_footer_cache_memo_query( memo, acc->pubkey, acc->prior_owner, acc->prior_lamports, acc->prior_executable, acc->prior_data, acc->prior_data_len ) : NULL;
  if( pre ) fd_lthash_sub( q->delta, pre ); /* before the slot is overwritten */
  else      push( q, NULL, 1, acc->pubkey, acc->prior_owner, acc->prior_lamports, acc->prior_executable, acc->prior_data, acc->prior_data_len );

  int kept = memo && fd_footer_cache_memo_insert( memo, acc->pubkey, acc->owner, acc->lamports, acc->executable, acc->data, acc->data_len );
  FD_TEST( kept || !pre ); /* a hit's prior image fit */
  if( kept ) push( q, memo, 0, memo->pubkey, memo->owner, memo->lamports, memo->executable, memo->data, memo->data_len );
  else       push( q, NULL, 0, acc->pubkey,  acc->owner,  acc->lamports,  acc->executable,  acc->data,  acc->data_len  );

  if( q->acc_cnt ) hash( q );
}

fd_lthash_value_t const *
fd_vote_queue_fini( fd_vote_queue_t * q ) {
  if( q->cnt ) hash( q );
  return q->delta;
}
