#include "fd_vote_codec.h"
#include "../../../../ballet/utf8/fd_utf8.h"
#include "../../../../ballet/txn/fd_compact_u16.h"
#include "../../../../ballet/txn/fd_txn.h"

/**********************************************************************/
/* Unified bincode (de)serialization macros.                          */
/* All macros operate on a cursor (uchar const ** data, ulong * sz).  */
/* CHECK returns 1 on failure (non-zero == error).                    */
/**********************************************************************/

#define CHECK( cond ) do {               \
  if( FD_UNLIKELY( !(cond) ) ) return 1; \
} while( 0 )

#define CHECK_RET_NULL( cond ) do {          \
  if( FD_UNLIKELY( !(cond) ) ) return NULL;  \
} while( 0 )

#define CHECK_U64_MUL_OVERFLOW( a, b ) do {                \
  ulong _dummy;                                            \
  CHECK( !__builtin_umull_overflow( (a), (b), &_dummy ) ); \
} while( 0 )

/**********************************************************************/
/* Read macros                                                        */
/**********************************************************************/

#define READ_BYTES( dst, n, data, sz ) do { \
  CHECK( (n)<=(*(sz)) );                    \
  fd_memcpy( (dst), *(data), (n) );         \
  *(data) += (n);                           \
  *(sz) -= (n);                             \
} while( 0 )

#define SKIP_BYTES( n, data, sz ) do { \
  CHECK( (n)<=(*(sz)) );               \
  *(data) += (n);                      \
  *(sz) -= (n);                        \
} while( 0 )

#define READ_U8( dst, data, sz ) do { \
  CHECK( 1UL<=(*(sz)) );              \
  (dst) = FD_LOAD( uchar, *(data) );  \
  *(data) += 1UL;                     \
  *(sz) -= 1UL;                       \
} while( 0 )

#define READ_U16( dst, data, sz ) do {  \
  CHECK( 2UL<=(*(sz)) );                \
  (dst) = FD_LOAD( ushort, *(data) );   \
  *(data) += 2UL;                       \
  *(sz) -= 2UL;                         \
} while( 0 )

#define READ_U32( dst, data, sz ) do { \
  CHECK( 4UL<=(*(sz)) );               \
  (dst) = FD_LOAD( uint, *(data) );    \
  *(data) += 4UL;                      \
  *(sz) -= 4UL;                        \
} while( 0 )

#define READ_U64( dst, data, sz ) do {  \
  CHECK( 8UL<=(*(sz)) );                \
  (dst) = FD_LOAD( ulong, *(data) );    \
  *(data) += 8UL;                       \
  *(sz) -= 8UL;                         \
} while( 0 )

#define READ_I64( dst, data, sz ) do { \
  CHECK( 8UL<=(*(sz)) );               \
  (dst) = FD_LOAD( long, *(data) );    \
  *(data) += 8UL;                      \
  *(sz) -= 8UL;                        \
} while( 0 )

#define READ_HASH( dst, data, sz ) \
  READ_BYTES( (dst).uc, 32UL, data, sz )

#define READ_PUBKEY READ_HASH

#define READ_BOOL( dst, data, sz ) do { \
  READ_U8( dst, data, sz );             \
  CHECK( (dst)==0 || (dst)==1 );        \
} while( 0 )

#define READ_OPTION READ_BOOL

#define READ_ENUM( dst, n, data, sz ) do { \
  CHECK( 4UL<=(*(sz)) );                   \
  (dst) = FD_LOAD( uint, *(data) );        \
  CHECK( (dst)<(n) );                      \
  *(data) += 4UL;                          \
  *(sz) -= 4UL;                            \
} while( 0 )

/* Varint decoder for u64 (LEB128). */
#define READ_U64_VARINT( dst, data, sz ) do {                                  \
  ulong _val = 0UL;                                                            \
  uint  _shift = 0U;                                                           \
  for(;;) {                                                                    \
    CHECK( 1UL<=(*(sz)) );                                                     \
    uchar _byte = FD_LOAD( uchar, *(data) );                                   \
    *(data) += 1UL;                                                            \
    *(sz) -= 1UL;                                                              \
    _val |= (ulong)(_byte & 0x7F) << _shift;                                   \
    if( FD_LIKELY( !(_byte & 0x80) ) ) {                                       \
      CHECK( (_val>>_shift)==(ulong)_byte );     /* last byte not truncated */ \
      CHECK( _byte || !_shift );                 /* no trailing zero bytes */  \
      (dst) = _val;                                                            \
      break;                                                                   \
    }                                                                          \
    _shift += 7U;                                                              \
    CHECK( _shift<64U );                                                       \
  }                                                                            \
} while( 0 )

#define READ_COMPACT_U16( dst, data, sz ) do {      \
  ulong _n = fd_cu16_dec( *(data), *(sz), &(dst) ); \
  CHECK( _n );                                      \
  *(data) += _n;                                    \
  *(sz)   -= _n;                                    \
} while( 0 )

/**********************************************************************/
/* Write macros                                                       */
/**********************************************************************/

#define WRITE_BYTES( src, n, out, out_sz ) do { \
  CHECK( (n)<=(*(out_sz)) );                    \
  fd_memcpy( *(out), (src), (n) );              \
  *(out) += (n);                                \
  *(out_sz) -= (n);                             \
} while( 0 )

#define WRITE_U8( val, out, out_sz ) do { \
  CHECK( 1UL<=(*(out_sz)) );              \
  FD_STORE( uchar, *(out), (val) );       \
  *(out) += 1UL;                          \
  *(out_sz) -= 1UL;                       \
} while( 0 )

#define WRITE_U16( val, out, out_sz ) do { \
  CHECK( 2UL<=(*(out_sz)) );               \
  FD_STORE( ushort, *(out), (val) );       \
  *(out) += 2UL;                           \
  *(out_sz) -= 2UL;                        \
} while( 0 )

#define WRITE_U32( val, out, out_sz ) do { \
  CHECK( 4UL<=(*(out_sz)) );               \
  FD_STORE( uint, *(out), (val) );         \
  *(out) += 4UL;                           \
  *(out_sz) -= 4UL;                        \
} while( 0 )

#define WRITE_U64( val, out, out_sz ) do { \
  CHECK( 8UL<=(*(out_sz)) );               \
  FD_STORE( ulong, *(out), (val) );        \
  *(out) += 8UL;                           \
  *(out_sz) -= 8UL;                        \
} while( 0 )

#define WRITE_I64( val, out, out_sz ) do { \
  CHECK( 8UL<=(*(out_sz)) );               \
  FD_STORE( long, *(out), (val) );         \
  *(out) += 8UL;                           \
  *(out_sz) -= 8UL;                        \
} while( 0 )

#define WRITE_PUBKEY( src, out, out_sz ) \
  WRITE_BYTES( (src).uc, 32UL, out, out_sz )

#define WRITE_BOOL( val, out, out_sz ) \
  WRITE_U8( (uchar)!!(val), out, out_sz )

#define WRITE_OPTION WRITE_BOOL

/**********************************************************************/
/* Vote account state -- deserialization helpers                       */
/* Each returns 0 on success, 1 on failure.                           */
/**********************************************************************/

/* Votes (is_v1_14_11=1 for v1_14_11 Vec<Lockout>, 0 for v3/v4
   Vec<LandedVote>) */
static int
deser_votes( fd_landed_vote_t * votes,
             int                is_v1_14_11,
             uchar const **     ptr,
             ulong *            rem ) {
  ulong votes_len;
  READ_U64( votes_len, ptr, rem );
  CHECK( votes_len<=MAX_LOCKOUT_HISTORY );

  for( ulong i=0UL; i<votes_len; i++ ) {
    fd_landed_vote_t * elem = deq_fd_landed_vote_t_push_tail_nocopy( votes );
    if( is_v1_14_11 ) {
      elem->latency = 0; /* Unused field for v1_14_11 */
    } else {
      READ_U8( elem->latency, ptr, rem );
    }
    READ_U64( elem->lockout.slot, ptr, rem );
    READ_U32( elem->lockout.confirmation_count, ptr, rem );
  }
  return 0;
}

/* Root slot (Option<u64>) */
static int
deser_root_slot( uchar *         has_root_slot,
                 ulong *         root_slot,
                 uchar const **  ptr,
                 ulong *         rem ) {
  uchar opt;
  READ_OPTION( opt, ptr, rem );
  *has_root_slot = opt;
  if( opt ) {
    READ_U64( *root_slot, ptr, rem );
  }
  return 0;
}

/* Authorized voters (BTreeMap<u64, Pubkey>) */
static int
deser_authorized_voters( fd_vote_authorized_voter_t *        pool,
                         fd_vote_authorized_voters_treap_t * treap,
                         uchar const **                      ptr,
                         ulong *                             rem ) {
  ulong authorized_voters_len;
  READ_U64( authorized_voters_len, ptr, rem );
  CHECK( authorized_voters_len<=MAX_AUTHORIZED_VOTERS );
  for( ulong i=0UL; i<authorized_voters_len; i++ ) {
    fd_vote_authorized_voter_t * voter = fd_vote_authorized_voters_pool_ele_acquire( pool );
    READ_U64( voter->epoch, ptr, rem );
    READ_PUBKEY( voter->pubkey, ptr, rem );
    voter->prio = voter->pubkey.uc[0];

    /* Check for existing entries, overwrite if exists */
    fd_vote_authorized_voter_t * existing_voter = fd_vote_authorized_voters_treap_ele_query( treap, voter->epoch, pool );
    if( FD_UNLIKELY( existing_voter ) ) {
      fd_vote_authorized_voters_treap_ele_remove( treap, existing_voter, pool );
      fd_vote_authorized_voters_pool_ele_release( pool, existing_voter );
    }

    fd_vote_authorized_voters_treap_ele_insert( treap, voter, pool );
  }
  return 0;
}

/* Prior voters (fixed-size circular buffer of 32 entries)
   We can directly memcpy the entire buffer because the wire
   format is identical to the in-memory representation of the
   array. */
static int
deser_prior_voters( fd_vote_prior_voters_t * prior_voters,
                    uchar const **           ptr,
                    ulong *                  rem ) {
  READ_BYTES( prior_voters->buf, PRIOR_VOTERS_MAX*sizeof(fd_vote_prior_voter_t), ptr, rem );
  READ_U64( prior_voters->idx, ptr, rem );
  READ_BOOL( prior_voters->is_empty, ptr, rem );
  return 0;
}

/* Epoch credits (Vec<EpochCredits>) */
static int
deser_epoch_credits( fd_vote_epoch_credits_t * epoch_credits,
                     uchar const **            ptr,
                     ulong *                   rem ) {
  ulong epoch_credits_len;
  READ_U64( epoch_credits_len, ptr, rem );
  CHECK( epoch_credits_len<=MAX_EPOCH_CREDITS_HISTORY );
  for( ulong i=0UL; i<epoch_credits_len; i++ ) {
    fd_vote_epoch_credits_t * elem = deq_fd_vote_epoch_credits_t_push_tail_nocopy( epoch_credits );
    READ_BYTES( elem, sizeof(fd_vote_epoch_credits_t), ptr, rem );
  }
  return 0;
}

/**********************************************************************/
/* Vote account state -- serialization helpers                        */
/* Each returns 0 on success, 1 on failure.                           */
/**********************************************************************/

/* Votes (is_v1_14_11=1 for v1_14_11 Vec<Lockout>, 0 for v3/v4
   Vec<LandedVote>) */
static int
ser_votes( fd_landed_vote_t const * votes,
           int                      is_v1_14_11,
           uchar **                 out,
           ulong *                  out_sz ) {
  if( FD_UNLIKELY( votes==NULL ) ) {
    WRITE_U64( 0UL, out, out_sz );
    return 0;
  }

  ulong votes_len = deq_fd_landed_vote_t_cnt( votes );
  WRITE_U64( votes_len, out, out_sz );

  for( deq_fd_landed_vote_t_iter_t iter = deq_fd_landed_vote_t_iter_init( votes );
       !deq_fd_landed_vote_t_iter_done( votes, iter );
       iter = deq_fd_landed_vote_t_iter_next( votes, iter ) ) {
    fd_landed_vote_t const * elem = deq_fd_landed_vote_t_iter_ele_const( votes, iter );
    if( !is_v1_14_11 ) {
      WRITE_U8( elem->latency, out, out_sz );
    }
    WRITE_U64( elem->lockout.slot, out, out_sz );
    WRITE_U32( elem->lockout.confirmation_count, out, out_sz );
  }
  return 0;
}

/* Root slot (Option<u64>) */
static int
ser_root_slot( uchar    has_root_slot,
               ulong    root_slot,
               uchar ** out,
               ulong *  out_sz ) {
  WRITE_BOOL( has_root_slot, out, out_sz );
  if( has_root_slot ) {
    WRITE_U64( root_slot, out, out_sz );
  }
  return 0;
}

/* Authorized voters (BTreeMap<u64, Pubkey>) */
static int
ser_authorized_voters( fd_vote_authorized_voter_t const *        pool,
                       fd_vote_authorized_voters_treap_t const * treap,
                       uchar **                                  out,
                       ulong *                                   out_sz ) {
  if( FD_UNLIKELY( treap==NULL ) ) {
    WRITE_U64( 0UL, out, out_sz );
    return 0;
  }

  ulong len = fd_vote_authorized_voters_treap_ele_cnt( treap );
  WRITE_U64( len, out, out_sz );

  for( fd_vote_authorized_voters_treap_fwd_iter_t iter = fd_vote_authorized_voters_treap_fwd_iter_init( treap, pool );
       !fd_vote_authorized_voters_treap_fwd_iter_done( iter );
       iter = fd_vote_authorized_voters_treap_fwd_iter_next( iter, pool ) ) {
    fd_vote_authorized_voter_t const * voter = fd_vote_authorized_voters_treap_fwd_iter_ele_const( iter, pool );
    WRITE_U64( voter->epoch, out, out_sz );
    WRITE_PUBKEY( voter->pubkey, out, out_sz );
  }
  return 0;
}

/* Prior voters (fixed-size circular buffer of 32 entries)
   We can directly memcpy the entire buffer because the wire
   format is identical to the in-memory representation of the
   array. */
static int
ser_prior_voters( fd_vote_prior_voters_t const * prior_voters,
                  uchar **                       out,
                  ulong *                        out_sz ) {
  WRITE_BYTES( prior_voters->buf, PRIOR_VOTERS_MAX*sizeof(fd_vote_prior_voter_t), out, out_sz );
  WRITE_U64( prior_voters->idx, out, out_sz );
  WRITE_BOOL( prior_voters->is_empty, out, out_sz );
  return 0;
}

/* Epoch credits (Vec<EpochCredits>) */
static int
ser_epoch_credits( fd_vote_epoch_credits_t const * epoch_credits,
                   uchar **                        out,
                   ulong *                         out_sz ) {
  if( FD_UNLIKELY( epoch_credits==NULL ) ) {
    WRITE_U64( 0UL, out, out_sz );
    return 0;
  }

  ulong len = deq_fd_vote_epoch_credits_t_cnt( epoch_credits );
  WRITE_U64( len, out, out_sz );

  for( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( epoch_credits );
       !deq_fd_vote_epoch_credits_t_iter_done( epoch_credits, iter );
       iter = deq_fd_vote_epoch_credits_t_iter_next( epoch_credits, iter ) ) {
    fd_vote_epoch_credits_t const * elem = deq_fd_vote_epoch_credits_t_iter_ele_const( epoch_credits, iter );
    WRITE_BYTES( elem, sizeof(fd_vote_epoch_credits_t), out, out_sz );
  }
  return 0;
}

/**********************************************************************/
/* Wire layout offsets                                                */
/**********************************************************************/

/* Fixed-offset byte positions within the bincode wire format.
   For v1_14_11 and v3 the fixed prefix is: discriminant, node_pubkey,
   authorized_withdrawer, commission.  For v4 the prefix additionally
   includes inflation_rewards_collector, block_revenue_collector,
   inflation_rewards_commission_bps, block_revenue_commission_bps,
   and pending_delegator_rewards before the first variable field. */

#define WIRE_OFF_NODE_PUBKEY       (4UL)
#define WIRE_OFF_V1V3_COMMISSION   (68UL)  /* 4 + 32 + 32 */
#define WIRE_OFF_V4_COMMISSION_BPS (132UL) /* 4 + 32 + 32 + 32 + 32 */

/* Byte size of a Lockout on the wire: u64 slot + u32 confirmation_count */
#define WIRE_LOCKOUT_SZ     (12UL)
/* Byte size of a LandedVote on the wire: u8 latency + u64 slot + u32 confirmation_count */
#define WIRE_LANDED_VOTE_SZ (13UL)
/* Byte size of an authorized voter entry: u64 epoch + 32B pubkey */
#define WIRE_AUTH_VOTER_SZ  (40UL)
/* Byte size of prior_voters on the wire: 32 * 48B + 8B idx + 1B is_empty */
#define WIRE_PRIOR_VOTERS_SZ (PRIOR_VOTERS_MAX * 48UL + 8UL + 1UL)

/* Offset of the votes vector (v1/v3) or BLS option (v4) — first byte
   after the fixed-offset prefix. */
#define WIRE_VOTES_OFF_V1_V3 (69UL)   /* 4 + 32 + 32 + 1 */
#define WIRE_BLS_OFF_V4      (144UL)  /* 4 + 32 + 32 + 32 + 32 + 2 + 2 + 8 */

/**********************************************************************/
/* Vote account state -- direct field accessors                       */
/* These read fields directly from raw bincode-encoded vote account   */
/* data without full deserialization.                                  */
/**********************************************************************/

int
fd_vote_account_node_pubkey( uchar const *  data,
                             ulong          data_sz,
                             fd_pubkey_t *  out ) {
  CHECK( data_sz>=WIRE_OFF_NODE_PUBKEY+32UL );
  fd_memcpy( out, data+WIRE_OFF_NODE_PUBKEY, 32UL );
  return 0;
}

int
fd_vote_account_commission( uchar const * data,
                            ulong         data_sz,
                            uchar *       out ) {
  uchar const * ptr       = data;
  ulong         remaining = data_sz;

  uint discriminant;
  READ_U32( discriminant, &ptr, &remaining );

  switch( discriminant ) {
    case fd_vote_state_versioned_enum_v1_14_11: /* fallthrough */
    case fd_vote_state_versioned_enum_v3:
      CHECK( data_sz>WIRE_OFF_V1V3_COMMISSION );
      *out = data[ WIRE_OFF_V1V3_COMMISSION ];
      return 0;
    case fd_vote_state_versioned_enum_v4:
      CHECK( data_sz>=WIRE_OFF_V4_COMMISSION_BPS+2UL );
      *out = (uchar)( FD_LOAD( ushort, data+WIRE_OFF_V4_COMMISSION_BPS )/100 );
      return 0;
    default:
      return 1;
  }
}

/* Seeks past variable-length fields to the start of epoch_credits.
   On success sets *out_ptr to the first entry and *out_cnt to the
   entry count.  Returns 0 on success, 1 on error. */

static int
seek_epoch_credits( uchar const *                    data,
                    ulong                            data_sz,
                    fd_vote_epoch_credits_t const ** out_ptr,
                    ulong *                          out_cnt ) {
  uchar const * ptr       = data;
  ulong         remaining = data_sz;

  uint discriminant;
  READ_U32( discriminant, &ptr, &remaining );

  switch( discriminant ) {
    case fd_vote_state_versioned_enum_v1_14_11: {
      SKIP_BYTES( WIRE_VOTES_OFF_V1_V3-4UL, &ptr, &remaining );

      /* Skip votes Vec<Lockout> */
      ulong votes_len;
      READ_U64( votes_len, &ptr, &remaining );
      CHECK_U64_MUL_OVERFLOW( votes_len, WIRE_LOCKOUT_SZ );
      SKIP_BYTES( votes_len*WIRE_LOCKOUT_SZ, &ptr, &remaining );

      /* Skip root_slot Option<u64> */
      uchar has_root_slot;
      READ_U8( has_root_slot, &ptr, &remaining );
      if( has_root_slot ) {
        SKIP_BYTES( 8UL, &ptr, &remaining );
      }

      /* Skip authorized_voters BTreeMap<u64, Pubkey> */
      ulong authorized_voters_len;
      READ_U64( authorized_voters_len, &ptr, &remaining );
      CHECK_U64_MUL_OVERFLOW( authorized_voters_len, WIRE_AUTH_VOTER_SZ );
      SKIP_BYTES( authorized_voters_len*WIRE_AUTH_VOTER_SZ, &ptr, &remaining );

      /* Skip prior_voters (fixed size) */
      SKIP_BYTES( WIRE_PRIOR_VOTERS_SZ, &ptr, &remaining );
      break;
    }

    case fd_vote_state_versioned_enum_v3: {
      SKIP_BYTES( WIRE_VOTES_OFF_V1_V3-4UL, &ptr, &remaining );

      /* Skip votes Vec<LandedVote> */
      ulong votes_len;
      READ_U64( votes_len, &ptr, &remaining );
      CHECK_U64_MUL_OVERFLOW( votes_len, WIRE_LANDED_VOTE_SZ );
      SKIP_BYTES( votes_len*WIRE_LANDED_VOTE_SZ, &ptr, &remaining );

      /* Skip root_slot Option<u64> */
      uchar has_root_slot;
      READ_U8( has_root_slot, &ptr, &remaining );
      if( has_root_slot ) {
        SKIP_BYTES( 8UL, &ptr, &remaining );
      }

      /* Skip authorized_voters BTreeMap<u64, Pubkey> */
      ulong authorized_voters_len;
      READ_U64( authorized_voters_len, &ptr, &remaining );
      CHECK_U64_MUL_OVERFLOW( authorized_voters_len, WIRE_AUTH_VOTER_SZ );
      SKIP_BYTES( authorized_voters_len*WIRE_AUTH_VOTER_SZ, &ptr, &remaining );

      /* Skip prior_voters (fixed size) */
      SKIP_BYTES( WIRE_PRIOR_VOTERS_SZ, &ptr, &remaining );
      break;
    }

    case fd_vote_state_versioned_enum_v4: {
      SKIP_BYTES( WIRE_BLS_OFF_V4-4UL, &ptr, &remaining );

      /* Skip Option<bls_pubkey_compressed> */
      uchar has_bls_pubkey;
      READ_U8( has_bls_pubkey, &ptr, &remaining );
      if( has_bls_pubkey ) {
        SKIP_BYTES( FD_BLS_PUBKEY_COMPRESSED_SZ, &ptr, &remaining );
      }

      /* Skip votes Vec<LandedVote> */
      ulong votes_len;
      READ_U64( votes_len, &ptr, &remaining );
      CHECK_U64_MUL_OVERFLOW( votes_len, WIRE_LANDED_VOTE_SZ );
      SKIP_BYTES( votes_len*WIRE_LANDED_VOTE_SZ, &ptr, &remaining );

      /* Skip root_slot Option<u64> */
      uchar has_root_slot;
      READ_U8( has_root_slot, &ptr, &remaining );
      if( has_root_slot ) {
        SKIP_BYTES( 8UL, &ptr, &remaining );
      }

      /* Skip authorized_voters BTreeMap<u64, Pubkey> */
      ulong authorized_voters_len;
      READ_U64( authorized_voters_len, &ptr, &remaining );
      CHECK_U64_MUL_OVERFLOW( authorized_voters_len, WIRE_AUTH_VOTER_SZ );
      SKIP_BYTES( authorized_voters_len*WIRE_AUTH_VOTER_SZ, &ptr, &remaining );
      break;
    }

    default:
      return 1;
  }

  /* Now at epoch_credits deque */
  ulong epoch_credits_len;
  READ_U64( epoch_credits_len, &ptr, &remaining );
  CHECK_U64_MUL_OVERFLOW( epoch_credits_len, sizeof(fd_vote_epoch_credits_t) );
  CHECK( epoch_credits_len*sizeof(fd_vote_epoch_credits_t)<=remaining );

  *out_ptr = (fd_vote_epoch_credits_t const *)ptr;
  *out_cnt = epoch_credits_len;
  return 0;
}

int
fd_vote_account_last_timestamp( uchar const *             data,
                                ulong                     data_sz,
                                fd_vote_block_timestamp_t * out ) {
  fd_vote_epoch_credits_t const * epoch_credits_ptr;
  ulong                           epoch_credits_len;
  CHECK( !seek_epoch_credits( data, data_sz, &epoch_credits_ptr, &epoch_credits_len ) );

  uchar const * timestamp_ptr = (uchar const *)( epoch_credits_ptr + epoch_credits_len );
  CHECK( timestamp_ptr+sizeof(fd_vote_block_timestamp_t)<=data+data_sz );

  fd_memcpy( out, timestamp_ptr, sizeof(fd_vote_block_timestamp_t) );
  return 0;
}

int
fd_vote_account_is_v4_with_bls_pubkey( uchar const * data,
                                       ulong         data_sz ) {
  if( FD_UNLIKELY( data_sz<WIRE_BLS_OFF_V4+1UL ) ) return 0;
  uint discriminant = FD_LOAD( uint, data );
  if( discriminant!=fd_vote_state_versioned_enum_v4 ) return 0;
  return !!data[ WIRE_BLS_OFF_V4 ];
}

fd_vote_epoch_credits_t const *
fd_vote_account_epoch_credits( uchar const * data,
                               ulong         data_sz,
                               ulong *       cnt ) {
  fd_vote_epoch_credits_t const * ptr;
  CHECK_RET_NULL( !seek_epoch_credits( data, data_sz, &ptr, cnt ) );
  return ptr;
}

/**********************************************************************/
/* Vote account state -- public API                                   */
/**********************************************************************/

fd_vote_state_versioned_t *
fd_vote_state_versioned_new( fd_vote_state_versioned_t * self,
                             uint                        kind ) {
  if( FD_UNLIKELY( !self ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  /* Init and join data structures */
  fd_landed_vote_t * votes = deq_fd_landed_vote_t_join(
    deq_fd_landed_vote_t_new( self->landed_votes_mem, MAX_LOCKOUT_HISTORY_CAPACITY )
  );
  fd_vote_epoch_credits_t * epoch_credits = deq_fd_vote_epoch_credits_t_join(
    deq_fd_vote_epoch_credits_t_new( self->epoch_credits_mem )
  );
  fd_vote_authorized_voter_t * authorized_voters_pool  = fd_vote_authorized_voters_pool_join(
    fd_vote_authorized_voters_pool_new( self->authorized_voters_pool_mem, MAX_AUTHORIZED_VOTERS_CAPACITY )
  );
  fd_vote_authorized_voters_treap_t * authorized_voters_treap = fd_vote_authorized_voters_treap_join(
    fd_vote_authorized_voters_treap_new( self->authorized_voters_treap_mem, MAX_AUTHORIZED_VOTERS_CAPACITY )
  );

  self->kind = kind;
  switch( kind ) {
    case fd_vote_state_versioned_enum_uninitialized:
      break;
    case fd_vote_state_versioned_enum_v1_14_11:
      memset( &self->v1_14_11, 0, sizeof(fd_vote_state_1_14_11_t) );
      self->v1_14_11.votes                   = votes;
      self->v1_14_11.epoch_credits           = epoch_credits;
      self->v1_14_11.authorized_voters.pool  = authorized_voters_pool;
      self->v1_14_11.authorized_voters.treap = authorized_voters_treap;
      break;
    case fd_vote_state_versioned_enum_v3:
      memset( &self->v3, 0, sizeof(fd_vote_state_v3_t) );
      self->v3.votes                   = votes;
      self->v3.epoch_credits           = epoch_credits;
      self->v3.authorized_voters.pool  = authorized_voters_pool;
      self->v3.authorized_voters.treap = authorized_voters_treap;
      break;
    case fd_vote_state_versioned_enum_v4:
      memset( &self->v4, 0, sizeof(fd_vote_state_v4_t) );
      self->v4.votes                    = votes;
      self->v4.epoch_credits            = epoch_credits;
      self->v4.authorized_voters.pool   = authorized_voters_pool;
      self->v4.authorized_voters.treap  = authorized_voters_treap;
      break;
    default:
      return NULL;
  }

  return self;
}

static int
fd_vote_state_versioned_deserialize_inner( fd_vote_state_versioned_t * self,
                                           uchar const *               payload,
                                           ulong                       payload_sz ) {
  CHECK( self!=NULL );
  CHECK( payload!=NULL );

  uchar const * ptr = payload;
  ulong         rem = payload_sz;

  uint kind;
  READ_U32( kind, &ptr, &rem );

  CHECK( fd_vote_state_versioned_new( self, kind )!=NULL );

  switch( self->kind ) {
    case fd_vote_state_versioned_enum_uninitialized:
      /* No-op, nothing to decode */
      return 0;

    case fd_vote_state_versioned_enum_v1_14_11: {
      READ_PUBKEY( self->v1_14_11.node_pubkey, &ptr, &rem );
      READ_PUBKEY( self->v1_14_11.authorized_withdrawer, &ptr, &rem );
      READ_U8( self->v1_14_11.commission, &ptr, &rem );
      CHECK( !deser_votes( self->v1_14_11.votes, 1, &ptr, &rem ) ); /* v1_14_11 wire format is Lockout, not LandedVote */
      CHECK( !deser_root_slot( &self->v1_14_11.has_root_slot, &self->v1_14_11.root_slot, &ptr, &rem ) );
      CHECK( !deser_authorized_voters( self->v1_14_11.authorized_voters.pool, self->v1_14_11.authorized_voters.treap, &ptr, &rem ) );
      CHECK( !deser_prior_voters( &self->v1_14_11.prior_voters, &ptr, &rem ) );
      CHECK( !deser_epoch_credits( self->v1_14_11.epoch_credits, &ptr, &rem ) );
      READ_BYTES( &self->v1_14_11.last_timestamp, sizeof(fd_vote_block_timestamp_t), &ptr, &rem );
      break;
    }

    case fd_vote_state_versioned_enum_v3: {
      READ_PUBKEY( self->v3.node_pubkey, &ptr, &rem );
      READ_PUBKEY( self->v3.authorized_withdrawer, &ptr, &rem );
      READ_U8( self->v3.commission, &ptr, &rem );
      CHECK( !deser_votes( self->v3.votes, 0, &ptr, &rem ) );
      CHECK( !deser_root_slot( &self->v3.has_root_slot, &self->v3.root_slot, &ptr, &rem ) );
      CHECK( !deser_authorized_voters( self->v3.authorized_voters.pool, self->v3.authorized_voters.treap, &ptr, &rem ) );
      CHECK( !deser_prior_voters( &self->v3.prior_voters, &ptr, &rem ) );
      CHECK( !deser_epoch_credits( self->v3.epoch_credits, &ptr, &rem ) );
      READ_BYTES( &self->v3.last_timestamp, sizeof(fd_vote_block_timestamp_t), &ptr, &rem );
      break;
    }

    case fd_vote_state_versioned_enum_v4: {
      READ_PUBKEY( self->v4.node_pubkey, &ptr, &rem );
      READ_PUBKEY( self->v4.authorized_withdrawer, &ptr, &rem );
      READ_PUBKEY( self->v4.inflation_rewards_collector, &ptr, &rem );
      READ_PUBKEY( self->v4.block_revenue_collector, &ptr, &rem );
      READ_U16( self->v4.inflation_rewards_commission_bps, &ptr, &rem );
      READ_U16( self->v4.block_revenue_commission_bps, &ptr, &rem );
      READ_U64( self->v4.pending_delegator_rewards, &ptr, &rem );

      /* Option<[u8; 48]> */
      READ_OPTION( self->v4.has_bls_pubkey_compressed, &ptr, &rem );
      if( self->v4.has_bls_pubkey_compressed ) {
        READ_BYTES( self->v4.bls_pubkey_compressed, FD_BLS_PUBKEY_COMPRESSED_SZ, &ptr, &rem );
      }

      CHECK( !deser_votes( self->v4.votes, 0, &ptr, &rem ) );
      CHECK( !deser_root_slot( &self->v4.has_root_slot, &self->v4.root_slot, &ptr, &rem ) );
      CHECK( !deser_authorized_voters( self->v4.authorized_voters.pool, self->v4.authorized_voters.treap, &ptr, &rem ) );
      CHECK( !deser_epoch_credits( self->v4.epoch_credits, &ptr, &rem ) ); /* v4 has no prior_voters */
      READ_BYTES( &self->v4.last_timestamp, sizeof(fd_vote_block_timestamp_t), &ptr, &rem );
      break;
    }

    default:
      return 1;
  }

  return 0;
}

fd_vote_state_versioned_t *
fd_vote_state_versioned_deserialize( fd_vote_state_versioned_t * self,
                                     uchar const *               payload,
                                     ulong                       payload_sz ) {
  CHECK_RET_NULL( !fd_vote_state_versioned_deserialize_inner( self, payload, payload_sz ) );
  return self;
}

int
fd_vote_state_versioned_serialize( fd_vote_state_versioned_t const * self,
                                   uchar *                           buf,
                                   ulong                             buf_sz ) {
  CHECK( self!=NULL );
  CHECK( buf!=NULL );

  uchar * out    = buf;
  ulong   out_sz = buf_sz;

  WRITE_U32( self->kind, &out, &out_sz );

  switch( self->kind ) {
    case fd_vote_state_versioned_enum_uninitialized:
      /* No-op, nothing to encode */
      return 0;

    case fd_vote_state_versioned_enum_v1_14_11: {
      WRITE_PUBKEY( self->v1_14_11.node_pubkey, &out, &out_sz );
      WRITE_PUBKEY( self->v1_14_11.authorized_withdrawer, &out, &out_sz );
      WRITE_U8( self->v1_14_11.commission, &out, &out_sz );
      CHECK( !ser_votes( self->v1_14_11.votes, 1, &out, &out_sz ) ); /* v1_14_11 wire format is Lockout, not LandedVote */
      CHECK( !ser_root_slot( self->v1_14_11.has_root_slot, self->v1_14_11.root_slot, &out, &out_sz ) );
      CHECK( !ser_authorized_voters( self->v1_14_11.authorized_voters.pool, self->v1_14_11.authorized_voters.treap, &out, &out_sz ) );
      CHECK( !ser_prior_voters( &self->v1_14_11.prior_voters, &out, &out_sz ) );
      CHECK( !ser_epoch_credits( self->v1_14_11.epoch_credits, &out, &out_sz ) );
      WRITE_BYTES( &self->v1_14_11.last_timestamp, sizeof(fd_vote_block_timestamp_t), &out, &out_sz );
      break;
    }

    case fd_vote_state_versioned_enum_v3: {
      WRITE_PUBKEY( self->v3.node_pubkey, &out, &out_sz );
      WRITE_PUBKEY( self->v3.authorized_withdrawer, &out, &out_sz );
      WRITE_U8( self->v3.commission, &out, &out_sz );
      CHECK( !ser_votes( self->v3.votes, 0, &out, &out_sz ) );
      CHECK( !ser_root_slot( self->v3.has_root_slot, self->v3.root_slot, &out, &out_sz ) );
      CHECK( !ser_authorized_voters( self->v3.authorized_voters.pool, self->v3.authorized_voters.treap, &out, &out_sz ) );
      CHECK( !ser_prior_voters( &self->v3.prior_voters, &out, &out_sz ) );
      CHECK( !ser_epoch_credits( self->v3.epoch_credits, &out, &out_sz ) );
      WRITE_BYTES( &self->v3.last_timestamp, sizeof(fd_vote_block_timestamp_t), &out, &out_sz );
      break;
    }

    case fd_vote_state_versioned_enum_v4: {
      WRITE_PUBKEY( self->v4.node_pubkey, &out, &out_sz );
      WRITE_PUBKEY( self->v4.authorized_withdrawer, &out, &out_sz );
      WRITE_PUBKEY( self->v4.inflation_rewards_collector, &out, &out_sz );
      WRITE_PUBKEY( self->v4.block_revenue_collector, &out, &out_sz );
      WRITE_U16( self->v4.inflation_rewards_commission_bps, &out, &out_sz );
      WRITE_U16( self->v4.block_revenue_commission_bps, &out, &out_sz );
      WRITE_U64( self->v4.pending_delegator_rewards, &out, &out_sz );

      /* Option<[u8; 48]> */
      WRITE_OPTION( self->v4.has_bls_pubkey_compressed, &out, &out_sz );
      if( self->v4.has_bls_pubkey_compressed ) {
        WRITE_BYTES( self->v4.bls_pubkey_compressed, FD_BLS_PUBKEY_COMPRESSED_SZ, &out, &out_sz );
      }

      CHECK( !ser_votes( self->v4.votes, 0, &out, &out_sz ) );
      CHECK( !ser_root_slot( self->v4.has_root_slot, self->v4.root_slot, &out, &out_sz ) );
      CHECK( !ser_authorized_voters( self->v4.authorized_voters.pool, self->v4.authorized_voters.treap, &out, &out_sz ) );
      CHECK( !ser_epoch_credits( self->v4.epoch_credits, &out, &out_sz ) ); /* v4 has no prior_voters */
      WRITE_BYTES( &self->v4.last_timestamp, sizeof(fd_vote_block_timestamp_t), &out, &out_sz );
      break;
    }

    default:
      return 1;
  }

  return 0;
}

ulong
fd_vote_state_versioned_serialized_size( fd_vote_state_versioned_t const * self ) {
  switch( self->kind ) {

    case fd_vote_state_versioned_enum_uninitialized:
      return 4UL;

    case fd_vote_state_versioned_enum_v1_14_11: {
      ulong votes_cnt         = self->v1_14_11.votes                   ? deq_fd_landed_vote_t_cnt( self->v1_14_11.votes )                                  : 0UL;
      ulong auth_voters_cnt   = self->v1_14_11.authorized_voters.treap ? fd_vote_authorized_voters_treap_ele_cnt( self->v1_14_11.authorized_voters.treap ) : 0UL;
      ulong epoch_credits_cnt = self->v1_14_11.epoch_credits           ? deq_fd_vote_epoch_credits_t_cnt( self->v1_14_11.epoch_credits )                   : 0UL;
      return WIRE_VOTES_OFF_V1_V3
           + 8UL + votes_cnt * WIRE_LOCKOUT_SZ
           + 1UL + (ulong)self->v1_14_11.has_root_slot * 8UL
           + 8UL + auth_voters_cnt * WIRE_AUTH_VOTER_SZ
           + WIRE_PRIOR_VOTERS_SZ
           + 8UL + epoch_credits_cnt * sizeof(fd_vote_epoch_credits_t)
           + sizeof(fd_vote_block_timestamp_t);
    }

    case fd_vote_state_versioned_enum_v3: {
      ulong votes_cnt         = self->v3.votes                   ? deq_fd_landed_vote_t_cnt( self->v3.votes )                                  : 0UL;
      ulong auth_voters_cnt   = self->v3.authorized_voters.treap ? fd_vote_authorized_voters_treap_ele_cnt( self->v3.authorized_voters.treap )  : 0UL;
      ulong epoch_credits_cnt = self->v3.epoch_credits           ? deq_fd_vote_epoch_credits_t_cnt( self->v3.epoch_credits )                    : 0UL;
      return WIRE_VOTES_OFF_V1_V3
           + 8UL + votes_cnt * WIRE_LANDED_VOTE_SZ
           + 1UL + (ulong)self->v3.has_root_slot * 8UL
           + 8UL + auth_voters_cnt * WIRE_AUTH_VOTER_SZ
           + WIRE_PRIOR_VOTERS_SZ
           + 8UL + epoch_credits_cnt * sizeof(fd_vote_epoch_credits_t)
           + sizeof(fd_vote_block_timestamp_t);
    }

    case fd_vote_state_versioned_enum_v4: {
      ulong votes_cnt         = self->v4.votes                   ? deq_fd_landed_vote_t_cnt( self->v4.votes )                                  : 0UL;
      ulong auth_voters_cnt   = self->v4.authorized_voters.treap ? fd_vote_authorized_voters_treap_ele_cnt( self->v4.authorized_voters.treap )  : 0UL;
      ulong epoch_credits_cnt = self->v4.epoch_credits           ? deq_fd_vote_epoch_credits_t_cnt( self->v4.epoch_credits )                    : 0UL;
      return WIRE_BLS_OFF_V4
           + 1UL + (ulong)self->v4.has_bls_pubkey_compressed * FD_BLS_PUBKEY_COMPRESSED_SZ
           + 8UL + votes_cnt * WIRE_LANDED_VOTE_SZ
           + 1UL + (ulong)self->v4.has_root_slot * 8UL
           + 8UL + auth_voters_cnt * WIRE_AUTH_VOTER_SZ
           + 8UL + epoch_credits_cnt * sizeof(fd_vote_epoch_credits_t)
           + sizeof(fd_vote_block_timestamp_t);
    }

    default:
      return 0UL;
  }
}

/**********************************************************************/
/* Vote instruction -- per-variant deserializers                      */
/**********************************************************************/

static int
deser_vote_authorize( fd_vote_authorize_t * out,
                      uchar const **        data,
                      ulong *               sz ) {
  READ_ENUM( out->discriminant, 3U, data, sz );
  if( out->discriminant==fd_vote_authorize_enum_voter_with_bls ) {
    READ_BYTES( out->voter_with_bls.bls_pubkey, FD_BLS_PUBKEY_COMPRESSED_SZ, data, sz );
    READ_BYTES( out->voter_with_bls.bls_proof_of_possession, FD_BLS_PROOF_OF_POSSESSION_COMPRESSED_SZ, data, sz );
  }
  return 0;
}

static int
deser_vote_init( fd_vote_init_t * out,
                 uchar const **   data,
                 ulong *          sz ) {
  READ_BYTES( out, sizeof(fd_vote_init_t), data, sz );
  return 0;
}

static int
deser_vote_init_v2( fd_vote_init_v2_t * out,
                    uchar const **      data,
                    ulong *             sz ) {
  READ_PUBKEY( out->node_pubkey, data, sz );
  READ_PUBKEY( out->authorized_voter, data, sz );
  READ_BYTES( out->authorized_voter_bls_pubkey, FD_BLS_PUBKEY_COMPRESSED_SZ, data, sz );
  READ_BYTES( out->authorized_voter_bls_proof_of_possession, FD_BLS_PROOF_OF_POSSESSION_COMPRESSED_SZ, data, sz );
  READ_PUBKEY( out->authorized_withdrawer, data, sz );
  READ_U16( out->inflation_rewards_commission_bps, data, sz );
  READ_PUBKEY( out->inflation_rewards_collector, data, sz );
  READ_U16( out->block_revenue_commission_bps, data, sz );
  READ_PUBKEY( out->block_revenue_collector, data, sz );
  return 0;
}

static int
deser_vote( fd_vote_t *     out,
            uchar const **  data,
            ulong *         sz ) {
  ulong slots_len;
  READ_U64( slots_len, data, sz );
  CHECK( slots_len<=FD_VOTE_INSTR_MAX_SLOT_NUMS_LEN );

  out->slots = deq_ulong_join( deq_ulong_new( out->slots_mem, FD_VOTE_INSTR_MAX_SLOT_NUMS_LEN ) );

  for( ulong i=0UL; i<slots_len; i++ ) {
    ulong * elem = deq_ulong_push_tail_nocopy( out->slots );
    READ_U64( *elem, data, sz );
  }

  READ_HASH( out->hash, data, sz );
  READ_OPTION( out->has_timestamp, data, sz );
  if( out->has_timestamp ) {
    READ_I64( out->timestamp, data, sz );
  }
  return 0;
}

static int
deser_vote_state_update( fd_vote_state_update_t * out,
                         uchar const **           data,
                         ulong *                  sz ) {
  ulong lockouts_len;
  READ_U64( lockouts_len, data, sz );
  CHECK( lockouts_len<=FD_VOTE_INSTR_MAX_LOCKOUTS_LEN );

  out->lockouts = deq_fd_vote_lockout_t_join( deq_fd_vote_lockout_t_new( out->lockouts_mem, FD_VOTE_INSTR_MAX_LOCKOUTS_LEN ) );

  for( ulong i=0; i<lockouts_len; i++ ) {
    fd_vote_lockout_t * elem = deq_fd_vote_lockout_t_push_tail_nocopy( out->lockouts );
    READ_U64( elem->slot, data, sz );
    READ_U32( elem->confirmation_count, data, sz );
  }

  READ_OPTION( out->has_root, data, sz );
  if( out->has_root ) {
    READ_U64( out->root, data, sz );
  }
  READ_HASH( out->hash, data, sz );
  READ_OPTION( out->has_timestamp, data, sz );
  if( out->has_timestamp ) {
    READ_I64( out->timestamp, data, sz );
  }
  return 0;
}

/* This function contains slightly custom deserialization logic to
   adhere to serde_compact_vote_state_update in Agave.
   https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v5.1.1/vote-interface/src/state/mod.rs#L265-L299 */
static int
deser_compact_vote_state_update( fd_compact_vote_state_update_t * out,
                                 uchar const **                   data,
                                 ulong *                          sz ) {
  READ_U64( out->root, data, sz );

  ushort lockouts_len;
  READ_COMPACT_U16( lockouts_len, data, sz );
  CHECK( lockouts_len<=FD_VOTE_INSTR_MAX_LOCKOUT_OFFSETS_LEN );
  out->lockouts_len = lockouts_len;

  out->lockouts = (fd_lockout_offset_t *)out->lockouts_mem;

  ulong slot = out->root!=ULONG_MAX ? out->root : 0UL;
  for( ushort i=0; i<lockouts_len; i++ ) {
    READ_U64_VARINT( out->lockouts[i].offset, data, sz );
    READ_U8( out->lockouts[i].confirmation_count, data, sz );

    /* Custom logic: check that slot+lockout_offset
       does not overflow */
    CHECK( !__builtin_uaddl_overflow( slot, out->lockouts[i].offset, &slot ) );
  }

  READ_HASH( out->hash, data, sz );
  READ_OPTION( out->has_timestamp, data, sz );
  if( out->has_timestamp ) {
    READ_I64( out->timestamp, data, sz );
  }
  return 0;
}

/* Similar to above. Tower sync uses delta-encoded lockout offsets,
   converting them to absolute slot numbers on the fly.  Mirrors the
   checked arithmetic from Agave's custom deserializer:
   https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v5.1.1/vote-interface/src/state/mod.rs#L360-L396 */

static int
deser_tower_sync( fd_tower_sync_t * out,
                  uchar const **    data,
                  ulong *           sz ) {
  READ_U64( out->root, data, sz );
  out->has_root = 1;

  /* First bit of custom logic: if root is ULONG_MAX, set root to 0. */
  if( FD_UNLIKELY( out->root==ULONG_MAX ) ) {
    out->has_root = 0;
    out->root     = 0UL;
  }

  ushort lockout_offsets_len;
  READ_COMPACT_U16( lockout_offsets_len, data, sz );
  CHECK( lockout_offsets_len<=FD_VOTE_INSTR_MAX_LOCKOUT_OFFSETS_LEN );

  out->lockouts = deq_fd_vote_lockout_t_join( deq_fd_vote_lockout_t_new( out->lockouts_mem, FD_VOTE_INSTR_MAX_LOCKOUT_OFFSETS_LEN ) );

  ulong last_slot = out->root;
  for( ushort i=0; i<lockout_offsets_len; i++ ) {
    fd_vote_lockout_t * elem = deq_fd_vote_lockout_t_push_tail_nocopy( out->lockouts );

    ulong offset;
    READ_U64_VARINT( offset, data, sz );

    uchar confirmation_count;
    READ_U8( confirmation_count, data, sz );

    /* Second bit of custom logic: check that last_slot+offset does not
       overflow */
    CHECK( !__builtin_uaddl_overflow( last_slot, offset, &elem->slot ) );
    elem->confirmation_count = (uint)confirmation_count;
    last_slot = elem->slot;
  }

  out->lockouts_cnt = (ulong)lockout_offsets_len;

  READ_HASH( out->hash, data, sz );
  READ_OPTION( out->has_timestamp, data, sz );
  if( out->has_timestamp ) {
    READ_I64( out->timestamp, data, sz );
  }
  READ_HASH( out->block_id, data, sz );
  return 0;
}

static int
deser_vote_authorize_with_seed( fd_vote_authorize_with_seed_args_t * out,
                                uchar const **                       data,
                                ulong *                              sz ) {
  CHECK( !deser_vote_authorize( &out->authorization_type, data, sz ) );
  READ_PUBKEY( out->current_authority_derived_key_owner, data, sz );

  ulong seed_len;
  READ_U64( seed_len, data, sz );
  CHECK( seed_len<=FD_TXN_MTU );
  out->current_authority_derived_key_seed_len = seed_len;

  READ_BYTES( out->current_authority_derived_key_seed, seed_len, data, sz );
  CHECK( fd_utf8_verify( (char const *)out->current_authority_derived_key_seed, seed_len ) );

  READ_PUBKEY( out->new_authority, data, sz );
  return 0;
}

static int
deser_vote_authorize_checked_with_seed( fd_vote_authorize_checked_with_seed_args_t * out,
                                        uchar const **                               data,
                                        ulong *                                      sz ) {
  CHECK( !deser_vote_authorize( &out->authorization_type, data, sz ) );
  READ_PUBKEY( out->current_authority_derived_key_owner, data, sz );

  ulong seed_len;
  READ_U64( seed_len, data, sz );
  CHECK( seed_len<=FD_TXN_MTU );
  out->current_authority_derived_key_seed_len = seed_len;

  READ_BYTES( out->current_authority_derived_key_seed, seed_len, data, sz );
  CHECK( fd_utf8_verify( (char const *)out->current_authority_derived_key_seed, seed_len ) );
  return 0;
}

/**********************************************************************/
/* Vote instruction -- top-level decoder                              */
/**********************************************************************/

static int
fd_vote_instruction_deserialize_inner( fd_vote_instruction_t * instruction,
                                       uchar const *           data,
                                       ulong                   data_sz ) {
  fd_memset( instruction, 0, sizeof(fd_vote_instruction_t) );

  uchar const ** p  = &data;
  ulong *        sz = &data_sz;

  READ_U32( instruction->discriminant, p, sz );

  switch( instruction->discriminant ) {

    case fd_vote_instruction_enum_initialize_account:
      return deser_vote_init( &instruction->initialize_account, p, sz );

    case fd_vote_instruction_enum_authorize: {
      READ_PUBKEY( instruction->authorize.pubkey, p, sz );
      return deser_vote_authorize( &instruction->authorize.vote_authorize, p, sz );
    }

    case fd_vote_instruction_enum_vote:
      return deser_vote( &instruction->vote, p, sz );

    case fd_vote_instruction_enum_withdraw:
      READ_U64( instruction->withdraw, p, sz );
      return 0;

    case fd_vote_instruction_enum_update_validator_identity:
      return 0;

    case fd_vote_instruction_enum_update_commission:
      READ_U8( instruction->update_commission, p, sz );
      return 0;

    case fd_vote_instruction_enum_vote_switch:
      CHECK( !deser_vote( &instruction->vote_switch.vote, p, sz ) );
      READ_HASH( instruction->vote_switch.hash, p, sz );
      return 0;

    case fd_vote_instruction_enum_authorize_checked:
      return deser_vote_authorize( &instruction->authorize_checked, p, sz );

    case fd_vote_instruction_enum_update_vote_state:
      return deser_vote_state_update( &instruction->update_vote_state, p, sz );

    case fd_vote_instruction_enum_update_vote_state_switch:
      CHECK( !deser_vote_state_update( &instruction->update_vote_state_switch.vote_state_update, p, sz ) );
      READ_HASH( instruction->update_vote_state_switch.hash, p, sz );
      return 0;

    case fd_vote_instruction_enum_authorize_with_seed:
      return deser_vote_authorize_with_seed( &instruction->authorize_with_seed, p, sz );

    case fd_vote_instruction_enum_authorize_checked_with_seed:
      return deser_vote_authorize_checked_with_seed( &instruction->authorize_checked_with_seed, p, sz );

    case fd_vote_instruction_enum_compact_update_vote_state:
      return deser_compact_vote_state_update( &instruction->compact_update_vote_state, p, sz );

    case fd_vote_instruction_enum_compact_update_vote_state_switch:
      CHECK( !deser_compact_vote_state_update( &instruction->compact_update_vote_state_switch.compact_vote_state_update, p, sz ) );
      READ_HASH( instruction->compact_update_vote_state_switch.hash, p, sz );
      return 0;

    case fd_vote_instruction_enum_tower_sync:
      return deser_tower_sync( &instruction->tower_sync, p, sz );

    case fd_vote_instruction_enum_tower_sync_switch:
      CHECK( !deser_tower_sync( &instruction->tower_sync_switch.tower_sync, p, sz ) );
      READ_HASH( instruction->tower_sync_switch.hash, p, sz );
      return 0;

    case fd_vote_instruction_enum_initialize_account_v2:
      return deser_vote_init_v2( &instruction->initialize_account_v2, p, sz );

    case fd_vote_instruction_enum_update_commission_collector:
      READ_ENUM( instruction->update_commission_collector.discriminant, 2U, p, sz );
      return 0;

    case fd_vote_instruction_enum_update_commission_bps:
      READ_U16( instruction->update_commission_bps.commission_bps, p, sz );
      READ_ENUM( instruction->update_commission_bps.kind.discriminant, 2U, p, sz );
      return 0;

    case fd_vote_instruction_enum_deposit_delegator_rewards:
      READ_U64( instruction->deposit_delegator_rewards.deposit, p, sz );
      return 0;

    default:
      return 1;
  }
}

fd_vote_instruction_t *
fd_vote_instruction_deserialize( fd_vote_instruction_t * instruction,
                                 uchar const *           data,
                                 ulong                   data_sz ) {
  CHECK_RET_NULL( !fd_vote_instruction_deserialize_inner( instruction, data, data_sz ) );
  return instruction;
}
