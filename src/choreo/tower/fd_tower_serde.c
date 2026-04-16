#include <stdio.h>

#include "fd_tower_serde.h"
#include "fd_tower.h"
#include "../../flamenco/txn/fd_txn_generate.h"
#include "../../flamenco/runtime/fd_system_ids.h"

#define SHORTVEC 0

#define DE( T, name ) do {                                \
    if( FD_UNLIKELY( buf_sz<sizeof(T) ) ) return -1;      \
    serde->name = *(T const *)fd_type_pun_const( buf );   \
    buf    += sizeof(T);                                  \
    buf_sz -= sizeof(T);                                  \
} while(0)

#define SER( T, name ) do {                               \
    if( FD_UNLIKELY( off+sizeof(T)>buf_max ) ) return -1; \
    FD_STORE( T, buf+off, serde->name );                  \
    off += sizeof(T);                                     \
} while(0)

static int
de_short_u16( ushort * dst, uchar const ** src, ulong * src_sz ) {
  uchar const * s = *src;
  if( FD_UNLIKELY( *src_sz<1 ) ) return -1;
  if( FD_LIKELY( !( 0x80U & s[0] ) ) ) {
    *dst = (ushort)s[0];
    *src += 1;
    *src_sz -= 1;
    return 0;
  }
  if( FD_UNLIKELY( *src_sz<2 ) ) return -1;
  if( FD_LIKELY( !( 0x80U & s[1] ) ) ) {
    if( FD_UNLIKELY( !s[1] ) ) return -1; /* non-canonical: value fits in 1 byte */
    *dst = (ushort)( (ulong)(s[0]&0x7FUL) + (((ulong)s[1])<<7) );
    *src += 2;
    *src_sz -= 2;
    return 0;
  }
  if( FD_UNLIKELY( *src_sz<3    ) ) return -1;
  if( FD_UNLIKELY( 0x80U & s[2] ) ) return -1; /* 3rd byte is final; continuation bit is invalid */
  if( FD_UNLIKELY( !s[2]        ) ) return -1; /* non-canonical: value fits in 2 bytes */
  ulong val = (ulong)(s[0]&0x7FUL) + (((ulong)(s[1]&0x7FUL))<<7) + (((ulong)s[2])<<14);
  if( FD_UNLIKELY( val>USHORT_MAX ) ) return -1;
  *dst = (ushort)val;
  *src += 3;
  *src_sz -= 3;
  return 0;
}

static int
de_var_int( ulong * dst, uchar const ** src, ulong * src_sz ) {
  *dst = 0;
  ulong bit = 0;
  while( FD_LIKELY( bit < 64 ) ) {
    if( FD_UNLIKELY( !*src_sz ) ) return -1;
    uchar byte = **src;
    (*src)++; (*src_sz)--;
    *dst |= (ulong)(byte & 0x7FUL) << bit;
    if( FD_LIKELY( (byte & 0x80U) == 0U ) ) {
      if( FD_UNLIKELY( (*dst>>bit) != byte                ) ) return -1;
      if( FD_UNLIKELY( byte==0U && (bit!=0U || *dst!=0UL) ) ) return -1;
      return 0;
    }
    bit += 7;
  }
  return -1;
}

static ulong
ser_short_u16( uchar * dst, ushort val ) {
  if     ( FD_LIKELY( val < 0x80U ) ) {
    dst[0] = (uchar)val;
    return 1;
  }
  else if( FD_LIKELY( val < 0x4000U ) ) {
    dst[0] = (uchar)((val & 0x7FUL) | 0x80U);
    dst[1] = (uchar)(val >> 7);
    return 2;
  }
  else {
    dst[0] = (uchar)((val & 0x7FUL) | 0x80U);
    dst[1] = (uchar)(((val >> 7) & 0x7FUL) | 0x80U);
    dst[2] = (uchar)(val >> 14);
    return 3;
  }
}

static ulong
ser_var_int( uchar * dst, ulong val ) {
  ulong off = 0;
  while( FD_LIKELY( val >= 0x80UL ) ) {
    dst[off] = (uchar)((val & 0x7FUL) | 0x80U);
    val >>= 7;
    off  += 1;
  }
  dst[off] = (uchar)val;
  return off + 1;
}

int
fd_compact_tower_sync_de( fd_compact_tower_sync_serde_t * serde,
                          uchar const *                   buf,
                          ulong                           buf_sz ) {
  DE( ulong, root );
  if( FD_UNLIKELY( de_short_u16( &serde->lockouts_cnt, &buf, &buf_sz ) ) ) return -1;
  if( FD_UNLIKELY( serde->lockouts_cnt > FD_TOWER_VOTE_MAX ) ) return -1;
  for( ulong i = 0; i < serde->lockouts_cnt; i++ ) {
    if( FD_UNLIKELY( de_var_int( &serde->lockouts[i].offset, &buf, &buf_sz ) ) ) return -1;
    DE( uchar, lockouts[i].confirmation_count );
  }
  DE( fd_hash_t, hash             );
  DE( uchar,     timestamp_option );
  if( FD_UNLIKELY( serde->timestamp_option!=1 && serde->timestamp_option!=0 ) ) return -1;
  if( FD_LIKELY( serde->timestamp_option ) ) {
    DE( long, timestamp );
  }
  DE( fd_hash_t, block_id );
  return 0;
}

int
fd_compact_tower_sync_ser( fd_compact_tower_sync_serde_t const * serde,
                           uchar *                               buf,
                           ulong                                 buf_max,
                           ulong *                               buf_sz ) {
  ulong off = 0;
  SER( ulong, root );
  off += ser_short_u16( buf+off, serde->lockouts_cnt );
  if( FD_UNLIKELY( serde->lockouts_cnt > FD_TOWER_VOTE_MAX ) ) return -1;
  for( ulong i = 0; i < serde->lockouts_cnt; i++ ) {
    off += ser_var_int( buf+off, serde->lockouts[i].offset );
    SER( uchar, lockouts[i].confirmation_count );
  }
  SER( fd_hash_t, hash             );
  SER( uchar,     timestamp_option );
  if( FD_LIKELY( serde->timestamp_option ) ) {
    SER( long, timestamp );
  }
  SER( fd_hash_t, block_id );
  if( FD_LIKELY( buf_sz ) ) *buf_sz = off;
  return 0;
}

static fd_lat_vote_t const *
v4_off( fd_vote_acc_t const * voter ) {
  return (fd_lat_vote_t const *)( voter->v4.bls_pubkey_compressed + voter->v4.has_bls_pubkey_compressed * sizeof(voter->v4.bls_pubkey_compressed) + sizeof(ulong) );
}

ulong
fd_vote_acc_vote_cnt( uchar const * vote_account_data ) {
  fd_vote_acc_t const * voter = (fd_vote_acc_t const *)fd_type_pun_const( vote_account_data );
  switch( voter->kind ) {
  case FD_VOTE_ACC_V4: return fd_ulong_load_8( voter->v4.bls_pubkey_compressed + voter->v4.has_bls_pubkey_compressed * sizeof(voter->v4.bls_pubkey_compressed) );
  case FD_VOTE_ACC_V3: return voter->v3.votes_cnt;
  case FD_VOTE_ACC_V2: return voter->v2.votes_cnt;
  default: FD_LOG_HEXDUMP_CRIT(( "bad voter", vote_account_data, 3762 ));
  }
}

/* fd_vote_acc_vote_slot takes a voter's vote account data and returns the
   voter's most recent vote slot in the tower.  Returns ULONG_MAX if
   they have an empty tower. */

ulong
fd_vote_acc_vote_slot( uchar const * vote_account_data ) {
  fd_vote_acc_t const * voter = (fd_vote_acc_t const *)fd_type_pun_const( vote_account_data );
  ulong              cnt   = fd_vote_acc_vote_cnt( vote_account_data );
  switch( voter->kind ) {
  case FD_VOTE_ACC_V4: return cnt ? v4_off( voter )[cnt-1].slot : ULONG_MAX;
  case FD_VOTE_ACC_V3: return cnt ? voter->v3.votes[cnt-1].slot : ULONG_MAX;
  case FD_VOTE_ACC_V2: return cnt ? voter->v2.votes[cnt-1].slot : ULONG_MAX;
  default: FD_LOG_HEXDUMP_CRIT(( "bad voter", vote_account_data, 3762 ));
  }
}

/* fd_vote_acc_root_slot takes a voter's vote account data and returns the
   voter's root slot.  Returns ULONG_MAX if they don't have a root. */

ulong
fd_vote_acc_root_slot( uchar const * vote_account_data ) {
  fd_vote_acc_t const * voter = (fd_vote_acc_t const *)fd_type_pun_const( vote_account_data );
  ulong              cnt   = fd_vote_acc_vote_cnt( vote_account_data );
  switch( voter->kind ) {
  case FD_VOTE_ACC_V4: { uchar root_option = fd_uchar_load_1_fast( (uchar *)&v4_off( voter )[cnt] ); return root_option ? fd_ulong_load_8_fast( (uchar *)&v4_off( voter )[cnt] + 1UL ) : ULONG_MAX; }
  case FD_VOTE_ACC_V3: { uchar root_option = fd_uchar_load_1_fast( (uchar *)&voter->v3.votes[cnt] ); return root_option ? fd_ulong_load_8_fast( (uchar *)&voter->v3.votes[cnt] + 1UL ) : ULONG_MAX; }
  case FD_VOTE_ACC_V2: { uchar root_option = fd_uchar_load_1_fast( (uchar *)&voter->v2.votes[cnt] ); return root_option ? fd_ulong_load_8_fast( (uchar *)&voter->v2.votes[cnt] + 1UL ) : ULONG_MAX; }
  default:          FD_LOG_CRIT(( "unhandled kind %u", voter->kind ));
  }
}

int
fd_txn_parse_simple_vote( fd_txn_t const * txn,
                          uchar    const * payload,
                          fd_pubkey_t *    opt_identity,
                          fd_pubkey_t *    opt_vote_acct,
                          ulong *          opt_vote_slot ) {
  fd_txn_instr_t const * instr      = &txn->instr[ 0 ];
  ulong required_accts = txn->signature_cnt==1 ? 2UL : 3UL;
  if( FD_UNLIKELY( !fd_txn_is_simple_vote_transaction( txn, payload ) || instr->data_sz < sizeof(uint) || txn->acct_addr_cnt < required_accts ) ) return 0;

  uchar const *          instr_data = payload + instr->data_off;
  uint                   kind       = fd_uint_load_4_fast( instr_data );
  /* Older vote instruction kinds are deprecated / ignored */
  if( FD_UNLIKELY( kind == FD_VOTE_IX_KIND_TOWER_SYNC || kind == FD_VOTE_IX_KIND_TOWER_SYNC_SWITCH ) ) {
    fd_compact_tower_sync_serde_t compact_tower_sync_serde[ 1 ];
    int err = fd_compact_tower_sync_de( compact_tower_sync_serde, instr_data + sizeof(uint), instr->data_sz - sizeof(uint) );
    if( FD_LIKELY( !err ) ) {
      if( !!opt_vote_slot ) {
        *opt_vote_slot = compact_tower_sync_serde->root;
        for( ulong i = 0; i < compact_tower_sync_serde->lockouts_cnt; i++ ) *opt_vote_slot += compact_tower_sync_serde->lockouts[ i ].offset;
      }
      fd_pubkey_t const * accs = (fd_pubkey_t const *)fd_type_pun_const( payload + txn->acct_addr_off );
      if( !!opt_vote_acct ) {
        if( FD_UNLIKELY( txn->signature_cnt==1 ) ) *opt_vote_acct = *(fd_pubkey_t const *)fd_type_pun_const( &accs[ 1 ] ); /* identity and authority same, account idx 1 is the vote account address */
        else                                       *opt_vote_acct = *(fd_pubkey_t const *)fd_type_pun_const( &accs[ 2 ] ); /* identity and authority diff, account idx 2 is the vote account address */
      }
      if( !!opt_identity ) {
        *opt_identity = *(fd_pubkey_t const *)fd_type_pun_const( &accs[ 0 ] );
      }
      return 1;
    }
  }
  return 0;
}

void
fd_tower_from_vote_acc( fd_tower_vote_t * votes,
                        ulong           * root,
                        uchar  const    * vote_acc ) {
  fd_vote_acc_t const * voter = (fd_vote_acc_t const *)fd_type_pun_const( vote_acc );
  uint                  kind  = fd_uint_load_4_fast( vote_acc ); /* skip node_pubkey */
  for( ulong i=0; i<fd_vote_acc_vote_cnt( vote_acc ); i++ ) {
    switch( kind ) {
    case FD_VOTE_ACC_V4: fd_tower_vote_push_tail( votes, (fd_tower_vote_t){ .slot = v4_off( voter )[i].slot, .conf = v4_off( voter )[i].conf } ); break;
    case FD_VOTE_ACC_V3: fd_tower_vote_push_tail( votes, (fd_tower_vote_t){ .slot = voter->v3.votes[i].slot, .conf = voter->v3.votes[i].conf } ); break;
    case FD_VOTE_ACC_V2: fd_tower_vote_push_tail( votes, (fd_tower_vote_t){ .slot = voter->v2.votes[i].slot, .conf = voter->v2.votes[i].conf } ); break;
    default: FD_LOG_ERR(( "unsupported vote_acc kind: %u", kind ));
    }
  }
  *root = fd_vote_acc_root_slot( vote_acc );
}

ulong
fd_tower_with_lat_from_vote_acc( fd_lat_vote_t tower[ static FD_TOWER_VOTE_MAX ],
                                 uchar const *      vote_acc ) {
  fd_vote_acc_t const * voter = (fd_vote_acc_t const *)fd_type_pun_const( vote_acc );
  uint                  kind  = fd_uint_load_4_fast( vote_acc ); /* skip node_pubkey */
  for( ulong i=0; i<fd_vote_acc_vote_cnt( vote_acc ); i++ ) {
    switch( kind ) {
    case FD_VOTE_ACC_V4: tower[ i ] = (fd_lat_vote_t){ .latency = v4_off( voter )[i].latency, .slot = v4_off( voter )[i].slot, .conf = v4_off( voter )[i].conf }; break;
    case FD_VOTE_ACC_V3: tower[ i ] = (fd_lat_vote_t){ .latency = voter->v3.votes[i].latency, .slot = voter->v3.votes[i].slot, .conf = voter->v3.votes[i].conf }; break;
    case FD_VOTE_ACC_V2: tower[ i ] = (fd_lat_vote_t){ .latency = UCHAR_MAX,                  .slot = voter->v2.votes[i].slot, .conf = voter->v2.votes[i].conf }; break;
    default: FD_LOG_ERR(( "unsupported vote_acc kind: %u", kind ));
    }
  }
  return fd_vote_acc_vote_cnt( vote_acc );
}

void
fd_tower_to_vote_txn( fd_tower_t const *    tower,
                      fd_hash_t const *     bank_hash,
                      fd_hash_t const *     block_id,
                      fd_hash_t const *     recent_blockhash,
                      fd_pubkey_t const *   validator_identity,
                      fd_pubkey_t const *   vote_authority,
                      fd_pubkey_t const *   vote_acc,
                      fd_txn_p_t *          vote_txn ) {

  fd_tower_vote_t * votes = fd_tower_votes( tower );
  ulong             root  = fd_tower_root( tower );

  FD_TEST( fd_tower_vote_cnt( votes )<=FD_TOWER_VOTE_MAX );
  fd_compact_tower_sync_serde_t tower_sync_serde = {
    .root             = fd_ulong_if( root == ULONG_MAX, 0UL, root ),
    .lockouts_cnt     = (ushort)fd_tower_vote_cnt( votes ),
    /* .lockouts populated below */
    .hash             = *bank_hash,
    .timestamp_option = 1,
    .timestamp        = fd_log_wallclock() / (long)1e9, /* seconds */
    .block_id         = *block_id
  };

  ulong i    = 0UL;
  ulong prev = tower_sync_serde.root;
  for( fd_tower_vote_iter_t iter = fd_tower_vote_iter_init( votes       );
                                  !fd_tower_vote_iter_done( votes, iter );
                            iter = fd_tower_vote_iter_next( votes, iter ) ) {
    fd_tower_vote_t const * vote                    = fd_tower_vote_iter_ele_const( votes, iter );
    tower_sync_serde.lockouts[i].offset             = vote->slot - prev;
    tower_sync_serde.lockouts[i].confirmation_count = (uchar)vote->conf;
    prev                                            = vote->slot;
    i++;
  }

  uchar * txn_out = vote_txn->payload;
  uchar * txn_meta_out = vote_txn->_;

  int same_addr = !memcmp( validator_identity, vote_authority, sizeof(fd_pubkey_t) );
  if( FD_LIKELY( same_addr ) ) {

    /* 0: validator identity
       1: vote account address
       2: vote program */

    fd_txn_accounts_t votes;
    votes.signature_cnt         = 1;
    votes.readonly_signed_cnt   = 0;
    votes.readonly_unsigned_cnt = 1;
    votes.acct_cnt              = 3;
    votes.signers_w             = validator_identity;
    votes.signers_r             = NULL;
    votes.non_signers_w         = vote_acc;
    votes.non_signers_r         = &fd_solana_vote_program_id;
    FD_TEST( fd_txn_base_generate( txn_meta_out, txn_out, votes.signature_cnt, &votes, recent_blockhash->uc ) );

  } else {

    /* 0: validator identity
       1: vote authority
       2: vote account address
       3: vote program */

    fd_txn_accounts_t votes;
    votes.signature_cnt         = 2;
    votes.readonly_signed_cnt   = 1;
    votes.readonly_unsigned_cnt = 1;
    votes.acct_cnt              = 4;
    votes.signers_w             = validator_identity;
    votes.signers_r             = vote_authority;
    votes.non_signers_w         = vote_acc;
    votes.non_signers_r         = &fd_solana_vote_program_id;
    FD_TEST( fd_txn_base_generate( txn_meta_out, txn_out, votes.signature_cnt, &votes, recent_blockhash->uc ) );
  }

  /* Add the vote instruction to the transaction. */

  uchar  vote_ix_buf[FD_TXN_MTU];
  ulong  vote_ix_sz = 0;
  FD_STORE( uint, vote_ix_buf, FD_VOTE_IX_KIND_TOWER_SYNC );
  FD_TEST( 0==fd_compact_tower_sync_ser( &tower_sync_serde, vote_ix_buf + sizeof(uint), FD_TXN_MTU - sizeof(uint), &vote_ix_sz ) );
  vote_ix_sz += sizeof(uint);
  uchar program_id;
  uchar ix_accs[2];
  if( FD_LIKELY( same_addr ) ) {
    ix_accs[0] = 1; /* vote account address */
    ix_accs[1] = 0; /* vote authority */
    program_id = 2; /* vote program */
  } else {
    ix_accs[0] = 2; /* vote account address */
    ix_accs[1] = 1; /* vote authority */
    program_id = 3; /* vote program */
  }
  vote_txn->payload_sz = fd_txn_add_instr( txn_meta_out, txn_out, program_id, ix_accs, 2, vote_ix_buf, vote_ix_sz );
}

static void
to_cstr( fd_tower_vote_t * votes, ulong root, char * s, ulong len ) {
  ulong off = 0;
  int   n;

  n = snprintf( s + off, len - off, "[Tower]\n\n" );
  if( FD_UNLIKELY( n < 0 )) FD_LOG_CRIT(( "snprintf: %d", n ));
  off += (ulong)n;

  if( FD_UNLIKELY( fd_tower_vote_empty( votes ) ) ) return;

  ulong max_slot = 0;

  /* Determine spacing. */

  for( fd_tower_vote_iter_t iter = fd_tower_vote_iter_init_rev( votes       );
                             !fd_tower_vote_iter_done_rev( votes, iter );
                       iter = fd_tower_vote_iter_prev    ( votes, iter ) ) {
    max_slot = fd_ulong_max( max_slot, fd_tower_vote_iter_ele_const( votes, iter )->slot );
  }

  /* Calculate the number of digits in the maximum slot value. */


  int digit_cnt = (int)fd_ulong_base10_dig_cnt( max_slot );

  /* Print the column headers. */

  if( off < len ) {
    n = snprintf( s + off, len - off, "slot%*s | %s\n", digit_cnt - (int)strlen("slot"), "", "confirmation count" );
    if( FD_UNLIKELY( n < 0 )) FD_LOG_CRIT(( "snprintf: %d", n ));
    off += (ulong)n;
  }

  /* Print the divider line. */

  for( int i = 0; i < digit_cnt && off < len; i++ ) {
    s[off++] = '-';
  }
  if( off < len ) {
    n = snprintf( s + off, len - off, " | " );
    if( FD_UNLIKELY( n < 0 )) FD_LOG_CRIT(( "snprintf: %d", n ));
    off += (ulong)n;
  }
  for( ulong i = 0; i < strlen( "confirmation count" ) && off < len; i++ ) {
    s[off++] = '-';
  }
  if( off < len ) {
    s[off++] = '\n';
  }

  /* Print each vote as a table. */

  for( fd_tower_vote_iter_t iter = fd_tower_vote_iter_init_rev( votes       );
                             !fd_tower_vote_iter_done_rev( votes, iter );
                       iter = fd_tower_vote_iter_prev    ( votes, iter ) ) {
    fd_tower_vote_t const * vote = fd_tower_vote_iter_ele_const( votes, iter );
    if( off < len ) {
      n = snprintf( s + off, len - off, "%*lu | %lu\n", digit_cnt, vote->slot, vote->conf );
      if( FD_UNLIKELY( n < 0 )) FD_LOG_CRIT(( "snprintf: %d", n ));
      off += (ulong)n;
    }
  }

  if( FD_UNLIKELY( root == ULONG_MAX ) ) {
    if( off < len ) {
      n = snprintf( s + off, len - off, "%*s | root\n", digit_cnt, "NULL" );
      if( FD_UNLIKELY( n < 0 )) FD_LOG_CRIT(( "snprintf: %d", n ));
      off += (ulong)n;
    }
  } else {
    if( off < len ) {
      n = snprintf( s + off, len - off, "%*lu | root\n", digit_cnt, root );
      if( FD_UNLIKELY( n < 0 )) FD_LOG_CRIT(( "snprintf: %d", n ));
      off += (ulong)n;
    }
  }

  /* Ensure null termination */
  if( off < len ) {
    s[off] = '\0';
  } else {
    s[len - 1] = '\0';
  }
}

char *
fd_tower_to_cstr( fd_tower_vote_t * votes,
                  ulong             root,
                  char *            cstr ) {
  to_cstr( votes, root, cstr, FD_TOWER_CSTR_MIN );
  return cstr;
}
