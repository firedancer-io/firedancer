#ifndef FD_CAVEY_DISCO_EXTXN_HEADER_H
#define FD_CAVEY_DISCO_EXTXN_HEADER_H


typedef struct {
  fd_signature_t signature;
  uchar          nonce[32];
  uchar          nonce_acct[32];
  uchar          nonce_auth[32];
} fd_sig_nonce_t;

typedef union {
  fd_signature_t signature;
  fd_sig_nonce_t sig_nonce;
} fd_extxn_msg_t;


/* Returns 0 on failure, 1 if not a durable nonce transaction, and 2 if
   it is.  FIXME: These return codes are set to harmonize with
   estimate_rewards_and_compute but -1/0/1 makes a lot more sense to me.
   */
static inline int
fd_validate_durable_nonce( fd_txn_m_t * txnm ) {
  fd_txn_t const * txn = fd_txn_m_txn_t_const( txnm );
  uchar const * payload = fd_txn_m_payload( txnm );

  static fd_acct_addr_t _lru_null_addr = { 0 };

  /* First instruction invokes system program with 4 bytes of
     instruction data with the little-endian value 4.  It also has 3
     accounts: the nonce account, recent blockhashes sysvar, and the
     nonce authority.  It seems like technically the nonce authority may
     not need to be passed in, but we disallow that.  We also allow
     trailing data and trailing accounts.  We want to organize the
     checks somewhat to minimize cache misses. */
  if( FD_UNLIKELY( txn->instr_cnt==0            ) ) return 1;
  if( FD_UNLIKELY( txn->instr[ 0 ].data_sz<4UL  ) ) return 1;
  if( FD_UNLIKELY( txn->instr[ 0 ].acct_cnt<3UL ) ) return 1; /* It seems like technically 2 is allowed, but never used */
  if( FD_LIKELY  ( fd_uint_load_4( payload + txn->instr[ 0 ].data_off )!=4U ) ) return 1;
  /* The program has to be a static account */
  fd_acct_addr_t const * accts = fd_txn_get_acct_addrs( txn, payload );
  if( FD_UNLIKELY( !fd_memeq( accts[ txn->instr[ 0 ].program_id ].b, _lru_null_addr.b, 32UL       ) ) ) return 1;
  if( FD_UNLIKELY( !fd_txn_is_signer( txn, payload[ txn->instr[ 0 ].acct_off+2 ] ) ) ) return 0;
  /* We could check recent blockhash, but it's not necessary */
  return 2;
}

/* when parsing these directly from a transaction, they are not contiguous in memory */
static inline ulong
kv_nonce_hash( ulong seed, uchar const * nonce, uchar const * nonce_acct, uchar const * nonce_auth ) {
  return fd_hash( seed, nonce,      32 ) 
       ^ fd_hash( seed, nonce_acct, 32 ) 
       ^ fd_hash( seed, nonce_auth, 32 );
}

/* useful when the 96 bytes consisting of [nonce, nonce_auth, nonce_acct] are contiguous */
static inline ulong
kv_nonce_hash_contiguous( ulong seed, fd_sig_nonce_t const * sig_nonce ) {
  return kv_nonce_hash( seed, sig_nonce->nonce, sig_nonce->nonce_auth, sig_nonce->nonce_acct );
}

#endif /* FD_CAVEY_DISCO_EXTXN_HEADER_H */