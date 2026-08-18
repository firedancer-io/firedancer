#ifndef HEADER_fd_src_disco_shred_fd_fec_samp_h
#define HEADER_fd_src_disco_shred_fd_fec_samp_h


/* This header defines a few methods for digesting a FEC set into a
   small hash and then probabilistically answering if a given shred
   might have been part of that FEC set using the hash.  These are
   designed for use by the FEC resolver only, but are factored out into
   this file to make them easier to iterate and test.

   Doing this probabilistically might seem excessive, but when Turbine
   is working perfectly, we expect 32 shreds to arrive after the FEC set
   is in the done_map, which means we expect to answer "was shred X
   probably part of FEC set Y?" 32 times per FEC set.  If we derive the
   Merkle root for shred X, which is the way to answer the question
   deterministically, that's about 40us of wasted computation per FEC
   set, which is a sizable fraction of the total computation per FEC
   set.  Plus, the answer to the question is almost always "yes" unless
   the leader is malicious and equivocating. */

FD_PROTOTYPES_BEGIN

/* fd_fec_samp_t is an opaque small type that contains the digest of a
   FEC set.  It's only 4 bytes right now and it is statically sized, so
   it can be declared on the stack or included in a struct. */
union fd_fec_samp;
typedef union fd_fec_samp fd_fec_samp_t;

/* fd_fec_samp_derive creates a digest of a FEC set and populates s with
   it.  s must point to a valid fd_fec_samp_t.  seed is an arbitrary
   value, intended to be different per-validator.  slot, fec_set_idx,
   signature, and root all describe the FEC set that is being digested.
   bmtree must be a valid tree initialized with all the shreds in the
   FEC set as leaves. */
static inline void
fd_fec_samp_derive( fd_fec_samp_t *            s,
                    ulong                      seed,
                    ulong                      slot,
                    uint                       fec_set_idx,
                    void const *               signature,
                    fd_bmtree_node_t   const * root,
                    fd_bmtree_commit_t const * bmtree );

/* fd_fec_samp_set_force_match modifies the digest s to match any and
   all shreds.  This is useful for cases where you have already detected
   equivocation and do not want to spend any more computation on the FEC
   set. */
static inline void fd_fec_samp_set_force_match( fd_fec_samp_t * s );


/* fd_fec_samp_matches answers queries of "is it likely that the shred
   pointed to by shred comes from the same FEC set (identified by Merkle
   root) whose digest is stored in s?"  Returns 1 if so, and 0 if it is
   certain the shred did not come from the digest in s. seed must be the
   same value provided to fd_fec_samp_derive.  It's expected that s has
   the same slot and fec_set_idx as the FEC set whose digest is stored
   in s, but that is not checked.  IMPORTANT: This function is
   probabilistic.  It may return 1 for shreds that did not come from the
   FEC set whose digest is stored in s.  However, it will never make a
   mistake in the other direction (returning 0 for a shred that actually
   did come from the FEC set digested into s).  If
   fd_fec_samp_set_force_match was called on s, always returns 1.
   This function is designed to be extremely fast in the common case.
   About 6% of the time, it will do a sha256 operation, but the rest of
   the time, it is just O(1) cheap operations.

   In general, if s does not come from the FEC set digested into s, and
   it comes from a replayable FEC set, it will return 0 (the correct
   answer) approximately 99.99% of the time (1-2^-14).
   There are certainly maliciously constructed FEC sets that are not
   actually valid that it can detect with much lower probability, only
   about 3%.
   Furthermore, extremely rarely (2^-32 of the time), a FEC set will
   return a degenerate digest, resulting in all shreds returning 1.
   See below for much more commentary on the probabilities. */
static inline int
fd_fec_samp_matches( fd_fec_samp_t const * s,
                     ulong                 seed,
                     fd_shred_t const *    shred );

FD_PROTOTYPES_END

/* Suppose we derive a sample from FEC set F containing shreds S_0, S_1,
   ... S_63, where S_i for i in [0, 32) are data shreds.  Let proof(S_i)
   be the operation that extracts the Merkle proof from shred S_i and
   contanates the elements into one long bitstring.  If F' is a
   different FEC set produced honetly, then we expect proof(S_i) and
   proof(S'_i) to be uncorrelated.  That is, for any set of n bit
   positions that we extract from both, the probability they will match
   at all n positions is 2^-n.

   However, that is not necessarily true when F' is constructed
   maliciously.  The easiest example of this is to suppose S_0==S'_0,
   ... S_30=S'_30 but S_31 != S'_31, then proof(S_i) and proof(S'_i)
   *will* be correlated for i<32.  However, the Reed-Solomon parity
   shreds will be different, which means proof(S_i) and proof(S'_i) will
   not be correlated for i>=32.

   More generally, since Reed-Solomon works on polynomials of degree<32,
   and modifying a shred can be seen as adding a non-zero polynomial,
   which then has no more than 31 zeros, if F!=F', then they differ in
   at least 33 shreds, assuming the erasure coding is computed correctly
   (otherwise it would be invalid).

   There is one other attack worth mentioning: the attacker could send
   shred S'_i but with a Merkle proof cloned from S_i.  Every shred in
   this sort of attack makes its own FEC set, so this attack can't
   really be used for real equivocation, but it's a bit lame if we're
   totally blind to that type of attack because we only consider Merkle
   proofs.  That means we do sometimes need to hash some shreds.

   If we didn't have Merkle proofs, we might try an approach like this:
   using the seed and the (slot, FEC index), choose 32 of the 64 shreds,
   and a bit position for each.  When you receive a shred, if it's one
   of the ones in the sample, compute the hash and test if the bit
   matches.  If it doesn't you know there's equivocation.  Because of
   our pigeon hole principle/fundamental theorem of algebra argument, we
   know that if the attacker modified any shred, he modified at least 33
   of them, which means our sample includes at least one of the modified
   shreds, so we can detect this equivocation at least with probability
   0.5.  We'll measure the cost of this as 0.5, since we expect to have
   to hash half of the shreds.  Since this approach is only shred-based,
   it's unaffected by the attacker playing games with the Merkle proof.

   On the other extreme, we could sample 16 bits from each of the
   highest nodes in the Merkle proof.  Again, assuming the erasure
   coding is legitimate, F and F' differ in at least 33 shreds, which
   means both halves of the Merkle tree have at least one differing
   leaf, so both children of the root will differ.  Since each shred
   must contain one of the immediate children of the root, the
   probability we miss an equivocation is 2^-16 (0.0015%).  In this
   approach, we never have to hash, so we'll say its cost is 0.
   However, obviously this approach doesn't catch equivocation when the
   attacker is playing the games with the Merkle proof we considered
   above (recall again that those games prevent this equivocating proof
   from ever being COMPLETE-able, and thus replayable).

   Does it ever make sense to take bits from another node?  I think it
   doesn't.  First of all, as in the case we considered earlier where
   S_i==S'_i for i<31, it's possible for other nodes in the Merkle tree
   for F and F' to be equal as long as they have fewer than 32 leaves
   under them.  Secondly, those bits are only useful for the fraction of
   shreds that include the node we sampled from.  Thirdly, those bits
   don't give any additional discriminating power beyond what they would
   if they were in the root.

   Then the only question becomes how many bits to allocate to direct
   hashes, and there's not a mathematical answer, since it's just about
   our desired sensitivity to the proof-cloning game.  If we store b
   bits from each hash of h shreds, and we expect to receive each of the
   64 shreds (which have all been modified but retain their orignal
   Merkle proofs) with equal probability then we'll detect this as
   equivocation with probability h/64*(1-2^-b), and this consumes h*b
   bits total.  This shows for a constant bit-budget, it's better to
   make h as large as possible and keep b as small as possible.
   Maximizing h also increases the hashing cost of the approach, so we
   don't want it too large.

   All put together, we'll use 14 bits for the left child of the root,
   14 bits for the right child of the root, and 4 bits for leaf hashes,
   one bit per hash for each of four shreds. */

union fd_fec_samp {
  uint val;
  struct {
    ushort data;
    ushort parity;
  };
};
typedef union fd_fec_samp fd_fec_samp_t;


/* The following are private helper functions/types */
typedef struct {
  ulong mask; /* in [0, 0xFF_FFFF_FFFF] */
  ulong offset; /* in [0, 15] */
  ulong shred0; /* in [0, 31] */
  ulong shred1; /* in [0, 31] */
  ulong shred_bit; /* in [0, 31], indicating which bit of the selected uint to compare */
  ulong shred0_off; /* in [0, 4] */
  ulong shred1_off; /* in [0, 4] */
} fd_fec_samp_dec_t;


FD_PROTOTYPES_BEGIN

static inline void
fd_fec_samp_decompose( ulong               entropy,
                       fd_fec_samp_dec_t * out ) {
  ulong final_bits = entropy>>59; /* 5 bits left */

  *out = (fd_fec_samp_dec_t) {
    .mask       = (entropy >>  0) & 0xFFFFFFFFFFUL,
    .offset     = (entropy >> 40) & 0xFUL,
    .shred0     = (entropy >> 44) & 0x1FUL,
    .shred1     = (entropy >> 49) & 0x1FUL,
    .shred_bit  = (entropy >> 54) & 0x1FUL,
      /* We don't have enough entropy left to choose one of 160 bits for
         each of the two shreds, so we'll just have them use the same
         bit within a uint and different uint. */
    .shred0_off = final_bits%5UL,
    .shred1_off = (final_bits/5UL)%5UL,
  };

  /* Fixup to make sure the two shreds are different */
  out->shred1 = fd_ulong_if( out->shred0==out->shred1, (out->shred1)^1UL, out->shred1 );
}

static inline ulong
fd_fec_samp_extract_cor_bits( ulong input,
                              ulong mask ) {
#if FD_HAS_AVX2 /* Actually BMI2, but the same CPUs support AVX2 as BMI2 */
  /* It's actually easier to take the first 14 bits with this AND than
     to make sure the mask only has 14 bits set to 1. */
  return 0x3FFFUL & _pext_u64( input, mask );
#else
  ulong cor_bits = 0UL;
  ulong j  = 1UL;
  for( ulong i=0UL; i<40UL; i++ ) if( 1UL & (mask>>i) ) { cor_bits |= fd_ulong_if( 1UL & (input>>i), j, 0UL ); j<<=1; }
  return cor_bits & 0x3FFFUL;
#endif
}

static inline ushort
fd_fec_samp_extract( fd_bmtree_commit_t const * bmtree,
                     fd_fec_samp_dec_t const *  entropy,
                     ulong                      leaf_off ) {
  union {
    uchar p[6][20];
    uchar raw[120 + 8]; /* allow tail reading */
    uint  uints[6][5];
  } proof;

  /* We can get the hash of shred n by getting the proof of shred n^1 */
  FD_TEST( -1!=fd_bmtree_get_proof( bmtree, proof.raw, leaf_off + (entropy->shred0 ^ 1UL) ) );

  ulong cor_bits = fd_fec_samp_extract_cor_bits( fd_ulong_load_5_fast( proof.p[5] + entropy->offset ), entropy->mask );

  ulong shred0_bit = 1UL & (proof.uints[0][entropy->shred0_off]>>entropy->shred_bit);

  FD_TEST( -1!=fd_bmtree_get_proof( bmtree, proof.raw, leaf_off + (entropy->shred1 ^ 1UL) ) );
  ulong shred1_bit = 1UL & (proof.uints[0][entropy->shred1_off]>>entropy->shred_bit);

  return (ushort)( (shred0_bit<<15) | (shred1_bit<<14) | cor_bits );
}

/* end of private helpers */

static inline void
fd_fec_samp_derive( fd_fec_samp_t *            s,
                    ulong                      seed,
                    ulong                      slot,
                    uint                       fec_set_idx,
                    void const *               signature,
                    fd_bmtree_node_t   const * root,
                    fd_bmtree_commit_t const * bmtree ) {
  /* We don't use either the signature (since it's not a trustworthy
     key) or the root (since it's not available in the shred) */
  (void)signature;
  (void)root;

  /* For the probabilities to be right above, it doesn't matter what
     bits we choose.  However, an adversary could grind hashes to make
     it collide if we were using well-known bits, and if all validators
     were using the same bits, we'd lose the advantage of
     per-validator statistical independence.  Ideally, we'd choose 14 of
     the 160 bits uniformly randomly without replacement, probably with
     something like reservoir sampling.  However, that's a lot of work,
     and we don't need that level of precision.  Instead we'll generate
     random 40 bits, and take the first 14 one bits it has (98% chance
     it will have at least 14 bits set to one), then use that as a mask
     with 5 contiguous bytes in the 20 byte proof element.  This is not
     exactly uniform (the last bit has only 0.08% chance of being
     selected, the first bit has a 3.1% chance of being selected,
     compared to 8.75% for each bit if we did things perfectly) but it's
     pretty close; entropy-wise, this is something like picking from 140
     bits instead of 160 bits. */
  fd_rng_t rng[1];
  fd_rng_join( fd_rng_new( rng, (uint)slot ^ (uint)(fec_set_idx<<20), seed ) );
  fd_fec_samp_dec_t data[1], parity[1];
  fd_fec_samp_decompose( fd_rng_ulong( rng ), data   );
  fd_fec_samp_decompose( fd_rng_ulong( rng ), parity );

  s->data   = fd_fec_samp_extract( bmtree, data,    0UL );
  s->parity = fd_fec_samp_extract( bmtree, parity, 32UL );

  /* It's possible, but extremely unlikely that s->val could be UINT_MAX
     at this point.  However, an attacker could bias the probabilities
     in that direction by grinding for hashes with a lot of 1 bits.  We
     can eliminate that attack vector with another xor */
  s->val ^= (uint)seed;

  fd_rng_delete( fd_rng_leave( rng ) );
}

static inline int
fd_fec_samp_matches( fd_fec_samp_t const * s_raw,
                     ulong                 seed,
                     fd_shred_t const *    shred ) {
  if( FD_UNLIKELY( s_raw->val==UINT_MAX ) ) return 1;

  fd_rng_t rng[1];
  fd_rng_join( fd_rng_new( rng, (uint)shred->slot ^ (uint)(shred->fec_set_idx<<20), seed ) );
  fd_fec_samp_dec_t entropy[1];
  /* undo the final xor from derive */
  fd_fec_samp_t s[1] = {{ .val = s_raw->val ^ (uint)seed }};

  int is_data_shred = fd_shred_is_data( fd_shred_type( shred->variant ) );
  ushort compare = fd_ushort_if( is_data_shred, s->data, s->parity );

  if( !is_data_shred ) fd_rng_ulong( rng ); /* advance rng */
  fd_fec_samp_decompose( fd_rng_ulong( rng ), entropy );
  fd_rng_delete( fd_rng_leave( rng ) );

  fd_shred_merkle_t const * nodes = fd_shred_merkle_nodes( shred );

  ulong cor_bits = fd_fec_samp_extract_cor_bits( fd_ulong_load_5( nodes[5] + entropy->offset ), entropy->mask );
  if( FD_UNLIKELY( cor_bits!=(compare&0x3FFFUL) ) ) return 0;

  ulong in_type_idx = fd_ulong_if( is_data_shred, shred->idx - shred->fec_set_idx, shred->code.idx );
  if( FD_UNLIKELY( (in_type_idx==entropy->shred0) | (in_type_idx==entropy->shred1) ) ) {
    /* This is one of the shreds we need to hash. */
    ulong merkle_protected_sz  = fd_ulong_if( is_data_shred, FD_SHRED_MIN_SZ, FD_SHRED_MAX_SZ )
                                  - FD_SHRED_SIGNATURE_SZ * (1UL+fd_shred_is_resigned( fd_shred_type( shred->variant ) ))
                                  - FD_SHRED_MERKLE_NODE_SZ*(FD_SHRED_MERKLE_LAYER_CNT-1UL);

    union {
      fd_bmtree_node_t leaf[1];
      uint             u[5];
    } l;

    fd_bmtree_hash_leaf( l.leaf, (uchar const *)shred + sizeof(fd_ed25519_sig_t), merkle_protected_sz, FD_BMTREE_LONG_PREFIX_SZ );
    ulong bit = 1UL & (l.u[ fd_ulong_if( in_type_idx==entropy->shred0, entropy->shred0_off, entropy->shred1_off ) ]>>entropy->shred_bit);
    if( FD_UNLIKELY( bit!=(1UL & fd_ulong_if( in_type_idx==entropy->shred0, compare>>15, compare>>14 ) ) ) ) return 0;
  }

  return 1;
}

static inline void fd_fec_samp_set_force_match( fd_fec_samp_t       * s ) { s->val        =  UINT_MAX; }

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_shred_fd_fec_samp_h */
