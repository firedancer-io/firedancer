#ifndef HEADER_fd_src_choreo_votor_ag_bls_serde_h
#define HEADER_fd_src_choreo_votor_ag_bls_serde_h

#include "ag_bls.h"

#define AG_BLS_DE_SUCCESS   ( 0)
#define AG_BLS_DE_ERR_SZ    (-1) /* Io(ReadSizeLimit), TrailingBytes, PreallocationSizeLimit */
#define AG_BLS_DE_ERR_INVAL (-2) /* InvalidTagEncoding, InvalidValue                         */

struct ag_bls_agg_serde {
  uchar         version;    /* solana_signer_store::Version  (u8 tag), base2 or base3  */
  ushort        bit_cnt;    /* solana_signer_store::num_bits (u16)                     */
  uchar const * payload;    /* solana_signer_store::data_bytes                         */
  ulong         payload_sz; /* bit_cnt rounded up to a byte (base2) or to five (base3) */
};
typedef struct ag_bls_agg_serde ag_bls_agg_serde_t;

/* the bitmap's own framing, ahead of its packed ranks */

#define AG_BLS_AGG_HDR_SZ ( sizeof(uchar)  /* version */ + \
                            sizeof(ushort) /* bit_cnt */ )

/* base2 spends a bit on a rank and base3 a trit, so a base3 bitmap over
   the same ranks is the wider of the two */

#define AG_BLS_AGG_SER_SZ( bit_cnt )      ( AG_BLS_AGG_HDR_SZ + ((bit_cnt)+7UL)/8UL )
#define AG_BLS_AGG_PAIR_SER_SZ( bit_cnt ) ( AG_BLS_AGG_HDR_SZ + ((bit_cnt)+4UL)/5UL )

#define AG_BLS_AGG_SER_MAX                ( AG_BLS_AGG_SER_SZ     ( AG_BLS_SIGNERS_MAX ) )
#define AG_BLS_AGG_PAIR_SER_MAX           ( AG_BLS_AGG_PAIR_SER_SZ( AG_BLS_SIGNERS_MAX ) )

FD_STATIC_ASSERT( AG_BLS_AGG_SER_MAX     ==259UL, ag_bls_serde );
FD_STATIC_ASSERT( AG_BLS_AGG_PAIR_SER_MAX==413UL, ag_bls_serde );

FD_PROTOTYPES_BEGIN

/* ag_bls_agg_ser_sz and ag_bls_agg_pair_ser_sz return the number of bytes
   the matching encoder will write, so a caller that has to frame the
   bitmap with a length can ask before it commits any. */

FD_FN_PURE ulong
ag_bls_agg_ser_sz( ag_bls_agg_t const * agg );

FD_FN_PURE ulong
ag_bls_agg_pair_ser_sz( ag_bls_agg_t const * base,
                        ag_bls_agg_t const * fb );

/* ag_bls_agg_ser writes agg's signer set as a base2 bitmap.
   ag_bls_agg_pair_ser writes the signer sets of base and fb as one base3
   bitmap: a rank is digit 1 when it signed the base aggregate, digit 2
   when it signed the fallback, and 0 when it signed neither, so the two
   sets have to be disjoint.  Both trim the bitmap to one past the highest
   rank in it, which is what agave does when it builds a certificate, and
   both return the number of bytes written.  buf must hold at least
   AG_BLS_AGG_SER_MAX (AG_BLS_AGG_PAIR_SER_MAX for the pair) bytes. */

ulong
ag_bls_agg_ser( ag_bls_agg_t const * agg,
                uchar *              buf );

ulong
ag_bls_agg_pair_ser( ag_bls_agg_t const * base,
                     ag_bls_agg_t const * fb,
                     uchar *              buf );

/* ag_bls_agg_de zeroes agg and decodes the b_sz byte base2 bitmap at b
   into its signer set.  It rejects a base3 bitmap: a message that admits
   only one partition has no second signer set to put one in.

   ag_bls_agg_pair_de zeroes and fills both halves, and takes either
   encoding, because either is legal wherever a fallback partition is --
   a base2 bitmap there simply says the fallback set is empty.

   A bitmap carries no signature, so the zeroing clears the one the
   aggregate had and the caller has to put it back.  Both return
   AG_BLS_DE_SUCCESS on success and a negative AG_BLS_DE_ERR_* code on
   failure. */

int
ag_bls_agg_de( ag_bls_agg_t * agg,
               uchar const *  b,
               ulong          b_sz );

int
ag_bls_agg_pair_de( ag_bls_agg_t * base,
                    ag_bls_agg_t * fb,
                    uchar const *  b,
                    ulong          b_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_votor_ag_bls_serde_h */
