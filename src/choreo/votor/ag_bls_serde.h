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

#define AG_BLS_AGG_HDR_SZ ( sizeof(uchar)  /* version */ + \
                            sizeof(ushort) /* bit_cnt */ )

#define AG_BLS_AGG_SER_SZ( bit_cnt )      ( AG_BLS_AGG_HDR_SZ + ((bit_cnt)+7UL)/8UL )
#define AG_BLS_AGG_PAIR_SER_SZ( bit_cnt ) ( AG_BLS_AGG_HDR_SZ + ((bit_cnt)+4UL)/5UL )

#define AG_BLS_AGG_SER_MAX                ( AG_BLS_AGG_SER_SZ     ( AG_BLS_SET_MAX ) )
#define AG_BLS_AGG_PAIR_SER_MAX           ( AG_BLS_AGG_PAIR_SER_SZ( AG_BLS_SET_MAX ) )

FD_STATIC_ASSERT( AG_BLS_AGG_SER_MAX     ==253UL, ag_bls_serde );
FD_STATIC_ASSERT( AG_BLS_AGG_PAIR_SER_MAX==403UL, ag_bls_serde );

FD_PROTOTYPES_BEGIN

FD_FN_PURE ulong
ag_bls_agg_ser_sz( ag_bls_agg_t const * agg );

FD_FN_PURE ulong
ag_bls_agg_pair_ser_sz( ag_bls_agg_t const * agg,
                        ag_bls_agg_t const * agg2 );

ulong
ag_bls_agg_ser( ag_bls_agg_t const * agg,
                uchar *              buf );

ulong
ag_bls_agg_pair_ser( ag_bls_agg_t const * agg,
                     ag_bls_agg_t const * agg2,
                     uchar *              buf );

int
ag_bls_agg_de( ag_bls_agg_t * agg,
               uchar const *  b,
               ulong          b_sz );

int
ag_bls_agg_pair_de( ag_bls_agg_t * agg,
                    ag_bls_agg_t * agg2,
                    uchar const *  b,
                    ulong          b_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_votor_ag_bls_serde_h */
