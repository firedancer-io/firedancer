#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif


#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "../../ballet/shred/fd_shred.h"
#include "../../ballet/bmtree/fd_bmtree.h"

extern int fd_ext_sanitize_shred( uchar const * shred_bytes, ulong shred_sz );
int fd_ext_larger_max_cost_per_block    ( void ) { return 0; }
int fd_ext_larger_shred_limits_per_block( void ) { return 0; }
int fd_ext_disable_status_cache         ( void ) { return 0; }

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_stderr_set(4);
  return 0;
}

#define FD_FEC_RESOLVER_SHRED_REJECTED 0
#define FD_REEDSOL_DATA_SHREDS_MAX 67UL
#define FD_REEDSOL_PARITY_SHREDS_MAX 67UL
#define INCLUSION_PROOF_LAYERS 10UL
#define resolver_max_shred_idx (32UL*1024UL)

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         shred_sz ) {

  fd_shred_t const * shred = fd_shred_parse( data, shred_sz );
  if( shred==NULL ) return 0;

  uchar variant    = shred->variant;
  uchar shred_type = fd_shred_type( variant );

  if( FD_UNLIKELY( (shred_type==FD_SHRED_TYPE_LEGACY_DATA) | (shred_type==FD_SHRED_TYPE_LEGACY_CODE) ) ) {
    /* Reject any legacy shreds */
    return 0;
  }

  if( FD_UNLIKELY( shred_sz<fd_shred_sz( shred )                    ) ) return FD_FEC_RESOLVER_SHRED_REJECTED;
  if( FD_UNLIKELY( shred->idx>=resolver_max_shred_idx               ) ) return FD_FEC_RESOLVER_SHRED_REJECTED;

  int is_data_shred = fd_shred_is_data( shred_type );

  if( !is_data_shred ) { /* Roughly 50/50 branch */
    if( FD_UNLIKELY( (shred->code.data_cnt>FD_REEDSOL_DATA_SHREDS_MAX) | (shred->code.code_cnt>FD_REEDSOL_PARITY_SHREDS_MAX) ) )
      return FD_FEC_RESOLVER_SHRED_REJECTED;
    if( FD_UNLIKELY( (shred->code.data_cnt==0UL) | (shred->code.code_cnt==0UL)                                               ) )
      return FD_FEC_RESOLVER_SHRED_REJECTED;
    if( FD_UNLIKELY( (ulong)shred->fec_set_idx+(ulong)shred->code.data_cnt>=resolver_max_shred_idx                          ) )
      return FD_FEC_RESOLVER_SHRED_REJECTED;
    if( FD_UNLIKELY( (ulong)shred->idx + (ulong)shred->code.code_cnt - (ulong)shred->code.idx>=resolver_max_shred_idx       ) )
      return FD_FEC_RESOLVER_SHRED_REJECTED;
  }
  ulong tree_depth  = fd_shred_merkle_cnt( variant );
  ulong in_type_idx = fd_ulong_if( is_data_shred, shred->idx - shred->fec_set_idx, shred->code.idx );
  ulong shred_idx   = fd_ulong_if( is_data_shred, in_type_idx, in_type_idx + shred->code.data_cnt  );

  if( FD_UNLIKELY( in_type_idx >= fd_ulong_if( is_data_shred, FD_REEDSOL_DATA_SHREDS_MAX, FD_REEDSOL_PARITY_SHREDS_MAX ) ) )
    return FD_FEC_RESOLVER_SHRED_REJECTED;
  /* This, combined with the check on shred->code.data_cnt implies that
     shred_idx is in [0, DATA_SHREDS_MAX+PARITY_SHREDS_MAX). */

  if( FD_UNLIKELY( tree_depth>INCLUSION_PROOF_LAYERS-1UL             ) ) return FD_FEC_RESOLVER_SHRED_REJECTED;
  if( FD_UNLIKELY( fd_bmtree_depth( shred_idx+1UL ) > tree_depth+1UL ) ) return FD_FEC_RESOLVER_SHRED_REJECTED;

  if( !fd_ext_sanitize_shred( data, shred_sz ) )
    __builtin_trap();

  FD_TEST( 1==fd_ext_sanitize_shred( data, shred_sz ) );

  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}

