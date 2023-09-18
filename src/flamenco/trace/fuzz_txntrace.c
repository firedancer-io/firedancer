#include <stddef.h>
#include <stdlib.h>

#include "../nanopb/pb_decode.h"
#include "../nanopb/pb_encode.h"
#include "../../util/fd_util.h"
#include "fd_trace.pb.h"
#include "fd_txntrace.h"

/* Setup **************************************************************/

/* fuzz_txntrace_mode specifies the permitted mutate mode */

static uint   fuzz_txntrace_mode;     /* mode param */
static void * fuzz_txntrace_scratch;  /* scratch space */

int
LLVMFuzzerInitialize( int  *   pargc,
                      char *** pargv ) {

  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( pargc, pargv );
  atexit( fd_halt );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>=fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  /* Command-line arguments */
  fuzz_txntrace_mode    = fd_env_strip_cmdline_uint ( pargc, pargv, "--txn-mutate", NULL, 0U       );
  char const * _page_sz = fd_env_strip_cmdline_cstr ( pargc, pargv, "--page-sz",    NULL, "normal" );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( pargc, pargv, "--numa-idx",   NULL, fd_shmem_numa_idx(cpu_idx) );

  /* Set up scratch memory */
  ulong page_sz  = fd_cstr_to_shmem_page_sz( _page_sz );
  ulong page_cnt = FD_TXNTRACE_SCRATCH_FOOTPRINT / page_sz;
        cpu_idx  = fd_shmem_cpu_idx( numa_idx );
  fuzz_txntrace_scratch = fd_shmem_acquire( page_sz, page_cnt, cpu_idx );
  if( FD_UNLIKELY( !fuzz_txntrace_scratch ) )
    FD_LOG_ERR(( "fd_shmem_acquire(%lu,%s,%lu) failed", page_sz, _page_sz, cpu_idx ));

  return 0;
}

/* Custom Mutator *****************************************************/

/* LLVMFuzzerMutate is an API function provided by libFuzzer. */

extern ulong
LLVMFuzzerMutate( uchar * data,
                  ulong   sz,
                  ulong   max_sz );

/* FD_TXNTRACE_MUTATE_{...} lists available mutation modes. */

#define FD_TXNTRACE_MUTATE_ALL             (0U)  /* mutate everything */
#define FD_TXNTRACE_MUTATE_ACCT_CNT        (1U)  /* add/remove txn account */
#define FD_TXNTRACE_MUTATE_ACCT_ADDR       (2U)  /* corrupt acct addr */
#define FD_TXNTRACE_MUTATE_ACCT_PERM       (3U)  /* change acct perm */
#define FD_TXNTRACE_MUTATE_ACCT_META       (4U)  /* change acct meta */
#define FD_TXNTRACE_MUTATE_ACCT_DATA       (5U)  /* mutate acct content */
#define FD_TXNTRACE_MUTATE_INSTR_ACCT_CNT  (6U)  /* add/remove instr accts */
#define FD_TXNTRACE_MUTATE_INSTR_ACCT      (7U)  /* replace instr acct */
#define FD_TXNTRACE_MUTATE_INSTR_DATA      (8U)  /* change instr data */
#define FD_TXNTRACE_MUTATE_MODE_CNT        (9U)  /* number of supported mutate modes */

static void
fd_txntrace_mutate_acct_cnt( fd_soltrace_TxnExecInput * input,
                             fd_rng_t *                 rng ) {
  (void)input; (void)rng;
}

static void
fd_txntrace_mutate_acct_addr( fd_soltrace_TxnExecInput * input,
                              fd_rng_t *                 rng ) {

  /* Flip a bit */
  ulong   acct_idx = fd_rng_ulong_roll( rng, input->accounts_count );
  uchar * addr     = input->transaction.account_keys[ acct_idx ];
  ulong   bit_idx  = fd_rng_ulong( rng ) & 255UL;

            addr[ bit_idx >> 3 ] =
  (uchar)( (addr[ bit_idx >> 3 ]) ^ (1UL<<( bit_idx & 7UL )) );

}

static void
fd_txntrace_mutate_acct_perm( fd_soltrace_TxnExecInput * input,
                              fd_rng_t *                 rng ) {
  (void)input; (void)rng;
}

static void
fd_txntrace_mutate_acct_meta( fd_soltrace_TxnExecInput * input,
                              fd_rng_t *                 rng ) {
  (void)input; (void)rng;
}

static void
fd_txntrace_mutate_acct_data( fd_soltrace_TxnExecInput * input,
                              fd_rng_t *                 rng ) {

  ulong              acct_idx = fd_rng_ulong_roll( rng, input->accounts_count );
  pb_bytes_array_t * data     = input->accounts[ acct_idx ].data;
  FD_TEST( input->accounts[ acct_idx ].data_compression == fd_soltrace_CompressionFormat_None );

  /* Raw account data mutate.
     TODO add program-aware mutate
     TODO support growing data */
  data->size = (ushort)LLVMFuzzerMutate( data->bytes, data->size, data->size );

}

static void
fd_txntrace_mutate_instr_acct_cnt( fd_soltrace_TxnExecInput * input,
                                   fd_rng_t *                 rng ) {
  (void)input; (void)rng;
}

static void
fd_txntrace_mutate_instr_acct( fd_soltrace_TxnExecInput * input,
                               fd_rng_t *                 rng ) {
  (void)input; (void)rng;
}

static void
fd_txntrace_mutate_instr_data( fd_soltrace_TxnExecInput * input,
                               fd_rng_t *                 rng ) {

  ulong              instr_idx = fd_rng_ulong_roll( rng, input->transaction.instructions_count );
  pb_bytes_array_t * data      = input->transaction.instructions[ instr_idx ].data;

  /* Raw instruction data mutate.
     TODO add program-aware mutate
     TODO support growing data */
  data->size = (ushort)LLVMFuzzerMutate( data->bytes, data->size, data->size );

}

/* fd_txntrace_mutate randomly mutates a TxnExecInput.  May do alloc
   calls to libc malloc/realloc/free.  Randomness is deterministically
   sourced from rng.  mode is one of FD_TXNTRACE_MUTATE_{...}. */

void
fd_txntrace_mutate( fd_soltrace_TxnExecInput * input,
                    fd_rng_t *                 rng,
                    uint                       mode ) {
  switch( mode ) {
  case FD_TXNTRACE_MUTATE_ACCT_CNT:
    fd_txntrace_mutate_acct_cnt( input, rng ); break;
  case FD_TXNTRACE_MUTATE_ACCT_ADDR:
    fd_txntrace_mutate_acct_addr( input, rng ); break;
  case FD_TXNTRACE_MUTATE_ACCT_PERM:
    fd_txntrace_mutate_acct_perm( input, rng ); break;
  case FD_TXNTRACE_MUTATE_ACCT_META:
    fd_txntrace_mutate_acct_meta( input, rng ); break;
  case FD_TXNTRACE_MUTATE_ACCT_DATA:
    fd_txntrace_mutate_acct_data( input, rng ); break;
  case FD_TXNTRACE_MUTATE_INSTR_ACCT_CNT:
    fd_txntrace_mutate_instr_acct_cnt( input, rng ); break;
  case FD_TXNTRACE_MUTATE_INSTR_ACCT:
    fd_txntrace_mutate_instr_acct( input, rng ); break;
  case FD_TXNTRACE_MUTATE_INSTR_DATA:
    fd_txntrace_mutate_instr_data( input, rng ); break;
  }
}

ulong
LLVMFuzzerCustomMutator( uchar * data,
                         ulong   sz,
                         ulong   max_sz,
                         uint    seed ) {
  /* Create deterministically seeded RNG */
  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );

  /* Deserialize */
  pb_istream_t stream = pb_istream_from_buffer( data, sz );
  fd_soltrace_TxnExecInput in[1];
  fd_memset( in, 0, sizeof(fd_soltrace_TxnExecInput) );
  if( FD_UNLIKELY( !pb_decode( &stream, fd_soltrace_TxnExecInput_fields, in ) ) )
    return 0UL;  /* cannot mutate invalid Protobuf */

  /* Select mutate mode */
  uint mode;
  if( fuzz_txntrace_mode==FD_TXNTRACE_MUTATE_ALL )
    mode = fd_rng_uint_roll( rng, FD_TXNTRACE_MUTATE_MODE_CNT );
  else
    mode = fuzz_txntrace_mode;

  /* Mutate */
  fd_txntrace_mutate( in, rng, mode );

  /* Re-serialize */
  pb_ostream_t ostream = pb_ostream_from_buffer( data, max_sz );
  if( FD_UNLIKELY( !pb_encode( &ostream, fd_soltrace_TxnExecInput_fields, in ) ) )
    return 0UL;  /* cannot mutate, insufficient output space */

  /* Clean up */
  pb_release( fd_soltrace_TxnExecInput_fields, in );
  fd_rng_delete( fd_rng_leave( rng ) );
  return ostream.bytes_written;
}

/* Fuzz Target ********************************************************/

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {

  /* Deserialize */
  pb_istream_t stream = pb_istream_from_buffer( data, size );
  fd_soltrace_TxnExecInput in[1];
  fd_memset( in, 0, sizeof(fd_soltrace_TxnExecInput) );
  if( FD_UNLIKELY( !pb_decode( &stream, fd_soltrace_TxnExecInput_fields, in ) ) )
    return -1;

  /* Execute */
  int err = fd_txntrace_replay( NULL, 0UL, in, fuzz_txntrace_scratch );

  /* Clean up */
  pb_release( fd_soltrace_TxnExecInput_fields, in );
  if( FD_UNLIKELY( err==FD_TXNTRACE_ERR_INVAL_INPUT ) )
    return -1;

  return 0;
}
