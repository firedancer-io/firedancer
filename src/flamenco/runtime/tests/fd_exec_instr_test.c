#define FD_SCRATCH_USE_HANDHOLDING 1
#include "fd_exec_instr_test.h"
#include "../fd_acc_mgr.h"
#include "../fd_executor.h"
#include "../context/fd_exec_epoch_ctx.h"
#include "../context/fd_exec_slot_ctx.h"
#include "../context/fd_exec_txn_ctx.h"
#include "../../../funk/fd_funk.h"
#include <assert.h>

struct __attribute__((aligned(32UL))) fd_exec_instr_test_runner_private {
  fd_funk_t * funk;
};

ulong
fd_exec_instr_test_runner_align( void ) {
  return alignof(fd_exec_instr_test_runner_t);
}

ulong
fd_exec_instr_test_runner_footprint( void ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_exec_instr_test_runner_t), sizeof(fd_exec_instr_test_runner_t) );
  l = FD_LAYOUT_APPEND( l, fd_funk_align(),                      fd_funk_footprint()                 );
  return l;
}

fd_exec_instr_test_runner_t *
fd_exec_instr_test_runner_new( void * mem,
                               ulong  wksp_tag ) {
  FD_SCRATCH_ALLOC_INIT( l, mem );
  void * runner_mem = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_instr_test_runner_t), sizeof(fd_exec_instr_test_runner_t) );
  void * funk_mem   = FD_SCRATCH_ALLOC_APPEND( l, fd_funk_align(),                      fd_funk_footprint()                 );
  FD_SCRATCH_ALLOC_FINI( l, alignof(fd_exec_instr_test_runner_t) );

  ulong txn_max = 4+fd_tile_cnt();
  ulong rec_max = 1024UL;
  fd_funk_t * funk = fd_funk_join( fd_funk_new( funk_mem, wksp_tag, (ulong)fd_tickcount(), txn_max, rec_max ) );
  if( FD_UNLIKELY( !funk ) ) {
    FD_LOG_WARNING(( "fd_funk_new() failed" ));
    return NULL;
  }

  fd_exec_instr_test_runner_t * runner = runner_mem;
  runner->funk = funk;
  return runner;
}

void *
fd_exec_instr_test_runner_delete( fd_exec_instr_test_runner_t * runner ) {
  if( FD_UNLIKELY( !runner ) ) return NULL;
  fd_funk_delete( fd_funk_leave( runner->funk ) );
  runner->funk = NULL;
  return runner;
}

static void
_load_account( fd_borrowed_account_t *           acc,
               fd_acc_mgr_t *                    acc_mgr,
               fd_funk_txn_t *                   funk_txn,
               fd_exec_test_acct_state_t const * state ) {
  fd_borrowed_account_init( acc );

  fd_pubkey_t pubkey[1];  memcpy( pubkey, state->address, sizeof(fd_pubkey_t) );

  int err = fd_acc_mgr_modify( /* acc_mgr     */ acc_mgr,
                               /* txn         */ funk_txn,
                               /* pubkey      */ pubkey,
                               /* do_create   */ 1,
                               /* min_data_sz */ state->data->size,
                               acc );
  assert( err==FD_ACC_MGR_SUCCESS );

  fd_memcpy( acc->data, state->data->bytes, state->data->size );

  acc->meta->info.lamports   = state->lamports;
  acc->meta->info.executable = state->executable;
  acc->meta->info.rent_epoch = state->rent_epoch;
  acc->meta->dlen = state->data->size;
  memcpy( acc->meta->info.owner, state->owner, sizeof(fd_pubkey_t) );
}

static int
_context_create( fd_exec_instr_test_runner_t *        runner,
                 fd_exec_instr_ctx_t *                ctx,
                 fd_exec_test_instr_context_t const * test_ctx ) {

  memset( ctx, 0, sizeof(fd_exec_instr_ctx_t) );

  fd_funk_t * funk = runner->funk;

  /* Generate unique ID for funk txn */

  static FD_TL ulong xid_seq = 0UL;

  fd_funk_txn_xid_t xid[1] = {0};
  xid->ul[0] = fd_log_app_id();
  xid->ul[1] = fd_log_thread_id();
  xid->ul[2] = xid_seq++;
  xid->ul[3] = (ulong)fd_tickcount();

  /* Create temporary funk transaction and scratch contexts */

  fd_funk_txn_t * funk_txn = fd_funk_txn_prepare( funk, NULL, xid, 1 );
  fd_scratch_push();

  /* Allocate contexts */

  uchar *               epoch_ctx_mem = fd_scratch_alloc( FD_EXEC_EPOCH_CTX_ALIGN, FD_EXEC_EPOCH_CTX_FOOTPRINT );
  uchar *               slot_ctx_mem  = fd_scratch_alloc( FD_EXEC_SLOT_CTX_ALIGN,  FD_EXEC_SLOT_CTX_FOOTPRINT  );
  uchar *               txn_ctx_mem   = fd_scratch_alloc( FD_EXEC_TXN_CTX_ALIGN,   FD_EXEC_TXN_CTX_FOOTPRINT   );

  fd_exec_epoch_ctx_t * epoch_ctx     = fd_exec_epoch_ctx_join( fd_exec_epoch_ctx_new( epoch_ctx_mem ) );
  fd_exec_slot_ctx_t *  slot_ctx      = fd_exec_slot_ctx_join ( fd_exec_slot_ctx_new ( slot_ctx_mem  ) );
  fd_exec_txn_ctx_t *   txn_ctx       = fd_exec_txn_ctx_join  ( fd_exec_txn_ctx_new  ( txn_ctx_mem   ) );

  epoch_ctx->valloc = fd_scratch_virtual();

  assert( epoch_ctx );
  assert( slot_ctx  );

  /* Set up epoch context */

  epoch_ctx->epoch_bank.rent.lamports_per_uint8_year = 3480;
  epoch_ctx->epoch_bank.rent.exemption_threshold = 2;
  epoch_ctx->epoch_bank.rent.burn_percent = 50;

  /* Restore feature flags */

  fd_features_disable_all( &epoch_ctx->features );
  for( ulong j=0UL; j < test_ctx->feature_set.features_count; j++ ) {
    ulong                   prefix = test_ctx->feature_set.features[j];
    fd_feature_id_t const * id     = fd_feature_id_query( prefix );
    if( FD_UNLIKELY( !id ) ) {
      FD_LOG_WARNING(( "Unsupported feature ID 0x%16lx", prefix ));
      return 0;
    }
    /* Enabled since genesis */
    fd_features_set( &epoch_ctx->features, id, 0UL );
  }

  /* Create account manager */

  fd_acc_mgr_t * acc_mgr = fd_acc_mgr_new( fd_scratch_alloc( FD_ACC_MGR_ALIGN, FD_ACC_MGR_FOOTPRINT ), funk );

  /* Set up slot context */

  slot_ctx->epoch_ctx = epoch_ctx;
  slot_ctx->funk_txn  = funk_txn;
  slot_ctx->acc_mgr   = acc_mgr;
  slot_ctx->valloc    = fd_scratch_virtual();

  /* TODO: Restore slot_bank */

  /* Set up txn context */

  txn_ctx->epoch_ctx = epoch_ctx;
  txn_ctx->slot_ctx  = slot_ctx;
  txn_ctx->funk_txn  = funk_txn;
  txn_ctx->acc_mgr   = acc_mgr;

  /* Set up instruction context */

  fd_instr_info_t * info = fd_scratch_alloc( alignof(fd_instr_info_t), sizeof(fd_instr_info_t) );
  assert( info );
  memset( info, 0, sizeof(fd_instr_info_t) );

  if( test_ctx->data ) {
    info->data_sz = (ushort)test_ctx->data->size;
    info->data    = test_ctx->data->bytes;
  }

  memcpy( info->program_id_pubkey.uc, test_ctx->program_id, sizeof(fd_pubkey_t) );

  /* Prepare borrowed account table (correctly handles aliasing) */

  fd_borrowed_account_t * borrowed_accts =
      fd_scratch_alloc( alignof(fd_borrowed_account_t), test_ctx->accounts_count * sizeof(fd_borrowed_account_t) );
  fd_memset( borrowed_accts, 0, test_ctx->accounts_count * sizeof(fd_borrowed_account_t) );

  /* Load accounts into database */

  for( ulong j=0UL; j < test_ctx->accounts_count; j++ )
    _load_account( &borrowed_accts[j], acc_mgr, funk_txn, &test_ctx->accounts[j] );

  /* Load instruction accounts */

  if( FD_UNLIKELY( test_ctx->instr_accounts_count > 128 ) ) {
    /* TODO remove this hardcoded constant */
    FD_LOG_WARNING(( "Too many instruction accounts" ));
    return 0;
  }
  for( ulong j=0UL; j < test_ctx->instr_accounts_count; j++ ) {
    uint index = test_ctx->instr_accounts[j].index;
    if( index >= test_ctx->accounts_count ) {
      FD_LOG_WARNING(( "Instruction account index out of range" ));
      return 0;
    }

    fd_borrowed_account_t * acc = &borrowed_accts[ index ];
    uint flags = 0;
    flags |= test_ctx->instr_accounts[j].is_writable ? FD_INSTR_ACCT_FLAGS_IS_WRITABLE : 0;
    flags |= test_ctx->instr_accounts[j].is_signer   ? FD_INSTR_ACCT_FLAGS_IS_SIGNER   : 0;

    info->borrowed_accounts[j] = acc;
    info->acct_flags       [j] = (uchar)flags;
    memcpy( info->acct_pubkeys[j].uc, acc->pubkey, sizeof(fd_pubkey_t) );
  }
  info->acct_cnt = (uchar)test_ctx->instr_accounts_count;

  ctx->epoch_ctx = epoch_ctx;
  ctx->slot_ctx  = slot_ctx;
  ctx->txn_ctx   = txn_ctx;
  ctx->funk_txn  = funk_txn;
  ctx->acc_mgr   = acc_mgr;
  ctx->valloc    = fd_scratch_virtual();
  ctx->instr     = info;

  return 1;
}

static void
_context_destroy( fd_exec_instr_test_runner_t * runner,
                  fd_exec_instr_ctx_t *         ctx ) {
  fd_exec_slot_ctx_t *  slot_ctx  = ctx->slot_ctx;
  fd_exec_epoch_ctx_t * epoch_ctx = slot_ctx->epoch_ctx;
  fd_acc_mgr_t *        acc_mgr   = slot_ctx->acc_mgr;
  fd_funk_txn_t *       funk_txn  = slot_ctx->funk_txn;

  fd_exec_slot_ctx_delete ( fd_exec_slot_ctx_leave ( slot_ctx  ) );
  fd_exec_epoch_ctx_delete( fd_exec_epoch_ctx_leave( epoch_ctx ) );
  fd_acc_mgr_delete( acc_mgr );
  fd_scratch_pop();
  fd_funk_txn_cancel( runner->funk, funk_txn, 1 );
}

static int
_diff_effects( fd_exec_instr_ctx_t *                ctx,
               fd_exec_test_instr_effects_t const * expected,
               int                                  exec_result ) {

  if( expected->result != exec_result ) {
    FD_LOG_WARNING(( "Expected result (%d-%s), got (%d-%s)",
                     expected->result, fd_executor_instr_strerror( expected->result ),
                     exec_result,      fd_executor_instr_strerror( exec_result      ) ));
    return 0;
  }

  if( ( exec_result==FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR    ) &
      ( expected->custom_err != ctx->txn_ctx->custom_err ) ) {
    FD_LOG_WARNING(( "Expected custom error %d, got %d",
                     expected->custom_err, ctx->txn_ctx->custom_err ));
    return 0;
  }


  /* TODO detect accounts that were modified locally but not in fixture */

  return 1;
}

int
fd_exec_instr_fixture_run( fd_exec_instr_test_runner_t *        runner,
                           fd_exec_test_instr_fixture_t const * test ) {

  fd_exec_instr_ctx_t ctx[1];
  if( FD_UNLIKELY( !_context_create( runner, ctx, &test->input ) ) )
    return 0;

  fd_pubkey_t program_id[1];  memcpy( program_id, test->input.program_id, sizeof(fd_pubkey_t) );
  fd_exec_instr_fn_t native_prog_fn = fd_executor_lookup_native_program( program_id );

  if( FD_UNLIKELY( !native_prog_fn ) ) {
    FD_LOG_WARNING(( "TODO: User deployed programs not yet supported" ));
    _context_destroy( runner, ctx );
    return 0;
  }

  int exec_result = native_prog_fn( *ctx );

  int ok = _diff_effects( ctx, &test->output, exec_result );

  _context_destroy( runner, ctx );
  return ok;
}

ulong
fd_exec_instr_test_run( fd_exec_instr_test_runner_t *        runner,
                        fd_exec_test_instr_context_t const * input,
                        fd_exec_test_instr_effects_t **      output,
                        void *                               output_buf,
                        ulong                                output_bufsz ) {

  fd_exec_instr_ctx_t ctx[1];
  _context_create( runner, ctx, input );

  FD_LOG_WARNING(( "TODO" ));
  (void)output; (void)output_buf; (void)output_bufsz;

  _context_destroy( runner, ctx );
  return 0UL;
}
