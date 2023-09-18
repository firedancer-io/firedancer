#include "fd_txntrace.h"
#define FD_SCRATCH_USE_HANDHOLDING 1

#include "fd_trace.pb.h"
#include "../fd_flamenco_base.h"
#include "../runtime/fd_runtime.h"
#include "../runtime/fd_executor.h"

static fd_rent_t const default_rent = {
  .lamports_per_uint8_year = 3480,
  .exemption_threshold     = 2.0,
  .burn_percent            = 50
};

/* TODO: fd_txntrace_load_sysvars logic is duplicated.  There should be
   some common place to restore sysvars. */

static void
fd_txntrace_load_sysvars( fd_global_ctx_t *                global,
                          fd_soltrace_KeyedAccount const * sysvar,
                          ulong                            sysvar_cnt ) {

  for( ulong i=0UL; i<sysvar_cnt; i++ ) {

    uchar const *                   key  = sysvar[i].pubkey;
    fd_soltrace_Account     const * acc  = &sysvar[i].account;
    fd_soltrace_AccountMeta const * meta = &acc->meta;

    fd_sysvar_set( global, meta->owner, (fd_pubkey_t const *)key,
                   acc->data->bytes, acc->data->size,
                   meta->slot, &meta->lamports );

    /* Update sysvar cache (ugly!) */

    if( 0==memcmp( key, global->sysvar_rent, sizeof(fd_pubkey_t) ) ) {
      FD_TEST( 0==fd_sysvar_rent_read( global, &global->bank.rent ) );
    }

  }

}

static void
fd_txntrace_load_defaults( fd_global_ctx_t * global ) {

  fd_memcpy( &global->bank.rent, &default_rent, sizeof(fd_rent_t) );
  fd_sysvar_rent_init( global );

}

static void
fd_txntrace_load_state( fd_global_ctx_t *                 global,
                        fd_soltrace_ImplicitState const * state ) {

  fd_txntrace_load_defaults( global );
  fd_txntrace_load_sysvars( global, state->sysvars, state->sysvars_count );

  fd_firedancer_banks_t * bank = &global->bank;
  bank->slot = state->slot;
  bank->prev_slot = state->slot;
  memcpy( bank->poh.uc, state->poh, 32UL );
  memcpy( bank->banks_hash.uc, state->bank_hash, 32UL );
  bank->capitalization = state->capitalization;
  bank->block_height = state->block_height;

}

/* fd_txn_o_t is a handle to a txn created by fd_txntrace_create.
   txn points to the transaction descriptor.  heap points to the first
   byte of the memory region that txn offsets point to.  heap is not a
   valid txn message. */

struct fd_txn_o {
  fd_txn_t *    txn;
  fd_rawtxn_b_t heap;
};

typedef struct fd_txn_o fd_txn_o_t;

/* fd_txntrace_create_tx creates a new fd_txn_t descriptor from the
   given message.  Does not create a valid serialized transaction.
   Returns a pointer to the transaction descriptor and heap memory,
   which is created in the current fd_scratch frame. */

static fd_txn_o_t
fd_txntrace_create( fd_solblock_Message const * msg ) {

  ulong sig_cnt  = msg->header.num_required_signatures;
  ulong addr_cnt = msg->account_keys_count;

  ulong const heap_base = (ulong)fd_scratch_prepare( 16UL );
  uchar *     heap      = (uchar *)heap_base;

  /* Input validation */

  if( ( msg->account_keys_count             > FD_TXN_ACCT_ADDR_MAX )
    | ( msg->header.num_required_signatures > FD_TXN_SIG_MAX       )
    | ( msg->header.num_readonly_signed_accounts > msg->header.num_required_signatures )
    | ( msg->header.num_readonly_signed_accounts + msg->header.num_readonly_unsigned_accounts > msg->account_keys_count ) ) {
    fd_scratch_cancel();
    return (fd_txn_o_t){0};
  }

  /* Allocate constant-size transaction parts */

  fd_signature_t * sigs = (fd_signature_t *)heap;
  heap += sig_cnt * sizeof(fd_signature_t);

  fd_pubkey_t * addrs = (fd_pubkey_t *)heap;
  heap += addr_cnt * sizeof(fd_pubkey_t);

  fd_hash_t * recent_blockhash = (fd_hash_t *)heap;
  heap += sizeof(fd_hash_t);

  fd_txn_t * txn = (fd_txn_t *)heap;
  heap += fd_txn_footprint( msg->instructions_count, msg->address_table_lookups_count );

  FD_TEST( (ulong)heap - heap_base <= USHORT_MAX );

  /* Assemble message body */

  *txn = (fd_txn_t) {
    .transaction_version   = FD_TXN_VLEGACY,
    .signature_cnt         = (uchar)sig_cnt,
    .signature_off         = (ushort)( (ulong)sigs - heap_base ),
    .message_off           = 0U,
    .readonly_signed_cnt   = (uchar)msg->header.num_readonly_signed_accounts,
    .readonly_unsigned_cnt = (uchar)msg->header.num_readonly_unsigned_accounts,
    .acct_addr_cnt         = (ushort)msg->account_keys_count,
    .acct_addr_off         = (ushort)( (ulong)addrs - heap_base ),
    .recent_blockhash_off  = (ushort)( (ulong)recent_blockhash - heap_base ),

    .addr_table_lookup_cnt        = (uchar)0U,
    .addr_table_adtl_writable_cnt = (uchar)0U,
    .addr_table_adtl_cnt          = (uchar)0U,

    .instr_cnt = (ushort)msg->instructions_count
  };

  fd_memset( sigs,  0,                  sig_cnt  * sizeof(fd_signature_t) );
  fd_memcpy( addrs, *msg->account_keys, addr_cnt * sizeof(fd_pubkey_t   ) );
  fd_memcpy( recent_blockhash, msg->recent_blockhash, sizeof(fd_hash_t) );

  /* Convert instructions */

  for( ulong i=0UL; i<(txn->instr_cnt); i++ ) {

    fd_solblock_Instruction const * src      = &msg->instructions[i];
    pb_bytes_array_t const *        src_data = src->data;
    pb_bytes_array_t const *        src_accs = src->accounts;

    /* Input validation */

    if( src->program_id_index > msg->account_keys_count ) {
      fd_scratch_cancel();
      return (fd_txn_o_t){0};
    }
    for( ulong i=0UL; i<(src_accs->size); i++ ) {
      if( src_accs->bytes[i] > msg->account_keys_count ) {
        fd_scratch_cancel();
        return (fd_txn_o_t){0};
      }
    }

    /* Allocate instruction parts */

    uchar * instr_accts = heap;
    heap += src->accounts->size;

    uchar * data = heap;
    heap += src->data->size;

    FD_TEST( (ulong)heap - heap_base <= USHORT_MAX );

    /* Assemble instruction */

    txn->instr[i] = (fd_txn_instr_t) {
      .program_id = (uchar)src->program_id_index,
      .acct_cnt   = (ushort)src_accs->size,
      .data_sz    = (ushort)src_data->size,
      .acct_off   = (ushort)( (ulong)instr_accts - heap_base ),
      .data_off   = (ushort)( (ulong)data        - heap_base )
    };

  }

  fd_scratch_publish( heap );

  return (fd_txn_o_t) {
    .heap = (fd_rawtxn_b_t) {
      .raw    = heap,
      .txn_sz = (ushort)( (ulong)heap - heap_base )
    },
    .txn  = txn
  };
}

static int
fd_txntrace_replay2( fd_global_ctx_t * global,
                     fd_txn_o_t        to ) {

  fd_execute_txn( &global->executor, to.txn, &to.heap );

  return FD_TXNTRACE_SUCCESS;
}

static int
fd_txntrace_replay1( void *                           out,
                     ulong                            out_sz,
                     fd_soltrace_TxnExecInput const * in,
                     fd_wksp_t *                      wksp ) {

  (void)out; (void)out_sz;

  /* Create funk database */

  ulong       const funk_seed = 123UL;
  ulong       const txn_max   = 16UL;
  ulong       const rec_max   = 1024UL;
  void *      const funk_mem  = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_footprint(), 1UL );
  fd_funk_t * const funk      = fd_funk_join( fd_funk_new( funk_mem, 1UL, funk_seed, txn_max, rec_max ) );

  /* Create a global context */

  fd_global_ctx_t * global = fd_global_ctx_join( fd_global_ctx_new(
      fd_scratch_alloc( FD_GLOBAL_CTX_ALIGN, FD_GLOBAL_CTX_FOOTPRINT ) ) );
  FD_TEST( global );

  global->valloc = fd_scratch_virtual();
  global->funk   = funk;

  fd_txntrace_load_state( global, &in->state );

  /* Create transaction */

  fd_scratch_push();
  fd_txn_o_t to = fd_txntrace_create( &in->transaction );
  int err = (!!to.txn) ? FD_TXNTRACE_SUCCESS : FD_TXNTRACE_ERR_INVAL_INPUT;
  if( !err ) err = fd_txntrace_replay2( global, to );
  fd_scratch_pop();

  /* Clean up */

  fd_global_ctx_delete( fd_global_ctx_leave( global ) );
  fd_wksp_free_laddr( fd_funk_delete( fd_funk_leave( funk ) ) );

  return err;
}

int
fd_txntrace_replay( void *                           out,
                    ulong                            out_sz,
                    fd_soltrace_TxnExecInput const * in,
                    uchar *                          scratch ) {

  /* Attach to scratch */

  ulong fmem[ 16 ];
  fd_scratch_attach( scratch, fmem, FD_TXNTRACE_SCRATCH_FOOTPRINT, 16UL );
  fd_scratch_push();

  /* Create a 384 MiB workspace */

  ulong const wksp_sz   = 0x18000000UL;
  void *      wksp_mem  = fd_scratch_alloc( FD_WKSP_ALIGN, 0x18000000UL );
  uint        wksp_seed = 42U;
  ulong       part_max  = fd_wksp_part_max_est( wksp_sz, 0x10000UL );
  ulong       data_max  = fd_wksp_data_max_est( wksp_sz, part_max );
  fd_wksp_t * wksp      = fd_wksp_new( wksp_mem, "txntrace", wksp_seed, part_max, data_max );
  FD_TEST( wksp );

  /* Guard region */

  ulong  const guard_align =  0x1000UL;  /*  4 KiB */
  ulong  const guard_sz    = 0x10000UL;  /* 64 KiB */
  void * const guard_wksp  = fd_scratch_alloc( guard_align, guard_sz );
  fd_asan_poison( guard_wksp, guard_sz );

  /* Run replay core */

  fd_scratch_push();
  int err = fd_txntrace_replay1( out, out_sz, in, wksp );
  fd_scratch_pop();

  /* Fini workspace */

  fd_wksp_delete( fd_wksp_leave( wksp ) );
  fd_asan_unpoison( guard_wksp, guard_sz );

  /* Fini scratch */

  fd_scratch_pop();
  fd_scratch_detach( NULL );

  return err;
}
