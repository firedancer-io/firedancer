#include "fd_txn_build.h"
#include "../../flamenco/runtime/fd_system_ids_pp.h"
#include "../../util/tmpl/fd_unit_test.c"

static uchar payload[ FD_TXN_MTU ];
static uchar txn_mem[ FD_TXN_MAX_SZ ] __attribute__((aligned(alignof(fd_txn_t))));

static void
addr_set( fd_acct_addr_t * addr,
          uchar            tag ) {
  for( ulong i=0UL; i<FD_TXN_ACCT_ADDR_SZ; i++ ) addr->b[ i ] = (uchar)( tag + (uchar)( 17UL*i ) );
}

static fd_acct_addr_t
addr( uchar tag ) {
  fd_acct_addr_t a;
  addr_set( &a, tag );
  return a;
}

static fd_txn_t *
build_txn( fd_txn_builder_t * builder,
           uint *             payload_sz ) {
  fd_memset( payload, 0xA5, sizeof(payload) );
  fd_memset( txn_mem, 0x5A, sizeof(txn_mem) );
  ushort txn_t_sz = 0U;
  *payload_sz = fd_txn_build( builder, payload, (fd_txn_t *)txn_mem, &txn_t_sz );
  FD_TEST( *payload_sz );
  FD_TEST( txn_t_sz==fd_txn_footprint( ((fd_txn_t *)txn_mem)->instr_cnt,
                                       ((fd_txn_t *)txn_mem)->addr_table_lookup_cnt ) );
  FD_TEST( fd_txn_parse( payload, *payload_sz, txn_mem, NULL )==txn_t_sz );
  return (fd_txn_t *)txn_mem;
}

FD_UNIT_TEST( builder_lifecycle ) {
  FD_TEST( !fd_txn_builder_new( NULL, 0UL ) );

  uchar misaligned[ sizeof(fd_txn_builder_t)+alignof(fd_txn_builder_t) ];
  void * p = (void *)( (ulong)misaligned|1UL );
  FD_TEST( !fd_txn_builder_new( p, 0UL ) );

  fd_txn_builder_t builder[1];
  FD_TEST( fd_txn_builder_new( builder, 1234UL )==builder );
  FD_TEST( fd_txn_builder_delete( builder )==builder );
}

FD_UNIT_TEST( legacy_order_and_promotion ) {
  fd_txn_builder_t builder[1];
  FD_TEST( fd_txn_builder_new( builder, 1UL ) );

  fd_acct_addr_t fee     = addr( 0x10 );
  fd_acct_addr_t program = addr( 0x20 );
  fd_acct_addr_t a_rw    = addr( 0x30 );
  fd_acct_addr_t b_prom  = addr( 0x40 );
  fd_acct_addr_t c_rs    = addr( 0x50 );
  fd_acct_addr_t d_ws    = addr( 0x60 );
  fd_acct_addr_t bhash   = addr( 0x70 );
  uchar const data[] = { 0xA0, 0xA1, 0xA2 };

  FD_TEST( fd_txn_builder_fee_payer_set( builder, &fee ) );
  fd_txn_builder_blockhash_set( builder, &bhash );
  FD_TEST( fd_txn_builder_instr_open( builder, &program, data, sizeof(data) ) );
  FD_TEST( fd_txn_builder_instr_account_push( builder, &a_rw,   FD_TXN_ACCT_CAT_WRITABLE ) );
  FD_TEST( fd_txn_builder_instr_account_push( builder, &b_prom, FD_TXN_ACCT_CAT_NONE     ) );
  FD_TEST( fd_txn_builder_instr_account_push( builder, &c_rs,   FD_TXN_ACCT_CAT_SIGNER   ) );
  FD_TEST( fd_txn_builder_instr_account_push( builder, &d_ws,   FD_TXN_ACCT_CAT_WRITABLE | FD_TXN_ACCT_CAT_SIGNER ) );
  FD_TEST( fd_txn_builder_instr_account_push( builder, &b_prom, FD_TXN_ACCT_CAT_WRITABLE ) );
  fd_txn_builder_instr_close( builder );

  uint payload_sz = 0U;
  fd_txn_t * txn = build_txn( builder, &payload_sz );
  (void)payload_sz;

  FD_TEST( txn->transaction_version==FD_TXN_VLEGACY );
  FD_TEST( txn->signature_cnt==3UL );
  FD_TEST( txn->readonly_signed_cnt==1UL );
  FD_TEST( txn->readonly_unsigned_cnt==1UL );
  FD_TEST( txn->acct_addr_cnt==6UL );
  FD_TEST( txn->addr_table_lookup_cnt==0UL );
  FD_TEST( fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_WRITABLE_SIGNER        )==2UL );
  FD_TEST( fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_READONLY_SIGNER        )==1UL );
  FD_TEST( fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_WRITABLE_NONSIGNER_IMM )==2UL );
  FD_TEST( fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_READONLY_NONSIGNER_IMM )==1UL );

  fd_acct_addr_t const * accts = fd_txn_get_acct_addrs( txn, payload );
  FD_TEST( !memcmp( &accts[0], &fee,     sizeof(fd_acct_addr_t) ) );
  FD_TEST( !memcmp( &accts[1], &d_ws,    sizeof(fd_acct_addr_t) ) );
  FD_TEST( !memcmp( &accts[2], &c_rs,    sizeof(fd_acct_addr_t) ) );
  FD_TEST( !memcmp( &accts[3], &a_rw,    sizeof(fd_acct_addr_t) ) );
  FD_TEST( !memcmp( &accts[4], &b_prom,  sizeof(fd_acct_addr_t) ) );
  FD_TEST( !memcmp( &accts[5], &program, sizeof(fd_acct_addr_t) ) );
  FD_TEST( !memcmp( fd_txn_get_recent_blockhash( txn, payload ), &bhash, sizeof(fd_acct_addr_t) ) );

  FD_TEST( txn->instr_cnt==1UL );
  fd_txn_instr_t const * instr = &txn->instr[0];
  FD_TEST( instr->program_id==5U );
  FD_TEST( instr->acct_cnt==5UL );
  uchar const * instr_accts = fd_txn_get_instr_accts( instr, payload );
  uchar const expected_accts[] = { 3U, 4U, 2U, 1U, 4U };
  FD_TEST( !memcmp( instr_accts, expected_accts, sizeof(expected_accts) ) );
  FD_TEST( instr->data_sz==sizeof(data) );
  FD_TEST( !memcmp( fd_txn_get_instr_data( instr, payload ), data, sizeof(data) ) );

  fd_txn_builder_delete( builder );
}

FD_UNIT_TEST( nonce_instruction ) {
  fd_txn_builder_t builder[1];
  FD_TEST( fd_txn_builder_new( builder, 2UL ) );

  fd_acct_addr_t fee       = addr( 0x11 );
  fd_acct_addr_t nonce     = addr( 0x22 );
  fd_acct_addr_t authority = addr( 0x33 );
  fd_acct_addr_t bhash     = addr( 0x44 );

  FD_TEST( fd_txn_builder_fee_payer_set( builder, &fee ) );
  fd_txn_builder_blockhash_set( builder, &bhash );
  FD_TEST( fd_txn_builder_nonce_set( builder, &nonce, &authority ) );

  uint payload_sz = 0U;
  fd_txn_t * txn = build_txn( builder, &payload_sz );
  (void)payload_sz;

  FD_TEST( txn->transaction_version==FD_TXN_VLEGACY );
  FD_TEST( txn->signature_cnt==2UL );
  FD_TEST( txn->readonly_signed_cnt==1UL );
  FD_TEST( txn->readonly_unsigned_cnt==2UL );
  FD_TEST( txn->acct_addr_cnt==5UL );
  FD_TEST( txn->instr_cnt==1UL );

  fd_acct_addr_t const system_prog        = { .b = { SYS_PROG_ID              } };
  fd_acct_addr_t const recent_blockhashes = { .b = { SYSVAR_RECENT_BLKHASH_ID } };
  fd_acct_addr_t const * accts = fd_txn_get_acct_addrs( txn, payload );
  FD_TEST( !memcmp( &accts[0], &fee,                sizeof(fd_acct_addr_t) ) );
  FD_TEST( !memcmp( &accts[1], &authority,          sizeof(fd_acct_addr_t) ) );
  FD_TEST( !memcmp( &accts[2], &nonce,              sizeof(fd_acct_addr_t) ) );
  FD_TEST( !memcmp( &accts[3], &system_prog,        sizeof(fd_acct_addr_t) ) );
  FD_TEST( !memcmp( &accts[4], &recent_blockhashes, sizeof(fd_acct_addr_t) ) );

  fd_txn_instr_t const * instr = &txn->instr[0];
  FD_TEST( instr->program_id==3U );
  FD_TEST( instr->acct_cnt==3UL );
  uchar const expected_accts[] = { 2U, 4U, 1U };
  FD_TEST( !memcmp( fd_txn_get_instr_accts( instr, payload ), expected_accts, sizeof(expected_accts) ) );
  uchar const expected_data[] = { 0x04, 0x00, 0x00, 0x00 };
  FD_TEST( instr->data_sz==sizeof(expected_data) );
  FD_TEST( !memcmp( fd_txn_get_instr_data( instr, payload ), expected_data, sizeof(expected_data) ) );

  fd_txn_builder_delete( builder );
}

FD_UNIT_TEST( alut_demotes_writable_and_readonly_accounts ) {
  fd_txn_builder_t builder[1];
  FD_TEST( fd_txn_builder_new( builder, 3UL ) );

  fd_acct_addr_t fee       = addr( 0x12 );
  fd_acct_addr_t program   = addr( 0x23 );
  fd_acct_addr_t writable  = addr( 0x34 );
  fd_acct_addr_t readonly  = addr( 0x45 );
  fd_acct_addr_t table     = addr( 0x67 );
  fd_acct_addr_t bhash     = addr( 0x89 );
  uchar const data[] = { 0xCA, 0xFE };

  FD_TEST( fd_txn_builder_fee_payer_set( builder, &fee ) );
  fd_txn_builder_blockhash_set( builder, &bhash );
  FD_TEST( fd_txn_builder_instr_open( builder, &program, data, sizeof(data) ) );
  FD_TEST( fd_txn_builder_instr_account_push( builder, &writable, FD_TXN_ACCT_CAT_WRITABLE ) );
  FD_TEST( fd_txn_builder_instr_account_push( builder, &readonly, FD_TXN_ACCT_CAT_NONE ) );
  fd_txn_builder_instr_close( builder );

  FD_TEST( fd_txn_builder_alut_open( builder, &table ) );
  fd_txn_builder_alut_address_push( builder, &writable, 9U );
  fd_txn_builder_alut_address_push( builder, &readonly, 7U );
  FD_TEST( !fd_txn_builder_instr_open( builder, &program, data, sizeof(data) ) );

  uint payload_sz = 0U;
  fd_txn_t * txn = build_txn( builder, &payload_sz );
  (void)payload_sz;

  FD_TEST( txn->transaction_version==FD_TXN_V0 );
  FD_TEST( txn->signature_cnt==1UL );
  FD_TEST( txn->readonly_signed_cnt==0UL );
  FD_TEST( txn->readonly_unsigned_cnt==2UL );
  FD_TEST( txn->acct_addr_cnt==3UL );
  FD_TEST( txn->addr_table_lookup_cnt==1UL );
  FD_TEST( txn->addr_table_adtl_writable_cnt==1UL );
  FD_TEST( txn->addr_table_adtl_cnt==2UL );
  FD_TEST( fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_WRITABLE_ALT )==1UL );
  FD_TEST( fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_READONLY_ALT )==1UL );

  fd_acct_addr_t const * accts = fd_txn_get_acct_addrs( txn, payload );
  FD_TEST( !memcmp( &accts[0], &fee,     sizeof(fd_acct_addr_t) ) );
  FD_TEST( !memcmp( &accts[1], &program, sizeof(fd_acct_addr_t) ) );
  FD_TEST( !memcmp( &accts[2], &table,   sizeof(fd_acct_addr_t) ) );

  fd_txn_instr_t const * instr = &txn->instr[0];
  FD_TEST( instr->program_id==1U );
  FD_TEST( instr->acct_cnt==2UL );
  uchar const expected_instr_accts[] = { 3U, 4U };
  FD_TEST( !memcmp( fd_txn_get_instr_accts( instr, payload ), expected_instr_accts, sizeof(expected_instr_accts) ) );

  fd_txn_acct_addr_lut_t const * luts = fd_txn_get_address_tables_const( txn );
  FD_TEST( !memcmp( payload + luts[0].addr_off, &table, sizeof(fd_acct_addr_t) ) );
  FD_TEST( luts[0].writable_cnt==1UL );
  FD_TEST( luts[0].readonly_cnt==1UL );
  FD_TEST( payload[ luts[0].writable_off ]==9U );
  FD_TEST( payload[ luts[0].readonly_off ]==7U );

  fd_txn_builder_delete( builder );
}

FD_UNIT_TEST( alut_keeps_pinned_and_unused_accounts_immediate ) {
  fd_txn_builder_t builder[1];
  FD_TEST( fd_txn_builder_new( builder, 4UL ) );

  fd_acct_addr_t fee     = addr( 0x13 );
  fd_acct_addr_t program = addr( 0x24 );
  fd_acct_addr_t signer  = addr( 0x35 );
  fd_acct_addr_t table   = addr( 0x46 );
  fd_acct_addr_t unknown = addr( 0x57 );
  fd_acct_addr_t bhash   = addr( 0x68 );

  FD_TEST( fd_txn_builder_fee_payer_set( builder, &fee ) );
  fd_txn_builder_blockhash_set( builder, &bhash );
  FD_TEST( fd_txn_builder_instr_open( builder, &program, NULL, 0UL ) );
  FD_TEST( fd_txn_builder_instr_account_push( builder, &signer, FD_TXN_ACCT_CAT_SIGNER ) );
  fd_txn_builder_instr_close( builder );
  FD_TEST( fd_txn_builder_alut_open( builder, &table ) );
  fd_txn_builder_alut_address_push( builder, &signer,  9U );
  fd_txn_builder_alut_address_push( builder, &program, 8U );
  fd_txn_builder_alut_address_push( builder, &table,   7U );
  fd_txn_builder_alut_address_push( builder, &unknown, 6U );

  uint payload_sz = 0U;
  fd_txn_t * txn = build_txn( builder, &payload_sz );
  (void)payload_sz;

  FD_TEST( txn->transaction_version==FD_TXN_VLEGACY );
  FD_TEST( txn->signature_cnt==2UL );
  FD_TEST( txn->readonly_signed_cnt==1UL );
  FD_TEST( txn->readonly_unsigned_cnt==2UL );
  FD_TEST( txn->acct_addr_cnt==4UL );
  FD_TEST( txn->addr_table_lookup_cnt==0UL );

  fd_acct_addr_t const * accts = fd_txn_get_acct_addrs( txn, payload );
  FD_TEST( !memcmp( &accts[0], &fee,     sizeof(fd_acct_addr_t) ) );
  FD_TEST( !memcmp( &accts[1], &signer,  sizeof(fd_acct_addr_t) ) );
  FD_TEST( !memcmp( &accts[2], &program, sizeof(fd_acct_addr_t) ) );
  FD_TEST( !memcmp( &accts[3], &table,   sizeof(fd_acct_addr_t) ) );

  fd_txn_builder_delete( builder );
}

FD_UNIT_TEST( alut_open_without_used_address_is_legacy ) {
  fd_txn_builder_t builder[1];
  FD_TEST( fd_txn_builder_new( builder, 5UL ) );

  fd_acct_addr_t fee     = addr( 0x13 );
  fd_acct_addr_t program = addr( 0x24 );
  fd_acct_addr_t table   = addr( 0x35 );
  fd_acct_addr_t unused  = addr( 0x46 );
  fd_acct_addr_t bhash   = addr( 0x57 );

  FD_TEST( fd_txn_builder_fee_payer_set( builder, &fee ) );
  fd_txn_builder_blockhash_set( builder, &bhash );
  FD_TEST( fd_txn_builder_instr_open( builder, &program, NULL, 0UL ) );
  fd_txn_builder_instr_close( builder );
  FD_TEST( fd_txn_builder_alut_open( builder, &table ) );
  fd_txn_builder_alut_address_push( builder, &unused, 1U );

  uint payload_sz = 0U;
  fd_txn_t * txn = build_txn( builder, &payload_sz );
  (void)payload_sz;

  FD_TEST( txn->transaction_version==FD_TXN_VLEGACY );
  FD_TEST( txn->addr_table_lookup_cnt==0UL );
  FD_TEST( txn->acct_addr_cnt==3UL );
  FD_TEST( txn->readonly_unsigned_cnt==2UL );

  fd_txn_builder_delete( builder );
}

FD_UNIT_TEST( instr_account_push_requires_open_instruction ) {
  fd_txn_builder_t builder[1];
  FD_TEST( fd_txn_builder_new( builder, 6UL ) );

  fd_acct_addr_t fee     = addr( 0x14 );
  FD_TEST( !fd_txn_builder_instr_account_push( builder, &fee, FD_TXN_ACCT_CAT_NONE ) );

  fd_txn_builder_delete( builder );
}

FD_UNIT_TEST( build_requires_fee_payer ) {
  fd_txn_builder_t builder[1];
  FD_TEST( fd_txn_builder_new( builder, 7UL ) );

  fd_acct_addr_t program = addr( 0x25 );
  fd_acct_addr_t bhash   = addr( 0x36 );
  fd_txn_builder_blockhash_set( builder, &bhash );
  FD_TEST( fd_txn_builder_instr_open( builder, &program, NULL, 0UL ) );
  fd_txn_builder_instr_close( builder );
  FD_TEST( !fd_txn_build_raw( builder, payload ) );

  fd_txn_builder_delete( builder );
}

FD_UNIT_TEST( fee_payer_set_only_once ) {
  fd_txn_builder_t builder[1];
  FD_TEST( fd_txn_builder_new( builder, 8UL ) );

  fd_acct_addr_t fee = addr( 0x14 );
  FD_TEST( fd_txn_builder_fee_payer_set( builder, &fee ) );
  FD_TEST( !fd_txn_builder_fee_payer_set( builder, &fee ) );

  fd_txn_builder_delete( builder );
}

FD_UNIT_TEST( instr_data_size_is_bounded ) {
  fd_txn_builder_t builder[1];
  FD_TEST( fd_txn_builder_new( builder, 9UL ) );

  fd_acct_addr_t fee     = addr( 0x14 );
  fd_acct_addr_t program = addr( 0x25 );
  fd_acct_addr_t bhash   = addr( 0x36 );
  FD_TEST( fd_txn_builder_fee_payer_set( builder, &fee ) );
  fd_txn_builder_blockhash_set( builder, &bhash );
  uchar too_much[ FD_TXN_MTU+1UL ] = {0};
  FD_TEST( !fd_txn_builder_instr_open( builder, &program, too_much, sizeof(too_much) ) );

  fd_txn_builder_delete( builder );
}

FD_UNIT_TEST( instruction_count_is_bounded ) {
  fd_txn_builder_t builder[1];
  FD_TEST( fd_txn_builder_new( builder, 10UL ) );

  fd_acct_addr_t fee     = addr( 0x14 );
  fd_acct_addr_t program = addr( 0x25 );
  fd_acct_addr_t bhash   = addr( 0x36 );
  FD_TEST( fd_txn_builder_fee_payer_set( builder, &fee ) );
  fd_txn_builder_blockhash_set( builder, &bhash );
  for( ulong i=0UL; i<FD_TXN_INSTR_MAX; i++ ) {
    FD_TEST( fd_txn_builder_instr_open( builder, &program, NULL, 0UL ) );
    fd_txn_builder_instr_close( builder );
  }
  FD_TEST( !fd_txn_builder_instr_open( builder, &program, NULL, 0UL ) );
  fd_txn_builder_delete( builder );
}

FD_UNIT_TEST( transaction_account_count_is_bounded ) {
  fd_txn_builder_t builder[1];
  FD_TEST( fd_txn_builder_new( builder, 11UL ) );

  fd_acct_addr_t fee     = addr( 0x14 );
  fd_acct_addr_t program = addr( 0x25 );
  fd_acct_addr_t bhash   = addr( 0x36 );
  FD_TEST( fd_txn_builder_fee_payer_set( builder, &fee ) );
  fd_txn_builder_blockhash_set( builder, &bhash );
  FD_TEST( fd_txn_builder_instr_open( builder, &program, NULL, 0UL ) );
  for( ulong i=0UL; i<FD_TXN_ACCT_ADDR_MAX-2UL; i++ ) {
    fd_acct_addr_t acct_i = addr( (uchar)( 0x80UL + i ) );
    FD_TEST( fd_txn_builder_instr_account_push( builder, &acct_i, FD_TXN_ACCT_CAT_NONE ) );
  }
  fd_acct_addr_t extra = addr( 0x7FU );
  FD_TEST( !fd_txn_builder_instr_account_push( builder, &extra, FD_TXN_ACCT_CAT_NONE ) );
  fd_txn_builder_delete( builder );
}


/* A reference is an instruction-local index, not a distinct account.
   This real transfer shape uses just four keys but114references. */
FD_UNIT_TEST( repeated_system_transfers ) {
  fd_txn_builder_t builder[1];
  FD_TEST( fd_txn_builder_new( builder, 12UL ) );
  fd_acct_addr_t fee    = addr( 0xA1 );
  fd_acct_addr_t sink   = addr( 0xB2 );
  fd_acct_addr_t bhash  = addr( 0xC3 );
  fd_acct_addr_t system = { .b = { SYS_PROG_ID } };
  fd_acct_addr_t budget = { .b = { COMPUTE_BUDGET_PROG_ID } };
  uchar const limit[]  = { 2, 0xC0, 0x5C, 0x15, 0 }; /*1,400,000CU*/
  uchar const price[]  = { 3, 0x80, 0x84, 0x1E, 0, 0, 0, 0, 0 }; /*2,000,000*/
  uchar const loaded[] = { 4, 0, 0, 1, 0 }; /*65,536bytes*/
  uchar const transfer[12] = { 2, 0, 0, 0, 1 }; /*System Transfer1lamport*/
  FD_TEST( fd_txn_builder_fee_payer_set( builder, &fee ) );
  fd_txn_builder_blockhash_set( builder, &bhash );
  FD_TEST( fd_txn_builder_instr_open( builder, &budget, limit, sizeof(limit) ) );
  fd_txn_builder_instr_close( builder );
  FD_TEST( fd_txn_builder_instr_open( builder, &budget, price, sizeof(price) ) );
  fd_txn_builder_instr_close( builder );
  FD_TEST( fd_txn_builder_instr_open( builder, &budget, loaded, sizeof(loaded) ) );
  fd_txn_builder_instr_close( builder );
  for( ulong i=0UL; i<57UL; i++ ) {
    FD_TEST( fd_txn_builder_instr_open( builder, &system, transfer, sizeof(transfer) ) );
    FD_TEST( fd_txn_builder_instr_account_push( builder, &fee, FD_TXN_ACCT_CAT_WRITABLE_SIGNER ) );
    FD_TEST( fd_txn_builder_instr_account_push( builder, &sink, FD_TXN_ACCT_CAT_WRITABLE ) );
    fd_txn_builder_instr_close( builder );
  }
  uint sz;
  fd_txn_t * txn = build_txn( builder, &sz );
  FD_TEST( sz==1227U && txn->transaction_version==FD_TXN_VLEGACY );
  FD_TEST( txn->acct_addr_cnt==4UL && txn->instr_cnt==60UL );
  for( ulong i=3UL; i<60UL; i++ ) {
    fd_txn_instr_t const * instr = txn->instr+i;
    FD_TEST( instr->program_id==3U && instr->acct_cnt==2U && instr->data_sz==12U );
    uchar const * refs = fd_txn_get_instr_accts( instr, payload );
    FD_TEST( refs[0]==0U && refs[1]==1U );
    FD_TEST( !memcmp( fd_txn_get_instr_data( instr, payload ), transfer, 12UL ) );
  }

  /* An independent wire encoding catches serializer offset/remapping errors. */
  uchar expected[ FD_TXN_MTU_V0 ] = {1};
  uchar * out = expected+65;
  *out++=1; *out++=0; *out++=2; *out++=4;
  fd_memcpy( out, &fee, 32UL ); out+=32;
  fd_memcpy( out, &sink, 32UL ); out+=32;
  fd_memcpy( out, &budget, 32UL ); out+=32;
  fd_memcpy( out, &system, 32UL ); out+=32;
  fd_memcpy( out, &bhash, 32UL ); out+=32;
  *out++=60;
  *out++=2; *out++=0; *out++=5; fd_memcpy( out, limit, 5UL ); out+=5;
  *out++=2; *out++=0; *out++=9; fd_memcpy( out, price, 9UL ); out+=9;
  *out++=2; *out++=0; *out++=5; fd_memcpy( out, loaded, 5UL ); out+=5;
  for( ulong i=0UL; i<57UL; i++ ) {
    *out++=3; *out++=2; *out++=0; *out++=1; *out++=12;
    fd_memcpy( out, transfer, 12UL ); out+=12;
  }
  FD_TEST( (ulong)(out-expected)==sz );
  FD_TEST( !memcmp( expected, payload, sz ) );

  /* This API chooses v0 only with used ALTs.  Independently wrap this
     exact message as no-ALT v0; parsing must preserve all114references. */
  uchar v0[ FD_TXN_MTU_V0 ];
  fd_memcpy( v0, payload, 65UL ); v0[65]=0x80U;
  fd_memcpy( v0+66, payload+65, sz-65UL ); v0[sz+1U]=0U;
  FD_TEST( sz+2U==1229U );
  FD_TEST( fd_txn_parse( v0, sz+2UL, txn_mem, NULL ) );
  txn = (fd_txn_t *)txn_mem;
  FD_TEST( txn->transaction_version==FD_TXN_V0 && txn->addr_table_lookup_cnt==0UL && txn->instr_cnt==60UL );
  for( ulong i=3UL; i<60UL; i++ ) {
    fd_txn_instr_t const * instr = txn->instr+i;
    uchar const * refs = fd_txn_get_instr_accts( instr, v0 );
    FD_TEST( instr->acct_cnt==2U && refs[0]==0U && refs[1]==1U );
    FD_TEST( !memcmp( fd_txn_get_instr_data( instr, v0 ), transfer, 12UL ) );
  }
  fd_txn_builder_delete( builder );

  /* Exercise builder-selected v0 through the public ALT API as well.
     Without CB instructions the57transfer message and one ALT fit. */
  FD_TEST( fd_txn_builder_new( builder, 13UL ) );
  FD_TEST( fd_txn_builder_fee_payer_set( builder, &fee ) );
  fd_txn_builder_blockhash_set( builder, &bhash );
  for( ulong i=0UL; i<57UL; i++ ) {
    FD_TEST( fd_txn_builder_instr_open( builder, &system, transfer, sizeof(transfer) ) );
    FD_TEST( fd_txn_builder_instr_account_push( builder, &fee, FD_TXN_ACCT_CAT_WRITABLE_SIGNER ) );
    FD_TEST( fd_txn_builder_instr_account_push( builder, &sink, FD_TXN_ACCT_CAT_WRITABLE ) );
    fd_txn_builder_instr_close( builder );
  }
  fd_acct_addr_t table = addr( 0xD4 );
  FD_TEST( fd_txn_builder_alut_open( builder, &table ) );
  fd_txn_builder_alut_address_push( builder, &sink, 7U );
  fd_txn_builder_alut_close( builder );
  txn = build_txn( builder, &sz );
  FD_TEST( sz==1204U && txn->transaction_version==FD_TXN_V0 );
  FD_TEST( txn->acct_addr_cnt==3UL && txn->addr_table_adtl_cnt==1UL && txn->instr_cnt==57UL );
  for( ulong i=0UL; i<57UL; i++ ) {
    fd_txn_instr_t const * instr = txn->instr+i;
    uchar const * refs = fd_txn_get_instr_accts( instr, payload );
    FD_TEST( instr->program_id==1U && instr->acct_cnt==2U && refs[0]==0U && refs[1]==3U );
    FD_TEST( !memcmp( fd_txn_get_instr_data( instr, payload ), transfer, 12UL ) );
  }
  fd_txn_builder_delete( builder );
}

static void
check_many_instruction_references( ulong total,
                                   int   use_alt ) {
  fd_txn_builder_t builder[1];
  FD_TEST( fd_txn_builder_new( builder, total ) );
  fd_acct_addr_t fee = addr( 0x11 );
  fd_acct_addr_t program = addr( 0x22 );
  fd_acct_addr_t other = use_alt ? addr( 0x33 ) : program;
  FD_TEST( fd_txn_builder_fee_payer_set( builder, &fee ) );
  ulong n = (total+63UL)/64UL;
  for( ulong i=0UL, at=0UL; i<n; i++ ) {
    FD_TEST( fd_txn_builder_instr_open( builder, &program, NULL, 0UL ) );
    for( ulong k=0UL; k<64UL && at<total; k++,at++ ) {
      fd_acct_addr_t const * acct = (i*7UL+k)%5UL==0UL ? &other : &fee;
      FD_TEST( fd_txn_builder_instr_account_push( builder, acct, FD_TXN_ACCT_CAT_NONE ) );
    }
    fd_txn_builder_instr_close( builder );
  }
  if( use_alt ) {
    fd_acct_addr_t table = addr( 0x44 );
    FD_TEST( fd_txn_builder_alut_open( builder, &table ) );
    fd_txn_builder_alut_address_push( builder, &other, 9U );
    fd_txn_builder_alut_close( builder );
  }
  uint expected_sz = (uint)((use_alt ? 235UL : 166UL)+3UL*n+total);
  /* The builder may collect an oversized message, but cannot serialize it. */
  if( expected_sz>FD_TXN_MTU_V0 ) {
    uchar guarded[ FD_TXN_MTU_V0+2UL ]; fd_memset( guarded, 0xA5, sizeof(guarded) );
    FD_TEST( !fd_txn_build_raw( builder, guarded+1 ) );
    FD_TEST( guarded[0]==0xA5U && guarded[FD_TXN_MTU_V0+1UL]==0xA5U );
  } else {
    uint sz;
    fd_txn_t * txn = build_txn( builder, &sz );
    FD_TEST( sz==expected_sz && txn->instr_cnt==n );
    FD_TEST( txn->transaction_version==(use_alt ? FD_TXN_V0 : FD_TXN_VLEGACY) );
    for( ulong i=0UL, at=0UL; i<n; i++ ) {
      fd_txn_instr_t const * instr = txn->instr+i;
      FD_TEST( instr->acct_cnt==fd_ulong_min( 64UL, total-at ) );
      uchar const * refs = fd_txn_get_instr_accts( instr, payload );
      for( ulong k=0UL; k<instr->acct_cnt; k++,at++ ) {
        uchar expected = (uchar)((i*7UL+k)%5UL==0UL ? (use_alt ? 3UL : 1UL) : 0UL);
        FD_TEST( refs[k]==expected );
      }
    }
  }
  fd_txn_builder_delete( builder );
}

FD_UNIT_TEST( instruction_reference_offsets_cross_uchar ) {
  ulong const refs[] = { 255UL, 256UL, 257UL, 320UL };
  for( ulong i=0UL; i<sizeof(refs)/sizeof(refs[0]); i++ ) {
    check_many_instruction_references( refs[i], 0 );
    check_many_instruction_references( refs[i], 1 );
  }
  check_many_instruction_references( 1018UL, 0 ); /*exact1232byte legacy*/
  check_many_instruction_references( 1019UL, 0 ); /*1233byte legacy rejected*/
  check_many_instruction_references(  952UL, 1 ); /*exact1232byte v0*/
  check_many_instruction_references(  953UL, 1 ); /*1233byte v0 rejected*/
}

FD_UNIT_TEST( instruction_reference_pool_and_local_limit ) {
  fd_txn_builder_t builder[1];
  FD_TEST( fd_txn_builder_new( builder, 14UL ) );
  fd_acct_addr_t fee = addr( 0x11 );
  fd_acct_addr_t program = addr( 0x22 );
  FD_TEST( fd_txn_builder_fee_payer_set( builder, &fee ) );
  /* The limit within each instruction remains64, including duplicates. */
  FD_TEST( fd_txn_builder_instr_open( builder, &program, NULL, 0UL ) );
  for( ulong i=0UL; i<FD_TXN_ACCT_ADDR_MAX; i++ ) FD_TEST( fd_txn_builder_instr_account_push( builder, &fee, FD_TXN_ACCT_CAT_NONE ) );
  FD_TEST( !fd_txn_builder_instr_account_push( builder, &fee, FD_TXN_ACCT_CAT_NONE ) );
  fd_txn_builder_instr_close( builder );
  for( ulong i=FD_TXN_ACCT_ADDR_MAX; i<FD_TXN_MTU_V0; ) {
    FD_TEST( fd_txn_builder_instr_open( builder, &program, NULL, 0UL ) );
    for( ulong k=0UL; k<FD_TXN_ACCT_ADDR_MAX && i<FD_TXN_MTU_V0; k++,i++ )
      FD_TEST( fd_txn_builder_instr_account_push( builder, &fee, FD_TXN_ACCT_CAT_NONE ) );
    fd_txn_builder_instr_close( builder );
  }
  FD_TEST( !fd_txn_builder_instr_account_push( builder, &fee, FD_TXN_ACCT_CAT_NONE ) );
  /* A later empty instruction's offset must also represent the full pool. */
  FD_TEST( fd_txn_builder_instr_open( builder, &program, NULL, 0UL ) );
  FD_TEST( !fd_txn_builder_instr_account_push( builder, &fee, FD_TXN_ACCT_CAT_NONE ) );
  FD_TEST( !fd_txn_build_raw( builder, payload ) );
  fd_txn_builder_delete( builder );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_unit_tests( argc, argv );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
