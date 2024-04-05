#include "fd_instr_info.h"

FD_FN_PURE int
fd_instr_any_signed( fd_instr_info_t const * info,
                     fd_pubkey_t const *     pubkey ) {
  int is_signer = 0;
  for( ulong j=0UL; j < info->acct_cnt; j++ )
    is_signer |=
      ( ( !!fd_instr_acc_is_signer_idx( info, j ) ) &
        ( 0==memcmp( pubkey->key, info->acct_pubkeys[j].key, sizeof(fd_pubkey_t) ) ) );
  return is_signer;
}

FD_FN_PURE ulong
fd_instr_info_sum_account_lamports( fd_instr_info_t const * instr ) {

  ulong total_lamports = 0;

  for( ulong i = 0; i < instr->acct_cnt; i++ ) {

    if( instr->borrowed_accounts[i] == NULL )
      continue;

    if( ( instr->is_duplicate[i]                          ) |
        ( instr->borrowed_accounts[i]->const_meta == NULL ) )
      continue;

    ulong acct_lamports = instr->borrowed_accounts[i]->const_meta->info.lamports;

    if( FD_UNLIKELY( __builtin_uaddl_overflow( total_lamports, acct_lamports, &total_lamports ) ) )
      FD_LOG_ERR(( "integer overflow" ));

  }

  return total_lamports;
}
