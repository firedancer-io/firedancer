#include "fd_vm_syscall.h"

FD_STATIC_ASSERT( offsetof( fd_vm_vec_t, addr )== 0UL, layout );
FD_STATIC_ASSERT( offsetof( fd_vm_vec_t, len  )== 8UL, layout );
FD_STATIC_ASSERT( sizeof  ( fd_vm_vec_t       )==16UL, layout );

FD_STATIC_ASSERT( offsetof( fd_vm_c_instruction_t, program_id_addr )== 0UL, layout );
FD_STATIC_ASSERT( offsetof( fd_vm_c_instruction_t, accounts_addr   )== 8UL, layout );
FD_STATIC_ASSERT( offsetof( fd_vm_c_instruction_t, accounts_len    )==16UL, layout );
FD_STATIC_ASSERT( offsetof( fd_vm_c_instruction_t, data_addr       )==24UL, layout );
FD_STATIC_ASSERT( offsetof( fd_vm_c_instruction_t, data_len        )==32UL, layout );
FD_STATIC_ASSERT( sizeof  ( fd_vm_c_instruction_t                  )==40UL, layout );

FD_STATIC_ASSERT( offsetof( fd_vm_c_account_meta_t, pubkey_addr )==0UL, layout );
FD_STATIC_ASSERT( offsetof( fd_vm_c_account_meta_t, is_writable )==8UL, layout );
FD_STATIC_ASSERT( offsetof( fd_vm_c_account_meta_t, is_signer   )==9UL, layout );
FD_STATIC_ASSERT( sizeof  ( fd_vm_c_account_meta_t              )==16UL, layout );

FD_STATIC_ASSERT( offsetof( fd_vm_c_account_info_t, pubkey_addr   )== 0UL, layout );
FD_STATIC_ASSERT( offsetof( fd_vm_c_account_info_t, lamports_addr )== 8UL, layout );
FD_STATIC_ASSERT( offsetof( fd_vm_c_account_info_t, data_sz       )==16UL, layout );
FD_STATIC_ASSERT( offsetof( fd_vm_c_account_info_t, data_addr     )==24UL, layout );
FD_STATIC_ASSERT( offsetof( fd_vm_c_account_info_t, owner_addr    )==32UL, layout );
FD_STATIC_ASSERT( offsetof( fd_vm_c_account_info_t, rent_epoch    )==40UL, layout );
FD_STATIC_ASSERT( offsetof( fd_vm_c_account_info_t, is_signer     )==48UL, layout );
FD_STATIC_ASSERT( offsetof( fd_vm_c_account_info_t, is_writable   )==49UL, layout );
FD_STATIC_ASSERT( offsetof( fd_vm_c_account_info_t, executable    )==50UL, layout );
FD_STATIC_ASSERT( sizeof  ( fd_vm_c_account_info_t                )==56UL, layout );

FD_STATIC_ASSERT( offsetof( fd_vm_rust_vec_t, addr )== 0UL, layout );
FD_STATIC_ASSERT( offsetof( fd_vm_rust_vec_t, cap  )== 8UL, layout );
FD_STATIC_ASSERT( offsetof( fd_vm_rust_vec_t, len  )==16UL, layout );
FD_STATIC_ASSERT( sizeof  ( fd_vm_rust_vec_t       )==24UL, layout );

FD_STATIC_ASSERT( offsetof( fd_vm_rust_instruction_t, accounts )== 0UL, layout );
FD_STATIC_ASSERT( offsetof( fd_vm_rust_instruction_t, data     )==24UL, layout );
FD_STATIC_ASSERT( offsetof( fd_vm_rust_instruction_t, pubkey   )==48UL, layout );
FD_STATIC_ASSERT( sizeof  ( fd_vm_rust_instruction_t           )==80UL, layout );

FD_STATIC_ASSERT( offsetof( fd_vm_rust_account_meta_t, pubkey      )== 0UL, layout );
FD_STATIC_ASSERT( offsetof( fd_vm_rust_account_meta_t, is_signer   )==32UL, layout );
FD_STATIC_ASSERT( offsetof( fd_vm_rust_account_meta_t, is_writable )==33UL, layout );
FD_STATIC_ASSERT( sizeof  ( fd_vm_rust_account_meta_t              )==34UL, layout );


int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* TODO: Add runtime tests here */

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
