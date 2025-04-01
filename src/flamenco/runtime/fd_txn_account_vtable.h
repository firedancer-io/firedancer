#ifndef HEADER_fd_src_flamenco_runtime_fd_txn_account_vtable_h
#define HEADER_fd_src_flamenco_runtime_fd_txn_account_vtable_h

#include "../types/fd_types.h"
#include "../../funk/fd_funk_rec.h"

struct fd_txn_account;
typedef struct fd_txn_account fd_txn_account_t;

/* Low-level API function defs */

/* Const getters */
typedef fd_account_meta_t        const * (* fd_txn_account_get_acc_meta_fn_t)         ( fd_txn_account_t const * acct );
typedef uchar                    const * (* fd_txn_account_get_acc_data_fn_t)         ( fd_txn_account_t const * acct );
typedef fd_funk_rec_t            const * (* fd_txn_account_get_acc_rec_fn_t)          ( fd_txn_account_t const * acct );
typedef uchar *                          (* fd_txn_account_get_acc_data_mut_fn_t)     ( fd_txn_account_t const * acct );

typedef void                             (* fd_txn_account_set_meta_readonly_fn_t)    ( fd_txn_account_t * acct, fd_account_meta_t const * meta );
typedef void                             (* fd_txn_account_set_meta_mutable_fn_t)     ( fd_txn_account_t * acct, fd_account_meta_t * meta );

typedef ulong                            (* fd_txn_account_get_data_len_fn_t)         ( fd_txn_account_t const * acct );
typedef int                              (* fd_txn_account_is_executable_fn_t)        ( fd_txn_account_t const * acct );
typedef fd_pubkey_t              const * (* fd_txn_account_get_owner_fn_t)            ( fd_txn_account_t const * acct );
typedef ulong                            (* fd_txn_account_get_lamports_fn_t)         ( fd_txn_account_t const * acct );
typedef ulong                            (* fd_txn_account_get_rent_epoch_fn_t)       ( fd_txn_account_t const * acct );
typedef fd_hash_t                const * (* fd_txn_account_get_hash_fn_t)             ( fd_txn_account_t const * acct );
typedef fd_solana_account_meta_t const * (* fd_txn_account_get_info_fn_t)             ( fd_txn_account_t const * acct );

/* Setters */
typedef void                             (* fd_txn_account_set_executable_fn_t)       ( fd_txn_account_t * acct, int is_executable );
typedef void                             (* fd_txn_account_set_owner_fn_t)            ( fd_txn_account_t * acct, fd_pubkey_t const * owner );
typedef void                             (* fd_txn_account_set_lamports_fn_t)         ( fd_txn_account_t * acct, ulong lamports );
typedef int                              (* fd_txn_account_checked_add_lamports_fn_t) ( fd_txn_account_t * acct, ulong lamports );
typedef int                              (* fd_txn_account_checked_sub_lamports_fn_t) ( fd_txn_account_t * acct, ulong lamports );
typedef void                             (* fd_txn_account_set_rent_epoch_fn_t)       ( fd_txn_account_t * acct, ulong rent_epoch );
typedef void                             (* fd_txn_account_set_data_fn_t)             ( fd_txn_account_t * acct, void const * new_data, ulong data_sz );
typedef void                             (* fd_txn_account_set_data_len_fn_t)         ( fd_txn_account_t * acct, ulong data_len );
typedef void                             (* fd_txn_account_set_slot_fn_t)             ( fd_txn_account_t * acct, ulong slot );
typedef void                             (* fd_txn_account_set_hash_fn_t)             ( fd_txn_account_t * acct, fd_hash_t const * hash );
typedef void                             (* fd_txn_account_clear_owner_fn_t)          ( fd_txn_account_t * acct );
typedef void                             (* fd_txn_account_set_meta_info_fn_t)        ( fd_txn_account_t * acct, fd_solana_account_meta_t const * info );
typedef void                             (* fd_txn_account_resize_fn_t)               ( fd_txn_account_t * acct, ulong data_len );

/* Attribute Accessors */
typedef ushort                           (* fd_txn_account_is_borrowed_fn_t)          ( fd_txn_account_t const * acct );
typedef int                              (* fd_txn_acccount_is_mutable_fn_t)          ( fd_txn_account_t const * acct );
typedef int                              (* fd_txn_account_is_readonly_fn_t)          ( fd_txn_account_t const * acct );

/* Borrow */
typedef int                              (* fd_txn_account_try_borrow_mut_fn_t)       ( fd_txn_account_t * acct );
typedef void                             (* fd_txn_account_drop_fn_t)                 ( fd_txn_account_t * acct );

/* Permissions mutators */
typedef void                             (* fd_txn_account_set_readonly_fn_t)         ( fd_txn_account_t * acct );
typedef void                             (* fd_txn_account_set_mutable_fn_t)          ( fd_txn_account_t * acct );

struct fd_txn_account_vtable {
  /* Const getters */
  fd_txn_account_get_acc_meta_fn_t         get_meta;
  fd_txn_account_get_acc_data_fn_t         get_data;
  fd_txn_account_get_acc_rec_fn_t          get_rec;

  fd_txn_account_get_acc_data_mut_fn_t     get_data_mut;

  fd_txn_account_set_meta_readonly_fn_t    set_meta_readonly;
  fd_txn_account_set_meta_mutable_fn_t     set_meta_mutable;

  fd_txn_account_get_data_len_fn_t         get_data_len;
  fd_txn_account_is_executable_fn_t        is_executable;
  fd_txn_account_get_owner_fn_t            get_owner;
  fd_txn_account_get_lamports_fn_t         get_lamports;
  fd_txn_account_get_rent_epoch_fn_t       get_rent_epoch;
  fd_txn_account_get_hash_fn_t             get_hash;
  fd_txn_account_get_info_fn_t             get_info;

  /* Setters */
  fd_txn_account_set_executable_fn_t       set_executable;
  fd_txn_account_set_owner_fn_t            set_owner;
  fd_txn_account_set_lamports_fn_t         set_lamports;
  fd_txn_account_checked_add_lamports_fn_t checked_add_lamports;
  fd_txn_account_checked_sub_lamports_fn_t checked_sub_lamports;
  fd_txn_account_set_rent_epoch_fn_t       set_rent_epoch;
  fd_txn_account_set_data_fn_t             set_data;
  fd_txn_account_set_data_len_fn_t         set_data_len;
  fd_txn_account_set_slot_fn_t             set_slot;
  fd_txn_account_set_hash_fn_t             set_hash;
  fd_txn_account_clear_owner_fn_t          clear_owner;
  fd_txn_account_set_meta_info_fn_t        set_info;
  fd_txn_account_resize_fn_t               resize;

  /* Attribute accessors */
  fd_txn_account_is_borrowed_fn_t          is_borrowed;
  fd_txn_acccount_is_mutable_fn_t          is_mutable;
  fd_txn_account_is_readonly_fn_t          is_readonly;

  /* Borrow */
  fd_txn_account_try_borrow_mut_fn_t        try_borrow_mut;
  fd_txn_account_drop_fn_t                  drop;

  /* Permissions mutators */
  fd_txn_account_set_readonly_fn_t          set_readonly;
  fd_txn_account_set_mutable_fn_t           set_mutable;
};
typedef struct fd_txn_account_vtable fd_txn_account_vtable_t;

extern const fd_txn_account_vtable_t fd_txn_account_writable_vtable;
extern const fd_txn_account_vtable_t fd_txn_account_readonly_vtable;

#endif /* HEADER_fd_src_flamenco_runtime_fd_txn_account_vtable_h */
