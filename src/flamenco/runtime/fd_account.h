#ifndef HEADER_fd_src_flamenco_runtime_fd_account_h
#define HEADER_fd_src_flamenco_runtime_fd_account_h

#include "../../ballet/txn/fd_txn.h"
#include "fd_runtime.h"

// Once these settle out, we will switch almost everything to not be inlined

static inline
int fd_account_sanity_check_raw(
  fd_txn_instr_t const * instr,
  fd_txn_t*         txn_descriptor,
  fd_rawtxn_b_t*    txn_raw,
  int cnt
) {
  if (instr->acct_cnt < cnt)
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;

  uchar *       instr_acc_idxs = ((uchar *)txn_raw->raw + instr->acct_off);
  ulong acct_addr_cnt = txn_descriptor->acct_addr_cnt;

  for (int i = 0; i < cnt; i++)
    if (instr_acc_idxs[i] >= acct_addr_cnt)
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;

  return FD_EXECUTOR_INSTR_SUCCESS;
}

static inline
int fd_account_sanity_check(instruction_ctx_t const *ctx, int cnt) {
  return fd_account_sanity_check_raw(ctx->instr, ctx->txn_ctx->txn_descriptor, ctx->txn_ctx->txn_raw, cnt);
}

static inline
void * fd_account_get_data(fd_account_meta_t *m) {
  return ((char *) m) + m->hlen;
}

static inline
int fd_account_is_early_verification_of_account_modifications_enabled(FD_FN_UNUSED instruction_ctx_t *ctx) {
  // this seems to be based on if rent is enabled in the transaction
  // context instead on if the feature flag is enabled..   Then, you
  // go look for the feature flag usage it is also confused...  Lets
  // just hardcode to 1 for now until the possibility of rent going
  // away is a higher possibility...

  // self.rent.is_some()

  return 1;
}

static inline
int fd_account_touch(FD_FN_UNUSED instruction_ctx_t *ctx, FD_FN_UNUSED fd_account_meta_t * acct, FD_FN_UNUSED fd_pubkey_t *key, FD_FN_UNUSED int *err) {
  return 1;
}

static inline
int fd_account_is_executable(FD_FN_UNUSED instruction_ctx_t *ctx,  const FD_FN_UNUSED fd_account_meta_t *acct, FD_FN_UNUSED  int *err) {
  return acct->info.executable;
}

//    /// Returns true if the owner of this account is the current `InstructionContext`s last program (instruction wide)
static inline
int fd_account_is_owned_by_current_program(const FD_FN_UNUSED instruction_ctx_t *ctx, const FD_FN_UNUSED fd_account_meta_t * acct, FD_FN_UNUSED  int *err) {
//        self.instruction_context
//            .get_last_program_key(self.transaction_context)
//            .map(|key| key == self.get_owner())
//            .unwrap_or_default()
  return 1;
}

static inline
int fd_account_can_data_be_resized(instruction_ctx_t *ctx, const fd_account_meta_t * acct, ulong new_length, int *err) {
  if (!fd_account_is_early_verification_of_account_modifications_enabled(ctx))
    return 1;

  if (acct->dlen != new_length && !fd_account_is_owned_by_current_program(ctx, acct, err)) {
    *err = FD_EXECUTOR_INSTR_ERR_ACC_DATA_SIZE_CHANGED;
    return 0;
  }

  if (new_length > MAX_PERMITTED_DATA_LENGTH) {
    *err = FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC;
    return 0;
  }

  return 1;
}

static inline
int fd_account_is_writable_idx(instruction_ctx_t *ctx, int idx) {
  ushort        acct_addr_cnt = ctx->txn_ctx->txn_descriptor->acct_addr_cnt;

  if (idx == acct_addr_cnt)
    return 0;

  // You just cannot write to a program...
  if (idx == ctx->instr->program_id)
    return 0;

  return fd_txn_is_writable(ctx->txn_ctx->txn_descriptor, idx);
}

static inline
int fd_account_is_writable(instruction_ctx_t *ctx, fd_pubkey_t *acct) {
  fd_pubkey_t * txn_accs = (fd_pubkey_t *)((uchar *)ctx->txn_ctx->txn_raw->raw + ctx->txn_ctx->txn_descriptor->acct_addr_off);
  ushort        acct_addr_cnt = ctx->txn_ctx->txn_descriptor->acct_addr_cnt;

  int idx = 0;
  for (; idx < acct_addr_cnt; idx++) {
    if (memcmp(&txn_accs[idx], acct, sizeof(fd_pubkey_t)) == 0)
      break;
  }

  return fd_account_is_writable_idx(ctx, idx);
}

static inline
int fd_account_can_data_be_changed(instruction_ctx_t *ctx, fd_account_meta_t * acct, fd_pubkey_t * key,  int *err) {
  if (!fd_account_is_early_verification_of_account_modifications_enabled(ctx))
    return 1;

  if (fd_account_is_executable(ctx, acct, err)) {
    *err = FD_EXECUTOR_INSTR_ERR_EXECUTABLE_DATA_MODIFIED;
    return 0;
  }

  if (!fd_account_is_writable(ctx, key)) {
    *err = FD_EXECUTOR_INSTR_ERR_READONLY_DATA_MODIFIED;
    return 0;
  }

  if (!fd_account_is_owned_by_current_program(ctx, acct, err)) {
    *err = FD_EXECUTOR_INSTR_ERR_EXTERNAL_DATA_MODIFIED;
    return 0;
  }

  return 1;
}

//
//    /// Returns the owner of this account (transaction wide)
//    pub fn get_owner(&self) -> &Pubkey {
//        self.account.owner()
//    }
//
//    /// Assignes the owner of this account (transaction wide)

static inline
int fd_account_is_zeroed(fd_account_meta_t * acct) {
  if (acct->dlen == 0)
    return 1;

  // TODO optimize this...
  uchar *data = ((uchar *) acct) + acct->hlen;
  for (ulong i = 0; i < acct->dlen; i++)
    if (data[i] != 0)
      return 0;

  return 1;
}

static inline
int fd_account_set_owner(instruction_ctx_t *ctx, fd_account_meta_t * acct, fd_pubkey_t *key, fd_pubkey_t *pubkey) {
  if (fd_account_is_early_verification_of_account_modifications_enabled(ctx)) {
    int err = 0;
    if (!fd_account_is_owned_by_current_program(ctx, acct, &err))
      return FD_EXECUTOR_INSTR_ERR_MODIFIED_PROGRAM_ID;
    if (!fd_account_is_writable(ctx, key))
      return FD_EXECUTOR_INSTR_ERR_MODIFIED_PROGRAM_ID;
    if (fd_account_is_executable(ctx, acct, &err))
      return FD_EXECUTOR_INSTR_ERR_MODIFIED_PROGRAM_ID;
    if (!fd_account_is_zeroed(acct))
      return FD_EXECUTOR_INSTR_ERR_MODIFIED_PROGRAM_ID;
    if (memcmp(&acct->info.owner, pubkey, sizeof(fd_pubkey_t)) == 0)
      return FD_ACC_MGR_SUCCESS;
    if (memcmp(acct->info.owner, ctx->global->solana_system_program, sizeof(acct->info.owner)) != 0)
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    // shouldn't the touch and compare here be outside the if?
    if (!fd_account_touch(ctx, acct, key, &err))
      return err;
  }
  memcpy(&acct->info.owner, pubkey, sizeof(fd_pubkey_t));

  return FD_ACC_MGR_SUCCESS;
}

//
//    /// Returns the number of lamports of this account (transaction wide)
//    pub fn get_lamports(&self) -> u64 {
//        self.account.lamports()
//    }
//
//    /// Overwrites the number of lamports of this account (transaction wide)
//    pub fn set_lamports(&mut self, lamports: u64) -> Result<(), InstructionError> {
//        if self
//            .transaction_context
//            .is_early_verification_of_account_modifications_enabled()
//        {
//            // An account not owned by the program cannot have its balance decrease
//            if !self.is_owned_by_current_program() && lamports < self.get_lamports() {
//                return Err(InstructionError::ExternalAccountLamportSpend);
//            }
//            // The balance of read-only may not change
//            if !self.is_writable() {
//                return Err(InstructionError::ReadonlyLamportChange);
//            }
//            // The balance of executable accounts may not change
//            if self.is_executable() {
//                return Err(InstructionError::ExecutableLamportChange);
//            }
//            // don't touch the account if the lamports do not change
//            if self.get_lamports() == lamports {
//                return Ok(());
//            }
//            self.touch()?;
//        }
//        self.account.set_lamports(lamports);
//        Ok(())
//    }
//
//    /// Adds lamports to this account (transaction wide)
//    pub fn checked_add_lamports(&mut self, lamports: u64) -> Result<(), InstructionError> {
//        self.set_lamports(
//            self.get_lamports()
//                .checked_add(lamports)
//                .ok_or(InstructionError::ArithmeticOverflow)?,
//        )
//    }
//
//    /// Subtracts lamports from this account (transaction wide)
//    pub fn checked_sub_lamports(&mut self, lamports: u64) -> Result<(), InstructionError> {
//        self.set_lamports(
//            self.get_lamports()
//                .checked_sub(lamports)
//                .ok_or(InstructionError::ArithmeticOverflow)?,
//        )
//    }
//
//    /// Returns a read-only slice of the account data (transaction wide)
//    pub fn get_data(&self) -> &[u8] {
//        self.account.data()
//    }
//
//    /// Returns a writable slice of the account data (transaction wide)
//    pub fn get_data_mut(&mut self) -> Result<&mut [u8], InstructionError> {
//        self.can_data_be_changed()?;
//        self.touch()?;
//        Ok(self.account.data_as_mut_slice())
//    }
//
//    /// Overwrites the account data and size (transaction wide)

static inline
int fd_account_check_set_data(instruction_ctx_t *ctx, fd_account_meta_t * acct, fd_pubkey_t *key, uchar *data, ulong new_length, int space_check, int *err) {
  if (!fd_account_can_data_be_resized(ctx, acct, new_length, err))
    return 0;

  if (!fd_account_can_data_be_changed(ctx, acct, key, err))
    return 0;

  fd_account_touch(ctx, acct, key, err);

  if (space_check && (acct->dlen < new_length)) {
    //do magic to make sure it fits...
  }

  acct->dlen = new_length;
  uchar *d = ((uchar *) acct) + acct->hlen;

  memcpy(d, data, new_length);

//    pub fn set_data(&mut self, data: &[u8]) -> Result<(), InstructionError> {
//        self.can_data_be_resized(data.len())?;
//        self.can_data_be_changed()?;
//        self.touch()?;
//        if data.len() == self.account.data().len() {
//            self.account.data_as_mut_slice().copy_from_slice(data);
//        } else {
//            let mut accounts_resize_delta = self
//                .transaction_context
//                .accounts_resize_delta
//                .try_borrow_mut()
//                .map_err(|_| InstructionError::GenericError)?;
//            *accounts_resize_delta = accounts_resize_delta
//                .saturating_add((data.len() as i64).saturating_sub(self.get_data().len() as i64));
//            self.account.set_data_from_slice(data);
//        }
  return 1;
}

//    /// Resizes the account data (transaction wide)
//    ///
//    /// Fills it with zeros at the end if is extended or truncates at the end otherwise.

static inline
int fd_account_check_set_data_length(instruction_ctx_t *ctx, fd_account_meta_t * acct, fd_pubkey_t *key, ulong new_length, int *err) {
  if (!fd_account_can_data_be_resized(ctx, acct, new_length, err))
    return 0;

  if (!fd_account_can_data_be_changed(ctx, acct, key, err))
    return 0;

  return 1;
}

static inline
int fd_account_set_data_length(instruction_ctx_t *ctx, fd_account_meta_t * acct, fd_pubkey_t *key, ulong new_length, int space_check, int *err) {
  if (!fd_account_can_data_be_resized(ctx, acct, new_length, err))
    return 0;

  if (!fd_account_can_data_be_changed(ctx, acct, key, err))
    return 0;

  if (acct->dlen == new_length)
    return 1;

  if (space_check && (acct->dlen < new_length)) {
    //do magic to make sure it fits...
  }

  fd_account_touch(ctx, acct, key, err);

  uchar *data = ((uchar *) acct) + acct->hlen;

  if (new_length > acct->dlen)
    memset(&data[acct->dlen], 0, new_length - acct->dlen);

  acct->dlen = new_length;

//        self.touch()?;
//        let mut accounts_resize_delta = self
//            .transaction_context
//            .accounts_resize_delta
//            .try_borrow_mut()
//            .map_err(|_| InstructionError::GenericError)?;
//        *accounts_resize_delta = accounts_resize_delta
//            .saturating_add((new_length as i64).saturating_sub(self.get_data().len() as i64));
//        self.account.data_mut().resize(new_length, 0);

  return 1;
}
//
//    /// Deserializes the account data into a state
//    pub fn get_state<T: serde::de::DeserializeOwned>(&self) -> Result<T, InstructionError> {
//        self.account
//            .deserialize_data()
//            .map_err(|_| InstructionError::InvalidAccountData)
//    }
//
//    /// Serializes a state into the account data
//    pub fn set_state<T: serde::Serialize>(&mut self, state: &T) -> Result<(), InstructionError> {
//        let data = self.get_data_mut()?;
//        let serialized_size =
//            bincode::serialized_size(state).map_err(|_| InstructionError::GenericError)?;
//        if serialized_size > data.len() as u64 {
//            return Err(InstructionError::AccountDataTooSmall);
//        }
//        bincode::serialize_into(&mut *data, state).map_err(|_| InstructionError::GenericError)?;
//        Ok(())
//    }
//
//    /// Configures whether this account is executable (transaction wide)
//    pub fn set_executable(&mut self, is_executable: bool) -> Result<(), InstructionError> {
//        if let Some(rent) = self.transaction_context.rent {
//            // To become executable an account must be rent exempt
//            if !rent.is_exempt(self.get_lamports(), self.get_data().len()) {
//                return Err(InstructionError::ExecutableAccountNotRentExempt);
//            }
//            // Only the owner can set the executable flag
//            if !self.is_owned_by_current_program() {
//                return Err(InstructionError::ExecutableModified);
//            }
//            // and only if the account is writable
//            if !self.is_writable() {
//                return Err(InstructionError::ExecutableModified);
//            }
//            // one can not clear the executable flag
//            if self.is_executable() && !is_executable {
//                return Err(InstructionError::ExecutableModified);
//            }
//            // don't touch the account if the executable flag does not change
//            if self.is_executable() == is_executable {
//                return Ok(());
//            }
//            self.touch()?;
//        }
//        self.account.set_executable(is_executable);
//        Ok(())
//    }
//
//    /// Returns the rent epoch of this account (transaction wide)
//    pub fn get_rent_epoch(&self) -> u64 {
//        self.account.rent_epoch()
//    }
//
//    /// Returns whether this account is a signer (instruction wide)

static inline
int fd_account_is_signer(instruction_ctx_t const *ctx, fd_pubkey_t * account) {
  uchar *       instr_acc_idxs = ((uchar *)ctx->txn_ctx->txn_raw->raw + ctx->instr->acct_off);
  fd_pubkey_t * txn_accs = (fd_pubkey_t *)((uchar *)ctx->txn_ctx->txn_raw->raw + ctx->txn_ctx->txn_descriptor->acct_addr_off);

  for ( ulong i = 0; i < ctx->instr->acct_cnt; i++ ) {
    if ( instr_acc_idxs[i] < ctx->txn_ctx->txn_descriptor->signature_cnt ) {
      fd_pubkey_t * signer = &txn_accs[instr_acc_idxs[i]];
      if ( memcmp( signer, account, sizeof(fd_pubkey_t) ) == 0 )
        return 1;
    }
  }
  return 0;

//        if self.index_in_instruction < self.instruction_context.program_accounts.len() {
//            return false;
//        }
//        self.instruction_context
//            .is_instruction_account_signer(
//                self.index_in_instruction
//                    .saturating_sub(self.instruction_context.program_accounts.len()),
//            )
//            .unwrap_or_default()
}
//


#endif
