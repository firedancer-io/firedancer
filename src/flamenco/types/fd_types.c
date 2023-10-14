#include "fd_types.h"

/* FIXME: Temporary scaffolding */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wunused-variable"
#if FD_USING_GCC==1 /* Clang doesn't understand these options */
#pragma GCC diagnostic ignored "-Wsuggest-attribute=const"
#pragma GCC diagnostic ignored "-Wsuggest-attribute=pure"
#endif

#ifdef _DISABLE_OPTIMIZATION
#pragma GCC optimize ("O0")
#endif

int fd_fee_calculator_decode(fd_fee_calculator_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode(&self->lamports_per_signature, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_fee_calculator_new(fd_fee_calculator_t* self) {
}
void fd_fee_calculator_destroy(fd_fee_calculator_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

void fd_fee_calculator_walk(fd_fee_calculator_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_fee_calculator", level++);
  fun(&self->lamports_per_signature, "lamports_per_signature", 11, "ulong", level + 1);
  fun(self, name, 33, "fd_fee_calculator", --level);
}
ulong fd_fee_calculator_size(fd_fee_calculator_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  return size;
}

int fd_fee_calculator_encode(fd_fee_calculator_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(&self->lamports_per_signature, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_hash_age_decode(fd_hash_age_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_fee_calculator_decode(&self->fee_calculator, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->hash_index, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->timestamp, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_hash_age_new(fd_hash_age_t* self) {
  fd_fee_calculator_new(&self->fee_calculator);
}
void fd_hash_age_destroy(fd_hash_age_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_fee_calculator_destroy(&self->fee_calculator, ctx);
}

void fd_hash_age_walk(fd_hash_age_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_hash_age", level++);
  fd_fee_calculator_walk(&self->fee_calculator, fun, "fee_calculator", level + 1);
  fun(&self->hash_index, "hash_index", 11, "ulong", level + 1);
  fun(&self->timestamp, "timestamp", 11, "ulong", level + 1);
  fun(self, name, 33, "fd_hash_age", --level);
}
ulong fd_hash_age_size(fd_hash_age_t const * self) {
  ulong size = 0;
  size += fd_fee_calculator_size(&self->fee_calculator);
  size += sizeof(ulong);
  size += sizeof(ulong);
  return size;
}

int fd_hash_age_encode(fd_hash_age_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_fee_calculator_encode(&self->fee_calculator, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->hash_index, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->timestamp, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_hash_hash_age_pair_decode(fd_hash_hash_age_pair_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_hash_decode(&self->key, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_age_decode(&self->val, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_hash_hash_age_pair_new(fd_hash_hash_age_pair_t* self) {
  fd_hash_new(&self->key);
  fd_hash_age_new(&self->val);
}
void fd_hash_hash_age_pair_destroy(fd_hash_hash_age_pair_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_hash_destroy(&self->key, ctx);
  fd_hash_age_destroy(&self->val, ctx);
}

void fd_hash_hash_age_pair_walk(fd_hash_hash_age_pair_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_hash_hash_age_pair", level++);
  fd_hash_walk(&self->key, fun, "key", level + 1);
  fd_hash_age_walk(&self->val, fun, "val", level + 1);
  fun(self, name, 33, "fd_hash_hash_age_pair", --level);
}
ulong fd_hash_hash_age_pair_size(fd_hash_hash_age_pair_t const * self) {
  ulong size = 0;
  size += fd_hash_size(&self->key);
  size += fd_hash_age_size(&self->val);
  return size;
}

int fd_hash_hash_age_pair_encode(fd_hash_hash_age_pair_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_hash_encode(&self->key, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_age_encode(&self->val, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_block_hash_queue_decode(fd_block_hash_queue_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode(&self->last_hash_index, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  {
    unsigned char o;
    err = fd_bincode_option_decode(&o, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    if (o) {
      self->last_hash = (fd_hash_t*)(*ctx->allocf)(ctx->allocf_arg, FD_HASH_ALIGN, FD_HASH_FOOTPRINT);
      fd_hash_new(self->last_hash);
      err = fd_hash_decode(self->last_hash, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    } else
      self->last_hash = NULL;
  }
  err = fd_bincode_uint64_decode(&self->ages_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->ages_len != 0) {
    self->ages = (fd_hash_hash_age_pair_t*)(*ctx->allocf)(ctx->allocf_arg, FD_HASH_HASH_AGE_PAIR_ALIGN, FD_HASH_HASH_AGE_PAIR_FOOTPRINT*self->ages_len);
    for (ulong i = 0; i < self->ages_len; ++i) {
      fd_hash_hash_age_pair_new(self->ages + i);
    }
    for (ulong i = 0; i < self->ages_len; ++i) {
      err = fd_hash_hash_age_pair_decode(self->ages + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else
    self->ages = NULL;
  err = fd_bincode_uint64_decode(&self->max_age, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_block_hash_queue_new(fd_block_hash_queue_t* self) {
  self->last_hash = NULL;
  self->ages = NULL;
}
void fd_block_hash_queue_destroy(fd_block_hash_queue_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->last_hash) {
    fd_hash_destroy(self->last_hash, ctx);
    (*ctx->freef)(ctx->freef_arg, self->last_hash);
    self->last_hash = NULL;
  }
  if (NULL != self->ages) {
    for (ulong i = 0; i < self->ages_len; ++i)
      fd_hash_hash_age_pair_destroy(self->ages + i, ctx);
    (*ctx->freef)(ctx->freef_arg, self->ages);
    self->ages = NULL;
  }
}

void fd_block_hash_queue_walk(fd_block_hash_queue_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_block_hash_queue", level++);
  fun(&self->last_hash_index, "last_hash_index", 11, "ulong", level + 1);
  // fun(&self->last_hash, "last_hash", 16, "option", level + 1);
  if (self->ages_len != 0) {
    fun(NULL, NULL, 30, "ages", level++);
    for (ulong i = 0; i < self->ages_len; ++i)
      fd_hash_hash_age_pair_walk(self->ages + i, fun, "hash_hash_age_pair", level + 1);
    fun(NULL, NULL, 31, "ages", --level);
  }
  fun(&self->max_age, "max_age", 11, "ulong", level + 1);
  fun(self, name, 33, "fd_block_hash_queue", --level);
}
ulong fd_block_hash_queue_size(fd_block_hash_queue_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(char);
  if (NULL !=  self->last_hash) {
    size += fd_hash_size(self->last_hash);
  }
  size += sizeof(ulong);
  for (ulong i = 0; i < self->ages_len; ++i)
    size += fd_hash_hash_age_pair_size(self->ages + i);
  size += sizeof(ulong);
  return size;
}

int fd_block_hash_queue_encode(fd_block_hash_queue_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(&self->last_hash_index, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->last_hash != NULL) {
    err = fd_bincode_option_encode(1, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    err = fd_hash_encode(self->last_hash, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  } else {
    err = fd_bincode_option_encode(0, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_bincode_uint64_encode(&self->ages_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->ages_len != 0) {
    for (ulong i = 0; i < self->ages_len; ++i) {
      err = fd_hash_hash_age_pair_encode(self->ages + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  err = fd_bincode_uint64_encode(&self->max_age, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_epoch_schedule_decode(fd_epoch_schedule_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode(&self->slots_per_epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->leader_schedule_slot_offset, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_decode(&self->warmup, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->first_normal_epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->first_normal_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_epoch_schedule_new(fd_epoch_schedule_t* self) {
}
void fd_epoch_schedule_destroy(fd_epoch_schedule_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

void fd_epoch_schedule_walk(fd_epoch_schedule_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_epoch_schedule", level++);
  fun(&self->slots_per_epoch, "slots_per_epoch", 11, "ulong", level + 1);
  fun(&self->leader_schedule_slot_offset, "leader_schedule_slot_offset", 11, "ulong", level + 1);
  fun(&self->warmup, "warmup", 9, "uchar", level + 1);
  fun(&self->first_normal_epoch, "first_normal_epoch", 11, "ulong", level + 1);
  fun(&self->first_normal_slot, "first_normal_slot", 11, "ulong", level + 1);
  fun(self, name, 33, "fd_epoch_schedule", --level);
}
ulong fd_epoch_schedule_size(fd_epoch_schedule_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(char);
  size += sizeof(ulong);
  size += sizeof(ulong);
  return size;
}

int fd_epoch_schedule_encode(fd_epoch_schedule_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(&self->slots_per_epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->leader_schedule_slot_offset, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_encode(&self->warmup, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->first_normal_epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->first_normal_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_fee_rate_governor_decode(fd_fee_rate_governor_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode(&self->target_lamports_per_signature, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->target_signatures_per_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->min_lamports_per_signature, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->max_lamports_per_signature, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_decode(&self->burn_percent, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_fee_rate_governor_new(fd_fee_rate_governor_t* self) {
}
void fd_fee_rate_governor_destroy(fd_fee_rate_governor_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

void fd_fee_rate_governor_walk(fd_fee_rate_governor_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_fee_rate_governor", level++);
  fun(&self->target_lamports_per_signature, "target_lamports_per_signature", 11, "ulong", level + 1);
  fun(&self->target_signatures_per_slot, "target_signatures_per_slot", 11, "ulong", level + 1);
  fun(&self->min_lamports_per_signature, "min_lamports_per_signature", 11, "ulong", level + 1);
  fun(&self->max_lamports_per_signature, "max_lamports_per_signature", 11, "ulong", level + 1);
  fun(&self->burn_percent, "burn_percent", 9, "uchar", level + 1);
  fun(self, name, 33, "fd_fee_rate_governor", --level);
}
ulong fd_fee_rate_governor_size(fd_fee_rate_governor_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(char);
  return size;
}

int fd_fee_rate_governor_encode(fd_fee_rate_governor_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(&self->target_lamports_per_signature, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->target_signatures_per_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->min_lamports_per_signature, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->max_lamports_per_signature, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_encode(&self->burn_percent, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_slot_pair_decode(fd_slot_pair_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode(&self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->val, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_slot_pair_new(fd_slot_pair_t* self) {
}
void fd_slot_pair_destroy(fd_slot_pair_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

void fd_slot_pair_walk(fd_slot_pair_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_slot_pair", level++);
  fun(&self->slot, "slot", 11, "ulong", level + 1);
  fun(&self->val, "val", 11, "ulong", level + 1);
  fun(self, name, 33, "fd_slot_pair", --level);
}
ulong fd_slot_pair_size(fd_slot_pair_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  return size;
}

int fd_slot_pair_encode(fd_slot_pair_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(&self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->val, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_hard_forks_decode(fd_hard_forks_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode(&self->hard_forks_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->hard_forks_len != 0) {
    self->hard_forks = (fd_slot_pair_t*)(*ctx->allocf)(ctx->allocf_arg, FD_SLOT_PAIR_ALIGN, FD_SLOT_PAIR_FOOTPRINT*self->hard_forks_len);
    for (ulong i = 0; i < self->hard_forks_len; ++i) {
      fd_slot_pair_new(self->hard_forks + i);
    }
    for (ulong i = 0; i < self->hard_forks_len; ++i) {
      err = fd_slot_pair_decode(self->hard_forks + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else
    self->hard_forks = NULL;
  return FD_BINCODE_SUCCESS;
}
void fd_hard_forks_new(fd_hard_forks_t* self) {
  self->hard_forks = NULL;
}
void fd_hard_forks_destroy(fd_hard_forks_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->hard_forks) {
    for (ulong i = 0; i < self->hard_forks_len; ++i)
      fd_slot_pair_destroy(self->hard_forks + i, ctx);
    (*ctx->freef)(ctx->freef_arg, self->hard_forks);
    self->hard_forks = NULL;
  }
}

void fd_hard_forks_walk(fd_hard_forks_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_hard_forks", level++);
  if (self->hard_forks_len != 0) {
    fun(NULL, NULL, 30, "hard_forks", level++);
    for (ulong i = 0; i < self->hard_forks_len; ++i)
      fd_slot_pair_walk(self->hard_forks + i, fun, "slot_pair", level + 1);
    fun(NULL, NULL, 31, "hard_forks", --level);
  }
  fun(self, name, 33, "fd_hard_forks", --level);
}
ulong fd_hard_forks_size(fd_hard_forks_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  for (ulong i = 0; i < self->hard_forks_len; ++i)
    size += fd_slot_pair_size(self->hard_forks + i);
  return size;
}

int fd_hard_forks_encode(fd_hard_forks_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(&self->hard_forks_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->hard_forks_len != 0) {
    for (ulong i = 0; i < self->hard_forks_len; ++i) {
      err = fd_slot_pair_encode(self->hard_forks + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}

int fd_inflation_decode(fd_inflation_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_double_decode(&self->initial, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_double_decode(&self->terminal, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_double_decode(&self->taper, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_double_decode(&self->foundation, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_double_decode(&self->foundation_term, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_double_decode(&self->__unused, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_inflation_new(fd_inflation_t* self) {
}
void fd_inflation_destroy(fd_inflation_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

void fd_inflation_walk(fd_inflation_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_inflation", level++);
  fun(&self->initial, "initial", 5, "double", level + 1);
  fun(&self->terminal, "terminal", 5, "double", level + 1);
  fun(&self->taper, "taper", 5, "double", level + 1);
  fun(&self->foundation, "foundation", 5, "double", level + 1);
  fun(&self->foundation_term, "foundation_term", 5, "double", level + 1);
  fun(&self->__unused, "__unused", 5, "double", level + 1);
  fun(self, name, 33, "fd_inflation", --level);
}
ulong fd_inflation_size(fd_inflation_t const * self) {
  ulong size = 0;
  size += sizeof(double);
  size += sizeof(double);
  size += sizeof(double);
  size += sizeof(double);
  size += sizeof(double);
  size += sizeof(double);
  return size;
}

int fd_inflation_encode(fd_inflation_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_double_encode(&self->initial, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_double_encode(&self->terminal, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_double_encode(&self->taper, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_double_encode(&self->foundation, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_double_encode(&self->foundation_term, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_double_encode(&self->__unused, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_rent_decode(fd_rent_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode(&self->lamports_per_uint8_year, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_double_decode(&self->exemption_threshold, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_decode(&self->burn_percent, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_rent_new(fd_rent_t* self) {
}
void fd_rent_destroy(fd_rent_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

void fd_rent_walk(fd_rent_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_rent", level++);
  fun(&self->lamports_per_uint8_year, "lamports_per_uint8_year", 11, "ulong", level + 1);
  fun(&self->exemption_threshold, "exemption_threshold", 5, "double", level + 1);
  fun(&self->burn_percent, "burn_percent", 9, "uchar", level + 1);
  fun(self, name, 33, "fd_rent", --level);
}
ulong fd_rent_size(fd_rent_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(double);
  size += sizeof(char);
  return size;
}

int fd_rent_encode(fd_rent_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(&self->lamports_per_uint8_year, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_double_encode(&self->exemption_threshold, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_encode(&self->burn_percent, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_rent_collector_decode(fd_rent_collector_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode(&self->epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_epoch_schedule_decode(&self->epoch_schedule, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_double_decode(&self->slots_per_year, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_rent_decode(&self->rent, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_rent_collector_new(fd_rent_collector_t* self) {
  fd_epoch_schedule_new(&self->epoch_schedule);
  fd_rent_new(&self->rent);
}
void fd_rent_collector_destroy(fd_rent_collector_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_epoch_schedule_destroy(&self->epoch_schedule, ctx);
  fd_rent_destroy(&self->rent, ctx);
}

void fd_rent_collector_walk(fd_rent_collector_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_rent_collector", level++);
  fun(&self->epoch, "epoch", 11, "ulong", level + 1);
  fd_epoch_schedule_walk(&self->epoch_schedule, fun, "epoch_schedule", level + 1);
  fun(&self->slots_per_year, "slots_per_year", 5, "double", level + 1);
  fd_rent_walk(&self->rent, fun, "rent", level + 1);
  fun(self, name, 33, "fd_rent_collector", --level);
}
ulong fd_rent_collector_size(fd_rent_collector_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += fd_epoch_schedule_size(&self->epoch_schedule);
  size += sizeof(double);
  size += fd_rent_size(&self->rent);
  return size;
}

int fd_rent_collector_encode(fd_rent_collector_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(&self->epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_epoch_schedule_encode(&self->epoch_schedule, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_double_encode(&self->slots_per_year, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_rent_encode(&self->rent, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_stake_history_entry_decode(fd_stake_history_entry_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode(&self->effective, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->activating, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->deactivating, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_stake_history_entry_new(fd_stake_history_entry_t* self) {
}
void fd_stake_history_entry_destroy(fd_stake_history_entry_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

void fd_stake_history_entry_walk(fd_stake_history_entry_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_stake_history_entry", level++);
  fun(&self->effective, "effective", 11, "ulong", level + 1);
  fun(&self->activating, "activating", 11, "ulong", level + 1);
  fun(&self->deactivating, "deactivating", 11, "ulong", level + 1);
  fun(self, name, 33, "fd_stake_history_entry", --level);
}
ulong fd_stake_history_entry_size(fd_stake_history_entry_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  return size;
}

int fd_stake_history_entry_encode(fd_stake_history_entry_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(&self->effective, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->activating, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->deactivating, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_stake_history_epochentry_pair_decode(fd_stake_history_epochentry_pair_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode(&self->epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_stake_history_entry_decode(&self->entry, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_stake_history_epochentry_pair_new(fd_stake_history_epochentry_pair_t* self) {
  fd_stake_history_entry_new(&self->entry);
}
void fd_stake_history_epochentry_pair_destroy(fd_stake_history_epochentry_pair_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_stake_history_entry_destroy(&self->entry, ctx);
}

void fd_stake_history_epochentry_pair_walk(fd_stake_history_epochentry_pair_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_stake_history_epochentry_pair", level++);
  fun(&self->epoch, "epoch", 11, "ulong", level + 1);
  fd_stake_history_entry_walk(&self->entry, fun, "entry", level + 1);
  fun(self, name, 33, "fd_stake_history_epochentry_pair", --level);
}
ulong fd_stake_history_epochentry_pair_size(fd_stake_history_epochentry_pair_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += fd_stake_history_entry_size(&self->entry);
  return size;
}

int fd_stake_history_epochentry_pair_encode(fd_stake_history_epochentry_pair_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(&self->epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_stake_history_entry_encode(&self->entry, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_stake_history_decode(fd_stake_history_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode(&self->entries_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->entries_len != 0) {
    self->entries = (fd_stake_history_epochentry_pair_t*)(*ctx->allocf)(ctx->allocf_arg, FD_STAKE_HISTORY_EPOCHENTRY_PAIR_ALIGN, FD_STAKE_HISTORY_EPOCHENTRY_PAIR_FOOTPRINT*self->entries_len);
    for (ulong i = 0; i < self->entries_len; ++i) {
      fd_stake_history_epochentry_pair_new(self->entries + i);
    }
    for (ulong i = 0; i < self->entries_len; ++i) {
      err = fd_stake_history_epochentry_pair_decode(self->entries + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else
    self->entries = NULL;
  return FD_BINCODE_SUCCESS;
}
void fd_stake_history_new(fd_stake_history_t* self) {
  self->entries = NULL;
}
void fd_stake_history_destroy(fd_stake_history_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->entries) {
    for (ulong i = 0; i < self->entries_len; ++i)
      fd_stake_history_epochentry_pair_destroy(self->entries + i, ctx);
    (*ctx->freef)(ctx->freef_arg, self->entries);
    self->entries = NULL;
  }
}

void fd_stake_history_walk(fd_stake_history_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_stake_history", level++);
  if (self->entries_len != 0) {
    fun(NULL, NULL, 30, "entries", level++);
    for (ulong i = 0; i < self->entries_len; ++i)
      fd_stake_history_epochentry_pair_walk(self->entries + i, fun, "stake_history_epochentry_pair", level + 1);
    fun(NULL, NULL, 31, "entries", --level);
  }
  fun(self, name, 33, "fd_stake_history", --level);
}
ulong fd_stake_history_size(fd_stake_history_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  for (ulong i = 0; i < self->entries_len; ++i)
    size += fd_stake_history_epochentry_pair_size(self->entries + i);
  return size;
}

int fd_stake_history_encode(fd_stake_history_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(&self->entries_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->entries_len != 0) {
    for (ulong i = 0; i < self->entries_len; ++i) {
      err = fd_stake_history_epochentry_pair_encode(self->entries + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}

int fd_solana_account_decode(fd_solana_account_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode(&self->lamports, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->data_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->data_len != 0) {
    self->data = (unsigned char*)(*ctx->allocf)(ctx->allocf_arg, 8UL, self->data_len);
    err = fd_bincode_bytes_decode(self->data, self->data_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  } else
    self->data = NULL;
  err = fd_pubkey_decode(&self->owner, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_decode(&self->executable, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->rent_epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_solana_account_new(fd_solana_account_t* self) {
  self->data = NULL;
  fd_pubkey_new(&self->owner);
}
void fd_solana_account_destroy(fd_solana_account_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->data) {
    (*ctx->freef)(ctx->freef_arg, self->data);
    self->data = NULL;
  }
  fd_pubkey_destroy(&self->owner, ctx);
}

void fd_solana_account_walk(fd_solana_account_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_solana_account", level++);
  fun(&self->lamports, "lamports", 11, "ulong", level + 1);
  fun(self->data, "data", 2, "unsigned char", level + 1);
  fd_pubkey_walk(&self->owner, fun, "owner", level + 1);
  fun(&self->executable, "executable", 9, "uchar", level + 1);
  fun(&self->rent_epoch, "rent_epoch", 11, "ulong", level + 1);
  fun(self, name, 33, "fd_solana_account", --level);
}
ulong fd_solana_account_size(fd_solana_account_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += self->data_len;
  size += fd_pubkey_size(&self->owner);
  size += sizeof(char);
  size += sizeof(ulong);
  return size;
}

int fd_solana_account_encode(fd_solana_account_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(&self->lamports, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->data_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->data_len != 0) {
    err = fd_bincode_bytes_encode(self->data, self->data_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_pubkey_encode(&self->owner, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_encode(&self->executable, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->rent_epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_vote_accounts_pair_decode(fd_vote_accounts_pair_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_decode(&self->key, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->stake, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_solana_account_decode(&self->value, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_accounts_pair_new(fd_vote_accounts_pair_t* self) {
  fd_pubkey_new(&self->key);
  fd_solana_account_new(&self->value);
}
void fd_vote_accounts_pair_destroy(fd_vote_accounts_pair_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->key, ctx);
  fd_solana_account_destroy(&self->value, ctx);
}

void fd_vote_accounts_pair_walk(fd_vote_accounts_pair_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_vote_accounts_pair", level++);
  fd_pubkey_walk(&self->key, fun, "key", level + 1);
  fun(&self->stake, "stake", 11, "ulong", level + 1);
  fd_solana_account_walk(&self->value, fun, "value", level + 1);
  fun(self, name, 33, "fd_vote_accounts_pair", --level);
}
ulong fd_vote_accounts_pair_size(fd_vote_accounts_pair_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->key);
  size += sizeof(ulong);
  size += fd_solana_account_size(&self->value);
  return size;
}

int fd_vote_accounts_pair_encode(fd_vote_accounts_pair_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->key, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->stake, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_solana_account_encode(&self->value, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_vote_accounts_decode(fd_vote_accounts_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode(&self->vote_accounts_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->vote_accounts_len != 0) {
    self->vote_accounts = (fd_vote_accounts_pair_t*)(*ctx->allocf)(ctx->allocf_arg, FD_VOTE_ACCOUNTS_PAIR_ALIGN, FD_VOTE_ACCOUNTS_PAIR_FOOTPRINT*self->vote_accounts_len);
    for (ulong i = 0; i < self->vote_accounts_len; ++i) {
      fd_vote_accounts_pair_new(self->vote_accounts + i);
    }
    for (ulong i = 0; i < self->vote_accounts_len; ++i) {
      err = fd_vote_accounts_pair_decode(self->vote_accounts + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else
    self->vote_accounts = NULL;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_accounts_new(fd_vote_accounts_t* self) {
  self->vote_accounts = NULL;
}
void fd_vote_accounts_destroy(fd_vote_accounts_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->vote_accounts) {
    for (ulong i = 0; i < self->vote_accounts_len; ++i)
      fd_vote_accounts_pair_destroy(self->vote_accounts + i, ctx);
    (*ctx->freef)(ctx->freef_arg, self->vote_accounts);
    self->vote_accounts = NULL;
  }
}

void fd_vote_accounts_walk(fd_vote_accounts_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_vote_accounts", level++);
  if (self->vote_accounts_len != 0) {
    fun(NULL, NULL, 30, "vote_accounts", level++);
    for (ulong i = 0; i < self->vote_accounts_len; ++i)
      fd_vote_accounts_pair_walk(self->vote_accounts + i, fun, "vote_accounts_pair", level + 1);
    fun(NULL, NULL, 31, "vote_accounts", --level);
  }
  fun(self, name, 33, "fd_vote_accounts", --level);
}
ulong fd_vote_accounts_size(fd_vote_accounts_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  for (ulong i = 0; i < self->vote_accounts_len; ++i)
    size += fd_vote_accounts_pair_size(self->vote_accounts + i);
  return size;
}

int fd_vote_accounts_encode(fd_vote_accounts_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(&self->vote_accounts_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->vote_accounts_len != 0) {
    for (ulong i = 0; i < self->vote_accounts_len; ++i) {
      err = fd_vote_accounts_pair_encode(self->vote_accounts + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}

int fd_delegation_decode(fd_delegation_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_decode(&self->voter_pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->stake, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->activation_epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->deactivation_epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_double_decode(&self->warmup_cooldown_rate, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_delegation_new(fd_delegation_t* self) {
  fd_pubkey_new(&self->voter_pubkey);
}
void fd_delegation_destroy(fd_delegation_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->voter_pubkey, ctx);
}

void fd_delegation_walk(fd_delegation_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_delegation", level++);
  fd_pubkey_walk(&self->voter_pubkey, fun, "voter_pubkey", level + 1);
  fun(&self->stake, "stake", 11, "ulong", level + 1);
  fun(&self->activation_epoch, "activation_epoch", 11, "ulong", level + 1);
  fun(&self->deactivation_epoch, "deactivation_epoch", 11, "ulong", level + 1);
  fun(&self->warmup_cooldown_rate, "warmup_cooldown_rate", 5, "double", level + 1);
  fun(self, name, 33, "fd_delegation", --level);
}
ulong fd_delegation_size(fd_delegation_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->voter_pubkey);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(double);
  return size;
}

int fd_delegation_encode(fd_delegation_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->voter_pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->stake, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->activation_epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->deactivation_epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_double_encode(&self->warmup_cooldown_rate, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_delegation_pair_decode(fd_delegation_pair_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_decode(&self->account, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_delegation_decode(&self->delegation, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_delegation_pair_new(fd_delegation_pair_t* self) {
  fd_pubkey_new(&self->account);
  fd_delegation_new(&self->delegation);
}
void fd_delegation_pair_destroy(fd_delegation_pair_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->account, ctx);
  fd_delegation_destroy(&self->delegation, ctx);
}

void fd_delegation_pair_walk(fd_delegation_pair_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_delegation_pair", level++);
  fd_pubkey_walk(&self->account, fun, "account", level + 1);
  fd_delegation_walk(&self->delegation, fun, "delegation", level + 1);
  fun(self, name, 33, "fd_delegation_pair", --level);
}
ulong fd_delegation_pair_size(fd_delegation_pair_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->account);
  size += fd_delegation_size(&self->delegation);
  return size;
}

int fd_delegation_pair_encode(fd_delegation_pair_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->account, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_delegation_encode(&self->delegation, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_stakes_decode(fd_stakes_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_vote_accounts_decode(&self->vote_accounts, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->stake_delegations = deq_fd_delegation_pair_t_alloc( ctx->allocf, ctx->allocf_arg );
  ulong stake_delegations_len;
  err = fd_bincode_uint64_decode(&stake_delegations_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if ( stake_delegations_len > deq_fd_delegation_pair_t_max(self->stake_delegations) ) return FD_BINCODE_ERR_SMALL_DEQUE;
  for (ulong i = 0; i < stake_delegations_len; ++i) {
    fd_delegation_pair_t * elem = deq_fd_delegation_pair_t_push_tail_nocopy(self->stake_delegations);
    fd_delegation_pair_new(elem);
    err = fd_delegation_pair_decode(elem, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_bincode_uint64_decode(&self->unused, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_stake_history_decode(&self->stake_history, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_stakes_new(fd_stakes_t* self) {
  fd_vote_accounts_new(&self->vote_accounts);
  self->stake_delegations = NULL;
  fd_stake_history_new(&self->stake_history);
}
void fd_stakes_destroy(fd_stakes_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_vote_accounts_destroy(&self->vote_accounts, ctx);
  if ( self->stake_delegations ) {
    for ( deq_fd_delegation_pair_t_iter_t iter = deq_fd_delegation_pair_t_iter_init( self->stake_delegations ); !deq_fd_delegation_pair_t_iter_done( self->stake_delegations, iter ); iter = deq_fd_delegation_pair_t_iter_next( self->stake_delegations, iter ) ) {
      fd_delegation_pair_t * ele = deq_fd_delegation_pair_t_iter_ele( self->stake_delegations, iter );
      fd_delegation_pair_destroy(ele, ctx);
    }
    (*ctx->freef)(ctx->freef_arg, deq_fd_delegation_pair_t_delete( deq_fd_delegation_pair_t_leave( self->stake_delegations) ) );
    self->stake_delegations = NULL;
  }
  fd_stake_history_destroy(&self->stake_history, ctx);
}

void fd_stakes_walk(fd_stakes_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_stakes", level++);
  fd_vote_accounts_walk(&self->vote_accounts, fun, "vote_accounts", level + 1);
  if ( self->stake_delegations ) {
    for ( deq_fd_delegation_pair_t_iter_t iter = deq_fd_delegation_pair_t_iter_init( self->stake_delegations ); !deq_fd_delegation_pair_t_iter_done( self->stake_delegations, iter ); iter = deq_fd_delegation_pair_t_iter_next( self->stake_delegations, iter ) ) {
      fd_delegation_pair_t * ele = deq_fd_delegation_pair_t_iter_ele( self->stake_delegations, iter );
      fd_delegation_pair_walk(ele, fun, "stake_delegations", level + 1);
    }
  }
  fun(&self->unused, "unused", 11, "ulong", level + 1);
  fun(&self->epoch, "epoch", 11, "ulong", level + 1);
  fd_stake_history_walk(&self->stake_history, fun, "stake_history", level + 1);
  fun(self, name, 33, "fd_stakes", --level);
}
ulong fd_stakes_size(fd_stakes_t const * self) {
  ulong size = 0;
  size += fd_vote_accounts_size(&self->vote_accounts);
  if ( self->stake_delegations ) {
    size += sizeof(ulong);
    for ( deq_fd_delegation_pair_t_iter_t iter = deq_fd_delegation_pair_t_iter_init( self->stake_delegations ); !deq_fd_delegation_pair_t_iter_done( self->stake_delegations, iter ); iter = deq_fd_delegation_pair_t_iter_next( self->stake_delegations, iter ) ) {
      fd_delegation_pair_t * ele = deq_fd_delegation_pair_t_iter_ele( self->stake_delegations, iter );
      size += fd_delegation_pair_size(ele);
    }
  }
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += fd_stake_history_size(&self->stake_history);
  return size;
}

int fd_stakes_encode(fd_stakes_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_vote_accounts_encode(&self->vote_accounts, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if ( self->stake_delegations ) {
    ulong stake_delegations_len = deq_fd_delegation_pair_t_cnt(self->stake_delegations);
    err = fd_bincode_uint64_encode(&stake_delegations_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    for ( deq_fd_delegation_pair_t_iter_t iter = deq_fd_delegation_pair_t_iter_init( self->stake_delegations ); !deq_fd_delegation_pair_t_iter_done( self->stake_delegations, iter ); iter = deq_fd_delegation_pair_t_iter_next( self->stake_delegations, iter ) ) {
      fd_delegation_pair_t * ele = deq_fd_delegation_pair_t_iter_ele( self->stake_delegations, iter );
      err = fd_delegation_pair_encode(ele, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else {
    ulong stake_delegations_len = 0;
    err = fd_bincode_uint64_encode(&stake_delegations_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_bincode_uint64_encode(&self->unused, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_stake_history_encode(&self->stake_history, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_bank_incremental_snapshot_persistence_decode(fd_bank_incremental_snapshot_persistence_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode(&self->full_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_decode(&self->full_hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->full_capitalization, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_decode(&self->incremental_hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->incremental_capitalization, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_bank_incremental_snapshot_persistence_new(fd_bank_incremental_snapshot_persistence_t* self) {
  fd_hash_new(&self->full_hash);
  fd_hash_new(&self->incremental_hash);
}
void fd_bank_incremental_snapshot_persistence_destroy(fd_bank_incremental_snapshot_persistence_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_hash_destroy(&self->full_hash, ctx);
  fd_hash_destroy(&self->incremental_hash, ctx);
}

void fd_bank_incremental_snapshot_persistence_walk(fd_bank_incremental_snapshot_persistence_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_bank_incremental_snapshot_persistence", level++);
  fun(&self->full_slot, "full_slot", 11, "ulong", level + 1);
  fd_hash_walk(&self->full_hash, fun, "full_hash", level + 1);
  fun(&self->full_capitalization, "full_capitalization", 11, "ulong", level + 1);
  fd_hash_walk(&self->incremental_hash, fun, "incremental_hash", level + 1);
  fun(&self->incremental_capitalization, "incremental_capitalization", 11, "ulong", level + 1);
  fun(self, name, 33, "fd_bank_incremental_snapshot_persistence", --level);
}
ulong fd_bank_incremental_snapshot_persistence_size(fd_bank_incremental_snapshot_persistence_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += fd_hash_size(&self->full_hash);
  size += sizeof(ulong);
  size += fd_hash_size(&self->incremental_hash);
  size += sizeof(ulong);
  return size;
}

int fd_bank_incremental_snapshot_persistence_encode(fd_bank_incremental_snapshot_persistence_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(&self->full_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_encode(&self->full_hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->full_capitalization, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_encode(&self->incremental_hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->incremental_capitalization, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_node_vote_accounts_decode(fd_node_vote_accounts_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode(&self->vote_accounts_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->vote_accounts_len != 0) {
    self->vote_accounts = (fd_pubkey_t*)(*ctx->allocf)(ctx->allocf_arg, FD_PUBKEY_ALIGN, FD_PUBKEY_FOOTPRINT*self->vote_accounts_len);
    for (ulong i = 0; i < self->vote_accounts_len; ++i) {
      fd_pubkey_new(self->vote_accounts + i);
    }
    for (ulong i = 0; i < self->vote_accounts_len; ++i) {
      err = fd_pubkey_decode(self->vote_accounts + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else
    self->vote_accounts = NULL;
  err = fd_bincode_uint64_decode(&self->total_stake, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_node_vote_accounts_new(fd_node_vote_accounts_t* self) {
  self->vote_accounts = NULL;
}
void fd_node_vote_accounts_destroy(fd_node_vote_accounts_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->vote_accounts) {
    for (ulong i = 0; i < self->vote_accounts_len; ++i)
      fd_pubkey_destroy(self->vote_accounts + i, ctx);
    (*ctx->freef)(ctx->freef_arg, self->vote_accounts);
    self->vote_accounts = NULL;
  }
}

void fd_node_vote_accounts_walk(fd_node_vote_accounts_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_node_vote_accounts", level++);
  if (self->vote_accounts_len != 0) {
    fun(NULL, NULL, 30, "vote_accounts", level++);
    for (ulong i = 0; i < self->vote_accounts_len; ++i)
      fd_pubkey_walk(self->vote_accounts + i, fun, "pubkey", level + 1);
    fun(NULL, NULL, 31, "vote_accounts", --level);
  }
  fun(&self->total_stake, "total_stake", 11, "ulong", level + 1);
  fun(self, name, 33, "fd_node_vote_accounts", --level);
}
ulong fd_node_vote_accounts_size(fd_node_vote_accounts_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  for (ulong i = 0; i < self->vote_accounts_len; ++i)
    size += fd_pubkey_size(self->vote_accounts + i);
  size += sizeof(ulong);
  return size;
}

int fd_node_vote_accounts_encode(fd_node_vote_accounts_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(&self->vote_accounts_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->vote_accounts_len != 0) {
    for (ulong i = 0; i < self->vote_accounts_len; ++i) {
      err = fd_pubkey_encode(self->vote_accounts + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  err = fd_bincode_uint64_encode(&self->total_stake, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_pubkey_node_vote_accounts_pair_decode(fd_pubkey_node_vote_accounts_pair_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_decode(&self->key, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_node_vote_accounts_decode(&self->value, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_pubkey_node_vote_accounts_pair_new(fd_pubkey_node_vote_accounts_pair_t* self) {
  fd_pubkey_new(&self->key);
  fd_node_vote_accounts_new(&self->value);
}
void fd_pubkey_node_vote_accounts_pair_destroy(fd_pubkey_node_vote_accounts_pair_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->key, ctx);
  fd_node_vote_accounts_destroy(&self->value, ctx);
}

void fd_pubkey_node_vote_accounts_pair_walk(fd_pubkey_node_vote_accounts_pair_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_pubkey_node_vote_accounts_pair", level++);
  fd_pubkey_walk(&self->key, fun, "key", level + 1);
  fd_node_vote_accounts_walk(&self->value, fun, "value", level + 1);
  fun(self, name, 33, "fd_pubkey_node_vote_accounts_pair", --level);
}
ulong fd_pubkey_node_vote_accounts_pair_size(fd_pubkey_node_vote_accounts_pair_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->key);
  size += fd_node_vote_accounts_size(&self->value);
  return size;
}

int fd_pubkey_node_vote_accounts_pair_encode(fd_pubkey_node_vote_accounts_pair_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->key, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_node_vote_accounts_encode(&self->value, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_pubkey_pubkey_pair_decode(fd_pubkey_pubkey_pair_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_decode(&self->key, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_decode(&self->value, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_pubkey_pubkey_pair_new(fd_pubkey_pubkey_pair_t* self) {
  fd_pubkey_new(&self->key);
  fd_pubkey_new(&self->value);
}
void fd_pubkey_pubkey_pair_destroy(fd_pubkey_pubkey_pair_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->key, ctx);
  fd_pubkey_destroy(&self->value, ctx);
}

void fd_pubkey_pubkey_pair_walk(fd_pubkey_pubkey_pair_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_pubkey_pubkey_pair", level++);
  fd_pubkey_walk(&self->key, fun, "key", level + 1);
  fd_pubkey_walk(&self->value, fun, "value", level + 1);
  fun(self, name, 33, "fd_pubkey_pubkey_pair", --level);
}
ulong fd_pubkey_pubkey_pair_size(fd_pubkey_pubkey_pair_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->key);
  size += fd_pubkey_size(&self->value);
  return size;
}

int fd_pubkey_pubkey_pair_encode(fd_pubkey_pubkey_pair_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->key, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->value, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_epoch_stakes_decode(fd_epoch_stakes_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_stakes_decode(&self->stakes, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->total_stake, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->node_id_to_vote_accounts_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->node_id_to_vote_accounts_len != 0) {
    self->node_id_to_vote_accounts = (fd_pubkey_node_vote_accounts_pair_t*)(*ctx->allocf)(ctx->allocf_arg, FD_PUBKEY_NODE_VOTE_ACCOUNTS_PAIR_ALIGN, FD_PUBKEY_NODE_VOTE_ACCOUNTS_PAIR_FOOTPRINT*self->node_id_to_vote_accounts_len);
    for (ulong i = 0; i < self->node_id_to_vote_accounts_len; ++i) {
      fd_pubkey_node_vote_accounts_pair_new(self->node_id_to_vote_accounts + i);
    }
    for (ulong i = 0; i < self->node_id_to_vote_accounts_len; ++i) {
      err = fd_pubkey_node_vote_accounts_pair_decode(self->node_id_to_vote_accounts + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else
    self->node_id_to_vote_accounts = NULL;
  err = fd_bincode_uint64_decode(&self->epoch_authorized_voters_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->epoch_authorized_voters_len != 0) {
    self->epoch_authorized_voters = (fd_pubkey_pubkey_pair_t*)(*ctx->allocf)(ctx->allocf_arg, FD_PUBKEY_PUBKEY_PAIR_ALIGN, FD_PUBKEY_PUBKEY_PAIR_FOOTPRINT*self->epoch_authorized_voters_len);
    for (ulong i = 0; i < self->epoch_authorized_voters_len; ++i) {
      fd_pubkey_pubkey_pair_new(self->epoch_authorized_voters + i);
    }
    for (ulong i = 0; i < self->epoch_authorized_voters_len; ++i) {
      err = fd_pubkey_pubkey_pair_decode(self->epoch_authorized_voters + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else
    self->epoch_authorized_voters = NULL;
  return FD_BINCODE_SUCCESS;
}
void fd_epoch_stakes_new(fd_epoch_stakes_t* self) {
  fd_stakes_new(&self->stakes);
  self->node_id_to_vote_accounts = NULL;
  self->epoch_authorized_voters = NULL;
}
void fd_epoch_stakes_destroy(fd_epoch_stakes_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_stakes_destroy(&self->stakes, ctx);
  if (NULL != self->node_id_to_vote_accounts) {
    for (ulong i = 0; i < self->node_id_to_vote_accounts_len; ++i)
      fd_pubkey_node_vote_accounts_pair_destroy(self->node_id_to_vote_accounts + i, ctx);
    (*ctx->freef)(ctx->freef_arg, self->node_id_to_vote_accounts);
    self->node_id_to_vote_accounts = NULL;
  }
  if (NULL != self->epoch_authorized_voters) {
    for (ulong i = 0; i < self->epoch_authorized_voters_len; ++i)
      fd_pubkey_pubkey_pair_destroy(self->epoch_authorized_voters + i, ctx);
    (*ctx->freef)(ctx->freef_arg, self->epoch_authorized_voters);
    self->epoch_authorized_voters = NULL;
  }
}

void fd_epoch_stakes_walk(fd_epoch_stakes_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_epoch_stakes", level++);
  fd_stakes_walk(&self->stakes, fun, "stakes", level + 1);
  fun(&self->total_stake, "total_stake", 11, "ulong", level + 1);
  if (self->node_id_to_vote_accounts_len != 0) {
    fun(NULL, NULL, 30, "node_id_to_vote_accounts", level++);
    for (ulong i = 0; i < self->node_id_to_vote_accounts_len; ++i)
      fd_pubkey_node_vote_accounts_pair_walk(self->node_id_to_vote_accounts + i, fun, "pubkey_node_vote_accounts_pair", level + 1);
    fun(NULL, NULL, 31, "node_id_to_vote_accounts", --level);
  }
  if (self->epoch_authorized_voters_len != 0) {
    fun(NULL, NULL, 30, "epoch_authorized_voters", level++);
    for (ulong i = 0; i < self->epoch_authorized_voters_len; ++i)
      fd_pubkey_pubkey_pair_walk(self->epoch_authorized_voters + i, fun, "pubkey_pubkey_pair", level + 1);
    fun(NULL, NULL, 31, "epoch_authorized_voters", --level);
  }
  fun(self, name, 33, "fd_epoch_stakes", --level);
}
ulong fd_epoch_stakes_size(fd_epoch_stakes_t const * self) {
  ulong size = 0;
  size += fd_stakes_size(&self->stakes);
  size += sizeof(ulong);
  size += sizeof(ulong);
  for (ulong i = 0; i < self->node_id_to_vote_accounts_len; ++i)
    size += fd_pubkey_node_vote_accounts_pair_size(self->node_id_to_vote_accounts + i);
  size += sizeof(ulong);
  for (ulong i = 0; i < self->epoch_authorized_voters_len; ++i)
    size += fd_pubkey_pubkey_pair_size(self->epoch_authorized_voters + i);
  return size;
}

int fd_epoch_stakes_encode(fd_epoch_stakes_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_stakes_encode(&self->stakes, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->total_stake, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->node_id_to_vote_accounts_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->node_id_to_vote_accounts_len != 0) {
    for (ulong i = 0; i < self->node_id_to_vote_accounts_len; ++i) {
      err = fd_pubkey_node_vote_accounts_pair_encode(self->node_id_to_vote_accounts + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  err = fd_bincode_uint64_encode(&self->epoch_authorized_voters_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->epoch_authorized_voters_len != 0) {
    for (ulong i = 0; i < self->epoch_authorized_voters_len; ++i) {
      err = fd_pubkey_pubkey_pair_encode(self->epoch_authorized_voters + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}

int fd_epoch_epoch_stakes_pair_decode(fd_epoch_epoch_stakes_pair_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode(&self->key, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_epoch_stakes_decode(&self->value, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_epoch_epoch_stakes_pair_new(fd_epoch_epoch_stakes_pair_t* self) {
  fd_epoch_stakes_new(&self->value);
}
void fd_epoch_epoch_stakes_pair_destroy(fd_epoch_epoch_stakes_pair_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_epoch_stakes_destroy(&self->value, ctx);
}

void fd_epoch_epoch_stakes_pair_walk(fd_epoch_epoch_stakes_pair_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_epoch_epoch_stakes_pair", level++);
  fun(&self->key, "key", 11, "ulong", level + 1);
  fd_epoch_stakes_walk(&self->value, fun, "value", level + 1);
  fun(self, name, 33, "fd_epoch_epoch_stakes_pair", --level);
}
ulong fd_epoch_epoch_stakes_pair_size(fd_epoch_epoch_stakes_pair_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += fd_epoch_stakes_size(&self->value);
  return size;
}

int fd_epoch_epoch_stakes_pair_encode(fd_epoch_epoch_stakes_pair_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(&self->key, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_epoch_stakes_encode(&self->value, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_pubkey_u64_pair_decode(fd_pubkey_u64_pair_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_decode(&self->_0, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->_1, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_pubkey_u64_pair_new(fd_pubkey_u64_pair_t* self) {
  fd_pubkey_new(&self->_0);
}
void fd_pubkey_u64_pair_destroy(fd_pubkey_u64_pair_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->_0, ctx);
}

void fd_pubkey_u64_pair_walk(fd_pubkey_u64_pair_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_pubkey_u64_pair", level++);
  fd_pubkey_walk(&self->_0, fun, "_0", level + 1);
  fun(&self->_1, "_1", 11, "ulong", level + 1);
  fun(self, name, 33, "fd_pubkey_u64_pair", --level);
}
ulong fd_pubkey_u64_pair_size(fd_pubkey_u64_pair_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->_0);
  size += sizeof(ulong);
  return size;
}

int fd_pubkey_u64_pair_encode(fd_pubkey_u64_pair_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->_0, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->_1, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_unused_accounts_decode(fd_unused_accounts_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode(&self->unused1_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->unused1_len != 0) {
    self->unused1 = (fd_pubkey_t*)(*ctx->allocf)(ctx->allocf_arg, FD_PUBKEY_ALIGN, FD_PUBKEY_FOOTPRINT*self->unused1_len);
    for (ulong i = 0; i < self->unused1_len; ++i) {
      fd_pubkey_new(self->unused1 + i);
    }
    for (ulong i = 0; i < self->unused1_len; ++i) {
      err = fd_pubkey_decode(self->unused1 + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else
    self->unused1 = NULL;
  err = fd_bincode_uint64_decode(&self->unused2_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->unused2_len != 0) {
    self->unused2 = (fd_pubkey_t*)(*ctx->allocf)(ctx->allocf_arg, FD_PUBKEY_ALIGN, FD_PUBKEY_FOOTPRINT*self->unused2_len);
    for (ulong i = 0; i < self->unused2_len; ++i) {
      fd_pubkey_new(self->unused2 + i);
    }
    for (ulong i = 0; i < self->unused2_len; ++i) {
      err = fd_pubkey_decode(self->unused2 + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else
    self->unused2 = NULL;
  err = fd_bincode_uint64_decode(&self->unused3_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->unused3_len != 0) {
    self->unused3 = (fd_pubkey_u64_pair_t*)(*ctx->allocf)(ctx->allocf_arg, FD_PUBKEY_U64_PAIR_ALIGN, FD_PUBKEY_U64_PAIR_FOOTPRINT*self->unused3_len);
    for (ulong i = 0; i < self->unused3_len; ++i) {
      fd_pubkey_u64_pair_new(self->unused3 + i);
    }
    for (ulong i = 0; i < self->unused3_len; ++i) {
      err = fd_pubkey_u64_pair_decode(self->unused3 + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else
    self->unused3 = NULL;
  return FD_BINCODE_SUCCESS;
}
void fd_unused_accounts_new(fd_unused_accounts_t* self) {
  self->unused1 = NULL;
  self->unused2 = NULL;
  self->unused3 = NULL;
}
void fd_unused_accounts_destroy(fd_unused_accounts_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->unused1) {
    for (ulong i = 0; i < self->unused1_len; ++i)
      fd_pubkey_destroy(self->unused1 + i, ctx);
    (*ctx->freef)(ctx->freef_arg, self->unused1);
    self->unused1 = NULL;
  }
  if (NULL != self->unused2) {
    for (ulong i = 0; i < self->unused2_len; ++i)
      fd_pubkey_destroy(self->unused2 + i, ctx);
    (*ctx->freef)(ctx->freef_arg, self->unused2);
    self->unused2 = NULL;
  }
  if (NULL != self->unused3) {
    for (ulong i = 0; i < self->unused3_len; ++i)
      fd_pubkey_u64_pair_destroy(self->unused3 + i, ctx);
    (*ctx->freef)(ctx->freef_arg, self->unused3);
    self->unused3 = NULL;
  }
}

void fd_unused_accounts_walk(fd_unused_accounts_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_unused_accounts", level++);
  if (self->unused1_len != 0) {
    fun(NULL, NULL, 30, "unused1", level++);
    for (ulong i = 0; i < self->unused1_len; ++i)
      fd_pubkey_walk(self->unused1 + i, fun, "pubkey", level + 1);
    fun(NULL, NULL, 31, "unused1", --level);
  }
  if (self->unused2_len != 0) {
    fun(NULL, NULL, 30, "unused2", level++);
    for (ulong i = 0; i < self->unused2_len; ++i)
      fd_pubkey_walk(self->unused2 + i, fun, "pubkey", level + 1);
    fun(NULL, NULL, 31, "unused2", --level);
  }
  if (self->unused3_len != 0) {
    fun(NULL, NULL, 30, "unused3", level++);
    for (ulong i = 0; i < self->unused3_len; ++i)
      fd_pubkey_u64_pair_walk(self->unused3 + i, fun, "pubkey_u64_pair", level + 1);
    fun(NULL, NULL, 31, "unused3", --level);
  }
  fun(self, name, 33, "fd_unused_accounts", --level);
}
ulong fd_unused_accounts_size(fd_unused_accounts_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  for (ulong i = 0; i < self->unused1_len; ++i)
    size += fd_pubkey_size(self->unused1 + i);
  size += sizeof(ulong);
  for (ulong i = 0; i < self->unused2_len; ++i)
    size += fd_pubkey_size(self->unused2 + i);
  size += sizeof(ulong);
  for (ulong i = 0; i < self->unused3_len; ++i)
    size += fd_pubkey_u64_pair_size(self->unused3 + i);
  return size;
}

int fd_unused_accounts_encode(fd_unused_accounts_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(&self->unused1_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->unused1_len != 0) {
    for (ulong i = 0; i < self->unused1_len; ++i) {
      err = fd_pubkey_encode(self->unused1 + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  err = fd_bincode_uint64_encode(&self->unused2_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->unused2_len != 0) {
    for (ulong i = 0; i < self->unused2_len; ++i) {
      err = fd_pubkey_encode(self->unused2 + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  err = fd_bincode_uint64_encode(&self->unused3_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->unused3_len != 0) {
    for (ulong i = 0; i < self->unused3_len; ++i) {
      err = fd_pubkey_u64_pair_encode(self->unused3 + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}

int fd_deserializable_versioned_bank_decode(fd_deserializable_versioned_bank_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_block_hash_queue_decode(&self->blockhash_queue, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->ancestors_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->ancestors_len != 0) {
    self->ancestors = (fd_slot_pair_t*)(*ctx->allocf)(ctx->allocf_arg, FD_SLOT_PAIR_ALIGN, FD_SLOT_PAIR_FOOTPRINT*self->ancestors_len);
    for (ulong i = 0; i < self->ancestors_len; ++i) {
      fd_slot_pair_new(self->ancestors + i);
    }
    for (ulong i = 0; i < self->ancestors_len; ++i) {
      err = fd_slot_pair_decode(self->ancestors + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else
    self->ancestors = NULL;
  err = fd_hash_decode(&self->hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_decode(&self->parent_hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->parent_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hard_forks_decode(&self->hard_forks, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->transaction_count, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->tick_height, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->signature_count, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->capitalization, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->max_tick_height, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  {
    unsigned char o;
    err = fd_bincode_option_decode(&o, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    if (o) {
      self->hashes_per_tick = (ulong*)(*ctx->allocf)(ctx->allocf_arg, 8, sizeof(ulong));
      err = fd_bincode_uint64_decode(self->hashes_per_tick, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    } else
      self->hashes_per_tick = NULL;
  }
  err = fd_bincode_uint64_decode(&self->ticks_per_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint128_decode(&self->ns_per_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->genesis_creation_time, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_double_decode(&self->slots_per_year, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->accounts_data_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->block_height, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_decode(&self->collector_id, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->collector_fees, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_fee_calculator_decode(&self->fee_calculator, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_fee_rate_governor_decode(&self->fee_rate_governor, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->collected_rent, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_rent_collector_decode(&self->rent_collector, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_epoch_schedule_decode(&self->epoch_schedule, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_inflation_decode(&self->inflation, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_stakes_decode(&self->stakes, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_unused_accounts_decode(&self->unused_accounts, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->epoch_stakes_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->epoch_stakes_len != 0) {
    self->epoch_stakes = (fd_epoch_epoch_stakes_pair_t*)(*ctx->allocf)(ctx->allocf_arg, FD_EPOCH_EPOCH_STAKES_PAIR_ALIGN, FD_EPOCH_EPOCH_STAKES_PAIR_FOOTPRINT*self->epoch_stakes_len);
    for (ulong i = 0; i < self->epoch_stakes_len; ++i) {
      fd_epoch_epoch_stakes_pair_new(self->epoch_stakes + i);
    }
    for (ulong i = 0; i < self->epoch_stakes_len; ++i) {
      err = fd_epoch_epoch_stakes_pair_decode(self->epoch_stakes + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else
    self->epoch_stakes = NULL;
  err = fd_bincode_uint8_decode((unsigned char *) &self->is_delta, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_deserializable_versioned_bank_new(fd_deserializable_versioned_bank_t* self) {
  fd_block_hash_queue_new(&self->blockhash_queue);
  self->ancestors = NULL;
  fd_hash_new(&self->hash);
  fd_hash_new(&self->parent_hash);
  fd_hard_forks_new(&self->hard_forks);
  self->hashes_per_tick = NULL;
  fd_pubkey_new(&self->collector_id);
  fd_fee_calculator_new(&self->fee_calculator);
  fd_fee_rate_governor_new(&self->fee_rate_governor);
  fd_rent_collector_new(&self->rent_collector);
  fd_epoch_schedule_new(&self->epoch_schedule);
  fd_inflation_new(&self->inflation);
  fd_stakes_new(&self->stakes);
  fd_unused_accounts_new(&self->unused_accounts);
  self->epoch_stakes = NULL;
}
void fd_deserializable_versioned_bank_destroy(fd_deserializable_versioned_bank_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_block_hash_queue_destroy(&self->blockhash_queue, ctx);
  if (NULL != self->ancestors) {
    for (ulong i = 0; i < self->ancestors_len; ++i)
      fd_slot_pair_destroy(self->ancestors + i, ctx);
    (*ctx->freef)(ctx->freef_arg, self->ancestors);
    self->ancestors = NULL;
  }
  fd_hash_destroy(&self->hash, ctx);
  fd_hash_destroy(&self->parent_hash, ctx);
  fd_hard_forks_destroy(&self->hard_forks, ctx);
  if (NULL != self->hashes_per_tick) {
    (*ctx->freef)(ctx->freef_arg, self->hashes_per_tick);
    self->hashes_per_tick = NULL;
  }
  fd_pubkey_destroy(&self->collector_id, ctx);
  fd_fee_calculator_destroy(&self->fee_calculator, ctx);
  fd_fee_rate_governor_destroy(&self->fee_rate_governor, ctx);
  fd_rent_collector_destroy(&self->rent_collector, ctx);
  fd_epoch_schedule_destroy(&self->epoch_schedule, ctx);
  fd_inflation_destroy(&self->inflation, ctx);
  fd_stakes_destroy(&self->stakes, ctx);
  fd_unused_accounts_destroy(&self->unused_accounts, ctx);
  if (NULL != self->epoch_stakes) {
    for (ulong i = 0; i < self->epoch_stakes_len; ++i)
      fd_epoch_epoch_stakes_pair_destroy(self->epoch_stakes + i, ctx);
    (*ctx->freef)(ctx->freef_arg, self->epoch_stakes);
    self->epoch_stakes = NULL;
  }
}

void fd_deserializable_versioned_bank_walk(fd_deserializable_versioned_bank_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_deserializable_versioned_bank", level++);
  fd_block_hash_queue_walk(&self->blockhash_queue, fun, "blockhash_queue", level + 1);
  if (self->ancestors_len != 0) {
    fun(NULL, NULL, 30, "ancestors", level++);
    for (ulong i = 0; i < self->ancestors_len; ++i)
      fd_slot_pair_walk(self->ancestors + i, fun, "slot_pair", level + 1);
    fun(NULL, NULL, 31, "ancestors", --level);
  }
  fd_hash_walk(&self->hash, fun, "hash", level + 1);
  fd_hash_walk(&self->parent_hash, fun, "parent_hash", level + 1);
  fun(&self->parent_slot, "parent_slot", 11, "ulong", level + 1);
  fd_hard_forks_walk(&self->hard_forks, fun, "hard_forks", level + 1);
  fun(&self->transaction_count, "transaction_count", 11, "ulong", level + 1);
  fun(&self->tick_height, "tick_height", 11, "ulong", level + 1);
  fun(&self->signature_count, "signature_count", 11, "ulong", level + 1);
  fun(&self->capitalization, "capitalization", 11, "ulong", level + 1);
  fun(&self->max_tick_height, "max_tick_height", 11, "ulong", level + 1);
  fun(self->hashes_per_tick, "hashes_per_tick", 11, "ulong", level + 1);
  fun(&self->ticks_per_slot, "ticks_per_slot", 11, "ulong", level + 1);
  fun(&self->ns_per_slot, "ns_per_slot", 8, "uint128", level + 1);
  fun(&self->genesis_creation_time, "genesis_creation_time", 11, "ulong", level + 1);
  fun(&self->slots_per_year, "slots_per_year", 5, "double", level + 1);
  fun(&self->accounts_data_len, "accounts_data_len", 11, "ulong", level + 1);
  fun(&self->slot, "slot", 11, "ulong", level + 1);
  fun(&self->epoch, "epoch", 11, "ulong", level + 1);
  fun(&self->block_height, "block_height", 11, "ulong", level + 1);
  fd_pubkey_walk(&self->collector_id, fun, "collector_id", level + 1);
  fun(&self->collector_fees, "collector_fees", 11, "ulong", level + 1);
  fd_fee_calculator_walk(&self->fee_calculator, fun, "fee_calculator", level + 1);
  fd_fee_rate_governor_walk(&self->fee_rate_governor, fun, "fee_rate_governor", level + 1);
  fun(&self->collected_rent, "collected_rent", 11, "ulong", level + 1);
  fd_rent_collector_walk(&self->rent_collector, fun, "rent_collector", level + 1);
  fd_epoch_schedule_walk(&self->epoch_schedule, fun, "epoch_schedule", level + 1);
  fd_inflation_walk(&self->inflation, fun, "inflation", level + 1);
  fd_stakes_walk(&self->stakes, fun, "stakes", level + 1);
  fd_unused_accounts_walk(&self->unused_accounts, fun, "unused_accounts", level + 1);
  if (self->epoch_stakes_len != 0) {
    fun(NULL, NULL, 30, "epoch_stakes", level++);
    for (ulong i = 0; i < self->epoch_stakes_len; ++i)
      fd_epoch_epoch_stakes_pair_walk(self->epoch_stakes + i, fun, "epoch_epoch_stakes_pair", level + 1);
    fun(NULL, NULL, 31, "epoch_stakes", --level);
  }
  fun(&self->is_delta, "is_delta", 1, "char", level + 1);
  fun(self, name, 33, "fd_deserializable_versioned_bank", --level);
}
ulong fd_deserializable_versioned_bank_size(fd_deserializable_versioned_bank_t const * self) {
  ulong size = 0;
  size += fd_block_hash_queue_size(&self->blockhash_queue);
  size += sizeof(ulong);
  for (ulong i = 0; i < self->ancestors_len; ++i)
    size += fd_slot_pair_size(self->ancestors + i);
  size += fd_hash_size(&self->hash);
  size += fd_hash_size(&self->parent_hash);
  size += sizeof(ulong);
  size += fd_hard_forks_size(&self->hard_forks);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(char);
  if (NULL !=  self->hashes_per_tick) {
    size += sizeof(ulong);
  }
  size += sizeof(ulong);
  size += sizeof(uint128);
  size += sizeof(ulong);
  size += sizeof(double);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += fd_pubkey_size(&self->collector_id);
  size += sizeof(ulong);
  size += fd_fee_calculator_size(&self->fee_calculator);
  size += fd_fee_rate_governor_size(&self->fee_rate_governor);
  size += sizeof(ulong);
  size += fd_rent_collector_size(&self->rent_collector);
  size += fd_epoch_schedule_size(&self->epoch_schedule);
  size += fd_inflation_size(&self->inflation);
  size += fd_stakes_size(&self->stakes);
  size += fd_unused_accounts_size(&self->unused_accounts);
  size += sizeof(ulong);
  for (ulong i = 0; i < self->epoch_stakes_len; ++i)
    size += fd_epoch_epoch_stakes_pair_size(self->epoch_stakes + i);
  size += sizeof(char);
  return size;
}

int fd_deserializable_versioned_bank_encode(fd_deserializable_versioned_bank_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_block_hash_queue_encode(&self->blockhash_queue, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->ancestors_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->ancestors_len != 0) {
    for (ulong i = 0; i < self->ancestors_len; ++i) {
      err = fd_slot_pair_encode(self->ancestors + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  err = fd_hash_encode(&self->hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_encode(&self->parent_hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->parent_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hard_forks_encode(&self->hard_forks, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->transaction_count, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->tick_height, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->signature_count, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->capitalization, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->max_tick_height, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->hashes_per_tick != NULL) {
    err = fd_bincode_option_encode(1, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    err = fd_bincode_uint64_encode(self->hashes_per_tick, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  } else {
    err = fd_bincode_option_encode(0, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_bincode_uint64_encode(&self->ticks_per_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint128_encode(&self->ns_per_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->genesis_creation_time, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_double_encode(&self->slots_per_year, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->accounts_data_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->block_height, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->collector_id, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->collector_fees, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_fee_calculator_encode(&self->fee_calculator, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_fee_rate_governor_encode(&self->fee_rate_governor, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->collected_rent, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_rent_collector_encode(&self->rent_collector, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_epoch_schedule_encode(&self->epoch_schedule, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_inflation_encode(&self->inflation, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_stakes_encode(&self->stakes, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_unused_accounts_encode(&self->unused_accounts, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->epoch_stakes_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->epoch_stakes_len != 0) {
    for (ulong i = 0; i < self->epoch_stakes_len; ++i) {
      err = fd_epoch_epoch_stakes_pair_encode(self->epoch_stakes + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  err = fd_bincode_uint8_encode((unsigned char *) &self->is_delta, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_serializable_account_storage_entry_decode(fd_serializable_account_storage_entry_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode(&self->id, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->accounts_current_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_serializable_account_storage_entry_new(fd_serializable_account_storage_entry_t* self) {
}
void fd_serializable_account_storage_entry_destroy(fd_serializable_account_storage_entry_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

void fd_serializable_account_storage_entry_walk(fd_serializable_account_storage_entry_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_serializable_account_storage_entry", level++);
  fun(&self->id, "id", 11, "ulong", level + 1);
  fun(&self->accounts_current_len, "accounts_current_len", 11, "ulong", level + 1);
  fun(self, name, 33, "fd_serializable_account_storage_entry", --level);
}
ulong fd_serializable_account_storage_entry_size(fd_serializable_account_storage_entry_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  return size;
}

int fd_serializable_account_storage_entry_encode(fd_serializable_account_storage_entry_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(&self->id, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->accounts_current_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_bank_hash_stats_decode(fd_bank_hash_stats_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode(&self->num_updated_accounts, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->num_removed_accounts, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->num_lamports_stored, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->total_data_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->num_executable_accounts, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_bank_hash_stats_new(fd_bank_hash_stats_t* self) {
}
void fd_bank_hash_stats_destroy(fd_bank_hash_stats_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

void fd_bank_hash_stats_walk(fd_bank_hash_stats_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_bank_hash_stats", level++);
  fun(&self->num_updated_accounts, "num_updated_accounts", 11, "ulong", level + 1);
  fun(&self->num_removed_accounts, "num_removed_accounts", 11, "ulong", level + 1);
  fun(&self->num_lamports_stored, "num_lamports_stored", 11, "ulong", level + 1);
  fun(&self->total_data_len, "total_data_len", 11, "ulong", level + 1);
  fun(&self->num_executable_accounts, "num_executable_accounts", 11, "ulong", level + 1);
  fun(self, name, 33, "fd_bank_hash_stats", --level);
}
ulong fd_bank_hash_stats_size(fd_bank_hash_stats_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  return size;
}

int fd_bank_hash_stats_encode(fd_bank_hash_stats_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(&self->num_updated_accounts, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->num_removed_accounts, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->num_lamports_stored, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->total_data_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->num_executable_accounts, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_bank_hash_info_decode(fd_bank_hash_info_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_hash_decode(&self->hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_decode(&self->snapshot_hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bank_hash_stats_decode(&self->stats, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_bank_hash_info_new(fd_bank_hash_info_t* self) {
  fd_hash_new(&self->hash);
  fd_hash_new(&self->snapshot_hash);
  fd_bank_hash_stats_new(&self->stats);
}
void fd_bank_hash_info_destroy(fd_bank_hash_info_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_hash_destroy(&self->hash, ctx);
  fd_hash_destroy(&self->snapshot_hash, ctx);
  fd_bank_hash_stats_destroy(&self->stats, ctx);
}

void fd_bank_hash_info_walk(fd_bank_hash_info_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_bank_hash_info", level++);
  fd_hash_walk(&self->hash, fun, "hash", level + 1);
  fd_hash_walk(&self->snapshot_hash, fun, "snapshot_hash", level + 1);
  fd_bank_hash_stats_walk(&self->stats, fun, "stats", level + 1);
  fun(self, name, 33, "fd_bank_hash_info", --level);
}
ulong fd_bank_hash_info_size(fd_bank_hash_info_t const * self) {
  ulong size = 0;
  size += fd_hash_size(&self->hash);
  size += fd_hash_size(&self->snapshot_hash);
  size += fd_bank_hash_stats_size(&self->stats);
  return size;
}

int fd_bank_hash_info_encode(fd_bank_hash_info_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_hash_encode(&self->hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_encode(&self->snapshot_hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bank_hash_stats_encode(&self->stats, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_slot_account_pair_decode(fd_slot_account_pair_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode(&self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong accounts_len;
  err = fd_bincode_uint64_decode(&accounts_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->accounts_pool = fd_serializable_account_storage_entry_t_map_alloc(ctx->allocf, ctx->allocf_arg, accounts_len);
  if( FD_UNLIKELY( !self->accounts_pool ) ) return FD_BINCODE_ERR_ALLOC;
  self->accounts_root = NULL;
  for (ulong i = 0; i < accounts_len; ++i) {
    fd_serializable_account_storage_entry_t_mapnode_t* node = fd_serializable_account_storage_entry_t_map_acquire(self->accounts_pool);
    if( FD_UNLIKELY( !node ) ) return FD_BINCODE_ERR_ALLOC;
    fd_serializable_account_storage_entry_new(&node->elem);
    err = fd_serializable_account_storage_entry_decode(&node->elem, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    fd_serializable_account_storage_entry_t_map_insert(self->accounts_pool, &self->accounts_root, node);
  }
  return FD_BINCODE_SUCCESS;
}
void fd_slot_account_pair_new(fd_slot_account_pair_t* self) {
  self->accounts_pool = NULL;
  self->accounts_root = NULL;
}
void fd_slot_account_pair_destroy(fd_slot_account_pair_t* self, fd_bincode_destroy_ctx_t * ctx) {
  for ( fd_serializable_account_storage_entry_t_mapnode_t* n = fd_serializable_account_storage_entry_t_map_minimum(self->accounts_pool, self->accounts_root); n; n = fd_serializable_account_storage_entry_t_map_successor(self->accounts_pool, n) ) {
    fd_serializable_account_storage_entry_destroy(&n->elem, ctx);
  }
  (*ctx->freef)(ctx->freef_arg, fd_serializable_account_storage_entry_t_map_delete(fd_serializable_account_storage_entry_t_map_leave(self->accounts_pool)));
  self->accounts_pool = NULL;
  self->accounts_root = NULL;
}

void fd_slot_account_pair_walk(fd_slot_account_pair_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_slot_account_pair", level++);
  fun(&self->slot, "slot", 11, "ulong", level + 1);
  //fun(&self->accounts, "accounts", 17, "map");
  fun(self, name, 33, "fd_slot_account_pair", --level);
}
ulong fd_slot_account_pair_size(fd_slot_account_pair_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  for ( fd_serializable_account_storage_entry_t_mapnode_t* n = fd_serializable_account_storage_entry_t_map_minimum(self->accounts_pool, self->accounts_root); n; n = fd_serializable_account_storage_entry_t_map_successor(self->accounts_pool, n) ) {
    size += fd_serializable_account_storage_entry_size(&n->elem);
  }
  return size;
}

int fd_slot_account_pair_encode(fd_slot_account_pair_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(&self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong accounts_len = fd_serializable_account_storage_entry_t_map_size(self->accounts_pool, self->accounts_root);
  err = fd_bincode_uint64_encode(&accounts_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  for ( fd_serializable_account_storage_entry_t_mapnode_t* n = fd_serializable_account_storage_entry_t_map_minimum(self->accounts_pool, self->accounts_root); n; n = fd_serializable_account_storage_entry_t_map_successor(self->accounts_pool, n) ) {
    err = fd_serializable_account_storage_entry_encode(&n->elem, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}

int fd_slot_map_pair_decode(fd_slot_map_pair_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode(&self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_decode(&self->hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_slot_map_pair_new(fd_slot_map_pair_t* self) {
  fd_hash_new(&self->hash);
}
void fd_slot_map_pair_destroy(fd_slot_map_pair_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_hash_destroy(&self->hash, ctx);
}

void fd_slot_map_pair_walk(fd_slot_map_pair_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_slot_map_pair", level++);
  fun(&self->slot, "slot", 11, "ulong", level + 1);
  fd_hash_walk(&self->hash, fun, "hash", level + 1);
  fun(self, name, 33, "fd_slot_map_pair", --level);
}
ulong fd_slot_map_pair_size(fd_slot_map_pair_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += fd_hash_size(&self->hash);
  return size;
}

int fd_slot_map_pair_encode(fd_slot_map_pair_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(&self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_encode(&self->hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_solana_accounts_db_fields_decode(fd_solana_accounts_db_fields_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  ulong storages_len;
  err = fd_bincode_uint64_decode(&storages_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->storages_pool = fd_slot_account_pair_t_map_alloc(ctx->allocf, ctx->allocf_arg, storages_len);
  if( FD_UNLIKELY( !self->storages_pool ) ) return FD_BINCODE_ERR_ALLOC;
  self->storages_root = NULL;
  for (ulong i = 0; i < storages_len; ++i) {
    fd_slot_account_pair_t_mapnode_t* node = fd_slot_account_pair_t_map_acquire(self->storages_pool);
    if( FD_UNLIKELY( !node ) ) return FD_BINCODE_ERR_ALLOC;
    fd_slot_account_pair_new(&node->elem);
    err = fd_slot_account_pair_decode(&node->elem, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    fd_slot_account_pair_t_map_insert(self->storages_pool, &self->storages_root, node);
  }
  err = fd_bincode_uint64_decode(&self->version, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bank_hash_info_decode(&self->bank_hash_info, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->historical_roots_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->historical_roots_len != 0) {
    self->historical_roots = (ulong*)(*ctx->allocf)(ctx->allocf_arg, 8UL, sizeof(ulong)*self->historical_roots_len);
    for (ulong i = 0; i < self->historical_roots_len; ++i) {
      err = fd_bincode_uint64_decode(self->historical_roots + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else
    self->historical_roots = NULL;
  err = fd_bincode_uint64_decode(&self->historical_roots_with_hash_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->historical_roots_with_hash_len != 0) {
    self->historical_roots_with_hash = (fd_slot_map_pair_t*)(*ctx->allocf)(ctx->allocf_arg, FD_SLOT_MAP_PAIR_ALIGN, FD_SLOT_MAP_PAIR_FOOTPRINT*self->historical_roots_with_hash_len);
    for (ulong i = 0; i < self->historical_roots_with_hash_len; ++i) {
      fd_slot_map_pair_new(self->historical_roots_with_hash + i);
    }
    for (ulong i = 0; i < self->historical_roots_with_hash_len; ++i) {
      err = fd_slot_map_pair_decode(self->historical_roots_with_hash + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else
    self->historical_roots_with_hash = NULL;
  return FD_BINCODE_SUCCESS;
}
void fd_solana_accounts_db_fields_new(fd_solana_accounts_db_fields_t* self) {
  self->storages_pool = NULL;
  self->storages_root = NULL;
  fd_bank_hash_info_new(&self->bank_hash_info);
  self->historical_roots = NULL;
  self->historical_roots_with_hash = NULL;
}
void fd_solana_accounts_db_fields_destroy(fd_solana_accounts_db_fields_t* self, fd_bincode_destroy_ctx_t * ctx) {
  for ( fd_slot_account_pair_t_mapnode_t* n = fd_slot_account_pair_t_map_minimum(self->storages_pool, self->storages_root); n; n = fd_slot_account_pair_t_map_successor(self->storages_pool, n) ) {
    fd_slot_account_pair_destroy(&n->elem, ctx);
  }
  (*ctx->freef)(ctx->freef_arg, fd_slot_account_pair_t_map_delete(fd_slot_account_pair_t_map_leave(self->storages_pool)));
  self->storages_pool = NULL;
  self->storages_root = NULL;
  fd_bank_hash_info_destroy(&self->bank_hash_info, ctx);
  if (NULL != self->historical_roots) {
    (*ctx->freef)(ctx->freef_arg, self->historical_roots);
    self->historical_roots = NULL;
  }
  if (NULL != self->historical_roots_with_hash) {
    for (ulong i = 0; i < self->historical_roots_with_hash_len; ++i)
      fd_slot_map_pair_destroy(self->historical_roots_with_hash + i, ctx);
    (*ctx->freef)(ctx->freef_arg, self->historical_roots_with_hash);
    self->historical_roots_with_hash = NULL;
  }
}

void fd_solana_accounts_db_fields_walk(fd_solana_accounts_db_fields_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_solana_accounts_db_fields", level++);
  //fun(&self->storages, "storages", 17, "map");
  fun(&self->version, "version", 11, "ulong", level + 1);
  fun(&self->slot, "slot", 11, "ulong", level + 1);
  fd_bank_hash_info_walk(&self->bank_hash_info, fun, "bank_hash_info", level + 1);
  if (self->historical_roots_len != 0) {
    fun(NULL, NULL, 30, "historical_roots", level++);
    for (ulong i = 0; i < self->historical_roots_len; ++i)
      fun(self->historical_roots + i, "historical_roots", 11, "ulong", level + 1);
    fun(NULL, NULL, 31, "historical_roots", --level);
  }
  if (self->historical_roots_with_hash_len != 0) {
    fun(NULL, NULL, 30, "historical_roots_with_hash", level++);
    for (ulong i = 0; i < self->historical_roots_with_hash_len; ++i)
      fd_slot_map_pair_walk(self->historical_roots_with_hash + i, fun, "slot_map_pair", level + 1);
    fun(NULL, NULL, 31, "historical_roots_with_hash", --level);
  }
  fun(self, name, 33, "fd_solana_accounts_db_fields", --level);
}
ulong fd_solana_accounts_db_fields_size(fd_solana_accounts_db_fields_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  for ( fd_slot_account_pair_t_mapnode_t* n = fd_slot_account_pair_t_map_minimum(self->storages_pool, self->storages_root); n; n = fd_slot_account_pair_t_map_successor(self->storages_pool, n) ) {
    size += fd_slot_account_pair_size(&n->elem);
  }
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += fd_bank_hash_info_size(&self->bank_hash_info);
  size += sizeof(ulong);
  size += self->historical_roots_len * sizeof(ulong);
  size += sizeof(ulong);
  for (ulong i = 0; i < self->historical_roots_with_hash_len; ++i)
    size += fd_slot_map_pair_size(self->historical_roots_with_hash + i);
  return size;
}

int fd_solana_accounts_db_fields_encode(fd_solana_accounts_db_fields_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  ulong storages_len = fd_slot_account_pair_t_map_size(self->storages_pool, self->storages_root);
  err = fd_bincode_uint64_encode(&storages_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  for ( fd_slot_account_pair_t_mapnode_t* n = fd_slot_account_pair_t_map_minimum(self->storages_pool, self->storages_root); n; n = fd_slot_account_pair_t_map_successor(self->storages_pool, n) ) {
    err = fd_slot_account_pair_encode(&n->elem, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_bincode_uint64_encode(&self->version, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bank_hash_info_encode(&self->bank_hash_info, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->historical_roots_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->historical_roots_len != 0) {
    for (ulong i = 0; i < self->historical_roots_len; ++i) {
      err = fd_bincode_uint64_encode(self->historical_roots + i, ctx);
    }
  }
  err = fd_bincode_uint64_encode(&self->historical_roots_with_hash_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->historical_roots_with_hash_len != 0) {
    for (ulong i = 0; i < self->historical_roots_with_hash_len; ++i) {
      err = fd_slot_map_pair_encode(self->historical_roots_with_hash + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}

int fd_solana_manifest_decode(fd_solana_manifest_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_deserializable_versioned_bank_decode(&self->bank, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_solana_accounts_db_fields_decode(&self->accounts_db, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->lamports_per_signature, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_solana_manifest_new(fd_solana_manifest_t* self) {
  fd_deserializable_versioned_bank_new(&self->bank);
  fd_solana_accounts_db_fields_new(&self->accounts_db);
}
void fd_solana_manifest_destroy(fd_solana_manifest_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_deserializable_versioned_bank_destroy(&self->bank, ctx);
  fd_solana_accounts_db_fields_destroy(&self->accounts_db, ctx);
}

void fd_solana_manifest_walk(fd_solana_manifest_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_solana_manifest", level++);
  fd_deserializable_versioned_bank_walk(&self->bank, fun, "bank", level + 1);
  fd_solana_accounts_db_fields_walk(&self->accounts_db, fun, "accounts_db", level + 1);
  fun(&self->lamports_per_signature, "lamports_per_signature", 11, "ulong", level + 1);
  fun(self, name, 33, "fd_solana_manifest", --level);
}
ulong fd_solana_manifest_size(fd_solana_manifest_t const * self) {
  ulong size = 0;
  size += fd_deserializable_versioned_bank_size(&self->bank);
  size += fd_solana_accounts_db_fields_size(&self->accounts_db);
  size += sizeof(ulong);
  return size;
}

int fd_solana_manifest_encode(fd_solana_manifest_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_deserializable_versioned_bank_encode(&self->bank, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_solana_accounts_db_fields_encode(&self->accounts_db, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->lamports_per_signature, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_rust_duration_decode(fd_rust_duration_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode(&self->seconds, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint32_decode(&self->nanoseconds, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_rust_duration_new(fd_rust_duration_t* self) {
}
void fd_rust_duration_destroy(fd_rust_duration_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

void fd_rust_duration_walk(fd_rust_duration_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_rust_duration", level++);
  fun(&self->seconds, "seconds", 11, "ulong", level + 1);
  fun(&self->nanoseconds, "nanoseconds", 7, "uint", level + 1);
  fun(self, name, 33, "fd_rust_duration", --level);
}
ulong fd_rust_duration_size(fd_rust_duration_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(uint);
  return size;
}

int fd_rust_duration_encode(fd_rust_duration_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(&self->seconds, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint32_encode(&self->nanoseconds, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_poh_config_decode(fd_poh_config_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_rust_duration_decode(&self->target_tick_duration, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  {
    unsigned char o;
    err = fd_bincode_option_decode(&o, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    if (o) {
      self->target_tick_count = (ulong*)(*ctx->allocf)(ctx->allocf_arg, 8, sizeof(ulong));
      err = fd_bincode_uint64_decode(self->target_tick_count, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    } else
      self->target_tick_count = NULL;
  }
  {
    unsigned char o;
    err = fd_bincode_option_decode(&o, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    if (o) {
      self->hashes_per_tick = (ulong*)(*ctx->allocf)(ctx->allocf_arg, 8, sizeof(ulong));
      err = fd_bincode_uint64_decode(self->hashes_per_tick, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    } else
      self->hashes_per_tick = NULL;
  }
  return FD_BINCODE_SUCCESS;
}
void fd_poh_config_new(fd_poh_config_t* self) {
  fd_rust_duration_new(&self->target_tick_duration);
  self->target_tick_count = NULL;
  self->hashes_per_tick = NULL;
}
void fd_poh_config_destroy(fd_poh_config_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_rust_duration_destroy(&self->target_tick_duration, ctx);
  if (NULL != self->target_tick_count) {
    (*ctx->freef)(ctx->freef_arg, self->target_tick_count);
    self->target_tick_count = NULL;
  }
  if (NULL != self->hashes_per_tick) {
    (*ctx->freef)(ctx->freef_arg, self->hashes_per_tick);
    self->hashes_per_tick = NULL;
  }
}

void fd_poh_config_walk(fd_poh_config_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_poh_config", level++);
  fd_rust_duration_walk(&self->target_tick_duration, fun, "target_tick_duration", level + 1);
  fun(self->target_tick_count, "target_tick_count", 11, "ulong", level + 1);
  fun(self->hashes_per_tick, "hashes_per_tick", 11, "ulong", level + 1);
  fun(self, name, 33, "fd_poh_config", --level);
}
ulong fd_poh_config_size(fd_poh_config_t const * self) {
  ulong size = 0;
  size += fd_rust_duration_size(&self->target_tick_duration);
  size += sizeof(char);
  if (NULL !=  self->target_tick_count) {
    size += sizeof(ulong);
  }
  size += sizeof(char);
  if (NULL !=  self->hashes_per_tick) {
    size += sizeof(ulong);
  }
  return size;
}

int fd_poh_config_encode(fd_poh_config_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_rust_duration_encode(&self->target_tick_duration, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->target_tick_count != NULL) {
    err = fd_bincode_option_encode(1, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    err = fd_bincode_uint64_encode(self->target_tick_count, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  } else {
    err = fd_bincode_option_encode(0, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  if (self->hashes_per_tick != NULL) {
    err = fd_bincode_option_encode(1, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    err = fd_bincode_uint64_encode(self->hashes_per_tick, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  } else {
    err = fd_bincode_option_encode(0, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}

int fd_string_pubkey_pair_decode(fd_string_pubkey_pair_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  ulong slen;
  err = fd_bincode_uint64_decode(&slen, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->string = (char*)(*ctx->allocf)(ctx->allocf_arg, 1, slen + 1);
  err = fd_bincode_bytes_decode((uchar *) self->string, slen, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->string[slen] = '\0';
  err = fd_pubkey_decode(&self->pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_string_pubkey_pair_new(fd_string_pubkey_pair_t* self) {
  self->string = NULL;
  fd_pubkey_new(&self->pubkey);
}
void fd_string_pubkey_pair_destroy(fd_string_pubkey_pair_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->string) {
    (*ctx->freef)(ctx->freef_arg, self->string);
    self->string = NULL;
  }
  fd_pubkey_destroy(&self->pubkey, ctx);
}

void fd_string_pubkey_pair_walk(fd_string_pubkey_pair_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_string_pubkey_pair", level++);
  fun(self->string, "string", 2, "char*", level + 1);
  fd_pubkey_walk(&self->pubkey, fun, "pubkey", level + 1);
  fun(self, name, 33, "fd_string_pubkey_pair", --level);
}
ulong fd_string_pubkey_pair_size(fd_string_pubkey_pair_t const * self) {
  ulong size = 0;
  size += sizeof(ulong) + strlen(self->string);
  size += fd_pubkey_size(&self->pubkey);
  return size;
}

int fd_string_pubkey_pair_encode(fd_string_pubkey_pair_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  ulong slen = strlen((char *) self->string);
  err = fd_bincode_uint64_encode(&slen, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_bytes_encode((uchar *) self->string, slen, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_pubkey_account_pair_decode(fd_pubkey_account_pair_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_decode(&self->key, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_solana_account_decode(&self->account, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_pubkey_account_pair_new(fd_pubkey_account_pair_t* self) {
  fd_pubkey_new(&self->key);
  fd_solana_account_new(&self->account);
}
void fd_pubkey_account_pair_destroy(fd_pubkey_account_pair_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->key, ctx);
  fd_solana_account_destroy(&self->account, ctx);
}

void fd_pubkey_account_pair_walk(fd_pubkey_account_pair_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_pubkey_account_pair", level++);
  fd_pubkey_walk(&self->key, fun, "key", level + 1);
  fd_solana_account_walk(&self->account, fun, "account", level + 1);
  fun(self, name, 33, "fd_pubkey_account_pair", --level);
}
ulong fd_pubkey_account_pair_size(fd_pubkey_account_pair_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->key);
  size += fd_solana_account_size(&self->account);
  return size;
}

int fd_pubkey_account_pair_encode(fd_pubkey_account_pair_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->key, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_solana_account_encode(&self->account, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_genesis_solana_decode(fd_genesis_solana_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode(&self->creation_time, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->accounts_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->accounts_len != 0) {
    self->accounts = (fd_pubkey_account_pair_t*)(*ctx->allocf)(ctx->allocf_arg, FD_PUBKEY_ACCOUNT_PAIR_ALIGN, FD_PUBKEY_ACCOUNT_PAIR_FOOTPRINT*self->accounts_len);
    for (ulong i = 0; i < self->accounts_len; ++i) {
      fd_pubkey_account_pair_new(self->accounts + i);
    }
    for (ulong i = 0; i < self->accounts_len; ++i) {
      err = fd_pubkey_account_pair_decode(self->accounts + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else
    self->accounts = NULL;
  err = fd_bincode_uint64_decode(&self->native_instruction_processors_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->native_instruction_processors_len != 0) {
    self->native_instruction_processors = (fd_string_pubkey_pair_t*)(*ctx->allocf)(ctx->allocf_arg, FD_STRING_PUBKEY_PAIR_ALIGN, FD_STRING_PUBKEY_PAIR_FOOTPRINT*self->native_instruction_processors_len);
    for (ulong i = 0; i < self->native_instruction_processors_len; ++i) {
      fd_string_pubkey_pair_new(self->native_instruction_processors + i);
    }
    for (ulong i = 0; i < self->native_instruction_processors_len; ++i) {
      err = fd_string_pubkey_pair_decode(self->native_instruction_processors + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else
    self->native_instruction_processors = NULL;
  err = fd_bincode_uint64_decode(&self->rewards_pools_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->rewards_pools_len != 0) {
    self->rewards_pools = (fd_pubkey_account_pair_t*)(*ctx->allocf)(ctx->allocf_arg, FD_PUBKEY_ACCOUNT_PAIR_ALIGN, FD_PUBKEY_ACCOUNT_PAIR_FOOTPRINT*self->rewards_pools_len);
    for (ulong i = 0; i < self->rewards_pools_len; ++i) {
      fd_pubkey_account_pair_new(self->rewards_pools + i);
    }
    for (ulong i = 0; i < self->rewards_pools_len; ++i) {
      err = fd_pubkey_account_pair_decode(self->rewards_pools + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else
    self->rewards_pools = NULL;
  err = fd_bincode_uint64_decode(&self->ticks_per_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->unused, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_poh_config_decode(&self->poh_config, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->__backwards_compat_with_v0_23, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_fee_rate_governor_decode(&self->fee_rate_governor, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_rent_decode(&self->rent, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_inflation_decode(&self->inflation, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_epoch_schedule_decode(&self->epoch_schedule, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint32_decode(&self->cluster_type, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_genesis_solana_new(fd_genesis_solana_t* self) {
  self->accounts = NULL;
  self->native_instruction_processors = NULL;
  self->rewards_pools = NULL;
  fd_poh_config_new(&self->poh_config);
  fd_fee_rate_governor_new(&self->fee_rate_governor);
  fd_rent_new(&self->rent);
  fd_inflation_new(&self->inflation);
  fd_epoch_schedule_new(&self->epoch_schedule);
}
void fd_genesis_solana_destroy(fd_genesis_solana_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->accounts) {
    for (ulong i = 0; i < self->accounts_len; ++i)
      fd_pubkey_account_pair_destroy(self->accounts + i, ctx);
    (*ctx->freef)(ctx->freef_arg, self->accounts);
    self->accounts = NULL;
  }
  if (NULL != self->native_instruction_processors) {
    for (ulong i = 0; i < self->native_instruction_processors_len; ++i)
      fd_string_pubkey_pair_destroy(self->native_instruction_processors + i, ctx);
    (*ctx->freef)(ctx->freef_arg, self->native_instruction_processors);
    self->native_instruction_processors = NULL;
  }
  if (NULL != self->rewards_pools) {
    for (ulong i = 0; i < self->rewards_pools_len; ++i)
      fd_pubkey_account_pair_destroy(self->rewards_pools + i, ctx);
    (*ctx->freef)(ctx->freef_arg, self->rewards_pools);
    self->rewards_pools = NULL;
  }
  fd_poh_config_destroy(&self->poh_config, ctx);
  fd_fee_rate_governor_destroy(&self->fee_rate_governor, ctx);
  fd_rent_destroy(&self->rent, ctx);
  fd_inflation_destroy(&self->inflation, ctx);
  fd_epoch_schedule_destroy(&self->epoch_schedule, ctx);
}

void fd_genesis_solana_walk(fd_genesis_solana_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_genesis_solana", level++);
  fun(&self->creation_time, "creation_time", 11, "ulong", level + 1);
  if (self->accounts_len != 0) {
    fun(NULL, NULL, 30, "accounts", level++);
    for (ulong i = 0; i < self->accounts_len; ++i)
      fd_pubkey_account_pair_walk(self->accounts + i, fun, "pubkey_account_pair", level + 1);
    fun(NULL, NULL, 31, "accounts", --level);
  }
  if (self->native_instruction_processors_len != 0) {
    fun(NULL, NULL, 30, "native_instruction_processors", level++);
    for (ulong i = 0; i < self->native_instruction_processors_len; ++i)
      fd_string_pubkey_pair_walk(self->native_instruction_processors + i, fun, "string_pubkey_pair", level + 1);
    fun(NULL, NULL, 31, "native_instruction_processors", --level);
  }
  if (self->rewards_pools_len != 0) {
    fun(NULL, NULL, 30, "rewards_pools", level++);
    for (ulong i = 0; i < self->rewards_pools_len; ++i)
      fd_pubkey_account_pair_walk(self->rewards_pools + i, fun, "pubkey_account_pair", level + 1);
    fun(NULL, NULL, 31, "rewards_pools", --level);
  }
  fun(&self->ticks_per_slot, "ticks_per_slot", 11, "ulong", level + 1);
  fun(&self->unused, "unused", 11, "ulong", level + 1);
  fd_poh_config_walk(&self->poh_config, fun, "poh_config", level + 1);
  fun(&self->__backwards_compat_with_v0_23, "__backwards_compat_with_v0_23", 11, "ulong", level + 1);
  fd_fee_rate_governor_walk(&self->fee_rate_governor, fun, "fee_rate_governor", level + 1);
  fd_rent_walk(&self->rent, fun, "rent", level + 1);
  fd_inflation_walk(&self->inflation, fun, "inflation", level + 1);
  fd_epoch_schedule_walk(&self->epoch_schedule, fun, "epoch_schedule", level + 1);
  fun(&self->cluster_type, "cluster_type", 7, "uint", level + 1);
  fun(self, name, 33, "fd_genesis_solana", --level);
}
ulong fd_genesis_solana_size(fd_genesis_solana_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  for (ulong i = 0; i < self->accounts_len; ++i)
    size += fd_pubkey_account_pair_size(self->accounts + i);
  size += sizeof(ulong);
  for (ulong i = 0; i < self->native_instruction_processors_len; ++i)
    size += fd_string_pubkey_pair_size(self->native_instruction_processors + i);
  size += sizeof(ulong);
  for (ulong i = 0; i < self->rewards_pools_len; ++i)
    size += fd_pubkey_account_pair_size(self->rewards_pools + i);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += fd_poh_config_size(&self->poh_config);
  size += sizeof(ulong);
  size += fd_fee_rate_governor_size(&self->fee_rate_governor);
  size += fd_rent_size(&self->rent);
  size += fd_inflation_size(&self->inflation);
  size += fd_epoch_schedule_size(&self->epoch_schedule);
  size += sizeof(uint);
  return size;
}

int fd_genesis_solana_encode(fd_genesis_solana_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(&self->creation_time, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->accounts_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->accounts_len != 0) {
    for (ulong i = 0; i < self->accounts_len; ++i) {
      err = fd_pubkey_account_pair_encode(self->accounts + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  err = fd_bincode_uint64_encode(&self->native_instruction_processors_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->native_instruction_processors_len != 0) {
    for (ulong i = 0; i < self->native_instruction_processors_len; ++i) {
      err = fd_string_pubkey_pair_encode(self->native_instruction_processors + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  err = fd_bincode_uint64_encode(&self->rewards_pools_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->rewards_pools_len != 0) {
    for (ulong i = 0; i < self->rewards_pools_len; ++i) {
      err = fd_pubkey_account_pair_encode(self->rewards_pools + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  err = fd_bincode_uint64_encode(&self->ticks_per_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->unused, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_poh_config_encode(&self->poh_config, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->__backwards_compat_with_v0_23, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_fee_rate_governor_encode(&self->fee_rate_governor, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_rent_encode(&self->rent, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_inflation_encode(&self->inflation, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_epoch_schedule_encode(&self->epoch_schedule, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint32_encode(&self->cluster_type, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_secp256k1_signature_offsets_decode(fd_secp256k1_signature_offsets_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint16_decode(&self->signature_offset, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_decode(&self->signature_instruction_index, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint16_decode(&self->eth_address_offset, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_decode(&self->eth_address_instruction_index, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint16_decode(&self->message_data_offset, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint16_decode(&self->message_data_size, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_decode(&self->message_instruction_index, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_secp256k1_signature_offsets_new(fd_secp256k1_signature_offsets_t* self) {
}
void fd_secp256k1_signature_offsets_destroy(fd_secp256k1_signature_offsets_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

void fd_secp256k1_signature_offsets_walk(fd_secp256k1_signature_offsets_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_secp256k1_signature_offsets", level++);
  fun(&self->signature_offset, "signature_offset", 12, "ushort", level + 1);
  fun(&self->signature_instruction_index, "signature_instruction_index", 9, "uchar", level + 1);
  fun(&self->eth_address_offset, "eth_address_offset", 12, "ushort", level + 1);
  fun(&self->eth_address_instruction_index, "eth_address_instruction_index", 9, "uchar", level + 1);
  fun(&self->message_data_offset, "message_data_offset", 12, "ushort", level + 1);
  fun(&self->message_data_size, "message_data_size", 12, "ushort", level + 1);
  fun(&self->message_instruction_index, "message_instruction_index", 9, "uchar", level + 1);
  fun(self, name, 33, "fd_secp256k1_signature_offsets", --level);
}
ulong fd_secp256k1_signature_offsets_size(fd_secp256k1_signature_offsets_t const * self) {
  ulong size = 0;
  size += sizeof(ushort);
  size += sizeof(char);
  size += sizeof(ushort);
  size += sizeof(char);
  size += sizeof(ushort);
  size += sizeof(ushort);
  size += sizeof(char);
  return size;
}

int fd_secp256k1_signature_offsets_encode(fd_secp256k1_signature_offsets_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint16_encode(&self->signature_offset, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_encode(&self->signature_instruction_index, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint16_encode(&self->eth_address_offset, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_encode(&self->eth_address_instruction_index, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint16_encode(&self->message_data_offset, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint16_encode(&self->message_data_size, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_encode(&self->message_instruction_index, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_sol_sysvar_clock_decode(fd_sol_sysvar_clock_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode(&self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode((unsigned long *) &self->epoch_start_timestamp, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->leader_schedule_epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode((unsigned long *) &self->unix_timestamp, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_sol_sysvar_clock_new(fd_sol_sysvar_clock_t* self) {
}
void fd_sol_sysvar_clock_destroy(fd_sol_sysvar_clock_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

void fd_sol_sysvar_clock_walk(fd_sol_sysvar_clock_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_sol_sysvar_clock", level++);
  fun(&self->slot, "slot", 11, "ulong", level + 1);
  fun(&self->epoch_start_timestamp, "epoch_start_timestamp", 6, "long", level + 1);
  fun(&self->epoch, "epoch", 11, "ulong", level + 1);
  fun(&self->leader_schedule_epoch, "leader_schedule_epoch", 11, "ulong", level + 1);
  fun(&self->unix_timestamp, "unix_timestamp", 6, "long", level + 1);
  fun(self, name, 33, "fd_sol_sysvar_clock", --level);
}
ulong fd_sol_sysvar_clock_size(fd_sol_sysvar_clock_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(long);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(long);
  return size;
}

int fd_sol_sysvar_clock_encode(fd_sol_sysvar_clock_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(&self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode((unsigned long *) &self->epoch_start_timestamp, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->leader_schedule_epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode((unsigned long *) &self->unix_timestamp, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_vote_lockout_decode(fd_vote_lockout_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode(&self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint32_decode(&self->confirmation_count, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_lockout_new(fd_vote_lockout_t* self) {
}
void fd_vote_lockout_destroy(fd_vote_lockout_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

void fd_vote_lockout_walk(fd_vote_lockout_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_vote_lockout", level++);
  fun(&self->slot, "slot", 11, "ulong", level + 1);
  fun(&self->confirmation_count, "confirmation_count", 7, "uint", level + 1);
  fun(self, name, 33, "fd_vote_lockout", --level);
}
ulong fd_vote_lockout_size(fd_vote_lockout_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(uint);
  return size;
}

int fd_vote_lockout_encode(fd_vote_lockout_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(&self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint32_encode(&self->confirmation_count, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_compact_vote_lockout_decode(fd_compact_vote_lockout_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_varint_decode(&self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_decode(&self->confirmation_count, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_compact_vote_lockout_new(fd_compact_vote_lockout_t* self) {
}
void fd_compact_vote_lockout_destroy(fd_compact_vote_lockout_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

void fd_compact_vote_lockout_walk(fd_compact_vote_lockout_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_compact_vote_lockout", level++);
  fun(&self->slot, "slot", 11, "ulong", level + 1);
  fun(&self->confirmation_count, "confirmation_count", 9, "uchar", level + 1);
  fun(self, name, 33, "fd_compact_vote_lockout", --level);
}
ulong fd_compact_vote_lockout_size(fd_compact_vote_lockout_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(char);
  return size;
}

int fd_compact_vote_lockout_encode(fd_compact_vote_lockout_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_varint_encode(self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_encode(&self->confirmation_count, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_vote_authorized_voter_decode(fd_vote_authorized_voter_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode(&self->epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_decode(&self->pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_authorized_voter_new(fd_vote_authorized_voter_t* self) {
  fd_pubkey_new(&self->pubkey);
}
void fd_vote_authorized_voter_destroy(fd_vote_authorized_voter_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->pubkey, ctx);
}

void fd_vote_authorized_voter_walk(fd_vote_authorized_voter_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_vote_authorized_voter", level++);
  fun(&self->epoch, "epoch", 11, "ulong", level + 1);
  fd_pubkey_walk(&self->pubkey, fun, "pubkey", level + 1);
  fun(self, name, 33, "fd_vote_authorized_voter", --level);
}
ulong fd_vote_authorized_voter_size(fd_vote_authorized_voter_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += fd_pubkey_size(&self->pubkey);
  return size;
}

int fd_vote_authorized_voter_encode(fd_vote_authorized_voter_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(&self->epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_vote_prior_voter_decode(fd_vote_prior_voter_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_decode(&self->pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->epoch_start, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->epoch_end, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_prior_voter_new(fd_vote_prior_voter_t* self) {
  fd_pubkey_new(&self->pubkey);
}
void fd_vote_prior_voter_destroy(fd_vote_prior_voter_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->pubkey, ctx);
}

void fd_vote_prior_voter_walk(fd_vote_prior_voter_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_vote_prior_voter", level++);
  fd_pubkey_walk(&self->pubkey, fun, "pubkey", level + 1);
  fun(&self->epoch_start, "epoch_start", 11, "ulong", level + 1);
  fun(&self->epoch_end, "epoch_end", 11, "ulong", level + 1);
  fun(self, name, 33, "fd_vote_prior_voter", --level);
}
ulong fd_vote_prior_voter_size(fd_vote_prior_voter_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->pubkey);
  size += sizeof(ulong);
  size += sizeof(ulong);
  return size;
}

int fd_vote_prior_voter_encode(fd_vote_prior_voter_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->epoch_start, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->epoch_end, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_vote_prior_voter_0_23_5_decode(fd_vote_prior_voter_0_23_5_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_decode(&self->pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->epoch_start, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->epoch_end, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_prior_voter_0_23_5_new(fd_vote_prior_voter_0_23_5_t* self) {
  fd_pubkey_new(&self->pubkey);
}
void fd_vote_prior_voter_0_23_5_destroy(fd_vote_prior_voter_0_23_5_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->pubkey, ctx);
}

void fd_vote_prior_voter_0_23_5_walk(fd_vote_prior_voter_0_23_5_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_vote_prior_voter_0_23_5", level++);
  fd_pubkey_walk(&self->pubkey, fun, "pubkey", level + 1);
  fun(&self->epoch_start, "epoch_start", 11, "ulong", level + 1);
  fun(&self->epoch_end, "epoch_end", 11, "ulong", level + 1);
  fun(&self->slot, "slot", 11, "ulong", level + 1);
  fun(self, name, 33, "fd_vote_prior_voter_0_23_5", --level);
}
ulong fd_vote_prior_voter_0_23_5_size(fd_vote_prior_voter_0_23_5_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->pubkey);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  return size;
}

int fd_vote_prior_voter_0_23_5_encode(fd_vote_prior_voter_0_23_5_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->epoch_start, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->epoch_end, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_vote_epoch_credits_decode(fd_vote_epoch_credits_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode(&self->epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->credits, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->prev_credits, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_epoch_credits_new(fd_vote_epoch_credits_t* self) {
}
void fd_vote_epoch_credits_destroy(fd_vote_epoch_credits_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

void fd_vote_epoch_credits_walk(fd_vote_epoch_credits_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_vote_epoch_credits", level++);
  fun(&self->epoch, "epoch", 11, "ulong", level + 1);
  fun(&self->credits, "credits", 11, "ulong", level + 1);
  fun(&self->prev_credits, "prev_credits", 11, "ulong", level + 1);
  fun(self, name, 33, "fd_vote_epoch_credits", --level);
}
ulong fd_vote_epoch_credits_size(fd_vote_epoch_credits_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  return size;
}

int fd_vote_epoch_credits_encode(fd_vote_epoch_credits_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(&self->epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->credits, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->prev_credits, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_vote_historical_authorized_voter_decode(fd_vote_historical_authorized_voter_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode(&self->epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_decode(&self->pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_historical_authorized_voter_new(fd_vote_historical_authorized_voter_t* self) {
  fd_pubkey_new(&self->pubkey);
}
void fd_vote_historical_authorized_voter_destroy(fd_vote_historical_authorized_voter_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->pubkey, ctx);
}

void fd_vote_historical_authorized_voter_walk(fd_vote_historical_authorized_voter_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_vote_historical_authorized_voter", level++);
  fun(&self->epoch, "epoch", 11, "ulong", level + 1);
  fd_pubkey_walk(&self->pubkey, fun, "pubkey", level + 1);
  fun(self, name, 33, "fd_vote_historical_authorized_voter", --level);
}
ulong fd_vote_historical_authorized_voter_size(fd_vote_historical_authorized_voter_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += fd_pubkey_size(&self->pubkey);
  return size;
}

int fd_vote_historical_authorized_voter_encode(fd_vote_historical_authorized_voter_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(&self->epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_vote_block_timestamp_decode(fd_vote_block_timestamp_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode(&self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->timestamp, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_block_timestamp_new(fd_vote_block_timestamp_t* self) {
}
void fd_vote_block_timestamp_destroy(fd_vote_block_timestamp_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

void fd_vote_block_timestamp_walk(fd_vote_block_timestamp_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_vote_block_timestamp", level++);
  fun(&self->slot, "slot", 11, "ulong", level + 1);
  fun(&self->timestamp, "timestamp", 11, "ulong", level + 1);
  fun(self, name, 33, "fd_vote_block_timestamp", --level);
}
ulong fd_vote_block_timestamp_size(fd_vote_block_timestamp_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  return size;
}

int fd_vote_block_timestamp_encode(fd_vote_block_timestamp_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(&self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->timestamp, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_vote_prior_voters_decode(fd_vote_prior_voters_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  for (ulong i = 0; i < 32; ++i) {
    err = fd_vote_prior_voter_decode(self->buf + i, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_bincode_uint64_decode(&self->idx, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_decode(&self->is_empty, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_prior_voters_new(fd_vote_prior_voters_t* self) {
  for (ulong i = 0; i < 32; ++i)
    fd_vote_prior_voter_new(self->buf + i);
}
void fd_vote_prior_voters_destroy(fd_vote_prior_voters_t* self, fd_bincode_destroy_ctx_t * ctx) {
  for (ulong i = 0; i < 32; ++i)
    fd_vote_prior_voter_destroy(self->buf + i, ctx);
}

void fd_vote_prior_voters_walk(fd_vote_prior_voters_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_vote_prior_voters", level++);
  for (ulong i = 0; i < 32; ++i)
    fd_vote_prior_voter_walk(self->buf + i, fun, "vote_prior_voter", level + 1);
  fun(&self->idx, "idx", 11, "ulong", level + 1);
  fun(&self->is_empty, "is_empty", 9, "uchar", level + 1);
  fun(self, name, 33, "fd_vote_prior_voters", --level);
}
ulong fd_vote_prior_voters_size(fd_vote_prior_voters_t const * self) {
  ulong size = 0;
  for (ulong i = 0; i < 32; ++i)
    size += fd_vote_prior_voter_size(self->buf + i);
  size += sizeof(ulong);
  size += sizeof(char);
  return size;
}

int fd_vote_prior_voters_encode(fd_vote_prior_voters_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  for (ulong i = 0; i < 32; ++i) {
    err = fd_vote_prior_voter_encode(self->buf + i, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_bincode_uint64_encode(&self->idx, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_encode(&self->is_empty, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_vote_prior_voters_0_23_5_decode(fd_vote_prior_voters_0_23_5_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  for (ulong i = 0; i < 32; ++i) {
    err = fd_vote_prior_voter_0_23_5_decode(self->buf + i, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_bincode_uint64_decode(&self->idx, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_decode(&self->is_empty, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_prior_voters_0_23_5_new(fd_vote_prior_voters_0_23_5_t* self) {
  for (ulong i = 0; i < 32; ++i)
    fd_vote_prior_voter_0_23_5_new(self->buf + i);
}
void fd_vote_prior_voters_0_23_5_destroy(fd_vote_prior_voters_0_23_5_t* self, fd_bincode_destroy_ctx_t * ctx) {
  for (ulong i = 0; i < 32; ++i)
    fd_vote_prior_voter_0_23_5_destroy(self->buf + i, ctx);
}

void fd_vote_prior_voters_0_23_5_walk(fd_vote_prior_voters_0_23_5_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_vote_prior_voters_0_23_5", level++);
  for (ulong i = 0; i < 32; ++i)
    fd_vote_prior_voter_0_23_5_walk(self->buf + i, fun, "vote_prior_voter_0_23_5", level + 1);
  fun(&self->idx, "idx", 11, "ulong", level + 1);
  fun(&self->is_empty, "is_empty", 9, "uchar", level + 1);
  fun(self, name, 33, "fd_vote_prior_voters_0_23_5", --level);
}
ulong fd_vote_prior_voters_0_23_5_size(fd_vote_prior_voters_0_23_5_t const * self) {
  ulong size = 0;
  for (ulong i = 0; i < 32; ++i)
    size += fd_vote_prior_voter_0_23_5_size(self->buf + i);
  size += sizeof(ulong);
  size += sizeof(char);
  return size;
}

int fd_vote_prior_voters_0_23_5_encode(fd_vote_prior_voters_0_23_5_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  for (ulong i = 0; i < 32; ++i) {
    err = fd_vote_prior_voter_0_23_5_encode(self->buf + i, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_bincode_uint64_encode(&self->idx, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_encode(&self->is_empty, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_vote_state_0_23_5_decode(fd_vote_state_0_23_5_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_decode(&self->voting_node, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_decode(&self->authorized_voter, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->authorized_voter_epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_vote_prior_voters_0_23_5_decode(&self->prior_voters, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_decode(&self->authorized_withdrawer, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_decode(&self->commission, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->votes = deq_fd_vote_lockout_t_alloc( ctx->allocf, ctx->allocf_arg );
  ulong votes_len;
  err = fd_bincode_uint64_decode(&votes_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if ( votes_len > deq_fd_vote_lockout_t_max(self->votes) ) return FD_BINCODE_ERR_SMALL_DEQUE;
  for (ulong i = 0; i < votes_len; ++i) {
    fd_vote_lockout_t * elem = deq_fd_vote_lockout_t_push_tail_nocopy(self->votes);
    fd_vote_lockout_new(elem);
    err = fd_vote_lockout_decode(elem, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  {
    unsigned char o;
    err = fd_bincode_option_decode(&o, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    if (o) {
      self->saved_root_slot = (ulong*)(*ctx->allocf)(ctx->allocf_arg, 8, sizeof(ulong));
      err = fd_bincode_uint64_decode(self->saved_root_slot, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    } else
      self->saved_root_slot = NULL;
  }
  self->epoch_credits = deq_fd_vote_epoch_credits_t_alloc( ctx->allocf, ctx->allocf_arg );
  ulong epoch_credits_len;
  err = fd_bincode_uint64_decode(&epoch_credits_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if ( epoch_credits_len > deq_fd_vote_epoch_credits_t_max(self->epoch_credits) ) return FD_BINCODE_ERR_SMALL_DEQUE;
  for (ulong i = 0; i < epoch_credits_len; ++i) {
    fd_vote_epoch_credits_t * elem = deq_fd_vote_epoch_credits_t_push_tail_nocopy(self->epoch_credits);
    fd_vote_epoch_credits_new(elem);
    err = fd_vote_epoch_credits_decode(elem, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_vote_block_timestamp_decode(&self->latest_timestamp, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_state_0_23_5_new(fd_vote_state_0_23_5_t* self) {
  fd_pubkey_new(&self->voting_node);
  fd_pubkey_new(&self->authorized_voter);
  fd_vote_prior_voters_0_23_5_new(&self->prior_voters);
  fd_pubkey_new(&self->authorized_withdrawer);
  self->votes = NULL;
  self->saved_root_slot = NULL;
  self->epoch_credits = NULL;
  fd_vote_block_timestamp_new(&self->latest_timestamp);
}
void fd_vote_state_0_23_5_destroy(fd_vote_state_0_23_5_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->voting_node, ctx);
  fd_pubkey_destroy(&self->authorized_voter, ctx);
  fd_vote_prior_voters_0_23_5_destroy(&self->prior_voters, ctx);
  fd_pubkey_destroy(&self->authorized_withdrawer, ctx);
  if ( self->votes ) {
    for ( deq_fd_vote_lockout_t_iter_t iter = deq_fd_vote_lockout_t_iter_init( self->votes ); !deq_fd_vote_lockout_t_iter_done( self->votes, iter ); iter = deq_fd_vote_lockout_t_iter_next( self->votes, iter ) ) {
      fd_vote_lockout_t * ele = deq_fd_vote_lockout_t_iter_ele( self->votes, iter );
      fd_vote_lockout_destroy(ele, ctx);
    }
    (*ctx->freef)(ctx->freef_arg, deq_fd_vote_lockout_t_delete( deq_fd_vote_lockout_t_leave( self->votes) ) );
    self->votes = NULL;
  }
  if (NULL != self->saved_root_slot) {
    (*ctx->freef)(ctx->freef_arg, self->saved_root_slot);
    self->saved_root_slot = NULL;
  }
  if ( self->epoch_credits ) {
    for ( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( self->epoch_credits ); !deq_fd_vote_epoch_credits_t_iter_done( self->epoch_credits, iter ); iter = deq_fd_vote_epoch_credits_t_iter_next( self->epoch_credits, iter ) ) {
      fd_vote_epoch_credits_t * ele = deq_fd_vote_epoch_credits_t_iter_ele( self->epoch_credits, iter );
      fd_vote_epoch_credits_destroy(ele, ctx);
    }
    (*ctx->freef)(ctx->freef_arg, deq_fd_vote_epoch_credits_t_delete( deq_fd_vote_epoch_credits_t_leave( self->epoch_credits) ) );
    self->epoch_credits = NULL;
  }
  fd_vote_block_timestamp_destroy(&self->latest_timestamp, ctx);
}

void fd_vote_state_0_23_5_walk(fd_vote_state_0_23_5_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_vote_state_0_23_5", level++);
  fd_pubkey_walk(&self->voting_node, fun, "voting_node", level + 1);
  fd_pubkey_walk(&self->authorized_voter, fun, "authorized_voter", level + 1);
  fun(&self->authorized_voter_epoch, "authorized_voter_epoch", 11, "ulong", level + 1);
  fd_vote_prior_voters_0_23_5_walk(&self->prior_voters, fun, "prior_voters", level + 1);
  fd_pubkey_walk(&self->authorized_withdrawer, fun, "authorized_withdrawer", level + 1);
  fun(&self->commission, "commission", 9, "uchar", level + 1);
  if ( self->votes ) {
    for ( deq_fd_vote_lockout_t_iter_t iter = deq_fd_vote_lockout_t_iter_init( self->votes ); !deq_fd_vote_lockout_t_iter_done( self->votes, iter ); iter = deq_fd_vote_lockout_t_iter_next( self->votes, iter ) ) {
      fd_vote_lockout_t * ele = deq_fd_vote_lockout_t_iter_ele( self->votes, iter );
      fd_vote_lockout_walk(ele, fun, "votes", level + 1);
    }
  }
  fun(self->saved_root_slot, "saved_root_slot", 11, "ulong", level + 1);
  if ( self->epoch_credits ) {
    for ( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( self->epoch_credits ); !deq_fd_vote_epoch_credits_t_iter_done( self->epoch_credits, iter ); iter = deq_fd_vote_epoch_credits_t_iter_next( self->epoch_credits, iter ) ) {
      fd_vote_epoch_credits_t * ele = deq_fd_vote_epoch_credits_t_iter_ele( self->epoch_credits, iter );
      fd_vote_epoch_credits_walk(ele, fun, "epoch_credits", level + 1);
    }
  }
  fd_vote_block_timestamp_walk(&self->latest_timestamp, fun, "latest_timestamp", level + 1);
  fun(self, name, 33, "fd_vote_state_0_23_5", --level);
}
ulong fd_vote_state_0_23_5_size(fd_vote_state_0_23_5_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->voting_node);
  size += fd_pubkey_size(&self->authorized_voter);
  size += sizeof(ulong);
  size += fd_vote_prior_voters_0_23_5_size(&self->prior_voters);
  size += fd_pubkey_size(&self->authorized_withdrawer);
  size += sizeof(char);
  if ( self->votes ) {
    size += sizeof(ulong);
    for ( deq_fd_vote_lockout_t_iter_t iter = deq_fd_vote_lockout_t_iter_init( self->votes ); !deq_fd_vote_lockout_t_iter_done( self->votes, iter ); iter = deq_fd_vote_lockout_t_iter_next( self->votes, iter ) ) {
      fd_vote_lockout_t * ele = deq_fd_vote_lockout_t_iter_ele( self->votes, iter );
      size += fd_vote_lockout_size(ele);
    }
  }
  size += sizeof(char);
  if (NULL !=  self->saved_root_slot) {
    size += sizeof(ulong);
  }
  if ( self->epoch_credits ) {
    size += sizeof(ulong);
    for ( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( self->epoch_credits ); !deq_fd_vote_epoch_credits_t_iter_done( self->epoch_credits, iter ); iter = deq_fd_vote_epoch_credits_t_iter_next( self->epoch_credits, iter ) ) {
      fd_vote_epoch_credits_t * ele = deq_fd_vote_epoch_credits_t_iter_ele( self->epoch_credits, iter );
      size += fd_vote_epoch_credits_size(ele);
    }
  }
  size += fd_vote_block_timestamp_size(&self->latest_timestamp);
  return size;
}

int fd_vote_state_0_23_5_encode(fd_vote_state_0_23_5_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->voting_node, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->authorized_voter, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->authorized_voter_epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_vote_prior_voters_0_23_5_encode(&self->prior_voters, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->authorized_withdrawer, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_encode(&self->commission, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if ( self->votes ) {
    ulong votes_len = deq_fd_vote_lockout_t_cnt(self->votes);
    err = fd_bincode_uint64_encode(&votes_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    for ( deq_fd_vote_lockout_t_iter_t iter = deq_fd_vote_lockout_t_iter_init( self->votes ); !deq_fd_vote_lockout_t_iter_done( self->votes, iter ); iter = deq_fd_vote_lockout_t_iter_next( self->votes, iter ) ) {
      fd_vote_lockout_t * ele = deq_fd_vote_lockout_t_iter_ele( self->votes, iter );
      err = fd_vote_lockout_encode(ele, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else {
    ulong votes_len = 0;
    err = fd_bincode_uint64_encode(&votes_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  if (self->saved_root_slot != NULL) {
    err = fd_bincode_option_encode(1, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    err = fd_bincode_uint64_encode(self->saved_root_slot, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  } else {
    err = fd_bincode_option_encode(0, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  if ( self->epoch_credits ) {
    ulong epoch_credits_len = deq_fd_vote_epoch_credits_t_cnt(self->epoch_credits);
    err = fd_bincode_uint64_encode(&epoch_credits_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    for ( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( self->epoch_credits ); !deq_fd_vote_epoch_credits_t_iter_done( self->epoch_credits, iter ); iter = deq_fd_vote_epoch_credits_t_iter_next( self->epoch_credits, iter ) ) {
      fd_vote_epoch_credits_t * ele = deq_fd_vote_epoch_credits_t_iter_ele( self->epoch_credits, iter );
      err = fd_vote_epoch_credits_encode(ele, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else {
    ulong epoch_credits_len = 0;
    err = fd_bincode_uint64_encode(&epoch_credits_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_vote_block_timestamp_encode(&self->latest_timestamp, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_vote_state_decode(fd_vote_state_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_decode(&self->voting_node, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_decode(&self->authorized_withdrawer, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_decode(&self->commission, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->votes = deq_fd_vote_lockout_t_alloc( ctx->allocf, ctx->allocf_arg );
  ulong votes_len;
  err = fd_bincode_uint64_decode(&votes_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if ( votes_len > deq_fd_vote_lockout_t_max(self->votes) ) return FD_BINCODE_ERR_SMALL_DEQUE;
  for (ulong i = 0; i < votes_len; ++i) {
    fd_vote_lockout_t * elem = deq_fd_vote_lockout_t_push_tail_nocopy(self->votes);
    fd_vote_lockout_new(elem);
    err = fd_vote_lockout_decode(elem, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  {
    unsigned char o;
    err = fd_bincode_option_decode(&o, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    if (o) {
      self->saved_root_slot = (ulong*)(*ctx->allocf)(ctx->allocf_arg, 8, sizeof(ulong));
      err = fd_bincode_uint64_decode(self->saved_root_slot, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    } else
      self->saved_root_slot = NULL;
  }
  self->authorized_voters = deq_fd_vote_historical_authorized_voter_t_alloc( ctx->allocf, ctx->allocf_arg );
  ulong authorized_voters_len;
  err = fd_bincode_uint64_decode(&authorized_voters_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if ( authorized_voters_len > deq_fd_vote_historical_authorized_voter_t_max(self->authorized_voters) ) return FD_BINCODE_ERR_SMALL_DEQUE;
  for (ulong i = 0; i < authorized_voters_len; ++i) {
    fd_vote_historical_authorized_voter_t * elem = deq_fd_vote_historical_authorized_voter_t_push_tail_nocopy(self->authorized_voters);
    fd_vote_historical_authorized_voter_new(elem);
    err = fd_vote_historical_authorized_voter_decode(elem, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_vote_prior_voters_decode(&self->prior_voters, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->epoch_credits = deq_fd_vote_epoch_credits_t_alloc( ctx->allocf, ctx->allocf_arg );
  ulong epoch_credits_len;
  err = fd_bincode_uint64_decode(&epoch_credits_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if ( epoch_credits_len > deq_fd_vote_epoch_credits_t_max(self->epoch_credits) ) return FD_BINCODE_ERR_SMALL_DEQUE;
  for (ulong i = 0; i < epoch_credits_len; ++i) {
    fd_vote_epoch_credits_t * elem = deq_fd_vote_epoch_credits_t_push_tail_nocopy(self->epoch_credits);
    fd_vote_epoch_credits_new(elem);
    err = fd_vote_epoch_credits_decode(elem, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_vote_block_timestamp_decode(&self->latest_timestamp, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_state_new(fd_vote_state_t* self) {
  fd_pubkey_new(&self->voting_node);
  fd_pubkey_new(&self->authorized_withdrawer);
  self->votes = NULL;
  self->saved_root_slot = NULL;
  self->authorized_voters = NULL;
  fd_vote_prior_voters_new(&self->prior_voters);
  self->epoch_credits = NULL;
  fd_vote_block_timestamp_new(&self->latest_timestamp);
}
void fd_vote_state_destroy(fd_vote_state_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->voting_node, ctx);
  fd_pubkey_destroy(&self->authorized_withdrawer, ctx);
  if ( self->votes ) {
    for ( deq_fd_vote_lockout_t_iter_t iter = deq_fd_vote_lockout_t_iter_init( self->votes ); !deq_fd_vote_lockout_t_iter_done( self->votes, iter ); iter = deq_fd_vote_lockout_t_iter_next( self->votes, iter ) ) {
      fd_vote_lockout_t * ele = deq_fd_vote_lockout_t_iter_ele( self->votes, iter );
      fd_vote_lockout_destroy(ele, ctx);
    }
    (*ctx->freef)(ctx->freef_arg, deq_fd_vote_lockout_t_delete( deq_fd_vote_lockout_t_leave( self->votes) ) );
    self->votes = NULL;
  }
  if (NULL != self->saved_root_slot) {
    (*ctx->freef)(ctx->freef_arg, self->saved_root_slot);
    self->saved_root_slot = NULL;
  }
  if ( self->authorized_voters ) {
    for ( deq_fd_vote_historical_authorized_voter_t_iter_t iter = deq_fd_vote_historical_authorized_voter_t_iter_init( self->authorized_voters ); !deq_fd_vote_historical_authorized_voter_t_iter_done( self->authorized_voters, iter ); iter = deq_fd_vote_historical_authorized_voter_t_iter_next( self->authorized_voters, iter ) ) {
      fd_vote_historical_authorized_voter_t * ele = deq_fd_vote_historical_authorized_voter_t_iter_ele( self->authorized_voters, iter );
      fd_vote_historical_authorized_voter_destroy(ele, ctx);
    }
    (*ctx->freef)(ctx->freef_arg, deq_fd_vote_historical_authorized_voter_t_delete( deq_fd_vote_historical_authorized_voter_t_leave( self->authorized_voters) ) );
    self->authorized_voters = NULL;
  }
  fd_vote_prior_voters_destroy(&self->prior_voters, ctx);
  if ( self->epoch_credits ) {
    for ( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( self->epoch_credits ); !deq_fd_vote_epoch_credits_t_iter_done( self->epoch_credits, iter ); iter = deq_fd_vote_epoch_credits_t_iter_next( self->epoch_credits, iter ) ) {
      fd_vote_epoch_credits_t * ele = deq_fd_vote_epoch_credits_t_iter_ele( self->epoch_credits, iter );
      fd_vote_epoch_credits_destroy(ele, ctx);
    }
    (*ctx->freef)(ctx->freef_arg, deq_fd_vote_epoch_credits_t_delete( deq_fd_vote_epoch_credits_t_leave( self->epoch_credits) ) );
    self->epoch_credits = NULL;
  }
  fd_vote_block_timestamp_destroy(&self->latest_timestamp, ctx);
}

void fd_vote_state_walk(fd_vote_state_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_vote_state", level++);
  fd_pubkey_walk(&self->voting_node, fun, "voting_node", level + 1);
  fd_pubkey_walk(&self->authorized_withdrawer, fun, "authorized_withdrawer", level + 1);
  fun(&self->commission, "commission", 9, "uchar", level + 1);
  if ( self->votes ) {
    for ( deq_fd_vote_lockout_t_iter_t iter = deq_fd_vote_lockout_t_iter_init( self->votes ); !deq_fd_vote_lockout_t_iter_done( self->votes, iter ); iter = deq_fd_vote_lockout_t_iter_next( self->votes, iter ) ) {
      fd_vote_lockout_t * ele = deq_fd_vote_lockout_t_iter_ele( self->votes, iter );
      fd_vote_lockout_walk(ele, fun, "votes", level + 1);
    }
  }
  fun(self->saved_root_slot, "saved_root_slot", 11, "ulong", level + 1);
  if ( self->authorized_voters ) {
    for ( deq_fd_vote_historical_authorized_voter_t_iter_t iter = deq_fd_vote_historical_authorized_voter_t_iter_init( self->authorized_voters ); !deq_fd_vote_historical_authorized_voter_t_iter_done( self->authorized_voters, iter ); iter = deq_fd_vote_historical_authorized_voter_t_iter_next( self->authorized_voters, iter ) ) {
      fd_vote_historical_authorized_voter_t * ele = deq_fd_vote_historical_authorized_voter_t_iter_ele( self->authorized_voters, iter );
      fd_vote_historical_authorized_voter_walk(ele, fun, "authorized_voters", level + 1);
    }
  }
  fd_vote_prior_voters_walk(&self->prior_voters, fun, "prior_voters", level + 1);
  if ( self->epoch_credits ) {
    for ( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( self->epoch_credits ); !deq_fd_vote_epoch_credits_t_iter_done( self->epoch_credits, iter ); iter = deq_fd_vote_epoch_credits_t_iter_next( self->epoch_credits, iter ) ) {
      fd_vote_epoch_credits_t * ele = deq_fd_vote_epoch_credits_t_iter_ele( self->epoch_credits, iter );
      fd_vote_epoch_credits_walk(ele, fun, "epoch_credits", level + 1);
    }
  }
  fd_vote_block_timestamp_walk(&self->latest_timestamp, fun, "latest_timestamp", level + 1);
  fun(self, name, 33, "fd_vote_state", --level);
}
ulong fd_vote_state_size(fd_vote_state_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->voting_node);
  size += fd_pubkey_size(&self->authorized_withdrawer);
  size += sizeof(char);
  if ( self->votes ) {
    size += sizeof(ulong);
    for ( deq_fd_vote_lockout_t_iter_t iter = deq_fd_vote_lockout_t_iter_init( self->votes ); !deq_fd_vote_lockout_t_iter_done( self->votes, iter ); iter = deq_fd_vote_lockout_t_iter_next( self->votes, iter ) ) {
      fd_vote_lockout_t * ele = deq_fd_vote_lockout_t_iter_ele( self->votes, iter );
      size += fd_vote_lockout_size(ele);
    }
  }
  size += sizeof(char);
  if (NULL !=  self->saved_root_slot) {
    size += sizeof(ulong);
  }
  if ( self->authorized_voters ) {
    size += sizeof(ulong);
    for ( deq_fd_vote_historical_authorized_voter_t_iter_t iter = deq_fd_vote_historical_authorized_voter_t_iter_init( self->authorized_voters ); !deq_fd_vote_historical_authorized_voter_t_iter_done( self->authorized_voters, iter ); iter = deq_fd_vote_historical_authorized_voter_t_iter_next( self->authorized_voters, iter ) ) {
      fd_vote_historical_authorized_voter_t * ele = deq_fd_vote_historical_authorized_voter_t_iter_ele( self->authorized_voters, iter );
      size += fd_vote_historical_authorized_voter_size(ele);
    }
  }
  size += fd_vote_prior_voters_size(&self->prior_voters);
  if ( self->epoch_credits ) {
    size += sizeof(ulong);
    for ( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( self->epoch_credits ); !deq_fd_vote_epoch_credits_t_iter_done( self->epoch_credits, iter ); iter = deq_fd_vote_epoch_credits_t_iter_next( self->epoch_credits, iter ) ) {
      fd_vote_epoch_credits_t * ele = deq_fd_vote_epoch_credits_t_iter_ele( self->epoch_credits, iter );
      size += fd_vote_epoch_credits_size(ele);
    }
  }
  size += fd_vote_block_timestamp_size(&self->latest_timestamp);
  return size;
}

int fd_vote_state_encode(fd_vote_state_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->voting_node, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->authorized_withdrawer, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_encode(&self->commission, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if ( self->votes ) {
    ulong votes_len = deq_fd_vote_lockout_t_cnt(self->votes);
    err = fd_bincode_uint64_encode(&votes_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    for ( deq_fd_vote_lockout_t_iter_t iter = deq_fd_vote_lockout_t_iter_init( self->votes ); !deq_fd_vote_lockout_t_iter_done( self->votes, iter ); iter = deq_fd_vote_lockout_t_iter_next( self->votes, iter ) ) {
      fd_vote_lockout_t * ele = deq_fd_vote_lockout_t_iter_ele( self->votes, iter );
      err = fd_vote_lockout_encode(ele, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else {
    ulong votes_len = 0;
    err = fd_bincode_uint64_encode(&votes_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  if (self->saved_root_slot != NULL) {
    err = fd_bincode_option_encode(1, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    err = fd_bincode_uint64_encode(self->saved_root_slot, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  } else {
    err = fd_bincode_option_encode(0, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  if ( self->authorized_voters ) {
    ulong authorized_voters_len = deq_fd_vote_historical_authorized_voter_t_cnt(self->authorized_voters);
    err = fd_bincode_uint64_encode(&authorized_voters_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    for ( deq_fd_vote_historical_authorized_voter_t_iter_t iter = deq_fd_vote_historical_authorized_voter_t_iter_init( self->authorized_voters ); !deq_fd_vote_historical_authorized_voter_t_iter_done( self->authorized_voters, iter ); iter = deq_fd_vote_historical_authorized_voter_t_iter_next( self->authorized_voters, iter ) ) {
      fd_vote_historical_authorized_voter_t * ele = deq_fd_vote_historical_authorized_voter_t_iter_ele( self->authorized_voters, iter );
      err = fd_vote_historical_authorized_voter_encode(ele, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else {
    ulong authorized_voters_len = 0;
    err = fd_bincode_uint64_encode(&authorized_voters_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_vote_prior_voters_encode(&self->prior_voters, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if ( self->epoch_credits ) {
    ulong epoch_credits_len = deq_fd_vote_epoch_credits_t_cnt(self->epoch_credits);
    err = fd_bincode_uint64_encode(&epoch_credits_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    for ( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( self->epoch_credits ); !deq_fd_vote_epoch_credits_t_iter_done( self->epoch_credits, iter ); iter = deq_fd_vote_epoch_credits_t_iter_next( self->epoch_credits, iter ) ) {
      fd_vote_epoch_credits_t * ele = deq_fd_vote_epoch_credits_t_iter_ele( self->epoch_credits, iter );
      err = fd_vote_epoch_credits_encode(ele, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else {
    ulong epoch_credits_len = 0;
    err = fd_bincode_uint64_encode(&epoch_credits_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_vote_block_timestamp_encode(&self->latest_timestamp, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

FD_FN_PURE uchar fd_vote_state_versioned_is_v0_23_5(fd_vote_state_versioned_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_vote_state_versioned_is_current(fd_vote_state_versioned_t const * self) {
  return self->discriminant == 1;
}
void fd_vote_state_versioned_inner_new(fd_vote_state_versioned_inner_t* self, uint discriminant);
int fd_vote_state_versioned_inner_decode(fd_vote_state_versioned_inner_t* self, uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  fd_vote_state_versioned_inner_new(self, discriminant);
  int err;
  switch (discriminant) {
  case 0: {
    return fd_vote_state_0_23_5_decode(&self->v0_23_5, ctx);
  }
  case 1: {
    return fd_vote_state_decode(&self->current, ctx);
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
int fd_vote_state_versioned_decode(fd_vote_state_versioned_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err = fd_bincode_uint32_decode(&self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_vote_state_versioned_inner_decode(&self->inner, self->discriminant, ctx);
}
void fd_vote_state_versioned_inner_new(fd_vote_state_versioned_inner_t* self, uint discriminant) {
  switch (discriminant) {
  case 0: {
    fd_vote_state_0_23_5_new(&self->v0_23_5);
    break;
  }
  case 1: {
    fd_vote_state_new(&self->current);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_vote_state_versioned_new(fd_vote_state_versioned_t* self) {
  self->discriminant = 0;
  fd_vote_state_versioned_inner_new(&self->inner, self->discriminant);
}
void fd_vote_state_versioned_inner_destroy(fd_vote_state_versioned_inner_t* self, uint discriminant, fd_bincode_destroy_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    fd_vote_state_0_23_5_destroy(&self->v0_23_5, ctx);
    break;
  }
  case 1: {
    fd_vote_state_destroy(&self->current, ctx);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_vote_state_versioned_destroy(fd_vote_state_versioned_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_vote_state_versioned_inner_destroy(&self->inner, self->discriminant, ctx);
}

void fd_vote_state_versioned_walk(fd_vote_state_versioned_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_vote_state_versioned", level++);
  // enum fd_vote_block_timestamp_walk(&self->latest_timestamp, fun, "latest_timestamp", level + 1);
  fun(self, name, 33, "fd_vote_state_versioned", --level);
}
ulong fd_vote_state_versioned_size(fd_vote_state_versioned_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 0: {
    size += fd_vote_state_0_23_5_size(&self->inner.v0_23_5);
    break;
  }
  case 1: {
    size += fd_vote_state_size(&self->inner.current);
    break;
  }
  }
  return size;
}

int fd_vote_state_versioned_inner_encode(fd_vote_state_versioned_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_vote_state_0_23_5_encode(&self->v0_23_5, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 1: {
    err = fd_vote_state_encode(&self->current, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_vote_state_versioned_encode(fd_vote_state_versioned_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode(&self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_vote_state_versioned_inner_encode(&self->inner, self->discriminant, ctx);
}

int fd_vote_state_update_decode(fd_vote_state_update_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode(&self->lockouts_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->lockouts_len != 0) {
    self->lockouts = (fd_vote_lockout_t*)(*ctx->allocf)(ctx->allocf_arg, FD_VOTE_LOCKOUT_ALIGN, FD_VOTE_LOCKOUT_FOOTPRINT*self->lockouts_len);
    for (ulong i = 0; i < self->lockouts_len; ++i) {
      fd_vote_lockout_new(self->lockouts + i);
    }
    for (ulong i = 0; i < self->lockouts_len; ++i) {
      err = fd_vote_lockout_decode(self->lockouts + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else
    self->lockouts = NULL;
  {
    unsigned char o;
    err = fd_bincode_option_decode(&o, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    if (o) {
      self->proposed_root = (ulong*)(*ctx->allocf)(ctx->allocf_arg, 8, sizeof(ulong));
      err = fd_bincode_uint64_decode(self->proposed_root, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    } else
      self->proposed_root = NULL;
  }
  err = fd_hash_decode(&self->hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  {
    unsigned char o;
    err = fd_bincode_option_decode(&o, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    if (o) {
      self->timestamp = (ulong*)(*ctx->allocf)(ctx->allocf_arg, 8, sizeof(ulong));
      err = fd_bincode_uint64_decode(self->timestamp, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    } else
      self->timestamp = NULL;
  }
  return FD_BINCODE_SUCCESS;
}
void fd_vote_state_update_new(fd_vote_state_update_t* self) {
  self->lockouts = NULL;
  self->proposed_root = NULL;
  fd_hash_new(&self->hash);
  self->timestamp = NULL;
}
void fd_vote_state_update_destroy(fd_vote_state_update_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->lockouts) {
    for (ulong i = 0; i < self->lockouts_len; ++i)
      fd_vote_lockout_destroy(self->lockouts + i, ctx);
    (*ctx->freef)(ctx->freef_arg, self->lockouts);
    self->lockouts = NULL;
  }
  if (NULL != self->proposed_root) {
    (*ctx->freef)(ctx->freef_arg, self->proposed_root);
    self->proposed_root = NULL;
  }
  fd_hash_destroy(&self->hash, ctx);
  if (NULL != self->timestamp) {
    (*ctx->freef)(ctx->freef_arg, self->timestamp);
    self->timestamp = NULL;
  }
}

void fd_vote_state_update_walk(fd_vote_state_update_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_vote_state_update", level++);
  if (self->lockouts_len != 0) {
    fun(NULL, NULL, 30, "lockouts", level++);
    for (ulong i = 0; i < self->lockouts_len; ++i)
      fd_vote_lockout_walk(self->lockouts + i, fun, "vote_lockout", level + 1);
    fun(NULL, NULL, 31, "lockouts", --level);
  }
  fun(self->proposed_root, "proposed_root", 11, "ulong", level + 1);
  fd_hash_walk(&self->hash, fun, "hash", level + 1);
  fun(self->timestamp, "timestamp", 11, "ulong", level + 1);
  fun(self, name, 33, "fd_vote_state_update", --level);
}
ulong fd_vote_state_update_size(fd_vote_state_update_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  for (ulong i = 0; i < self->lockouts_len; ++i)
    size += fd_vote_lockout_size(self->lockouts + i);
  size += sizeof(char);
  if (NULL !=  self->proposed_root) {
    size += sizeof(ulong);
  }
  size += fd_hash_size(&self->hash);
  size += sizeof(char);
  if (NULL !=  self->timestamp) {
    size += sizeof(ulong);
  }
  return size;
}

int fd_vote_state_update_encode(fd_vote_state_update_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(&self->lockouts_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->lockouts_len != 0) {
    for (ulong i = 0; i < self->lockouts_len; ++i) {
      err = fd_vote_lockout_encode(self->lockouts + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  if (self->proposed_root != NULL) {
    err = fd_bincode_option_encode(1, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    err = fd_bincode_uint64_encode(self->proposed_root, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  } else {
    err = fd_bincode_option_encode(0, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_hash_encode(&self->hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->timestamp != NULL) {
    err = fd_bincode_option_encode(1, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    err = fd_bincode_uint64_encode(self->timestamp, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  } else {
    err = fd_bincode_option_encode(0, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}

int fd_compact_vote_state_update_decode(fd_compact_vote_state_update_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode(&self->proposed_root, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_compact_u16_decode(&self->lockouts_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->lockouts_len != 0) {
    self->lockouts = (fd_compact_vote_lockout_t*)(*ctx->allocf)(ctx->allocf_arg, FD_COMPACT_VOTE_LOCKOUT_ALIGN, FD_COMPACT_VOTE_LOCKOUT_FOOTPRINT*self->lockouts_len);
    for (ulong i = 0; i < self->lockouts_len; ++i) {
      fd_compact_vote_lockout_new(self->lockouts + i);
    }
    for (ulong i = 0; i < self->lockouts_len; ++i) {
      err = fd_compact_vote_lockout_decode(self->lockouts + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else
    self->lockouts = NULL;
  err = fd_hash_decode(&self->hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  {
    unsigned char o;
    err = fd_bincode_option_decode(&o, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    if (o) {
      self->timestamp = (ulong*)(*ctx->allocf)(ctx->allocf_arg, 8, sizeof(ulong));
      err = fd_bincode_uint64_decode(self->timestamp, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    } else
      self->timestamp = NULL;
  }
  return FD_BINCODE_SUCCESS;
}
void fd_compact_vote_state_update_new(fd_compact_vote_state_update_t* self) {
  self->lockouts = NULL;
  fd_hash_new(&self->hash);
  self->timestamp = NULL;
}
void fd_compact_vote_state_update_destroy(fd_compact_vote_state_update_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->lockouts) {
    for (ulong i = 0; i < self->lockouts_len; ++i)
      fd_compact_vote_lockout_destroy(self->lockouts + i, ctx);
    (*ctx->freef)(ctx->freef_arg, self->lockouts);
    self->lockouts = NULL;
  }
  fd_hash_destroy(&self->hash, ctx);
  if (NULL != self->timestamp) {
    (*ctx->freef)(ctx->freef_arg, self->timestamp);
    self->timestamp = NULL;
  }
}

void fd_compact_vote_state_update_walk(fd_compact_vote_state_update_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_compact_vote_state_update", level++);
  fun(&self->proposed_root, "proposed_root", 11, "ulong", level + 1);
  if (self->lockouts_len != 0) {
    fun(NULL, NULL, 30, "lockouts", level++);
    for (ulong i = 0; i < self->lockouts_len; ++i)
      fd_compact_vote_lockout_walk(self->lockouts + i, fun, "compact_vote_lockout", level + 1);
    fun(NULL, NULL, 31, "lockouts", --level);
  }
  fd_hash_walk(&self->hash, fun, "hash", level + 1);
  fun(self->timestamp, "timestamp", 11, "ulong", level + 1);
  fun(self, name, 33, "fd_compact_vote_state_update", --level);
}
ulong fd_compact_vote_state_update_size(fd_compact_vote_state_update_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  for (ulong i = 0; i < self->lockouts_len; ++i)
    size += fd_compact_vote_lockout_size(self->lockouts + i);
  size += fd_hash_size(&self->hash);
  size += sizeof(char);
  if (NULL !=  self->timestamp) {
    size += sizeof(ulong);
  }
  return size;
}

int fd_compact_vote_state_update_encode(fd_compact_vote_state_update_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(&self->proposed_root, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_compact_u16_encode(&self->lockouts_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->lockouts_len != 0) {
    for (ulong i = 0; i < self->lockouts_len; ++i) {
      err = fd_compact_vote_lockout_encode(self->lockouts + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  err = fd_hash_encode(&self->hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->timestamp != NULL) {
    err = fd_bincode_option_encode(1, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    err = fd_bincode_uint64_encode(self->timestamp, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  } else {
    err = fd_bincode_option_encode(0, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}

int fd_compact_vote_state_update_switch_decode(fd_compact_vote_state_update_switch_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_compact_vote_state_update_decode(&self->compact_vote_state_update, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_decode(&self->hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_compact_vote_state_update_switch_new(fd_compact_vote_state_update_switch_t* self) {
  fd_compact_vote_state_update_new(&self->compact_vote_state_update);
  fd_hash_new(&self->hash);
}
void fd_compact_vote_state_update_switch_destroy(fd_compact_vote_state_update_switch_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_compact_vote_state_update_destroy(&self->compact_vote_state_update, ctx);
  fd_hash_destroy(&self->hash, ctx);
}

void fd_compact_vote_state_update_switch_walk(fd_compact_vote_state_update_switch_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_compact_vote_state_update_switch", level++);
  fd_compact_vote_state_update_walk(&self->compact_vote_state_update, fun, "compact_vote_state_update", level + 1);
  fd_hash_walk(&self->hash, fun, "hash", level + 1);
  fun(self, name, 33, "fd_compact_vote_state_update_switch", --level);
}
ulong fd_compact_vote_state_update_switch_size(fd_compact_vote_state_update_switch_t const * self) {
  ulong size = 0;
  size += fd_compact_vote_state_update_size(&self->compact_vote_state_update);
  size += fd_hash_size(&self->hash);
  return size;
}

int fd_compact_vote_state_update_switch_encode(fd_compact_vote_state_update_switch_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_compact_vote_state_update_encode(&self->compact_vote_state_update, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_encode(&self->hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_slot_history_inner_decode(fd_slot_history_inner_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode(&self->blocks_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->blocks_len != 0) {
    self->blocks = (ulong*)(*ctx->allocf)(ctx->allocf_arg, 8UL, sizeof(ulong)*self->blocks_len);
    for (ulong i = 0; i < self->blocks_len; ++i) {
      err = fd_bincode_uint64_decode(self->blocks + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else
    self->blocks = NULL;
  return FD_BINCODE_SUCCESS;
}
void fd_slot_history_inner_new(fd_slot_history_inner_t* self) {
  self->blocks = NULL;
}
void fd_slot_history_inner_destroy(fd_slot_history_inner_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->blocks) {
    (*ctx->freef)(ctx->freef_arg, self->blocks);
    self->blocks = NULL;
  }
}

void fd_slot_history_inner_walk(fd_slot_history_inner_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_slot_history_inner", level++);
  if (self->blocks_len != 0) {
    fun(NULL, NULL, 30, "blocks", level++);
    for (ulong i = 0; i < self->blocks_len; ++i)
      fun(self->blocks + i, "blocks", 11, "ulong", level + 1);
    fun(NULL, NULL, 31, "blocks", --level);
  }
  fun(self, name, 33, "fd_slot_history_inner", --level);
}
ulong fd_slot_history_inner_size(fd_slot_history_inner_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += self->blocks_len * sizeof(ulong);
  return size;
}

int fd_slot_history_inner_encode(fd_slot_history_inner_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(&self->blocks_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->blocks_len != 0) {
    for (ulong i = 0; i < self->blocks_len; ++i) {
      err = fd_bincode_uint64_encode(self->blocks + i, ctx);
    }
  }
  return FD_BINCODE_SUCCESS;
}

int fd_slot_history_bitvec_decode(fd_slot_history_bitvec_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  {
    unsigned char o;
    err = fd_bincode_option_decode(&o, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    if (o) {
      self->bits = (fd_slot_history_inner_t*)(*ctx->allocf)(ctx->allocf_arg, FD_SLOT_HISTORY_INNER_ALIGN, FD_SLOT_HISTORY_INNER_FOOTPRINT);
      fd_slot_history_inner_new(self->bits);
      err = fd_slot_history_inner_decode(self->bits, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    } else
      self->bits = NULL;
  }
  err = fd_bincode_uint64_decode(&self->len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_slot_history_bitvec_new(fd_slot_history_bitvec_t* self) {
  self->bits = NULL;
}
void fd_slot_history_bitvec_destroy(fd_slot_history_bitvec_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->bits) {
    fd_slot_history_inner_destroy(self->bits, ctx);
    (*ctx->freef)(ctx->freef_arg, self->bits);
    self->bits = NULL;
  }
}

void fd_slot_history_bitvec_walk(fd_slot_history_bitvec_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_slot_history_bitvec", level++);
  // fun(&self->bits, "bits", 16, "option", level + 1);
  fun(&self->len, "len", 11, "ulong", level + 1);
  fun(self, name, 33, "fd_slot_history_bitvec", --level);
}
ulong fd_slot_history_bitvec_size(fd_slot_history_bitvec_t const * self) {
  ulong size = 0;
  size += sizeof(char);
  if (NULL !=  self->bits) {
    size += fd_slot_history_inner_size(self->bits);
  }
  size += sizeof(ulong);
  return size;
}

int fd_slot_history_bitvec_encode(fd_slot_history_bitvec_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  if (self->bits != NULL) {
    err = fd_bincode_option_encode(1, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    err = fd_slot_history_inner_encode(self->bits, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  } else {
    err = fd_bincode_option_encode(0, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_bincode_uint64_encode(&self->len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_slot_history_decode(fd_slot_history_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_slot_history_bitvec_decode(&self->bits, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->next_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_slot_history_new(fd_slot_history_t* self) {
  fd_slot_history_bitvec_new(&self->bits);
}
void fd_slot_history_destroy(fd_slot_history_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_slot_history_bitvec_destroy(&self->bits, ctx);
}

void fd_slot_history_walk(fd_slot_history_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_slot_history", level++);
  fd_slot_history_bitvec_walk(&self->bits, fun, "bits", level + 1);
  fun(&self->next_slot, "next_slot", 11, "ulong", level + 1);
  fun(self, name, 33, "fd_slot_history", --level);
}
ulong fd_slot_history_size(fd_slot_history_t const * self) {
  ulong size = 0;
  size += fd_slot_history_bitvec_size(&self->bits);
  size += sizeof(ulong);
  return size;
}

int fd_slot_history_encode(fd_slot_history_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_slot_history_bitvec_encode(&self->bits, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->next_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_slot_hash_decode(fd_slot_hash_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode(&self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_decode(&self->hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_slot_hash_new(fd_slot_hash_t* self) {
  fd_hash_new(&self->hash);
}
void fd_slot_hash_destroy(fd_slot_hash_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_hash_destroy(&self->hash, ctx);
}

void fd_slot_hash_walk(fd_slot_hash_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_slot_hash", level++);
  fun(&self->slot, "slot", 11, "ulong", level + 1);
  fd_hash_walk(&self->hash, fun, "hash", level + 1);
  fun(self, name, 33, "fd_slot_hash", --level);
}
ulong fd_slot_hash_size(fd_slot_hash_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += fd_hash_size(&self->hash);
  return size;
}

int fd_slot_hash_encode(fd_slot_hash_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(&self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_encode(&self->hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_slot_hashes_decode(fd_slot_hashes_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  self->hashes = deq_fd_slot_hash_t_alloc( ctx->allocf, ctx->allocf_arg );
  ulong hashes_len;
  err = fd_bincode_uint64_decode(&hashes_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if ( hashes_len > deq_fd_slot_hash_t_max(self->hashes) ) return FD_BINCODE_ERR_SMALL_DEQUE;
  for (ulong i = 0; i < hashes_len; ++i) {
    fd_slot_hash_t * elem = deq_fd_slot_hash_t_push_tail_nocopy(self->hashes);
    fd_slot_hash_new(elem);
    err = fd_slot_hash_decode(elem, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
void fd_slot_hashes_new(fd_slot_hashes_t* self) {
  self->hashes = NULL;
}
void fd_slot_hashes_destroy(fd_slot_hashes_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if ( self->hashes ) {
    for ( deq_fd_slot_hash_t_iter_t iter = deq_fd_slot_hash_t_iter_init( self->hashes ); !deq_fd_slot_hash_t_iter_done( self->hashes, iter ); iter = deq_fd_slot_hash_t_iter_next( self->hashes, iter ) ) {
      fd_slot_hash_t * ele = deq_fd_slot_hash_t_iter_ele( self->hashes, iter );
      fd_slot_hash_destroy(ele, ctx);
    }
    (*ctx->freef)(ctx->freef_arg, deq_fd_slot_hash_t_delete( deq_fd_slot_hash_t_leave( self->hashes) ) );
    self->hashes = NULL;
  }
}

void fd_slot_hashes_walk(fd_slot_hashes_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_slot_hashes", level++);
  if ( self->hashes ) {
    for ( deq_fd_slot_hash_t_iter_t iter = deq_fd_slot_hash_t_iter_init( self->hashes ); !deq_fd_slot_hash_t_iter_done( self->hashes, iter ); iter = deq_fd_slot_hash_t_iter_next( self->hashes, iter ) ) {
      fd_slot_hash_t * ele = deq_fd_slot_hash_t_iter_ele( self->hashes, iter );
      fd_slot_hash_walk(ele, fun, "hashes", level + 1);
    }
  }
  fun(self, name, 33, "fd_slot_hashes", --level);
}
ulong fd_slot_hashes_size(fd_slot_hashes_t const * self) {
  ulong size = 0;
  if ( self->hashes ) {
    size += sizeof(ulong);
    for ( deq_fd_slot_hash_t_iter_t iter = deq_fd_slot_hash_t_iter_init( self->hashes ); !deq_fd_slot_hash_t_iter_done( self->hashes, iter ); iter = deq_fd_slot_hash_t_iter_next( self->hashes, iter ) ) {
      fd_slot_hash_t * ele = deq_fd_slot_hash_t_iter_ele( self->hashes, iter );
      size += fd_slot_hash_size(ele);
    }
  }
  return size;
}

int fd_slot_hashes_encode(fd_slot_hashes_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  if ( self->hashes ) {
    ulong hashes_len = deq_fd_slot_hash_t_cnt(self->hashes);
    err = fd_bincode_uint64_encode(&hashes_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    for ( deq_fd_slot_hash_t_iter_t iter = deq_fd_slot_hash_t_iter_init( self->hashes ); !deq_fd_slot_hash_t_iter_done( self->hashes, iter ); iter = deq_fd_slot_hash_t_iter_next( self->hashes, iter ) ) {
      fd_slot_hash_t * ele = deq_fd_slot_hash_t_iter_ele( self->hashes, iter );
      err = fd_slot_hash_encode(ele, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else {
    ulong hashes_len = 0;
    err = fd_bincode_uint64_encode(&hashes_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}

int fd_block_block_hash_entry_decode(fd_block_block_hash_entry_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_hash_decode(&self->blockhash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_fee_calculator_decode(&self->fee_calculator, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_block_block_hash_entry_new(fd_block_block_hash_entry_t* self) {
  fd_hash_new(&self->blockhash);
  fd_fee_calculator_new(&self->fee_calculator);
}
void fd_block_block_hash_entry_destroy(fd_block_block_hash_entry_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_hash_destroy(&self->blockhash, ctx);
  fd_fee_calculator_destroy(&self->fee_calculator, ctx);
}

void fd_block_block_hash_entry_walk(fd_block_block_hash_entry_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_block_block_hash_entry", level++);
  fd_hash_walk(&self->blockhash, fun, "blockhash", level + 1);
  fd_fee_calculator_walk(&self->fee_calculator, fun, "fee_calculator", level + 1);
  fun(self, name, 33, "fd_block_block_hash_entry", --level);
}
ulong fd_block_block_hash_entry_size(fd_block_block_hash_entry_t const * self) {
  ulong size = 0;
  size += fd_hash_size(&self->blockhash);
  size += fd_fee_calculator_size(&self->fee_calculator);
  return size;
}

int fd_block_block_hash_entry_encode(fd_block_block_hash_entry_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_hash_encode(&self->blockhash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_fee_calculator_encode(&self->fee_calculator, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_recent_block_hashes_decode(fd_recent_block_hashes_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  self->hashes = deq_fd_block_block_hash_entry_t_alloc( ctx->allocf, ctx->allocf_arg );
  ulong hashes_len;
  err = fd_bincode_uint64_decode(&hashes_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if ( hashes_len > deq_fd_block_block_hash_entry_t_max(self->hashes) ) return FD_BINCODE_ERR_SMALL_DEQUE;
  for (ulong i = 0; i < hashes_len; ++i) {
    fd_block_block_hash_entry_t * elem = deq_fd_block_block_hash_entry_t_push_tail_nocopy(self->hashes);
    fd_block_block_hash_entry_new(elem);
    err = fd_block_block_hash_entry_decode(elem, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
void fd_recent_block_hashes_new(fd_recent_block_hashes_t* self) {
  self->hashes = NULL;
}
void fd_recent_block_hashes_destroy(fd_recent_block_hashes_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if ( self->hashes ) {
    for ( deq_fd_block_block_hash_entry_t_iter_t iter = deq_fd_block_block_hash_entry_t_iter_init( self->hashes ); !deq_fd_block_block_hash_entry_t_iter_done( self->hashes, iter ); iter = deq_fd_block_block_hash_entry_t_iter_next( self->hashes, iter ) ) {
      fd_block_block_hash_entry_t * ele = deq_fd_block_block_hash_entry_t_iter_ele( self->hashes, iter );
      fd_block_block_hash_entry_destroy(ele, ctx);
    }
    (*ctx->freef)(ctx->freef_arg, deq_fd_block_block_hash_entry_t_delete( deq_fd_block_block_hash_entry_t_leave( self->hashes) ) );
    self->hashes = NULL;
  }
}

void fd_recent_block_hashes_walk(fd_recent_block_hashes_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_recent_block_hashes", level++);
  if ( self->hashes ) {
    for ( deq_fd_block_block_hash_entry_t_iter_t iter = deq_fd_block_block_hash_entry_t_iter_init( self->hashes ); !deq_fd_block_block_hash_entry_t_iter_done( self->hashes, iter ); iter = deq_fd_block_block_hash_entry_t_iter_next( self->hashes, iter ) ) {
      fd_block_block_hash_entry_t * ele = deq_fd_block_block_hash_entry_t_iter_ele( self->hashes, iter );
      fd_block_block_hash_entry_walk(ele, fun, "hashes", level + 1);
    }
  }
  fun(self, name, 33, "fd_recent_block_hashes", --level);
}
ulong fd_recent_block_hashes_size(fd_recent_block_hashes_t const * self) {
  ulong size = 0;
  if ( self->hashes ) {
    size += sizeof(ulong);
    for ( deq_fd_block_block_hash_entry_t_iter_t iter = deq_fd_block_block_hash_entry_t_iter_init( self->hashes ); !deq_fd_block_block_hash_entry_t_iter_done( self->hashes, iter ); iter = deq_fd_block_block_hash_entry_t_iter_next( self->hashes, iter ) ) {
      fd_block_block_hash_entry_t * ele = deq_fd_block_block_hash_entry_t_iter_ele( self->hashes, iter );
      size += fd_block_block_hash_entry_size(ele);
    }
  }
  return size;
}

int fd_recent_block_hashes_encode(fd_recent_block_hashes_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  if ( self->hashes ) {
    ulong hashes_len = deq_fd_block_block_hash_entry_t_cnt(self->hashes);
    err = fd_bincode_uint64_encode(&hashes_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    for ( deq_fd_block_block_hash_entry_t_iter_t iter = deq_fd_block_block_hash_entry_t_iter_init( self->hashes ); !deq_fd_block_block_hash_entry_t_iter_done( self->hashes, iter ); iter = deq_fd_block_block_hash_entry_t_iter_next( self->hashes, iter ) ) {
      fd_block_block_hash_entry_t * ele = deq_fd_block_block_hash_entry_t_iter_ele( self->hashes, iter );
      err = fd_block_block_hash_entry_encode(ele, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else {
    ulong hashes_len = 0;
    err = fd_bincode_uint64_encode(&hashes_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}

int fd_slot_meta_decode(fd_slot_meta_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode(&self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->consumed, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->received, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->first_shred_timestamp, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->last_index, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->parent_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->next_slot_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->next_slot_len != 0) {
    self->next_slot = (ulong*)(*ctx->allocf)(ctx->allocf_arg, 8UL, sizeof(ulong)*self->next_slot_len);
    for (ulong i = 0; i < self->next_slot_len; ++i) {
      err = fd_bincode_uint64_decode(self->next_slot + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else
    self->next_slot = NULL;
  err = fd_bincode_uint8_decode(&self->is_connected, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->entry_end_indexes_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->entry_end_indexes_len != 0) {
    self->entry_end_indexes = (uint*)(*ctx->allocf)(ctx->allocf_arg, 8UL, sizeof(uint)*self->entry_end_indexes_len);
    for (ulong i = 0; i < self->entry_end_indexes_len; ++i) {
      err = fd_bincode_uint32_decode(self->entry_end_indexes + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else
    self->entry_end_indexes = NULL;
  return FD_BINCODE_SUCCESS;
}
void fd_slot_meta_new(fd_slot_meta_t* self) {
  self->next_slot = NULL;
  self->entry_end_indexes = NULL;
}
void fd_slot_meta_destroy(fd_slot_meta_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->next_slot) {
    (*ctx->freef)(ctx->freef_arg, self->next_slot);
    self->next_slot = NULL;
  }
  if (NULL != self->entry_end_indexes) {
    (*ctx->freef)(ctx->freef_arg, self->entry_end_indexes);
    self->entry_end_indexes = NULL;
  }
}

void fd_slot_meta_walk(fd_slot_meta_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_slot_meta", level++);
  fun(&self->slot, "slot", 11, "ulong", level + 1);
  fun(&self->consumed, "consumed", 11, "ulong", level + 1);
  fun(&self->received, "received", 11, "ulong", level + 1);
  fun(&self->first_shred_timestamp, "first_shred_timestamp", 11, "ulong", level + 1);
  fun(&self->last_index, "last_index", 11, "ulong", level + 1);
  fun(&self->parent_slot, "parent_slot", 11, "ulong", level + 1);
  if (self->next_slot_len != 0) {
    fun(NULL, NULL, 30, "next_slot", level++);
    for (ulong i = 0; i < self->next_slot_len; ++i)
      fun(self->next_slot + i, "next_slot", 11, "ulong", level + 1);
    fun(NULL, NULL, 31, "next_slot", --level);
  }
  fun(&self->is_connected, "is_connected", 9, "uchar", level + 1);
  if (self->entry_end_indexes_len != 0) {
    fun(NULL, NULL, 30, "entry_end_indexes", level++);
    for (ulong i = 0; i < self->entry_end_indexes_len; ++i)
      fun(self->entry_end_indexes + i, "entry_end_indexes", 7, "uint", level + 1);
    fun(NULL, NULL, 31, "entry_end_indexes", --level);
  }
  fun(self, name, 33, "fd_slot_meta", --level);
}
ulong fd_slot_meta_size(fd_slot_meta_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += self->next_slot_len * sizeof(ulong);
  size += sizeof(char);
  size += sizeof(ulong);
  size += self->entry_end_indexes_len * sizeof(uint);
  return size;
}

int fd_slot_meta_encode(fd_slot_meta_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(&self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->consumed, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->received, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->first_shred_timestamp, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->last_index, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->parent_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->next_slot_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->next_slot_len != 0) {
    for (ulong i = 0; i < self->next_slot_len; ++i) {
      err = fd_bincode_uint64_encode(self->next_slot + i, ctx);
    }
  }
  err = fd_bincode_uint8_encode(&self->is_connected, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->entry_end_indexes_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->entry_end_indexes_len != 0) {
    for (ulong i = 0; i < self->entry_end_indexes_len; ++i) {
      err = fd_bincode_uint32_encode(self->entry_end_indexes + i, ctx);
    }
  }
  return FD_BINCODE_SUCCESS;
}

int fd_slot_meta_meta_decode(fd_slot_meta_meta_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode(&self->start_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->end_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_slot_meta_meta_new(fd_slot_meta_meta_t* self) {
}
void fd_slot_meta_meta_destroy(fd_slot_meta_meta_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

void fd_slot_meta_meta_walk(fd_slot_meta_meta_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_slot_meta_meta", level++);
  fun(&self->start_slot, "start_slot", 11, "ulong", level + 1);
  fun(&self->end_slot, "end_slot", 11, "ulong", level + 1);
  fun(self, name, 33, "fd_slot_meta_meta", --level);
}
ulong fd_slot_meta_meta_size(fd_slot_meta_meta_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  return size;
}

int fd_slot_meta_meta_encode(fd_slot_meta_meta_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(&self->start_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->end_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_clock_timestamp_vote_decode(fd_clock_timestamp_vote_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_decode(&self->pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode((unsigned long *) &self->timestamp, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_clock_timestamp_vote_new(fd_clock_timestamp_vote_t* self) {
  fd_pubkey_new(&self->pubkey);
}
void fd_clock_timestamp_vote_destroy(fd_clock_timestamp_vote_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->pubkey, ctx);
}

void fd_clock_timestamp_vote_walk(fd_clock_timestamp_vote_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_clock_timestamp_vote", level++);
  fd_pubkey_walk(&self->pubkey, fun, "pubkey", level + 1);
  fun(&self->timestamp, "timestamp", 6, "long", level + 1);
  fun(&self->slot, "slot", 11, "ulong", level + 1);
  fun(self, name, 33, "fd_clock_timestamp_vote", --level);
}
ulong fd_clock_timestamp_vote_size(fd_clock_timestamp_vote_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->pubkey);
  size += sizeof(long);
  size += sizeof(ulong);
  return size;
}

int fd_clock_timestamp_vote_encode(fd_clock_timestamp_vote_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode((unsigned long *) &self->timestamp, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_clock_timestamp_votes_decode(fd_clock_timestamp_votes_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  self->votes = deq_fd_clock_timestamp_vote_t_alloc( ctx->allocf, ctx->allocf_arg );
  ulong votes_len;
  err = fd_bincode_uint64_decode(&votes_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if ( votes_len > deq_fd_clock_timestamp_vote_t_max(self->votes) ) return FD_BINCODE_ERR_SMALL_DEQUE;
  for (ulong i = 0; i < votes_len; ++i) {
    fd_clock_timestamp_vote_t * elem = deq_fd_clock_timestamp_vote_t_push_tail_nocopy(self->votes);
    fd_clock_timestamp_vote_new(elem);
    err = fd_clock_timestamp_vote_decode(elem, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
void fd_clock_timestamp_votes_new(fd_clock_timestamp_votes_t* self) {
  self->votes = NULL;
}
void fd_clock_timestamp_votes_destroy(fd_clock_timestamp_votes_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if ( self->votes ) {
    for ( deq_fd_clock_timestamp_vote_t_iter_t iter = deq_fd_clock_timestamp_vote_t_iter_init( self->votes ); !deq_fd_clock_timestamp_vote_t_iter_done( self->votes, iter ); iter = deq_fd_clock_timestamp_vote_t_iter_next( self->votes, iter ) ) {
      fd_clock_timestamp_vote_t * ele = deq_fd_clock_timestamp_vote_t_iter_ele( self->votes, iter );
      fd_clock_timestamp_vote_destroy(ele, ctx);
    }
    (*ctx->freef)(ctx->freef_arg, deq_fd_clock_timestamp_vote_t_delete( deq_fd_clock_timestamp_vote_t_leave( self->votes) ) );
    self->votes = NULL;
  }
}

void fd_clock_timestamp_votes_walk(fd_clock_timestamp_votes_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_clock_timestamp_votes", level++);
  if ( self->votes ) {
    for ( deq_fd_clock_timestamp_vote_t_iter_t iter = deq_fd_clock_timestamp_vote_t_iter_init( self->votes ); !deq_fd_clock_timestamp_vote_t_iter_done( self->votes, iter ); iter = deq_fd_clock_timestamp_vote_t_iter_next( self->votes, iter ) ) {
      fd_clock_timestamp_vote_t * ele = deq_fd_clock_timestamp_vote_t_iter_ele( self->votes, iter );
      fd_clock_timestamp_vote_walk(ele, fun, "votes", level + 1);
    }
  }
  fun(self, name, 33, "fd_clock_timestamp_votes", --level);
}
ulong fd_clock_timestamp_votes_size(fd_clock_timestamp_votes_t const * self) {
  ulong size = 0;
  if ( self->votes ) {
    size += sizeof(ulong);
    for ( deq_fd_clock_timestamp_vote_t_iter_t iter = deq_fd_clock_timestamp_vote_t_iter_init( self->votes ); !deq_fd_clock_timestamp_vote_t_iter_done( self->votes, iter ); iter = deq_fd_clock_timestamp_vote_t_iter_next( self->votes, iter ) ) {
      fd_clock_timestamp_vote_t * ele = deq_fd_clock_timestamp_vote_t_iter_ele( self->votes, iter );
      size += fd_clock_timestamp_vote_size(ele);
    }
  }
  return size;
}

int fd_clock_timestamp_votes_encode(fd_clock_timestamp_votes_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  if ( self->votes ) {
    ulong votes_len = deq_fd_clock_timestamp_vote_t_cnt(self->votes);
    err = fd_bincode_uint64_encode(&votes_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    for ( deq_fd_clock_timestamp_vote_t_iter_t iter = deq_fd_clock_timestamp_vote_t_iter_init( self->votes ); !deq_fd_clock_timestamp_vote_t_iter_done( self->votes, iter ); iter = deq_fd_clock_timestamp_vote_t_iter_next( self->votes, iter ) ) {
      fd_clock_timestamp_vote_t * ele = deq_fd_clock_timestamp_vote_t_iter_ele( self->votes, iter );
      err = fd_clock_timestamp_vote_encode(ele, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else {
    ulong votes_len = 0;
    err = fd_bincode_uint64_encode(&votes_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}

int fd_sysvar_fees_decode(fd_sysvar_fees_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_fee_calculator_decode(&self->fee_calculator, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_sysvar_fees_new(fd_sysvar_fees_t* self) {
  fd_fee_calculator_new(&self->fee_calculator);
}
void fd_sysvar_fees_destroy(fd_sysvar_fees_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_fee_calculator_destroy(&self->fee_calculator, ctx);
}

void fd_sysvar_fees_walk(fd_sysvar_fees_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_sysvar_fees", level++);
  fd_fee_calculator_walk(&self->fee_calculator, fun, "fee_calculator", level + 1);
  fun(self, name, 33, "fd_sysvar_fees", --level);
}
ulong fd_sysvar_fees_size(fd_sysvar_fees_t const * self) {
  ulong size = 0;
  size += fd_fee_calculator_size(&self->fee_calculator);
  return size;
}

int fd_sysvar_fees_encode(fd_sysvar_fees_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_fee_calculator_encode(&self->fee_calculator, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_config_keys_pair_decode(fd_config_keys_pair_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_decode(&self->key, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_decode(&self->signer, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_config_keys_pair_new(fd_config_keys_pair_t* self) {
  fd_pubkey_new(&self->key);
}
void fd_config_keys_pair_destroy(fd_config_keys_pair_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->key, ctx);
}

void fd_config_keys_pair_walk(fd_config_keys_pair_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_config_keys_pair", level++);
  fd_pubkey_walk(&self->key, fun, "key", level + 1);
  fun(&self->signer, "signer", 9, "uchar", level + 1);
  fun(self, name, 33, "fd_config_keys_pair", --level);
}
ulong fd_config_keys_pair_size(fd_config_keys_pair_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->key);
  size += sizeof(char);
  return size;
}

int fd_config_keys_pair_encode(fd_config_keys_pair_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->key, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_encode(&self->signer, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_stake_config_decode(fd_stake_config_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_compact_u16_decode(&self->config_keys_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->config_keys_len != 0) {
    self->config_keys = (fd_config_keys_pair_t*)(*ctx->allocf)(ctx->allocf_arg, FD_CONFIG_KEYS_PAIR_ALIGN, FD_CONFIG_KEYS_PAIR_FOOTPRINT*self->config_keys_len);
    for (ulong i = 0; i < self->config_keys_len; ++i) {
      fd_config_keys_pair_new(self->config_keys + i);
    }
    for (ulong i = 0; i < self->config_keys_len; ++i) {
      err = fd_config_keys_pair_decode(self->config_keys + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else
    self->config_keys = NULL;
  err = fd_bincode_double_decode(&self->warmup_cooldown_rate, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_decode(&self->slash_penalty, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_stake_config_new(fd_stake_config_t* self) {
  self->config_keys = NULL;
}
void fd_stake_config_destroy(fd_stake_config_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->config_keys) {
    for (ulong i = 0; i < self->config_keys_len; ++i)
      fd_config_keys_pair_destroy(self->config_keys + i, ctx);
    (*ctx->freef)(ctx->freef_arg, self->config_keys);
    self->config_keys = NULL;
  }
}

void fd_stake_config_walk(fd_stake_config_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_stake_config", level++);
  if (self->config_keys_len != 0) {
    fun(NULL, NULL, 30, "config_keys", level++);
    for (ulong i = 0; i < self->config_keys_len; ++i)
      fd_config_keys_pair_walk(self->config_keys + i, fun, "config_keys_pair", level + 1);
    fun(NULL, NULL, 31, "config_keys", --level);
  }
  fun(&self->warmup_cooldown_rate, "warmup_cooldown_rate", 5, "double", level + 1);
  fun(&self->slash_penalty, "slash_penalty", 9, "uchar", level + 1);
  fun(self, name, 33, "fd_stake_config", --level);
}
ulong fd_stake_config_size(fd_stake_config_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  for (ulong i = 0; i < self->config_keys_len; ++i)
    size += fd_config_keys_pair_size(self->config_keys + i);
  size += sizeof(double);
  size += sizeof(char);
  return size;
}

int fd_stake_config_encode(fd_stake_config_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_compact_u16_encode(&self->config_keys_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->config_keys_len != 0) {
    for (ulong i = 0; i < self->config_keys_len; ++i) {
      err = fd_config_keys_pair_encode(self->config_keys + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  err = fd_bincode_double_encode(&self->warmup_cooldown_rate, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_encode(&self->slash_penalty, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_firedancer_banks_decode(fd_firedancer_banks_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_deserializable_versioned_bank_decode(&self->solana_bank, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_stakes_decode(&self->stakes, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_recent_block_hashes_decode(&self->recent_block_hashes, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_clock_timestamp_votes_decode(&self->timestamp_votes, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_firedancer_banks_new(fd_firedancer_banks_t* self) {
  fd_deserializable_versioned_bank_new(&self->solana_bank);
  fd_stakes_new(&self->stakes);
  fd_recent_block_hashes_new(&self->recent_block_hashes);
  fd_clock_timestamp_votes_new(&self->timestamp_votes);
}
void fd_firedancer_banks_destroy(fd_firedancer_banks_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_deserializable_versioned_bank_destroy(&self->solana_bank, ctx);
  fd_stakes_destroy(&self->stakes, ctx);
  fd_recent_block_hashes_destroy(&self->recent_block_hashes, ctx);
  fd_clock_timestamp_votes_destroy(&self->timestamp_votes, ctx);
}

void fd_firedancer_banks_walk(fd_firedancer_banks_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_firedancer_banks", level++);
  fd_deserializable_versioned_bank_walk(&self->solana_bank, fun, "solana_bank", level + 1);
  fd_stakes_walk(&self->stakes, fun, "stakes", level + 1);
  fd_recent_block_hashes_walk(&self->recent_block_hashes, fun, "recent_block_hashes", level + 1);
  fd_clock_timestamp_votes_walk(&self->timestamp_votes, fun, "timestamp_votes", level + 1);
  fun(self, name, 33, "fd_firedancer_banks", --level);
}
ulong fd_firedancer_banks_size(fd_firedancer_banks_t const * self) {
  ulong size = 0;
  size += fd_deserializable_versioned_bank_size(&self->solana_bank);
  size += fd_stakes_size(&self->stakes);
  size += fd_recent_block_hashes_size(&self->recent_block_hashes);
  size += fd_clock_timestamp_votes_size(&self->timestamp_votes);
  return size;
}

int fd_firedancer_banks_encode(fd_firedancer_banks_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_deserializable_versioned_bank_encode(&self->solana_bank, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_stakes_encode(&self->stakes, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_recent_block_hashes_encode(&self->recent_block_hashes, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_clock_timestamp_votes_encode(&self->timestamp_votes, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_vote_decode(fd_vote_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  self->slots = deq_ulong_alloc( ctx->allocf, ctx->allocf_arg );
  ulong slots_len;
  err = fd_bincode_uint64_decode(&slots_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if ( slots_len > deq_ulong_max(self->slots) ) return FD_BINCODE_ERR_SMALL_DEQUE;
  for (ulong i = 0; i < slots_len; ++i) {
    ulong * elem = deq_ulong_push_tail_nocopy(self->slots);
    err = fd_bincode_uint64_decode(elem, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_hash_decode(&self->hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  {
    unsigned char o;
    err = fd_bincode_option_decode(&o, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    if (o) {
      self->timestamp = (ulong*)(*ctx->allocf)(ctx->allocf_arg, 8, sizeof(ulong));
      err = fd_bincode_uint64_decode(self->timestamp, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    } else
      self->timestamp = NULL;
  }
  return FD_BINCODE_SUCCESS;
}
void fd_vote_new(fd_vote_t* self) {
  self->slots = NULL;
  fd_hash_new(&self->hash);
  self->timestamp = NULL;
}
void fd_vote_destroy(fd_vote_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if ( self->slots ) {
    (*ctx->freef)(ctx->freef_arg, deq_ulong_delete( deq_ulong_leave( self->slots) ) );
    self->slots = NULL;
  }
  fd_hash_destroy(&self->hash, ctx);
  if (NULL != self->timestamp) {
    (*ctx->freef)(ctx->freef_arg, self->timestamp);
    self->timestamp = NULL;
  }
}

void fd_vote_walk(fd_vote_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_vote", level++);
  if ( self->slots ) {
    for ( deq_ulong_iter_t iter = deq_ulong_iter_init( self->slots ); !deq_ulong_iter_done( self->slots, iter ); iter = deq_ulong_iter_next( self->slots, iter ) ) {
      ulong * ele = deq_ulong_iter_ele( self->slots, iter );
      //fd_bincode_uint64_walk(ele, ctx);
    }
  }
  fd_hash_walk(&self->hash, fun, "hash", level + 1);
  fun(self->timestamp, "timestamp", 11, "ulong", level + 1);
  fun(self, name, 33, "fd_vote", --level);
}
ulong fd_vote_size(fd_vote_t const * self) {
  ulong size = 0;
  if ( self->slots ) {
    size += sizeof(ulong);
    size += deq_ulong_cnt(self->slots) * sizeof(ulong);
  }
  size += fd_hash_size(&self->hash);
  size += sizeof(char);
  if (NULL !=  self->timestamp) {
    size += sizeof(ulong);
  }
  return size;
}

int fd_vote_encode(fd_vote_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  if ( self->slots ) {
    ulong slots_len = deq_ulong_cnt(self->slots);
    err = fd_bincode_uint64_encode(&slots_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    for ( deq_ulong_iter_t iter = deq_ulong_iter_init( self->slots ); !deq_ulong_iter_done( self->slots, iter ); iter = deq_ulong_iter_next( self->slots, iter ) ) {
      ulong * ele = deq_ulong_iter_ele( self->slots, iter );
      err = fd_bincode_uint64_encode(ele, ctx);
    }
  } else {
    ulong slots_len = 0;
    err = fd_bincode_uint64_encode(&slots_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_hash_encode(&self->hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->timestamp != NULL) {
    err = fd_bincode_option_encode(1, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    err = fd_bincode_uint64_encode(self->timestamp, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  } else {
    err = fd_bincode_option_encode(0, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}

int fd_vote_init_decode(fd_vote_init_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_decode(&self->node_pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_decode(&self->authorized_voter, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_decode(&self->authorized_withdrawer, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_decode(&self->commission, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_init_new(fd_vote_init_t* self) {
  fd_pubkey_new(&self->node_pubkey);
  fd_pubkey_new(&self->authorized_voter);
  fd_pubkey_new(&self->authorized_withdrawer);
}
void fd_vote_init_destroy(fd_vote_init_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->node_pubkey, ctx);
  fd_pubkey_destroy(&self->authorized_voter, ctx);
  fd_pubkey_destroy(&self->authorized_withdrawer, ctx);
}

void fd_vote_init_walk(fd_vote_init_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_vote_init", level++);
  fd_pubkey_walk(&self->node_pubkey, fun, "node_pubkey", level + 1);
  fd_pubkey_walk(&self->authorized_voter, fun, "authorized_voter", level + 1);
  fd_pubkey_walk(&self->authorized_withdrawer, fun, "authorized_withdrawer", level + 1);
  fun(&self->commission, "commission", 9, "uchar", level + 1);
  fun(self, name, 33, "fd_vote_init", --level);
}
ulong fd_vote_init_size(fd_vote_init_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->node_pubkey);
  size += fd_pubkey_size(&self->authorized_voter);
  size += fd_pubkey_size(&self->authorized_withdrawer);
  size += sizeof(char);
  return size;
}

int fd_vote_init_encode(fd_vote_init_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->node_pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->authorized_voter, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->authorized_withdrawer, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_encode(&self->commission, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

FD_FN_PURE uchar fd_vote_authorize_is_voter(fd_vote_authorize_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_vote_authorize_is_withdrawer(fd_vote_authorize_t const * self) {
  return self->discriminant == 1;
}
void fd_vote_authorize_inner_new(fd_vote_authorize_inner_t* self, uint discriminant);
int fd_vote_authorize_inner_decode(fd_vote_authorize_inner_t* self, uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  fd_vote_authorize_inner_new(self, discriminant);
  int err;
  switch (discriminant) {
  case 0: {
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
int fd_vote_authorize_decode(fd_vote_authorize_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err = fd_bincode_uint32_decode(&self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_vote_authorize_inner_decode(&self->inner, self->discriminant, ctx);
}
void fd_vote_authorize_inner_new(fd_vote_authorize_inner_t* self, uint discriminant) {
  switch (discriminant) {
  case 0: {
    break;
  }
  case 1: {
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_vote_authorize_new(fd_vote_authorize_t* self) {
  self->discriminant = 0;
  fd_vote_authorize_inner_new(&self->inner, self->discriminant);
}
void fd_vote_authorize_inner_destroy(fd_vote_authorize_inner_t* self, uint discriminant, fd_bincode_destroy_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    break;
  }
  case 1: {
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_vote_authorize_destroy(fd_vote_authorize_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_vote_authorize_inner_destroy(&self->inner, self->discriminant, ctx);
}

void fd_vote_authorize_walk(fd_vote_authorize_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_vote_authorize", level++);
  // enum fd_unsigned char_walk(&self->commission, fun, "commission", level + 1);
  fun(self, name, 33, "fd_vote_authorize", --level);
}
ulong fd_vote_authorize_size(fd_vote_authorize_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  }
  return size;
}

int fd_vote_authorize_inner_encode(fd_vote_authorize_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx) {
  return FD_BINCODE_SUCCESS;
}
int fd_vote_authorize_encode(fd_vote_authorize_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode(&self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_vote_authorize_inner_encode(&self->inner, self->discriminant, ctx);
}

int fd_vote_authorize_pubkey_decode(fd_vote_authorize_pubkey_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_decode(&self->pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_vote_authorize_decode(&self->vote_authorize, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_authorize_pubkey_new(fd_vote_authorize_pubkey_t* self) {
  fd_pubkey_new(&self->pubkey);
  fd_vote_authorize_new(&self->vote_authorize);
}
void fd_vote_authorize_pubkey_destroy(fd_vote_authorize_pubkey_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->pubkey, ctx);
  fd_vote_authorize_destroy(&self->vote_authorize, ctx);
}

void fd_vote_authorize_pubkey_walk(fd_vote_authorize_pubkey_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_vote_authorize_pubkey", level++);
  fd_pubkey_walk(&self->pubkey, fun, "pubkey", level + 1);
  fd_vote_authorize_walk(&self->vote_authorize, fun, "vote_authorize", level + 1);
  fun(self, name, 33, "fd_vote_authorize_pubkey", --level);
}
ulong fd_vote_authorize_pubkey_size(fd_vote_authorize_pubkey_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->pubkey);
  size += fd_vote_authorize_size(&self->vote_authorize);
  return size;
}

int fd_vote_authorize_pubkey_encode(fd_vote_authorize_pubkey_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_vote_authorize_encode(&self->vote_authorize, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_vote_switch_decode(fd_vote_switch_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_vote_decode(&self->vote, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_decode(&self->hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_switch_new(fd_vote_switch_t* self) {
  fd_vote_new(&self->vote);
  fd_hash_new(&self->hash);
}
void fd_vote_switch_destroy(fd_vote_switch_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_vote_destroy(&self->vote, ctx);
  fd_hash_destroy(&self->hash, ctx);
}

void fd_vote_switch_walk(fd_vote_switch_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_vote_switch", level++);
  fd_vote_walk(&self->vote, fun, "vote", level + 1);
  fd_hash_walk(&self->hash, fun, "hash", level + 1);
  fun(self, name, 33, "fd_vote_switch", --level);
}
ulong fd_vote_switch_size(fd_vote_switch_t const * self) {
  ulong size = 0;
  size += fd_vote_size(&self->vote);
  size += fd_hash_size(&self->hash);
  return size;
}

int fd_vote_switch_encode(fd_vote_switch_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_vote_encode(&self->vote, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_encode(&self->hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_update_vote_state_switch_decode(fd_update_vote_state_switch_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_vote_state_update_decode(&self->vote_state_update, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_decode(&self->hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_update_vote_state_switch_new(fd_update_vote_state_switch_t* self) {
  fd_vote_state_update_new(&self->vote_state_update);
  fd_hash_new(&self->hash);
}
void fd_update_vote_state_switch_destroy(fd_update_vote_state_switch_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_vote_state_update_destroy(&self->vote_state_update, ctx);
  fd_hash_destroy(&self->hash, ctx);
}

void fd_update_vote_state_switch_walk(fd_update_vote_state_switch_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_update_vote_state_switch", level++);
  fd_vote_state_update_walk(&self->vote_state_update, fun, "vote_state_update", level + 1);
  fd_hash_walk(&self->hash, fun, "hash", level + 1);
  fun(self, name, 33, "fd_update_vote_state_switch", --level);
}
ulong fd_update_vote_state_switch_size(fd_update_vote_state_switch_t const * self) {
  ulong size = 0;
  size += fd_vote_state_update_size(&self->vote_state_update);
  size += fd_hash_size(&self->hash);
  return size;
}

int fd_update_vote_state_switch_encode(fd_update_vote_state_switch_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_vote_state_update_encode(&self->vote_state_update, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_encode(&self->hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_vote_authorize_with_seed_args_decode(fd_vote_authorize_with_seed_args_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_vote_authorize_decode(&self->authorization_type, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_decode(&self->current_authority_derived_key_owner, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong slen;
  err = fd_bincode_uint64_decode(&slen, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->current_authority_derived_key_seed = (char*)(*ctx->allocf)(ctx->allocf_arg, 1, slen + 1);
  err = fd_bincode_bytes_decode((uchar *) self->current_authority_derived_key_seed, slen, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->current_authority_derived_key_seed[slen] = '\0';
  err = fd_pubkey_decode(&self->new_authority, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_authorize_with_seed_args_new(fd_vote_authorize_with_seed_args_t* self) {
  fd_vote_authorize_new(&self->authorization_type);
  fd_pubkey_new(&self->current_authority_derived_key_owner);
  self->current_authority_derived_key_seed = NULL;
  fd_pubkey_new(&self->new_authority);
}
void fd_vote_authorize_with_seed_args_destroy(fd_vote_authorize_with_seed_args_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_vote_authorize_destroy(&self->authorization_type, ctx);
  fd_pubkey_destroy(&self->current_authority_derived_key_owner, ctx);
  if (NULL != self->current_authority_derived_key_seed) {
    (*ctx->freef)(ctx->freef_arg, self->current_authority_derived_key_seed);
    self->current_authority_derived_key_seed = NULL;
  }
  fd_pubkey_destroy(&self->new_authority, ctx);
}

void fd_vote_authorize_with_seed_args_walk(fd_vote_authorize_with_seed_args_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_vote_authorize_with_seed_args", level++);
  fd_vote_authorize_walk(&self->authorization_type, fun, "authorization_type", level + 1);
  fd_pubkey_walk(&self->current_authority_derived_key_owner, fun, "current_authority_derived_key_owner", level + 1);
  fun(self->current_authority_derived_key_seed, "current_authority_derived_key_seed", 2, "char*", level + 1);
  fd_pubkey_walk(&self->new_authority, fun, "new_authority", level + 1);
  fun(self, name, 33, "fd_vote_authorize_with_seed_args", --level);
}
ulong fd_vote_authorize_with_seed_args_size(fd_vote_authorize_with_seed_args_t const * self) {
  ulong size = 0;
  size += fd_vote_authorize_size(&self->authorization_type);
  size += fd_pubkey_size(&self->current_authority_derived_key_owner);
  size += sizeof(ulong) + strlen(self->current_authority_derived_key_seed);
  size += fd_pubkey_size(&self->new_authority);
  return size;
}

int fd_vote_authorize_with_seed_args_encode(fd_vote_authorize_with_seed_args_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_vote_authorize_encode(&self->authorization_type, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->current_authority_derived_key_owner, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong slen = strlen((char *) self->current_authority_derived_key_seed);
  err = fd_bincode_uint64_encode(&slen, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_bytes_encode((uchar *) self->current_authority_derived_key_seed, slen, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->new_authority, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_vote_authorize_checked_with_seed_args_decode(fd_vote_authorize_checked_with_seed_args_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_vote_authorize_decode(&self->authorization_type, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_decode(&self->current_authority_derived_key_owner, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong slen;
  err = fd_bincode_uint64_decode(&slen, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->current_authority_derived_key_seed = (char*)(*ctx->allocf)(ctx->allocf_arg, 1, slen + 1);
  err = fd_bincode_bytes_decode((uchar *) self->current_authority_derived_key_seed, slen, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->current_authority_derived_key_seed[slen] = '\0';
  return FD_BINCODE_SUCCESS;
}
void fd_vote_authorize_checked_with_seed_args_new(fd_vote_authorize_checked_with_seed_args_t* self) {
  fd_vote_authorize_new(&self->authorization_type);
  fd_pubkey_new(&self->current_authority_derived_key_owner);
  self->current_authority_derived_key_seed = NULL;
}
void fd_vote_authorize_checked_with_seed_args_destroy(fd_vote_authorize_checked_with_seed_args_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_vote_authorize_destroy(&self->authorization_type, ctx);
  fd_pubkey_destroy(&self->current_authority_derived_key_owner, ctx);
  if (NULL != self->current_authority_derived_key_seed) {
    (*ctx->freef)(ctx->freef_arg, self->current_authority_derived_key_seed);
    self->current_authority_derived_key_seed = NULL;
  }
}

void fd_vote_authorize_checked_with_seed_args_walk(fd_vote_authorize_checked_with_seed_args_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_vote_authorize_checked_with_seed_args", level++);
  fd_vote_authorize_walk(&self->authorization_type, fun, "authorization_type", level + 1);
  fd_pubkey_walk(&self->current_authority_derived_key_owner, fun, "current_authority_derived_key_owner", level + 1);
  fun(self->current_authority_derived_key_seed, "current_authority_derived_key_seed", 2, "char*", level + 1);
  fun(self, name, 33, "fd_vote_authorize_checked_with_seed_args", --level);
}
ulong fd_vote_authorize_checked_with_seed_args_size(fd_vote_authorize_checked_with_seed_args_t const * self) {
  ulong size = 0;
  size += fd_vote_authorize_size(&self->authorization_type);
  size += fd_pubkey_size(&self->current_authority_derived_key_owner);
  size += sizeof(ulong) + strlen(self->current_authority_derived_key_seed);
  return size;
}

int fd_vote_authorize_checked_with_seed_args_encode(fd_vote_authorize_checked_with_seed_args_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_vote_authorize_encode(&self->authorization_type, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->current_authority_derived_key_owner, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong slen = strlen((char *) self->current_authority_derived_key_seed);
  err = fd_bincode_uint64_encode(&slen, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_bytes_encode((uchar *) self->current_authority_derived_key_seed, slen, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

FD_FN_PURE uchar fd_vote_instruction_is_initialize_account(fd_vote_instruction_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_vote_instruction_is_authorize(fd_vote_instruction_t const * self) {
  return self->discriminant == 1;
}
FD_FN_PURE uchar fd_vote_instruction_is_vote(fd_vote_instruction_t const * self) {
  return self->discriminant == 2;
}
FD_FN_PURE uchar fd_vote_instruction_is_withdraw(fd_vote_instruction_t const * self) {
  return self->discriminant == 3;
}
FD_FN_PURE uchar fd_vote_instruction_is_update_validator_identity(fd_vote_instruction_t const * self) {
  return self->discriminant == 4;
}
FD_FN_PURE uchar fd_vote_instruction_is_update_commission(fd_vote_instruction_t const * self) {
  return self->discriminant == 5;
}
FD_FN_PURE uchar fd_vote_instruction_is_vote_switch(fd_vote_instruction_t const * self) {
  return self->discriminant == 6;
}
FD_FN_PURE uchar fd_vote_instruction_is_authorize_checked(fd_vote_instruction_t const * self) {
  return self->discriminant == 7;
}
FD_FN_PURE uchar fd_vote_instruction_is_update_vote_state(fd_vote_instruction_t const * self) {
  return self->discriminant == 8;
}
FD_FN_PURE uchar fd_vote_instruction_is_update_vote_state_switch(fd_vote_instruction_t const * self) {
  return self->discriminant == 9;
}
FD_FN_PURE uchar fd_vote_instruction_is_authorize_with_seed(fd_vote_instruction_t const * self) {
  return self->discriminant == 10;
}
FD_FN_PURE uchar fd_vote_instruction_is_authorize_checked_with_seed(fd_vote_instruction_t const * self) {
  return self->discriminant == 11;
}
FD_FN_PURE uchar fd_vote_instruction_is_compact_update_vote_state(fd_vote_instruction_t const * self) {
  return self->discriminant == 12;
}
FD_FN_PURE uchar fd_vote_instruction_is_compact_update_vote_state_switch(fd_vote_instruction_t const * self) {
  return self->discriminant == 13;
}
void fd_vote_instruction_inner_new(fd_vote_instruction_inner_t* self, uint discriminant);
int fd_vote_instruction_inner_decode(fd_vote_instruction_inner_t* self, uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  fd_vote_instruction_inner_new(self, discriminant);
  int err;
  switch (discriminant) {
  case 0: {
    return fd_vote_init_decode(&self->initialize_account, ctx);
  }
  case 1: {
    return fd_vote_authorize_pubkey_decode(&self->authorize, ctx);
  }
  case 2: {
    return fd_vote_decode(&self->vote, ctx);
  }
  case 3: {
    err = fd_bincode_uint64_decode(&self->withdraw, ctx);
  if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 4: {
    return FD_BINCODE_SUCCESS;
  }
  case 5: {
    err = fd_bincode_uint8_decode(&self->update_commission, ctx);
  if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 6: {
    return fd_vote_switch_decode(&self->vote_switch, ctx);
  }
  case 7: {
    return fd_vote_authorize_decode(&self->authorize_checked, ctx);
  }
  case 8: {
    return fd_vote_state_update_decode(&self->update_vote_state, ctx);
  }
  case 9: {
    return fd_update_vote_state_switch_decode(&self->update_vote_state_switch, ctx);
  }
  case 10: {
    return fd_vote_authorize_with_seed_args_decode(&self->authorize_with_seed, ctx);
  }
  case 11: {
    return fd_vote_authorize_checked_with_seed_args_decode(&self->authorize_checked_with_seed, ctx);
  }
  case 12: {
    return fd_compact_vote_state_update_decode(&self->compact_update_vote_state, ctx);
  }
  case 13: {
    return fd_compact_vote_state_update_switch_decode(&self->compact_update_vote_state_switch, ctx);
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
int fd_vote_instruction_decode(fd_vote_instruction_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err = fd_bincode_uint32_decode(&self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_vote_instruction_inner_decode(&self->inner, self->discriminant, ctx);
}
void fd_vote_instruction_inner_new(fd_vote_instruction_inner_t* self, uint discriminant) {
  switch (discriminant) {
  case 0: {
    fd_vote_init_new(&self->initialize_account);
    break;
  }
  case 1: {
    fd_vote_authorize_pubkey_new(&self->authorize);
    break;
  }
  case 2: {
    fd_vote_new(&self->vote);
    break;
  }
  case 3: {
    break;
  }
  case 4: {
    break;
  }
  case 5: {
    break;
  }
  case 6: {
    fd_vote_switch_new(&self->vote_switch);
    break;
  }
  case 7: {
    fd_vote_authorize_new(&self->authorize_checked);
    break;
  }
  case 8: {
    fd_vote_state_update_new(&self->update_vote_state);
    break;
  }
  case 9: {
    fd_update_vote_state_switch_new(&self->update_vote_state_switch);
    break;
  }
  case 10: {
    fd_vote_authorize_with_seed_args_new(&self->authorize_with_seed);
    break;
  }
  case 11: {
    fd_vote_authorize_checked_with_seed_args_new(&self->authorize_checked_with_seed);
    break;
  }
  case 12: {
    fd_compact_vote_state_update_new(&self->compact_update_vote_state);
    break;
  }
  case 13: {
    fd_compact_vote_state_update_switch_new(&self->compact_update_vote_state_switch);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_vote_instruction_new(fd_vote_instruction_t* self) {
  self->discriminant = 0;
  fd_vote_instruction_inner_new(&self->inner, self->discriminant);
}
void fd_vote_instruction_inner_destroy(fd_vote_instruction_inner_t* self, uint discriminant, fd_bincode_destroy_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    fd_vote_init_destroy(&self->initialize_account, ctx);
    break;
  }
  case 1: {
    fd_vote_authorize_pubkey_destroy(&self->authorize, ctx);
    break;
  }
  case 2: {
    fd_vote_destroy(&self->vote, ctx);
    break;
  }
  case 3: {
    break;
  }
  case 4: {
    break;
  }
  case 5: {
    break;
  }
  case 6: {
    fd_vote_switch_destroy(&self->vote_switch, ctx);
    break;
  }
  case 7: {
    fd_vote_authorize_destroy(&self->authorize_checked, ctx);
    break;
  }
  case 8: {
    fd_vote_state_update_destroy(&self->update_vote_state, ctx);
    break;
  }
  case 9: {
    fd_update_vote_state_switch_destroy(&self->update_vote_state_switch, ctx);
    break;
  }
  case 10: {
    fd_vote_authorize_with_seed_args_destroy(&self->authorize_with_seed, ctx);
    break;
  }
  case 11: {
    fd_vote_authorize_checked_with_seed_args_destroy(&self->authorize_checked_with_seed, ctx);
    break;
  }
  case 12: {
    fd_compact_vote_state_update_destroy(&self->compact_update_vote_state, ctx);
    break;
  }
  case 13: {
    fd_compact_vote_state_update_switch_destroy(&self->compact_update_vote_state_switch, ctx);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_vote_instruction_destroy(fd_vote_instruction_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_vote_instruction_inner_destroy(&self->inner, self->discriminant, ctx);
}

void fd_vote_instruction_walk(fd_vote_instruction_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_vote_instruction", level++);
  // enum fd_char*_walk(&self->current_authority_derived_key_seed, fun, "current_authority_derived_key_seed", level + 1);
  fun(self, name, 33, "fd_vote_instruction", --level);
}
ulong fd_vote_instruction_size(fd_vote_instruction_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 0: {
    size += fd_vote_init_size(&self->inner.initialize_account);
    break;
  }
  case 1: {
    size += fd_vote_authorize_pubkey_size(&self->inner.authorize);
    break;
  }
  case 2: {
    size += fd_vote_size(&self->inner.vote);
    break;
  }
  case 3: {
    size += sizeof(ulong);
    break;
  }
  case 5: {
    size += sizeof(char);
    break;
  }
  case 6: {
    size += fd_vote_switch_size(&self->inner.vote_switch);
    break;
  }
  case 7: {
    size += fd_vote_authorize_size(&self->inner.authorize_checked);
    break;
  }
  case 8: {
    size += fd_vote_state_update_size(&self->inner.update_vote_state);
    break;
  }
  case 9: {
    size += fd_update_vote_state_switch_size(&self->inner.update_vote_state_switch);
    break;
  }
  case 10: {
    size += fd_vote_authorize_with_seed_args_size(&self->inner.authorize_with_seed);
    break;
  }
  case 11: {
    size += fd_vote_authorize_checked_with_seed_args_size(&self->inner.authorize_checked_with_seed);
    break;
  }
  case 12: {
    size += fd_compact_vote_state_update_size(&self->inner.compact_update_vote_state);
    break;
  }
  case 13: {
    size += fd_compact_vote_state_update_switch_size(&self->inner.compact_update_vote_state_switch);
    break;
  }
  }
  return size;
}

int fd_vote_instruction_inner_encode(fd_vote_instruction_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_vote_init_encode(&self->initialize_account, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 1: {
    err = fd_vote_authorize_pubkey_encode(&self->authorize, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 2: {
    err = fd_vote_encode(&self->vote, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 3: {
    err = fd_bincode_uint64_encode(&self->withdraw, ctx);
  if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 5: {
    err = fd_bincode_uint8_encode(&self->update_commission, ctx);
  if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 6: {
    err = fd_vote_switch_encode(&self->vote_switch, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 7: {
    err = fd_vote_authorize_encode(&self->authorize_checked, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 8: {
    err = fd_vote_state_update_encode(&self->update_vote_state, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 9: {
    err = fd_update_vote_state_switch_encode(&self->update_vote_state_switch, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 10: {
    err = fd_vote_authorize_with_seed_args_encode(&self->authorize_with_seed, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 11: {
    err = fd_vote_authorize_checked_with_seed_args_encode(&self->authorize_checked_with_seed, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 12: {
    err = fd_compact_vote_state_update_encode(&self->compact_update_vote_state, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 13: {
    err = fd_compact_vote_state_update_switch_encode(&self->compact_update_vote_state_switch, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_vote_instruction_encode(fd_vote_instruction_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode(&self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_vote_instruction_inner_encode(&self->inner, self->discriminant, ctx);
}

int fd_system_program_instruction_create_account_decode(fd_system_program_instruction_create_account_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode(&self->lamports, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->space, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_decode(&self->owner, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_system_program_instruction_create_account_new(fd_system_program_instruction_create_account_t* self) {
  fd_pubkey_new(&self->owner);
}
void fd_system_program_instruction_create_account_destroy(fd_system_program_instruction_create_account_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->owner, ctx);
}

void fd_system_program_instruction_create_account_walk(fd_system_program_instruction_create_account_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_system_program_instruction_create_account", level++);
  fun(&self->lamports, "lamports", 11, "ulong", level + 1);
  fun(&self->space, "space", 11, "ulong", level + 1);
  fd_pubkey_walk(&self->owner, fun, "owner", level + 1);
  fun(self, name, 33, "fd_system_program_instruction_create_account", --level);
}
ulong fd_system_program_instruction_create_account_size(fd_system_program_instruction_create_account_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += fd_pubkey_size(&self->owner);
  return size;
}

int fd_system_program_instruction_create_account_encode(fd_system_program_instruction_create_account_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(&self->lamports, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->space, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->owner, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_system_program_instruction_create_account_with_seed_decode(fd_system_program_instruction_create_account_with_seed_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_decode(&self->base, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong slen;
  err = fd_bincode_uint64_decode(&slen, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->seed = (char*)(*ctx->allocf)(ctx->allocf_arg, 1, slen + 1);
  err = fd_bincode_bytes_decode((uchar *) self->seed, slen, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->seed[slen] = '\0';
  err = fd_bincode_uint64_decode(&self->lamports, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->space, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_decode(&self->owner, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_system_program_instruction_create_account_with_seed_new(fd_system_program_instruction_create_account_with_seed_t* self) {
  fd_pubkey_new(&self->base);
  self->seed = NULL;
  fd_pubkey_new(&self->owner);
}
void fd_system_program_instruction_create_account_with_seed_destroy(fd_system_program_instruction_create_account_with_seed_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->base, ctx);
  if (NULL != self->seed) {
    (*ctx->freef)(ctx->freef_arg, self->seed);
    self->seed = NULL;
  }
  fd_pubkey_destroy(&self->owner, ctx);
}

void fd_system_program_instruction_create_account_with_seed_walk(fd_system_program_instruction_create_account_with_seed_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_system_program_instruction_create_account_with_seed", level++);
  fd_pubkey_walk(&self->base, fun, "base", level + 1);
  fun(self->seed, "seed", 2, "char*", level + 1);
  fun(&self->lamports, "lamports", 11, "ulong", level + 1);
  fun(&self->space, "space", 11, "ulong", level + 1);
  fd_pubkey_walk(&self->owner, fun, "owner", level + 1);
  fun(self, name, 33, "fd_system_program_instruction_create_account_with_seed", --level);
}
ulong fd_system_program_instruction_create_account_with_seed_size(fd_system_program_instruction_create_account_with_seed_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->base);
  size += sizeof(ulong) + strlen(self->seed);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += fd_pubkey_size(&self->owner);
  return size;
}

int fd_system_program_instruction_create_account_with_seed_encode(fd_system_program_instruction_create_account_with_seed_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->base, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong slen = strlen((char *) self->seed);
  err = fd_bincode_uint64_encode(&slen, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_bytes_encode((uchar *) self->seed, slen, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->lamports, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->space, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->owner, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_system_program_instruction_allocate_with_seed_decode(fd_system_program_instruction_allocate_with_seed_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_decode(&self->base, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong slen;
  err = fd_bincode_uint64_decode(&slen, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->seed = (char*)(*ctx->allocf)(ctx->allocf_arg, 1, slen + 1);
  err = fd_bincode_bytes_decode((uchar *) self->seed, slen, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->seed[slen] = '\0';
  err = fd_bincode_uint64_decode(&self->space, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_decode(&self->owner, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_system_program_instruction_allocate_with_seed_new(fd_system_program_instruction_allocate_with_seed_t* self) {
  fd_pubkey_new(&self->base);
  self->seed = NULL;
  fd_pubkey_new(&self->owner);
}
void fd_system_program_instruction_allocate_with_seed_destroy(fd_system_program_instruction_allocate_with_seed_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->base, ctx);
  if (NULL != self->seed) {
    (*ctx->freef)(ctx->freef_arg, self->seed);
    self->seed = NULL;
  }
  fd_pubkey_destroy(&self->owner, ctx);
}

void fd_system_program_instruction_allocate_with_seed_walk(fd_system_program_instruction_allocate_with_seed_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_system_program_instruction_allocate_with_seed", level++);
  fd_pubkey_walk(&self->base, fun, "base", level + 1);
  fun(self->seed, "seed", 2, "char*", level + 1);
  fun(&self->space, "space", 11, "ulong", level + 1);
  fd_pubkey_walk(&self->owner, fun, "owner", level + 1);
  fun(self, name, 33, "fd_system_program_instruction_allocate_with_seed", --level);
}
ulong fd_system_program_instruction_allocate_with_seed_size(fd_system_program_instruction_allocate_with_seed_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->base);
  size += sizeof(ulong) + strlen(self->seed);
  size += sizeof(ulong);
  size += fd_pubkey_size(&self->owner);
  return size;
}

int fd_system_program_instruction_allocate_with_seed_encode(fd_system_program_instruction_allocate_with_seed_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->base, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong slen = strlen((char *) self->seed);
  err = fd_bincode_uint64_encode(&slen, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_bytes_encode((uchar *) self->seed, slen, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->space, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->owner, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_system_program_instruction_assign_with_seed_decode(fd_system_program_instruction_assign_with_seed_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_decode(&self->base, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong slen;
  err = fd_bincode_uint64_decode(&slen, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->seed = (char*)(*ctx->allocf)(ctx->allocf_arg, 1, slen + 1);
  err = fd_bincode_bytes_decode((uchar *) self->seed, slen, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->seed[slen] = '\0';
  err = fd_pubkey_decode(&self->owner, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_system_program_instruction_assign_with_seed_new(fd_system_program_instruction_assign_with_seed_t* self) {
  fd_pubkey_new(&self->base);
  self->seed = NULL;
  fd_pubkey_new(&self->owner);
}
void fd_system_program_instruction_assign_with_seed_destroy(fd_system_program_instruction_assign_with_seed_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->base, ctx);
  if (NULL != self->seed) {
    (*ctx->freef)(ctx->freef_arg, self->seed);
    self->seed = NULL;
  }
  fd_pubkey_destroy(&self->owner, ctx);
}

void fd_system_program_instruction_assign_with_seed_walk(fd_system_program_instruction_assign_with_seed_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_system_program_instruction_assign_with_seed", level++);
  fd_pubkey_walk(&self->base, fun, "base", level + 1);
  fun(self->seed, "seed", 2, "char*", level + 1);
  fd_pubkey_walk(&self->owner, fun, "owner", level + 1);
  fun(self, name, 33, "fd_system_program_instruction_assign_with_seed", --level);
}
ulong fd_system_program_instruction_assign_with_seed_size(fd_system_program_instruction_assign_with_seed_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->base);
  size += sizeof(ulong) + strlen(self->seed);
  size += fd_pubkey_size(&self->owner);
  return size;
}

int fd_system_program_instruction_assign_with_seed_encode(fd_system_program_instruction_assign_with_seed_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->base, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong slen = strlen((char *) self->seed);
  err = fd_bincode_uint64_encode(&slen, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_bytes_encode((uchar *) self->seed, slen, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->owner, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_system_program_instruction_transfer_with_seed_decode(fd_system_program_instruction_transfer_with_seed_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode(&self->lamports, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong slen;
  err = fd_bincode_uint64_decode(&slen, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->from_seed = (char*)(*ctx->allocf)(ctx->allocf_arg, 1, slen + 1);
  err = fd_bincode_bytes_decode((uchar *) self->from_seed, slen, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->from_seed[slen] = '\0';
  err = fd_pubkey_decode(&self->from_owner, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_system_program_instruction_transfer_with_seed_new(fd_system_program_instruction_transfer_with_seed_t* self) {
  self->from_seed = NULL;
  fd_pubkey_new(&self->from_owner);
}
void fd_system_program_instruction_transfer_with_seed_destroy(fd_system_program_instruction_transfer_with_seed_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->from_seed) {
    (*ctx->freef)(ctx->freef_arg, self->from_seed);
    self->from_seed = NULL;
  }
  fd_pubkey_destroy(&self->from_owner, ctx);
}

void fd_system_program_instruction_transfer_with_seed_walk(fd_system_program_instruction_transfer_with_seed_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_system_program_instruction_transfer_with_seed", level++);
  fun(&self->lamports, "lamports", 11, "ulong", level + 1);
  fun(self->from_seed, "from_seed", 2, "char*", level + 1);
  fd_pubkey_walk(&self->from_owner, fun, "from_owner", level + 1);
  fun(self, name, 33, "fd_system_program_instruction_transfer_with_seed", --level);
}
ulong fd_system_program_instruction_transfer_with_seed_size(fd_system_program_instruction_transfer_with_seed_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong) + strlen(self->from_seed);
  size += fd_pubkey_size(&self->from_owner);
  return size;
}

int fd_system_program_instruction_transfer_with_seed_encode(fd_system_program_instruction_transfer_with_seed_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(&self->lamports, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong slen = strlen((char *) self->from_seed);
  err = fd_bincode_uint64_encode(&slen, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_bytes_encode((uchar *) self->from_seed, slen, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->from_owner, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

FD_FN_PURE uchar fd_system_program_instruction_is_create_account(fd_system_program_instruction_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_system_program_instruction_is_assign(fd_system_program_instruction_t const * self) {
  return self->discriminant == 1;
}
FD_FN_PURE uchar fd_system_program_instruction_is_transfer(fd_system_program_instruction_t const * self) {
  return self->discriminant == 2;
}
FD_FN_PURE uchar fd_system_program_instruction_is_create_account_with_seed(fd_system_program_instruction_t const * self) {
  return self->discriminant == 3;
}
FD_FN_PURE uchar fd_system_program_instruction_is_advance_nonce_account(fd_system_program_instruction_t const * self) {
  return self->discriminant == 4;
}
FD_FN_PURE uchar fd_system_program_instruction_is_withdraw_nonce_account(fd_system_program_instruction_t const * self) {
  return self->discriminant == 5;
}
FD_FN_PURE uchar fd_system_program_instruction_is_initialize_nonce_account(fd_system_program_instruction_t const * self) {
  return self->discriminant == 6;
}
FD_FN_PURE uchar fd_system_program_instruction_is_authorize_nonce_account(fd_system_program_instruction_t const * self) {
  return self->discriminant == 7;
}
FD_FN_PURE uchar fd_system_program_instruction_is_allocate(fd_system_program_instruction_t const * self) {
  return self->discriminant == 8;
}
FD_FN_PURE uchar fd_system_program_instruction_is_allocate_with_seed(fd_system_program_instruction_t const * self) {
  return self->discriminant == 9;
}
FD_FN_PURE uchar fd_system_program_instruction_is_assign_with_seed(fd_system_program_instruction_t const * self) {
  return self->discriminant == 10;
}
FD_FN_PURE uchar fd_system_program_instruction_is_transfer_with_seed(fd_system_program_instruction_t const * self) {
  return self->discriminant == 11;
}
FD_FN_PURE uchar fd_system_program_instruction_is_upgrade_nonce_account(fd_system_program_instruction_t const * self) {
  return self->discriminant == 12;
}
void fd_system_program_instruction_inner_new(fd_system_program_instruction_inner_t* self, uint discriminant);
int fd_system_program_instruction_inner_decode(fd_system_program_instruction_inner_t* self, uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  fd_system_program_instruction_inner_new(self, discriminant);
  int err;
  switch (discriminant) {
  case 0: {
    return fd_system_program_instruction_create_account_decode(&self->create_account, ctx);
  }
  case 1: {
    return fd_pubkey_decode(&self->assign, ctx);
  }
  case 2: {
    err = fd_bincode_uint64_decode(&self->transfer, ctx);
  if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 3: {
    return fd_system_program_instruction_create_account_with_seed_decode(&self->create_account_with_seed, ctx);
  }
  case 4: {
    return FD_BINCODE_SUCCESS;
  }
  case 5: {
    err = fd_bincode_uint64_decode(&self->withdraw_nonce_account, ctx);
  if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 6: {
    return fd_pubkey_decode(&self->initialize_nonce_account, ctx);
  }
  case 7: {
    return fd_pubkey_decode(&self->authorize_nonce_account, ctx);
  }
  case 8: {
    err = fd_bincode_uint64_decode(&self->allocate, ctx);
  if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 9: {
    return fd_system_program_instruction_allocate_with_seed_decode(&self->allocate_with_seed, ctx);
  }
  case 10: {
    return fd_system_program_instruction_assign_with_seed_decode(&self->assign_with_seed, ctx);
  }
  case 11: {
    return fd_system_program_instruction_transfer_with_seed_decode(&self->transfer_with_seed, ctx);
  }
  case 12: {
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
int fd_system_program_instruction_decode(fd_system_program_instruction_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err = fd_bincode_uint32_decode(&self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_system_program_instruction_inner_decode(&self->inner, self->discriminant, ctx);
}
void fd_system_program_instruction_inner_new(fd_system_program_instruction_inner_t* self, uint discriminant) {
  switch (discriminant) {
  case 0: {
    fd_system_program_instruction_create_account_new(&self->create_account);
    break;
  }
  case 1: {
    fd_pubkey_new(&self->assign);
    break;
  }
  case 2: {
    break;
  }
  case 3: {
    fd_system_program_instruction_create_account_with_seed_new(&self->create_account_with_seed);
    break;
  }
  case 4: {
    break;
  }
  case 5: {
    break;
  }
  case 6: {
    fd_pubkey_new(&self->initialize_nonce_account);
    break;
  }
  case 7: {
    fd_pubkey_new(&self->authorize_nonce_account);
    break;
  }
  case 8: {
    break;
  }
  case 9: {
    fd_system_program_instruction_allocate_with_seed_new(&self->allocate_with_seed);
    break;
  }
  case 10: {
    fd_system_program_instruction_assign_with_seed_new(&self->assign_with_seed);
    break;
  }
  case 11: {
    fd_system_program_instruction_transfer_with_seed_new(&self->transfer_with_seed);
    break;
  }
  case 12: {
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_system_program_instruction_new(fd_system_program_instruction_t* self) {
  self->discriminant = 0;
  fd_system_program_instruction_inner_new(&self->inner, self->discriminant);
}
void fd_system_program_instruction_inner_destroy(fd_system_program_instruction_inner_t* self, uint discriminant, fd_bincode_destroy_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    fd_system_program_instruction_create_account_destroy(&self->create_account, ctx);
    break;
  }
  case 1: {
    fd_pubkey_destroy(&self->assign, ctx);
    break;
  }
  case 2: {
    break;
  }
  case 3: {
    fd_system_program_instruction_create_account_with_seed_destroy(&self->create_account_with_seed, ctx);
    break;
  }
  case 4: {
    break;
  }
  case 5: {
    break;
  }
  case 6: {
    fd_pubkey_destroy(&self->initialize_nonce_account, ctx);
    break;
  }
  case 7: {
    fd_pubkey_destroy(&self->authorize_nonce_account, ctx);
    break;
  }
  case 8: {
    break;
  }
  case 9: {
    fd_system_program_instruction_allocate_with_seed_destroy(&self->allocate_with_seed, ctx);
    break;
  }
  case 10: {
    fd_system_program_instruction_assign_with_seed_destroy(&self->assign_with_seed, ctx);
    break;
  }
  case 11: {
    fd_system_program_instruction_transfer_with_seed_destroy(&self->transfer_with_seed, ctx);
    break;
  }
  case 12: {
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_system_program_instruction_destroy(fd_system_program_instruction_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_system_program_instruction_inner_destroy(&self->inner, self->discriminant, ctx);
}

void fd_system_program_instruction_walk(fd_system_program_instruction_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_system_program_instruction", level++);
  // enum fd_pubkey_walk(&self->from_owner, fun, "from_owner", level + 1);
  fun(self, name, 33, "fd_system_program_instruction", --level);
}
ulong fd_system_program_instruction_size(fd_system_program_instruction_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 0: {
    size += fd_system_program_instruction_create_account_size(&self->inner.create_account);
    break;
  }
  case 1: {
    size += fd_pubkey_size(&self->inner.assign);
    break;
  }
  case 2: {
    size += sizeof(ulong);
    break;
  }
  case 3: {
    size += fd_system_program_instruction_create_account_with_seed_size(&self->inner.create_account_with_seed);
    break;
  }
  case 5: {
    size += sizeof(ulong);
    break;
  }
  case 6: {
    size += fd_pubkey_size(&self->inner.initialize_nonce_account);
    break;
  }
  case 7: {
    size += fd_pubkey_size(&self->inner.authorize_nonce_account);
    break;
  }
  case 8: {
    size += sizeof(ulong);
    break;
  }
  case 9: {
    size += fd_system_program_instruction_allocate_with_seed_size(&self->inner.allocate_with_seed);
    break;
  }
  case 10: {
    size += fd_system_program_instruction_assign_with_seed_size(&self->inner.assign_with_seed);
    break;
  }
  case 11: {
    size += fd_system_program_instruction_transfer_with_seed_size(&self->inner.transfer_with_seed);
    break;
  }
  }
  return size;
}

int fd_system_program_instruction_inner_encode(fd_system_program_instruction_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_system_program_instruction_create_account_encode(&self->create_account, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 1: {
    err = fd_pubkey_encode(&self->assign, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 2: {
    err = fd_bincode_uint64_encode(&self->transfer, ctx);
  if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 3: {
    err = fd_system_program_instruction_create_account_with_seed_encode(&self->create_account_with_seed, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 5: {
    err = fd_bincode_uint64_encode(&self->withdraw_nonce_account, ctx);
  if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 6: {
    err = fd_pubkey_encode(&self->initialize_nonce_account, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 7: {
    err = fd_pubkey_encode(&self->authorize_nonce_account, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 8: {
    err = fd_bincode_uint64_encode(&self->allocate, ctx);
  if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 9: {
    err = fd_system_program_instruction_allocate_with_seed_encode(&self->allocate_with_seed, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 10: {
    err = fd_system_program_instruction_assign_with_seed_encode(&self->assign_with_seed, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 11: {
    err = fd_system_program_instruction_transfer_with_seed_encode(&self->transfer_with_seed, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_system_program_instruction_encode(fd_system_program_instruction_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode(&self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_system_program_instruction_inner_encode(&self->inner, self->discriminant, ctx);
}

FD_FN_PURE uchar fd_system_error_is_account_already_in_use(fd_system_error_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_system_error_is_result_with_negative_lamports(fd_system_error_t const * self) {
  return self->discriminant == 1;
}
FD_FN_PURE uchar fd_system_error_is_invalid_program_id(fd_system_error_t const * self) {
  return self->discriminant == 2;
}
FD_FN_PURE uchar fd_system_error_is_invalid_account_data_length(fd_system_error_t const * self) {
  return self->discriminant == 3;
}
FD_FN_PURE uchar fd_system_error_is_max_seed_length_exceeded(fd_system_error_t const * self) {
  return self->discriminant == 4;
}
FD_FN_PURE uchar fd_system_error_is_address_with_seed_mismatch(fd_system_error_t const * self) {
  return self->discriminant == 5;
}
FD_FN_PURE uchar fd_system_error_is_nonce_no_recent_blockhashes(fd_system_error_t const * self) {
  return self->discriminant == 6;
}
FD_FN_PURE uchar fd_system_error_is_nonce_blockhash_not_expired(fd_system_error_t const * self) {
  return self->discriminant == 7;
}
FD_FN_PURE uchar fd_system_error_is_nonce_unexpected_blockhash_value(fd_system_error_t const * self) {
  return self->discriminant == 8;
}
void fd_system_error_inner_new(fd_system_error_inner_t* self, uint discriminant);
int fd_system_error_inner_decode(fd_system_error_inner_t* self, uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  fd_system_error_inner_new(self, discriminant);
  int err;
  switch (discriminant) {
  case 0: {
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    return FD_BINCODE_SUCCESS;
  }
  case 2: {
    return FD_BINCODE_SUCCESS;
  }
  case 3: {
    return FD_BINCODE_SUCCESS;
  }
  case 4: {
    return FD_BINCODE_SUCCESS;
  }
  case 5: {
    return FD_BINCODE_SUCCESS;
  }
  case 6: {
    return FD_BINCODE_SUCCESS;
  }
  case 7: {
    return FD_BINCODE_SUCCESS;
  }
  case 8: {
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
int fd_system_error_decode(fd_system_error_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err = fd_bincode_uint32_decode(&self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_system_error_inner_decode(&self->inner, self->discriminant, ctx);
}
void fd_system_error_inner_new(fd_system_error_inner_t* self, uint discriminant) {
  switch (discriminant) {
  case 0: {
    break;
  }
  case 1: {
    break;
  }
  case 2: {
    break;
  }
  case 3: {
    break;
  }
  case 4: {
    break;
  }
  case 5: {
    break;
  }
  case 6: {
    break;
  }
  case 7: {
    break;
  }
  case 8: {
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_system_error_new(fd_system_error_t* self) {
  self->discriminant = 0;
  fd_system_error_inner_new(&self->inner, self->discriminant);
}
void fd_system_error_inner_destroy(fd_system_error_inner_t* self, uint discriminant, fd_bincode_destroy_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    break;
  }
  case 1: {
    break;
  }
  case 2: {
    break;
  }
  case 3: {
    break;
  }
  case 4: {
    break;
  }
  case 5: {
    break;
  }
  case 6: {
    break;
  }
  case 7: {
    break;
  }
  case 8: {
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_system_error_destroy(fd_system_error_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_system_error_inner_destroy(&self->inner, self->discriminant, ctx);
}

void fd_system_error_walk(fd_system_error_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_system_error", level++);
  // enum fd_pubkey_walk(&self->from_owner, fun, "from_owner", level + 1);
  fun(self, name, 33, "fd_system_error", --level);
}
ulong fd_system_error_size(fd_system_error_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  }
  return size;
}

int fd_system_error_inner_encode(fd_system_error_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx) {
  return FD_BINCODE_SUCCESS;
}
int fd_system_error_encode(fd_system_error_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode(&self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_system_error_inner_encode(&self->inner, self->discriminant, ctx);
}

int fd_stake_authorized_decode(fd_stake_authorized_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_decode(&self->staker, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_decode(&self->withdrawer, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_stake_authorized_new(fd_stake_authorized_t* self) {
  fd_pubkey_new(&self->staker);
  fd_pubkey_new(&self->withdrawer);
}
void fd_stake_authorized_destroy(fd_stake_authorized_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->staker, ctx);
  fd_pubkey_destroy(&self->withdrawer, ctx);
}

void fd_stake_authorized_walk(fd_stake_authorized_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_stake_authorized", level++);
  fd_pubkey_walk(&self->staker, fun, "staker", level + 1);
  fd_pubkey_walk(&self->withdrawer, fun, "withdrawer", level + 1);
  fun(self, name, 33, "fd_stake_authorized", --level);
}
ulong fd_stake_authorized_size(fd_stake_authorized_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->staker);
  size += fd_pubkey_size(&self->withdrawer);
  return size;
}

int fd_stake_authorized_encode(fd_stake_authorized_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->staker, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->withdrawer, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_stake_lockup_decode(fd_stake_lockup_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode(&self->unix_timestamp, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_decode(&self->custodian, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_stake_lockup_new(fd_stake_lockup_t* self) {
  fd_pubkey_new(&self->custodian);
}
void fd_stake_lockup_destroy(fd_stake_lockup_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->custodian, ctx);
}

void fd_stake_lockup_walk(fd_stake_lockup_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_stake_lockup", level++);
  fun(&self->unix_timestamp, "unix_timestamp", 11, "ulong", level + 1);
  fun(&self->epoch, "epoch", 11, "ulong", level + 1);
  fd_pubkey_walk(&self->custodian, fun, "custodian", level + 1);
  fun(self, name, 33, "fd_stake_lockup", --level);
}
ulong fd_stake_lockup_size(fd_stake_lockup_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += fd_pubkey_size(&self->custodian);
  return size;
}

int fd_stake_lockup_encode(fd_stake_lockup_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(&self->unix_timestamp, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->custodian, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_stake_instruction_initialize_decode(fd_stake_instruction_initialize_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_stake_authorized_decode(&self->authorized, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_decode(&self->lockup, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_stake_instruction_initialize_new(fd_stake_instruction_initialize_t* self) {
  fd_stake_authorized_new(&self->authorized);
  fd_pubkey_new(&self->lockup);
}
void fd_stake_instruction_initialize_destroy(fd_stake_instruction_initialize_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_stake_authorized_destroy(&self->authorized, ctx);
  fd_pubkey_destroy(&self->lockup, ctx);
}

void fd_stake_instruction_initialize_walk(fd_stake_instruction_initialize_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_stake_instruction_initialize", level++);
  fd_stake_authorized_walk(&self->authorized, fun, "authorized", level + 1);
  fd_pubkey_walk(&self->lockup, fun, "lockup", level + 1);
  fun(self, name, 33, "fd_stake_instruction_initialize", --level);
}
ulong fd_stake_instruction_initialize_size(fd_stake_instruction_initialize_t const * self) {
  ulong size = 0;
  size += fd_stake_authorized_size(&self->authorized);
  size += fd_pubkey_size(&self->lockup);
  return size;
}

int fd_stake_instruction_initialize_encode(fd_stake_instruction_initialize_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_stake_authorized_encode(&self->authorized, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->lockup, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

FD_FN_PURE uchar fd_stake_authorize_is_staker(fd_stake_authorize_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_stake_authorize_is_withdrawer(fd_stake_authorize_t const * self) {
  return self->discriminant == 1;
}
void fd_stake_authorize_inner_new(fd_stake_authorize_inner_t* self, uint discriminant);
int fd_stake_authorize_inner_decode(fd_stake_authorize_inner_t* self, uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  fd_stake_authorize_inner_new(self, discriminant);
  int err;
  switch (discriminant) {
  case 0: {
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
int fd_stake_authorize_decode(fd_stake_authorize_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err = fd_bincode_uint32_decode(&self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_stake_authorize_inner_decode(&self->inner, self->discriminant, ctx);
}
void fd_stake_authorize_inner_new(fd_stake_authorize_inner_t* self, uint discriminant) {
  switch (discriminant) {
  case 0: {
    break;
  }
  case 1: {
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_stake_authorize_new(fd_stake_authorize_t* self) {
  self->discriminant = 0;
  fd_stake_authorize_inner_new(&self->inner, self->discriminant);
}
void fd_stake_authorize_inner_destroy(fd_stake_authorize_inner_t* self, uint discriminant, fd_bincode_destroy_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    break;
  }
  case 1: {
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_stake_authorize_destroy(fd_stake_authorize_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_stake_authorize_inner_destroy(&self->inner, self->discriminant, ctx);
}

void fd_stake_authorize_walk(fd_stake_authorize_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_stake_authorize", level++);
  // enum fd_pubkey_walk(&self->lockup, fun, "lockup", level + 1);
  fun(self, name, 33, "fd_stake_authorize", --level);
}
ulong fd_stake_authorize_size(fd_stake_authorize_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  }
  return size;
}

int fd_stake_authorize_inner_encode(fd_stake_authorize_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx) {
  return FD_BINCODE_SUCCESS;
}
int fd_stake_authorize_encode(fd_stake_authorize_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode(&self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_stake_authorize_inner_encode(&self->inner, self->discriminant, ctx);
}

int fd_stake_instruction_authorize_decode(fd_stake_instruction_authorize_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_decode(&self->pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_stake_authorize_decode(&self->stake_authorize, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_stake_instruction_authorize_new(fd_stake_instruction_authorize_t* self) {
  fd_pubkey_new(&self->pubkey);
  fd_stake_authorize_new(&self->stake_authorize);
}
void fd_stake_instruction_authorize_destroy(fd_stake_instruction_authorize_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->pubkey, ctx);
  fd_stake_authorize_destroy(&self->stake_authorize, ctx);
}

void fd_stake_instruction_authorize_walk(fd_stake_instruction_authorize_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_stake_instruction_authorize", level++);
  fd_pubkey_walk(&self->pubkey, fun, "pubkey", level + 1);
  fd_stake_authorize_walk(&self->stake_authorize, fun, "stake_authorize", level + 1);
  fun(self, name, 33, "fd_stake_instruction_authorize", --level);
}
ulong fd_stake_instruction_authorize_size(fd_stake_instruction_authorize_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->pubkey);
  size += fd_stake_authorize_size(&self->stake_authorize);
  return size;
}

int fd_stake_instruction_authorize_encode(fd_stake_instruction_authorize_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_stake_authorize_encode(&self->stake_authorize, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_lockup_args_decode(fd_lockup_args_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  {
    unsigned char o;
    err = fd_bincode_option_decode(&o, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    if (o) {
      self->unix_timestamp = (ulong*)(*ctx->allocf)(ctx->allocf_arg, 8, sizeof(ulong));
      err = fd_bincode_uint64_decode(self->unix_timestamp, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    } else
      self->unix_timestamp = NULL;
  }
  {
    unsigned char o;
    err = fd_bincode_option_decode(&o, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    if (o) {
      self->epoch = (ulong*)(*ctx->allocf)(ctx->allocf_arg, 8, sizeof(ulong));
      err = fd_bincode_uint64_decode(self->epoch, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    } else
      self->epoch = NULL;
  }
  {
    unsigned char o;
    err = fd_bincode_option_decode(&o, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    if (o) {
      self->custodian = (fd_pubkey_t*)(*ctx->allocf)(ctx->allocf_arg, FD_PUBKEY_ALIGN, FD_PUBKEY_FOOTPRINT);
      fd_pubkey_new(self->custodian);
      err = fd_pubkey_decode(self->custodian, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    } else
      self->custodian = NULL;
  }
  return FD_BINCODE_SUCCESS;
}
void fd_lockup_args_new(fd_lockup_args_t* self) {
  self->unix_timestamp = NULL;
  self->epoch = NULL;
  self->custodian = NULL;
}
void fd_lockup_args_destroy(fd_lockup_args_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->unix_timestamp) {
    (*ctx->freef)(ctx->freef_arg, self->unix_timestamp);
    self->unix_timestamp = NULL;
  }
  if (NULL != self->epoch) {
    (*ctx->freef)(ctx->freef_arg, self->epoch);
    self->epoch = NULL;
  }
  if (NULL != self->custodian) {
    fd_pubkey_destroy(self->custodian, ctx);
    (*ctx->freef)(ctx->freef_arg, self->custodian);
    self->custodian = NULL;
  }
}

void fd_lockup_args_walk(fd_lockup_args_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_lockup_args", level++);
  fun(self->unix_timestamp, "unix_timestamp", 11, "ulong", level + 1);
  fun(self->epoch, "epoch", 11, "ulong", level + 1);
  // fun(&self->custodian, "custodian", 16, "option", level + 1);
  fun(self, name, 33, "fd_lockup_args", --level);
}
ulong fd_lockup_args_size(fd_lockup_args_t const * self) {
  ulong size = 0;
  size += sizeof(char);
  if (NULL !=  self->unix_timestamp) {
    size += sizeof(ulong);
  }
  size += sizeof(char);
  if (NULL !=  self->epoch) {
    size += sizeof(ulong);
  }
  size += sizeof(char);
  if (NULL !=  self->custodian) {
    size += fd_pubkey_size(self->custodian);
  }
  return size;
}

int fd_lockup_args_encode(fd_lockup_args_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  if (self->unix_timestamp != NULL) {
    err = fd_bincode_option_encode(1, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    err = fd_bincode_uint64_encode(self->unix_timestamp, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  } else {
    err = fd_bincode_option_encode(0, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  if (self->epoch != NULL) {
    err = fd_bincode_option_encode(1, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    err = fd_bincode_uint64_encode(self->epoch, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  } else {
    err = fd_bincode_option_encode(0, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  if (self->custodian != NULL) {
    err = fd_bincode_option_encode(1, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    err = fd_pubkey_encode(self->custodian, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  } else {
    err = fd_bincode_option_encode(0, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}

int fd_authorize_with_seed_args_decode(fd_authorize_with_seed_args_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_decode(&self->new_authorized_pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_stake_authorize_decode(&self->stake_authorize, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong slen;
  err = fd_bincode_uint64_decode(&slen, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->authority_seed = (char*)(*ctx->allocf)(ctx->allocf_arg, 1, slen + 1);
  err = fd_bincode_bytes_decode((uchar *) self->authority_seed, slen, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->authority_seed[slen] = '\0';
  err = fd_pubkey_decode(&self->authority_owner, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_authorize_with_seed_args_new(fd_authorize_with_seed_args_t* self) {
  fd_pubkey_new(&self->new_authorized_pubkey);
  fd_stake_authorize_new(&self->stake_authorize);
  self->authority_seed = NULL;
  fd_pubkey_new(&self->authority_owner);
}
void fd_authorize_with_seed_args_destroy(fd_authorize_with_seed_args_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->new_authorized_pubkey, ctx);
  fd_stake_authorize_destroy(&self->stake_authorize, ctx);
  if (NULL != self->authority_seed) {
    (*ctx->freef)(ctx->freef_arg, self->authority_seed);
    self->authority_seed = NULL;
  }
  fd_pubkey_destroy(&self->authority_owner, ctx);
}

void fd_authorize_with_seed_args_walk(fd_authorize_with_seed_args_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_authorize_with_seed_args", level++);
  fd_pubkey_walk(&self->new_authorized_pubkey, fun, "new_authorized_pubkey", level + 1);
  fd_stake_authorize_walk(&self->stake_authorize, fun, "stake_authorize", level + 1);
  fun(self->authority_seed, "authority_seed", 2, "char*", level + 1);
  fd_pubkey_walk(&self->authority_owner, fun, "authority_owner", level + 1);
  fun(self, name, 33, "fd_authorize_with_seed_args", --level);
}
ulong fd_authorize_with_seed_args_size(fd_authorize_with_seed_args_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->new_authorized_pubkey);
  size += fd_stake_authorize_size(&self->stake_authorize);
  size += sizeof(ulong) + strlen(self->authority_seed);
  size += fd_pubkey_size(&self->authority_owner);
  return size;
}

int fd_authorize_with_seed_args_encode(fd_authorize_with_seed_args_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->new_authorized_pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_stake_authorize_encode(&self->stake_authorize, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong slen = strlen((char *) self->authority_seed);
  err = fd_bincode_uint64_encode(&slen, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_bytes_encode((uchar *) self->authority_seed, slen, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->authority_owner, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_authorize_checked_with_seed_args_decode(fd_authorize_checked_with_seed_args_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_stake_authorize_decode(&self->stake_authorize, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong slen;
  err = fd_bincode_uint64_decode(&slen, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->authority_seed = (char*)(*ctx->allocf)(ctx->allocf_arg, 1, slen + 1);
  err = fd_bincode_bytes_decode((uchar *) self->authority_seed, slen, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->authority_seed[slen] = '\0';
  err = fd_pubkey_decode(&self->authority_owner, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_authorize_checked_with_seed_args_new(fd_authorize_checked_with_seed_args_t* self) {
  fd_stake_authorize_new(&self->stake_authorize);
  self->authority_seed = NULL;
  fd_pubkey_new(&self->authority_owner);
}
void fd_authorize_checked_with_seed_args_destroy(fd_authorize_checked_with_seed_args_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_stake_authorize_destroy(&self->stake_authorize, ctx);
  if (NULL != self->authority_seed) {
    (*ctx->freef)(ctx->freef_arg, self->authority_seed);
    self->authority_seed = NULL;
  }
  fd_pubkey_destroy(&self->authority_owner, ctx);
}

void fd_authorize_checked_with_seed_args_walk(fd_authorize_checked_with_seed_args_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_authorize_checked_with_seed_args", level++);
  fd_stake_authorize_walk(&self->stake_authorize, fun, "stake_authorize", level + 1);
  fun(self->authority_seed, "authority_seed", 2, "char*", level + 1);
  fd_pubkey_walk(&self->authority_owner, fun, "authority_owner", level + 1);
  fun(self, name, 33, "fd_authorize_checked_with_seed_args", --level);
}
ulong fd_authorize_checked_with_seed_args_size(fd_authorize_checked_with_seed_args_t const * self) {
  ulong size = 0;
  size += fd_stake_authorize_size(&self->stake_authorize);
  size += sizeof(ulong) + strlen(self->authority_seed);
  size += fd_pubkey_size(&self->authority_owner);
  return size;
}

int fd_authorize_checked_with_seed_args_encode(fd_authorize_checked_with_seed_args_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_stake_authorize_encode(&self->stake_authorize, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong slen = strlen((char *) self->authority_seed);
  err = fd_bincode_uint64_encode(&slen, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_bytes_encode((uchar *) self->authority_seed, slen, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->authority_owner, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_lockup_checked_args_decode(fd_lockup_checked_args_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  {
    unsigned char o;
    err = fd_bincode_option_decode(&o, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    if (o) {
      self->unix_timestamp = (ulong*)(*ctx->allocf)(ctx->allocf_arg, 8, sizeof(ulong));
      err = fd_bincode_uint64_decode(self->unix_timestamp, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    } else
      self->unix_timestamp = NULL;
  }
  {
    unsigned char o;
    err = fd_bincode_option_decode(&o, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    if (o) {
      self->epoch = (ulong*)(*ctx->allocf)(ctx->allocf_arg, 8, sizeof(ulong));
      err = fd_bincode_uint64_decode(self->epoch, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    } else
      self->epoch = NULL;
  }
  return FD_BINCODE_SUCCESS;
}
void fd_lockup_checked_args_new(fd_lockup_checked_args_t* self) {
  self->unix_timestamp = NULL;
  self->epoch = NULL;
}
void fd_lockup_checked_args_destroy(fd_lockup_checked_args_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->unix_timestamp) {
    (*ctx->freef)(ctx->freef_arg, self->unix_timestamp);
    self->unix_timestamp = NULL;
  }
  if (NULL != self->epoch) {
    (*ctx->freef)(ctx->freef_arg, self->epoch);
    self->epoch = NULL;
  }
}

void fd_lockup_checked_args_walk(fd_lockup_checked_args_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_lockup_checked_args", level++);
  fun(self->unix_timestamp, "unix_timestamp", 11, "ulong", level + 1);
  fun(self->epoch, "epoch", 11, "ulong", level + 1);
  fun(self, name, 33, "fd_lockup_checked_args", --level);
}
ulong fd_lockup_checked_args_size(fd_lockup_checked_args_t const * self) {
  ulong size = 0;
  size += sizeof(char);
  if (NULL !=  self->unix_timestamp) {
    size += sizeof(ulong);
  }
  size += sizeof(char);
  if (NULL !=  self->epoch) {
    size += sizeof(ulong);
  }
  return size;
}

int fd_lockup_checked_args_encode(fd_lockup_checked_args_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  if (self->unix_timestamp != NULL) {
    err = fd_bincode_option_encode(1, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    err = fd_bincode_uint64_encode(self->unix_timestamp, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  } else {
    err = fd_bincode_option_encode(0, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  if (self->epoch != NULL) {
    err = fd_bincode_option_encode(1, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    err = fd_bincode_uint64_encode(self->epoch, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  } else {
    err = fd_bincode_option_encode(0, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}

FD_FN_PURE uchar fd_stake_instruction_is_initialize(fd_stake_instruction_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_stake_instruction_is_authorize(fd_stake_instruction_t const * self) {
  return self->discriminant == 1;
}
FD_FN_PURE uchar fd_stake_instruction_is_delegate_stake(fd_stake_instruction_t const * self) {
  return self->discriminant == 2;
}
FD_FN_PURE uchar fd_stake_instruction_is_split(fd_stake_instruction_t const * self) {
  return self->discriminant == 3;
}
FD_FN_PURE uchar fd_stake_instruction_is_withdraw(fd_stake_instruction_t const * self) {
  return self->discriminant == 4;
}
FD_FN_PURE uchar fd_stake_instruction_is_deactivate(fd_stake_instruction_t const * self) {
  return self->discriminant == 5;
}
FD_FN_PURE uchar fd_stake_instruction_is_set_lockup(fd_stake_instruction_t const * self) {
  return self->discriminant == 6;
}
FD_FN_PURE uchar fd_stake_instruction_is_merge(fd_stake_instruction_t const * self) {
  return self->discriminant == 7;
}
FD_FN_PURE uchar fd_stake_instruction_is_authorize_with_seed(fd_stake_instruction_t const * self) {
  return self->discriminant == 8;
}
FD_FN_PURE uchar fd_stake_instruction_is_initialize_checked(fd_stake_instruction_t const * self) {
  return self->discriminant == 9;
}
FD_FN_PURE uchar fd_stake_instruction_is_authorize_checked(fd_stake_instruction_t const * self) {
  return self->discriminant == 10;
}
FD_FN_PURE uchar fd_stake_instruction_is_authorize_checked_with_seed(fd_stake_instruction_t const * self) {
  return self->discriminant == 11;
}
FD_FN_PURE uchar fd_stake_instruction_is_set_lockup_checked(fd_stake_instruction_t const * self) {
  return self->discriminant == 12;
}
void fd_stake_instruction_inner_new(fd_stake_instruction_inner_t* self, uint discriminant);
int fd_stake_instruction_inner_decode(fd_stake_instruction_inner_t* self, uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  fd_stake_instruction_inner_new(self, discriminant);
  int err;
  switch (discriminant) {
  case 0: {
    return fd_stake_instruction_initialize_decode(&self->initialize, ctx);
  }
  case 1: {
    return fd_stake_instruction_authorize_decode(&self->authorize, ctx);
  }
  case 2: {
    return FD_BINCODE_SUCCESS;
  }
  case 3: {
    err = fd_bincode_uint64_decode(&self->split, ctx);
  if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 4: {
    err = fd_bincode_uint64_decode(&self->withdraw, ctx);
  if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 5: {
    return FD_BINCODE_SUCCESS;
  }
  case 6: {
    return FD_BINCODE_SUCCESS;
  }
  case 7: {
    return FD_BINCODE_SUCCESS;
  }
  case 8: {
    return fd_authorize_with_seed_args_decode(&self->authorize_with_seed, ctx);
  }
  case 9: {
    return FD_BINCODE_SUCCESS;
  }
  case 10: {
    return fd_stake_authorize_decode(&self->authorize_checked, ctx);
  }
  case 11: {
    return fd_authorize_checked_with_seed_args_decode(&self->authorize_checked_with_seed, ctx);
  }
  case 12: {
    return fd_lockup_checked_args_decode(&self->set_lockup_checked, ctx);
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
int fd_stake_instruction_decode(fd_stake_instruction_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err = fd_bincode_uint32_decode(&self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_stake_instruction_inner_decode(&self->inner, self->discriminant, ctx);
}
void fd_stake_instruction_inner_new(fd_stake_instruction_inner_t* self, uint discriminant) {
  switch (discriminant) {
  case 0: {
    fd_stake_instruction_initialize_new(&self->initialize);
    break;
  }
  case 1: {
    fd_stake_instruction_authorize_new(&self->authorize);
    break;
  }
  case 2: {
    break;
  }
  case 3: {
    break;
  }
  case 4: {
    break;
  }
  case 5: {
    break;
  }
  case 6: {
    break;
  }
  case 7: {
    break;
  }
  case 8: {
    fd_authorize_with_seed_args_new(&self->authorize_with_seed);
    break;
  }
  case 9: {
    break;
  }
  case 10: {
    fd_stake_authorize_new(&self->authorize_checked);
    break;
  }
  case 11: {
    fd_authorize_checked_with_seed_args_new(&self->authorize_checked_with_seed);
    break;
  }
  case 12: {
    fd_lockup_checked_args_new(&self->set_lockup_checked);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_stake_instruction_new(fd_stake_instruction_t* self) {
  self->discriminant = 0;
  fd_stake_instruction_inner_new(&self->inner, self->discriminant);
}
void fd_stake_instruction_inner_destroy(fd_stake_instruction_inner_t* self, uint discriminant, fd_bincode_destroy_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    fd_stake_instruction_initialize_destroy(&self->initialize, ctx);
    break;
  }
  case 1: {
    fd_stake_instruction_authorize_destroy(&self->authorize, ctx);
    break;
  }
  case 2: {
    break;
  }
  case 3: {
    break;
  }
  case 4: {
    break;
  }
  case 5: {
    break;
  }
  case 6: {
    break;
  }
  case 7: {
    break;
  }
  case 8: {
    fd_authorize_with_seed_args_destroy(&self->authorize_with_seed, ctx);
    break;
  }
  case 9: {
    break;
  }
  case 10: {
    fd_stake_authorize_destroy(&self->authorize_checked, ctx);
    break;
  }
  case 11: {
    fd_authorize_checked_with_seed_args_destroy(&self->authorize_checked_with_seed, ctx);
    break;
  }
  case 12: {
    fd_lockup_checked_args_destroy(&self->set_lockup_checked, ctx);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_stake_instruction_destroy(fd_stake_instruction_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_stake_instruction_inner_destroy(&self->inner, self->discriminant, ctx);
}

void fd_stake_instruction_walk(fd_stake_instruction_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_stake_instruction", level++);
  // enum fd_option_walk(&self->epoch, fun, "epoch", level + 1);
  fun(self, name, 33, "fd_stake_instruction", --level);
}
ulong fd_stake_instruction_size(fd_stake_instruction_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 0: {
    size += fd_stake_instruction_initialize_size(&self->inner.initialize);
    break;
  }
  case 1: {
    size += fd_stake_instruction_authorize_size(&self->inner.authorize);
    break;
  }
  case 3: {
    size += sizeof(ulong);
    break;
  }
  case 4: {
    size += sizeof(ulong);
    break;
  }
  case 8: {
    size += fd_authorize_with_seed_args_size(&self->inner.authorize_with_seed);
    break;
  }
  case 10: {
    size += fd_stake_authorize_size(&self->inner.authorize_checked);
    break;
  }
  case 11: {
    size += fd_authorize_checked_with_seed_args_size(&self->inner.authorize_checked_with_seed);
    break;
  }
  case 12: {
    size += fd_lockup_checked_args_size(&self->inner.set_lockup_checked);
    break;
  }
  }
  return size;
}

int fd_stake_instruction_inner_encode(fd_stake_instruction_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_stake_instruction_initialize_encode(&self->initialize, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 1: {
    err = fd_stake_instruction_authorize_encode(&self->authorize, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 3: {
    err = fd_bincode_uint64_encode(&self->split, ctx);
  if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 4: {
    err = fd_bincode_uint64_encode(&self->withdraw, ctx);
  if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 8: {
    err = fd_authorize_with_seed_args_encode(&self->authorize_with_seed, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 10: {
    err = fd_stake_authorize_encode(&self->authorize_checked, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 11: {
    err = fd_authorize_checked_with_seed_args_encode(&self->authorize_checked_with_seed, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 12: {
    err = fd_lockup_checked_args_encode(&self->set_lockup_checked, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_stake_instruction_encode(fd_stake_instruction_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode(&self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_stake_instruction_inner_encode(&self->inner, self->discriminant, ctx);
}

int fd_stake_state_meta_decode(fd_stake_state_meta_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode(&self->rent_exempt_reserve, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_stake_authorized_decode(&self->authorized, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_stake_lockup_decode(&self->lockup, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_stake_state_meta_new(fd_stake_state_meta_t* self) {
  fd_stake_authorized_new(&self->authorized);
  fd_stake_lockup_new(&self->lockup);
}
void fd_stake_state_meta_destroy(fd_stake_state_meta_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_stake_authorized_destroy(&self->authorized, ctx);
  fd_stake_lockup_destroy(&self->lockup, ctx);
}

void fd_stake_state_meta_walk(fd_stake_state_meta_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_stake_state_meta", level++);
  fun(&self->rent_exempt_reserve, "rent_exempt_reserve", 11, "ulong", level + 1);
  fd_stake_authorized_walk(&self->authorized, fun, "authorized", level + 1);
  fd_stake_lockup_walk(&self->lockup, fun, "lockup", level + 1);
  fun(self, name, 33, "fd_stake_state_meta", --level);
}
ulong fd_stake_state_meta_size(fd_stake_state_meta_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += fd_stake_authorized_size(&self->authorized);
  size += fd_stake_lockup_size(&self->lockup);
  return size;
}

int fd_stake_state_meta_encode(fd_stake_state_meta_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(&self->rent_exempt_reserve, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_stake_authorized_encode(&self->authorized, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_stake_lockup_encode(&self->lockup, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_stake_decode(fd_stake_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_delegation_decode(&self->delegation, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->credits_observed, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_stake_new(fd_stake_t* self) {
  fd_delegation_new(&self->delegation);
}
void fd_stake_destroy(fd_stake_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_delegation_destroy(&self->delegation, ctx);
}

void fd_stake_walk(fd_stake_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_stake", level++);
  fd_delegation_walk(&self->delegation, fun, "delegation", level + 1);
  fun(&self->credits_observed, "credits_observed", 11, "ulong", level + 1);
  fun(self, name, 33, "fd_stake", --level);
}
ulong fd_stake_size(fd_stake_t const * self) {
  ulong size = 0;
  size += fd_delegation_size(&self->delegation);
  size += sizeof(ulong);
  return size;
}

int fd_stake_encode(fd_stake_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_delegation_encode(&self->delegation, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->credits_observed, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_stake_state_stake_decode(fd_stake_state_stake_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_stake_state_meta_decode(&self->meta, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_stake_decode(&self->stake, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_stake_state_stake_new(fd_stake_state_stake_t* self) {
  fd_stake_state_meta_new(&self->meta);
  fd_stake_new(&self->stake);
}
void fd_stake_state_stake_destroy(fd_stake_state_stake_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_stake_state_meta_destroy(&self->meta, ctx);
  fd_stake_destroy(&self->stake, ctx);
}

void fd_stake_state_stake_walk(fd_stake_state_stake_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_stake_state_stake", level++);
  fd_stake_state_meta_walk(&self->meta, fun, "meta", level + 1);
  fd_stake_walk(&self->stake, fun, "stake", level + 1);
  fun(self, name, 33, "fd_stake_state_stake", --level);
}
ulong fd_stake_state_stake_size(fd_stake_state_stake_t const * self) {
  ulong size = 0;
  size += fd_stake_state_meta_size(&self->meta);
  size += fd_stake_size(&self->stake);
  return size;
}

int fd_stake_state_stake_encode(fd_stake_state_stake_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_stake_state_meta_encode(&self->meta, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_stake_encode(&self->stake, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

FD_FN_PURE uchar fd_stake_state_is_uninitialized(fd_stake_state_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_stake_state_is_initialized(fd_stake_state_t const * self) {
  return self->discriminant == 1;
}
FD_FN_PURE uchar fd_stake_state_is_stake(fd_stake_state_t const * self) {
  return self->discriminant == 2;
}
FD_FN_PURE uchar fd_stake_state_is_rewards_pool(fd_stake_state_t const * self) {
  return self->discriminant == 3;
}
void fd_stake_state_inner_new(fd_stake_state_inner_t* self, uint discriminant);
int fd_stake_state_inner_decode(fd_stake_state_inner_t* self, uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  fd_stake_state_inner_new(self, discriminant);
  int err;
  switch (discriminant) {
  case 0: {
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    return fd_stake_state_meta_decode(&self->initialized, ctx);
  }
  case 2: {
    return fd_stake_state_stake_decode(&self->stake, ctx);
  }
  case 3: {
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
int fd_stake_state_decode(fd_stake_state_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err = fd_bincode_uint32_decode(&self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_stake_state_inner_decode(&self->inner, self->discriminant, ctx);
}
void fd_stake_state_inner_new(fd_stake_state_inner_t* self, uint discriminant) {
  switch (discriminant) {
  case 0: {
    break;
  }
  case 1: {
    fd_stake_state_meta_new(&self->initialized);
    break;
  }
  case 2: {
    fd_stake_state_stake_new(&self->stake);
    break;
  }
  case 3: {
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_stake_state_new(fd_stake_state_t* self) {
  self->discriminant = 0;
  fd_stake_state_inner_new(&self->inner, self->discriminant);
}
void fd_stake_state_inner_destroy(fd_stake_state_inner_t* self, uint discriminant, fd_bincode_destroy_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    break;
  }
  case 1: {
    fd_stake_state_meta_destroy(&self->initialized, ctx);
    break;
  }
  case 2: {
    fd_stake_state_stake_destroy(&self->stake, ctx);
    break;
  }
  case 3: {
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_stake_state_destroy(fd_stake_state_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_stake_state_inner_destroy(&self->inner, self->discriminant, ctx);
}

void fd_stake_state_walk(fd_stake_state_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_stake_state", level++);
  // enum fd_stake_walk(&self->stake, fun, "stake", level + 1);
  fun(self, name, 33, "fd_stake_state", --level);
}
ulong fd_stake_state_size(fd_stake_state_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 1: {
    size += fd_stake_state_meta_size(&self->inner.initialized);
    break;
  }
  case 2: {
    size += fd_stake_state_stake_size(&self->inner.stake);
    break;
  }
  }
  return size;
}

int fd_stake_state_inner_encode(fd_stake_state_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 1: {
    err = fd_stake_state_meta_encode(&self->initialized, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 2: {
    err = fd_stake_state_stake_encode(&self->stake, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_stake_state_encode(fd_stake_state_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode(&self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_stake_state_inner_encode(&self->inner, self->discriminant, ctx);
}

int fd_nonce_data_decode(fd_nonce_data_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_decode(&self->authority, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_decode(&self->durable_nonce, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_fee_calculator_decode(&self->fee_calculator, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_nonce_data_new(fd_nonce_data_t* self) {
  fd_pubkey_new(&self->authority);
  fd_hash_new(&self->durable_nonce);
  fd_fee_calculator_new(&self->fee_calculator);
}
void fd_nonce_data_destroy(fd_nonce_data_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->authority, ctx);
  fd_hash_destroy(&self->durable_nonce, ctx);
  fd_fee_calculator_destroy(&self->fee_calculator, ctx);
}

void fd_nonce_data_walk(fd_nonce_data_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_nonce_data", level++);
  fd_pubkey_walk(&self->authority, fun, "authority", level + 1);
  fd_hash_walk(&self->durable_nonce, fun, "durable_nonce", level + 1);
  fd_fee_calculator_walk(&self->fee_calculator, fun, "fee_calculator", level + 1);
  fun(self, name, 33, "fd_nonce_data", --level);
}
ulong fd_nonce_data_size(fd_nonce_data_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->authority);
  size += fd_hash_size(&self->durable_nonce);
  size += fd_fee_calculator_size(&self->fee_calculator);
  return size;
}

int fd_nonce_data_encode(fd_nonce_data_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->authority, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_encode(&self->durable_nonce, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_fee_calculator_encode(&self->fee_calculator, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

FD_FN_PURE uchar fd_nonce_state_is_uninitialized(fd_nonce_state_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_nonce_state_is_initialized(fd_nonce_state_t const * self) {
  return self->discriminant == 1;
}
void fd_nonce_state_inner_new(fd_nonce_state_inner_t* self, uint discriminant);
int fd_nonce_state_inner_decode(fd_nonce_state_inner_t* self, uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  fd_nonce_state_inner_new(self, discriminant);
  int err;
  switch (discriminant) {
  case 0: {
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    return fd_nonce_data_decode(&self->initialized, ctx);
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
int fd_nonce_state_decode(fd_nonce_state_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err = fd_bincode_uint32_decode(&self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_nonce_state_inner_decode(&self->inner, self->discriminant, ctx);
}
void fd_nonce_state_inner_new(fd_nonce_state_inner_t* self, uint discriminant) {
  switch (discriminant) {
  case 0: {
    break;
  }
  case 1: {
    fd_nonce_data_new(&self->initialized);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_nonce_state_new(fd_nonce_state_t* self) {
  self->discriminant = 0;
  fd_nonce_state_inner_new(&self->inner, self->discriminant);
}
void fd_nonce_state_inner_destroy(fd_nonce_state_inner_t* self, uint discriminant, fd_bincode_destroy_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    break;
  }
  case 1: {
    fd_nonce_data_destroy(&self->initialized, ctx);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_nonce_state_destroy(fd_nonce_state_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_nonce_state_inner_destroy(&self->inner, self->discriminant, ctx);
}

void fd_nonce_state_walk(fd_nonce_state_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_nonce_state", level++);
  // enum fd_fee_calculator_walk(&self->fee_calculator, fun, "fee_calculator", level + 1);
  fun(self, name, 33, "fd_nonce_state", --level);
}
ulong fd_nonce_state_size(fd_nonce_state_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 1: {
    size += fd_nonce_data_size(&self->inner.initialized);
    break;
  }
  }
  return size;
}

int fd_nonce_state_inner_encode(fd_nonce_state_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 1: {
    err = fd_nonce_data_encode(&self->initialized, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_nonce_state_encode(fd_nonce_state_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode(&self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_nonce_state_inner_encode(&self->inner, self->discriminant, ctx);
}

FD_FN_PURE uchar fd_nonce_state_versions_is_legacy(fd_nonce_state_versions_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_nonce_state_versions_is_current(fd_nonce_state_versions_t const * self) {
  return self->discriminant == 1;
}
void fd_nonce_state_versions_inner_new(fd_nonce_state_versions_inner_t* self, uint discriminant);
int fd_nonce_state_versions_inner_decode(fd_nonce_state_versions_inner_t* self, uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  fd_nonce_state_versions_inner_new(self, discriminant);
  int err;
  switch (discriminant) {
  case 0: {
    return fd_nonce_state_decode(&self->legacy, ctx);
  }
  case 1: {
    return fd_nonce_state_decode(&self->current, ctx);
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
int fd_nonce_state_versions_decode(fd_nonce_state_versions_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err = fd_bincode_uint32_decode(&self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_nonce_state_versions_inner_decode(&self->inner, self->discriminant, ctx);
}
void fd_nonce_state_versions_inner_new(fd_nonce_state_versions_inner_t* self, uint discriminant) {
  switch (discriminant) {
  case 0: {
    fd_nonce_state_new(&self->legacy);
    break;
  }
  case 1: {
    fd_nonce_state_new(&self->current);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_nonce_state_versions_new(fd_nonce_state_versions_t* self) {
  self->discriminant = 0;
  fd_nonce_state_versions_inner_new(&self->inner, self->discriminant);
}
void fd_nonce_state_versions_inner_destroy(fd_nonce_state_versions_inner_t* self, uint discriminant, fd_bincode_destroy_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    fd_nonce_state_destroy(&self->legacy, ctx);
    break;
  }
  case 1: {
    fd_nonce_state_destroy(&self->current, ctx);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_nonce_state_versions_destroy(fd_nonce_state_versions_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_nonce_state_versions_inner_destroy(&self->inner, self->discriminant, ctx);
}

void fd_nonce_state_versions_walk(fd_nonce_state_versions_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_nonce_state_versions", level++);
  // enum fd_fee_calculator_walk(&self->fee_calculator, fun, "fee_calculator", level + 1);
  fun(self, name, 33, "fd_nonce_state_versions", --level);
}
ulong fd_nonce_state_versions_size(fd_nonce_state_versions_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 0: {
    size += fd_nonce_state_size(&self->inner.legacy);
    break;
  }
  case 1: {
    size += fd_nonce_state_size(&self->inner.current);
    break;
  }
  }
  return size;
}

int fd_nonce_state_versions_inner_encode(fd_nonce_state_versions_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_nonce_state_encode(&self->legacy, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 1: {
    err = fd_nonce_state_encode(&self->current, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_nonce_state_versions_encode(fd_nonce_state_versions_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode(&self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_nonce_state_versions_inner_encode(&self->inner, self->discriminant, ctx);
}

int fd_compute_budget_program_instruction_request_units_deprecated_decode(fd_compute_budget_program_instruction_request_units_deprecated_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_decode(&self->units, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint32_decode(&self->additional_fee, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_compute_budget_program_instruction_request_units_deprecated_new(fd_compute_budget_program_instruction_request_units_deprecated_t* self) {
}
void fd_compute_budget_program_instruction_request_units_deprecated_destroy(fd_compute_budget_program_instruction_request_units_deprecated_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

void fd_compute_budget_program_instruction_request_units_deprecated_walk(fd_compute_budget_program_instruction_request_units_deprecated_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_compute_budget_program_instruction_request_units_deprecated", level++);
  fun(&self->units, "units", 7, "uint", level + 1);
  fun(&self->additional_fee, "additional_fee", 7, "uint", level + 1);
  fun(self, name, 33, "fd_compute_budget_program_instruction_request_units_deprecated", --level);
}
ulong fd_compute_budget_program_instruction_request_units_deprecated_size(fd_compute_budget_program_instruction_request_units_deprecated_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  size += sizeof(uint);
  return size;
}

int fd_compute_budget_program_instruction_request_units_deprecated_encode(fd_compute_budget_program_instruction_request_units_deprecated_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode(&self->units, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint32_encode(&self->additional_fee, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

FD_FN_PURE uchar fd_compute_budget_program_instruction_is_request_units_deprecated(fd_compute_budget_program_instruction_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_compute_budget_program_instruction_is_request_heap_frame(fd_compute_budget_program_instruction_t const * self) {
  return self->discriminant == 1;
}
FD_FN_PURE uchar fd_compute_budget_program_instruction_is_set_compute_unit_limit(fd_compute_budget_program_instruction_t const * self) {
  return self->discriminant == 2;
}
FD_FN_PURE uchar fd_compute_budget_program_instruction_is_set_compute_unit_price(fd_compute_budget_program_instruction_t const * self) {
  return self->discriminant == 3;
}
void fd_compute_budget_program_instruction_inner_new(fd_compute_budget_program_instruction_inner_t* self, uint discriminant);
int fd_compute_budget_program_instruction_inner_decode(fd_compute_budget_program_instruction_inner_t* self, uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  fd_compute_budget_program_instruction_inner_new(self, discriminant);
  int err;
  switch (discriminant) {
  case 0: {
    return fd_compute_budget_program_instruction_request_units_deprecated_decode(&self->request_units_deprecated, ctx);
  }
  case 1: {
    err = fd_bincode_uint32_decode(&self->request_heap_frame, ctx);
  if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 2: {
    err = fd_bincode_uint32_decode(&self->set_compute_unit_limit, ctx);
  if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 3: {
    err = fd_bincode_uint64_decode(&self->set_compute_unit_price, ctx);
  if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
int fd_compute_budget_program_instruction_decode(fd_compute_budget_program_instruction_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err = fd_bincode_uint32_decode(&self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_compute_budget_program_instruction_inner_decode(&self->inner, self->discriminant, ctx);
}
void fd_compute_budget_program_instruction_inner_new(fd_compute_budget_program_instruction_inner_t* self, uint discriminant) {
  switch (discriminant) {
  case 0: {
    fd_compute_budget_program_instruction_request_units_deprecated_new(&self->request_units_deprecated);
    break;
  }
  case 1: {
    break;
  }
  case 2: {
    break;
  }
  case 3: {
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_compute_budget_program_instruction_new(fd_compute_budget_program_instruction_t* self) {
  self->discriminant = 0;
  fd_compute_budget_program_instruction_inner_new(&self->inner, self->discriminant);
}
void fd_compute_budget_program_instruction_inner_destroy(fd_compute_budget_program_instruction_inner_t* self, uint discriminant, fd_bincode_destroy_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    fd_compute_budget_program_instruction_request_units_deprecated_destroy(&self->request_units_deprecated, ctx);
    break;
  }
  case 1: {
    break;
  }
  case 2: {
    break;
  }
  case 3: {
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_compute_budget_program_instruction_destroy(fd_compute_budget_program_instruction_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_compute_budget_program_instruction_inner_destroy(&self->inner, self->discriminant, ctx);
}

void fd_compute_budget_program_instruction_walk(fd_compute_budget_program_instruction_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_compute_budget_program_instruction", level++);
  // enum fd_uint_walk(&self->additional_fee, fun, "additional_fee", level + 1);
  fun(self, name, 33, "fd_compute_budget_program_instruction", --level);
}
ulong fd_compute_budget_program_instruction_size(fd_compute_budget_program_instruction_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 0: {
    size += fd_compute_budget_program_instruction_request_units_deprecated_size(&self->inner.request_units_deprecated);
    break;
  }
  case 1: {
    size += sizeof(uint);
    break;
  }
  case 2: {
    size += sizeof(uint);
    break;
  }
  case 3: {
    size += sizeof(ulong);
    break;
  }
  }
  return size;
}

int fd_compute_budget_program_instruction_inner_encode(fd_compute_budget_program_instruction_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_compute_budget_program_instruction_request_units_deprecated_encode(&self->request_units_deprecated, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 1: {
    err = fd_bincode_uint32_encode(&self->request_heap_frame, ctx);
  if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 2: {
    err = fd_bincode_uint32_encode(&self->set_compute_unit_limit, ctx);
  if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 3: {
    err = fd_bincode_uint64_encode(&self->set_compute_unit_price, ctx);
  if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_compute_budget_program_instruction_encode(fd_compute_budget_program_instruction_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode(&self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_compute_budget_program_instruction_inner_encode(&self->inner, self->discriminant, ctx);
}

int fd_config_keys_decode(fd_config_keys_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_compact_u16_decode(&self->keys_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->keys_len != 0) {
    self->keys = (fd_config_keys_pair_t*)(*ctx->allocf)(ctx->allocf_arg, FD_CONFIG_KEYS_PAIR_ALIGN, FD_CONFIG_KEYS_PAIR_FOOTPRINT*self->keys_len);
    for (ulong i = 0; i < self->keys_len; ++i) {
      fd_config_keys_pair_new(self->keys + i);
    }
    for (ulong i = 0; i < self->keys_len; ++i) {
      err = fd_config_keys_pair_decode(self->keys + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else
    self->keys = NULL;
  return FD_BINCODE_SUCCESS;
}
void fd_config_keys_new(fd_config_keys_t* self) {
  self->keys = NULL;
}
void fd_config_keys_destroy(fd_config_keys_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->keys) {
    for (ulong i = 0; i < self->keys_len; ++i)
      fd_config_keys_pair_destroy(self->keys + i, ctx);
    (*ctx->freef)(ctx->freef_arg, self->keys);
    self->keys = NULL;
  }
}

void fd_config_keys_walk(fd_config_keys_t* self, fd_walk_fun_t fun, const char *name, int level) {
  fun(self, name, 32, "fd_config_keys", level++);
  if (self->keys_len != 0) {
    fun(NULL, NULL, 30, "keys", level++);
    for (ulong i = 0; i < self->keys_len; ++i)
      fd_config_keys_pair_walk(self->keys + i, fun, "config_keys_pair", level + 1);
    fun(NULL, NULL, 31, "keys", --level);
  }
  fun(self, name, 33, "fd_config_keys", --level);
}
ulong fd_config_keys_size(fd_config_keys_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  for (ulong i = 0; i < self->keys_len; ++i)
    size += fd_config_keys_pair_size(self->keys + i);
  return size;
}

int fd_config_keys_encode(fd_config_keys_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_compact_u16_encode(&self->keys_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->keys_len != 0) {
    for (ulong i = 0; i < self->keys_len; ++i) {
      err = fd_config_keys_pair_encode(self->keys + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}

#define REDBLK_T fd_serializable_account_storage_entry_t_mapnode_t
#define REDBLK_NAME fd_serializable_account_storage_entry_t_map
#define REDBLK_IMPL_STYLE 2
#include "../../util/tmpl/fd_redblack.c"
#undef REDBLK_T
#undef REDBLK_NAME
long fd_serializable_account_storage_entry_t_map_compare(fd_serializable_account_storage_entry_t_mapnode_t * left, fd_serializable_account_storage_entry_t_mapnode_t * right) {
  return (long)(left->elem.id - right->elem.id);
}
#define REDBLK_T fd_slot_account_pair_t_mapnode_t
#define REDBLK_NAME fd_slot_account_pair_t_map
#define REDBLK_IMPL_STYLE 2
#include "../../util/tmpl/fd_redblack.c"
#undef REDBLK_T
#undef REDBLK_NAME
long fd_slot_account_pair_t_map_compare(fd_slot_account_pair_t_mapnode_t * left, fd_slot_account_pair_t_mapnode_t * right) {
  return (long)(left->elem.slot - right->elem.slot);
}

/* FIXME: SEE ABOVE PUSH */
#pragma GCC diagnostic pop
