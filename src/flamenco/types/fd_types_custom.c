#ifndef SOURCE_fd_src_flamenco_types_fd_types_c
#error "fd_types_custom.c is part of the fd_types.c compile uint"
#endif /* !SOURCE_fd_src_flamenco_types_fd_types_c */

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
  self->slots_per_epoch = 0;
  self->leader_schedule_slot_offset = 0;
  self->warmup = 0;
  memset( self->_pad11, 0, 7UL );
  self->first_normal_epoch = 0;
  self->first_normal_slot = 0;
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
