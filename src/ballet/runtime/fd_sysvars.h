#ifndef HEADER_fd_src_ballet_runtime_fd_sysvars_h
#define HEADER_fd_src_ballet_runtime_fd_sysvars_h

#include "../fd_ballet_base.h"

FD_PROTOTYPES_BEGIN

/* ####### Clock SysVar ####### */

typedef ulong fd_unix_timestamp_t;
typedef ulong fd_slot_t;
typedef ulong fd_epoch_t;

FD_FN_UNUSED static uchar fd_sysvar_clock_account_pubkey[] = { 0x06, 0xA7, 0xD5, 0x17, 0x18, 0xC7, 0x74, 0xC9, 0x28, 0x56, 0x63, 0x98, 0x69, 0x1D, 0x5E, 0xB6,
                                                               0x8B, 0x5E, 0xB8, 0xA3, 0x9B, 0x4B, 0x6D, 0x5C, 0x73, 0x55, 0x5B, 0x21, 0x00, 0x00, 0x00, 0x00 };
 
/* A representation of network time */
struct fd_clock_data {
  /* The current Slot. */
  fd_slot_t slot;
  /* Timestamp of the first Slot in this Epoch. */
  fd_unix_timestamp_t epoch_start_timestamp;
  /* The current Epoch */
  fd_epoch_t epoch;
  /* The future `Epoch` for which the leader schedule has most recently been calculated. */
  fd_epoch_t leader_schedule_epoch;
  /* The approximate real world time of the current slot */
  fd_unix_timestamp_t unix_timestamp;
};
typedef struct fd_clock_data fd_clock_data_t;

/* ####### SlotHashes SysVar ####### */

FD_FN_UNUSED static uchar fd_sysvar_slothashes_account_pubkey[]   = { 0x06, 0xA7, 0xD5, 0x17, 0x18, 0x75, 0xF7, 0x29, 0xC7, 0x3D, 0x93, 0x40, 0x8F, 0x21, 0x61, 0x20,
                                                                      0x06, 0x7E, 0xD8, 0x8C, 0x76, 0xE0, 0x8C, 0x28, 0x7F, 0xC1, 0x94, 0x60, 0x00, 0x00, 0x00, 0x00 };

// struct fd_slothash {
//   fd_slot_t slot;
//   uchar[32] hash;
// };

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_runtime_fd_sysvars_h */
