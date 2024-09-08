#include "fd_aes_base.h"

union fd_gcm128 {
  struct {
    ulong hi;
    ulong lo;
  };
# if FD_HAS_INT128
  uint128 u128;
# endif
};

typedef union fd_gcm128 fd_gcm128_t;

struct __attribute__((aligned(64UL))) fd_aes_gcm_ref_state {
  /* Offset of Yi, EKi, EK0, len, Xi, H, and Htable is hardcoded in
     asm modules -- Do not change offsets */

  /* Following 6 names follow names in GCM specification */
  union {
    ulong u[ 2];
    uint  d[ 4];
    uchar c[16];
    ulong t[ 2];
  } Yi, EKi, EK0, len, Xi, H;
  fd_gcm128_t Htable[16];

  uint    mres, ares;
  uchar   Xn[48];

  fd_aes_key_ref_t key;
};
typedef struct fd_aes_gcm_ref_state fd_aes_gcm_ref_t;

void
fd_gcm_init_4bit( fd_gcm128_t Htable[16],
                  ulong const H[2] );

void
fd_gcm_gmult_4bit( ulong         Xi[2],
                   fd_gcm128_t const Htable[16] );

void
fd_gcm_ghash_4bit( ulong             Xi[2],
                   fd_gcm128_t const Htable[16],
                   uchar const *     in,
                   ulong             len );
