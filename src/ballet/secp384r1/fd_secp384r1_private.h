#ifndef HEADER_fd_src_ballet_secp384r1_fd_secp384r1_private_h
#define HEADER_fd_src_ballet_secp384r1_fd_secp384r1_private_h

#include "fd_secp384r1.h"
#include "../bigint/fd_uint384.h"

FD_PROTOTYPES_BEGIN

typedef fd_uint384_t fd_secp384r1_fp_t;
typedef fd_uint384_t fd_secp384r1_scalar_t;

struct fd_secp384r1_point {
  fd_secp384r1_fp_t x[1];
  fd_secp384r1_fp_t y[1];
  fd_secp384r1_fp_t z[1];
};
typedef struct fd_secp384r1_point fd_secp384r1_point_t;

static const fd_uint384_t fd_secp384r1_const_zero[1] = {{{
  0, 0, 0, 0, 0, 0,
}}};

/* p = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF */
static const fd_secp384r1_fp_t fd_secp384r1_const_p[1] = {{{
  0x00000000FFFFFFFF, 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFE,
  0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
}}};

/* 1 in Montgomery form: R mod p */
static const fd_secp384r1_fp_t fd_secp384r1_const_one_mont[1] = {{{
  0xFFFFFFFF00000001UL, 0x00000000FFFFFFFFUL, 0x0000000000000001UL,
  0x0000000000000000UL, 0x0000000000000000UL, 0x0000000000000000UL,
}}};

/* a = -3 in Montgomery form */
static const fd_secp384r1_fp_t fd_secp384r1_const_a_mont[1] = {{{
  0x00000003FFFFFFFCUL, 0xFFFFFFFC00000000UL, 0xFFFFFFFFFFFFFFFBUL,
  0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL,
}}};

/* b in Montgomery form  */
static const fd_secp384r1_fp_t fd_secp384r1_const_b_mont[1] = {{{
  0x081188719D412DCCUL, 0xF729ADD87A4C32ECUL, 0x77F2209B1920022EUL,
  0xE3374BEE94938AE2UL, 0xB62B21F41F022094UL, 0xCD08114B604FBFF9UL,
}}};

/* n (curve order, NOT Montgomery) */
static const fd_secp384r1_scalar_t fd_secp384r1_const_n[1] = {{{
  0xECEC196ACCC52973UL, 0x581A0DB248B0A77AUL, 0xC7634D81F4372DDFUL,
  0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL,
}}};

/* (n-1)/2 for low-S check */
static const fd_secp384r1_scalar_t fd_secp384r1_const_n_m1_half[1] = {{{
  0x76760CB5666294B9UL, 0xAC0D06D9245853BDUL, 0xE3B1A6C0FA1B96EFUL,
  0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL, 0x7FFFFFFFFFFFFFFFUL,
}}};

/* Generator G in Jacobian Montgomery form (Gx_mont, Gy_mont, 1_mont).
   18 ulongs = 3 coords * 6 limbs. */
static const ulong fd_secp384r1_const_g_mont[18] = {
  /* Gx in Montgomery form */
  0x3DD0756649C0B528UL, 0x20E378E2A0D6CE38UL, 0x879C3AFC541B4D6EUL,
  0x6454868459A30EFFUL, 0x812FF723614EDE2BUL, 0x4D3AADC2299E1513UL,
  /* Gy in Montgomery form */
  0x23043DAD4B03A4FEUL, 0xA1BFA8BF7BB4A9ACUL, 0x8BADE7562E83B050UL,
  0xC6C3521968F4FFD9UL, 0xDD8002263969A840UL, 0x2B78ABC25A15C5E9UL,
  /* Gz = 1 in Montgomery form */
  0xFFFFFFFF00000001UL, 0x00000000FFFFFFFFUL, 0x0000000000000001UL,
  0x0000000000000000UL, 0x0000000000000000UL, 0x0000000000000000UL,
};

FD_PROTOTYPES_END

#include "fd_secp384r1_s2n.c"

#endif
