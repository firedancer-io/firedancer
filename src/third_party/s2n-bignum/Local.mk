ifdef FD_HAS_S2NBIGNUM
ifdef FD_HAS_X86
S2N_BIGNUM_ASMS:=\
  x86/curve25519/curve25519_x25519 \
  x86/curve25519/curve25519_x25519_alt \
  x86/curve25519/curve25519_x25519base \
  x86/curve25519/curve25519_x25519base_alt \
  x86/fastmul/bignum_mul_4_8 \
  x86/fastmul/bignum_mul_4_8_alt \
  x86/generic/bignum_demont \
  x86/generic/bignum_modinv \
  x86/generic/bignum_montmul \
  x86/generic/bignum_sub \
  x86/p256/bignum_add_p256 \
  x86/p256/bignum_demont_p256 \
  x86/p256/bignum_demont_p256_alt \
  x86/p256/bignum_mod_n256 \
  x86/p256/bignum_mod_n256_4 \
  x86/p256/bignum_mod_n256_alt \
  x86/p256/bignum_montinv_p256 \
  x86/p256/bignum_montmul_p256 \
  x86/p256/bignum_montmul_p256_alt \
  x86/p256/bignum_montsqr_p256 \
  x86/p256/bignum_montsqr_p256_alt \
  x86/p256/bignum_optneg_p256 \
  x86/p256/bignum_tomont_p256 \
  x86/p256/bignum_tomont_p256_alt \
  x86/p256/p256_montjdouble \
  x86/p256/p256_montjdouble_alt \
  x86/p256/p256_montjmixadd \
  x86/p256/p256_montjmixadd_alt \
  x86/p256/p256_montjscalarmul \
  x86/p256/p256_montjscalarmul_alt \
  x86/p256/p256_scalarmulbase \
  x86/p256/p256_scalarmulbase_alt \
  x86/secp256k1/bignum_add_p256k1 \
  x86/secp256k1/bignum_demont_p256k1 \
  x86/secp256k1/bignum_double_p256k1 \
  x86/secp256k1/bignum_mod_n256k1_4 \
  x86/secp256k1/bignum_montmul_p256k1 \
  x86/secp256k1/bignum_montmul_p256k1_alt \
  x86/secp256k1/bignum_montsqr_p256k1 \
  x86/secp256k1/bignum_montsqr_p256k1_alt \
  x86/secp256k1/bignum_neg_p256k1 \
  x86/secp256k1/bignum_sub_p256k1 \
  x86/secp256k1/bignum_tomont_p256k1 \
  x86/secp256k1/bignum_tomont_p256k1_alt \
  x86/secp256k1/bignum_triple_p256k1 \
  x86/secp256k1/bignum_triple_p256k1_alt \
  x86/sha3/sha3_keccak_f1600
$(call add-asms,$(S2N_BIGNUM_ASMS),fd_ballet)
endif
ifdef FD_HAS_ARM
# __ADX__ is never set on aarch64 so the *_s2n.c wrappers always take
# the _alt redirects; only that variant set is vendored.
S2N_BIGNUM_ASMS:=\
  arm/curve25519/curve25519_x25519_byte_alt \
  arm/curve25519/curve25519_x25519base_byte_alt \
  arm/fastmul/bignum_mul_4_8_alt \
  arm/generic/bignum_demont \
  arm/generic/bignum_modinv \
  arm/generic/bignum_montmul \
  arm/generic/bignum_sub \
  arm/p256/bignum_add_p256 \
  arm/p256/bignum_demont_p256 \
  arm/p256/bignum_mod_n256 \
  arm/p256/bignum_mod_n256_4 \
  arm/p256/bignum_montinv_p256 \
  arm/p256/bignum_montmul_p256_alt \
  arm/p256/bignum_montsqr_p256_alt \
  arm/p256/bignum_optneg_p256 \
  arm/p256/bignum_tomont_p256 \
  arm/p256/p256_montjdouble_alt \
  arm/p256/p256_montjmixadd_alt \
  arm/p256/p256_montjscalarmul_alt \
  arm/p256/p256_scalarmulbase_alt \
  arm/secp256k1/bignum_add_p256k1 \
  arm/secp256k1/bignum_demont_p256k1 \
  arm/secp256k1/bignum_double_p256k1 \
  arm/secp256k1/bignum_mod_n256k1_4 \
  arm/secp256k1/bignum_montmul_p256k1_alt \
  arm/secp256k1/bignum_montsqr_p256k1_alt \
  arm/secp256k1/bignum_neg_p256k1 \
  arm/secp256k1/bignum_sub_p256k1 \
  arm/secp256k1/bignum_tomont_p256k1 \
  arm/secp256k1/bignum_triple_p256k1 \
  arm/sha3/sha3_keccak_f1600
$(call add-asms,$(S2N_BIGNUM_ASMS),fd_ballet)
endif
endif
