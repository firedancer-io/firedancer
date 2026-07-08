#!/usr/bin/env bash

# Re-imports the s2n-bignum subset used by Firedancer.
#
# The vendored set is derived mechanically, never hand-edited:
# symbols = ( undefined syms of built libfd_*.a  INTERSECT
#             defined syms of upstream x86 lib )
#           UNION the `#define X X_alt` redirects in the *_s2n.c
#           wrappers (selected when __ADX__ is unset, e.g.
#           -march=haswell), then mapped to one .S file each via
#           S2N_BN_SYMBOL().  s2n-bignum is formally verified;
#           local patches would invalidate the proofs.
#
# ARM: __ADX__ is never defined on aarch64, so the wrappers always
# take the _alt redirects and only that variant set is reachable;
# some arm/ files define both the base symbol and an _alt alias.
#
# To adopt a new s2n-bignum function: add the caller first, rerun
# this script, and commit the newly pulled .S file(s).

set -euo pipefail

cd -- "$( dirname -- "${BASH_SOURCE[0]}" )"

readonly S2N_COMMIT="cba3956c7a20d22f08ef6f49fe162e9d7c07867c"
readonly S2N_URL="https://github.com/awslabs/s2n-bignum"

readonly -a S2N_HDRS=(
  include/s2n-bignum.h
  include/_internal_s2n_bignum.h
  include/_internal_s2n_bignum_x86.h
  include/_internal_s2n_bignum_arm.h
)

readonly -a S2N_FILES=(
  x86/curve25519/curve25519_x25519.S
  x86/curve25519/curve25519_x25519_alt.S
  x86/curve25519/curve25519_x25519base.S
  x86/curve25519/curve25519_x25519base_alt.S
  x86/fastmul/bignum_mul_4_8.S
  x86/fastmul/bignum_mul_4_8_alt.S
  x86/generic/bignum_demont.S
  x86/generic/bignum_modinv.S
  x86/generic/bignum_montmul.S
  x86/generic/bignum_sub.S
  x86/p256/bignum_add_p256.S
  x86/p256/bignum_demont_p256.S
  x86/p256/bignum_demont_p256_alt.S
  x86/p256/bignum_mod_n256.S
  x86/p256/bignum_mod_n256_4.S
  x86/p256/bignum_mod_n256_alt.S
  x86/p256/bignum_montinv_p256.S
  x86/p256/bignum_montmul_p256.S
  x86/p256/bignum_montmul_p256_alt.S
  x86/p256/bignum_montsqr_p256.S
  x86/p256/bignum_montsqr_p256_alt.S
  x86/p256/bignum_optneg_p256.S
  x86/p256/bignum_tomont_p256.S
  x86/p256/bignum_tomont_p256_alt.S
  x86/p256/p256_montjdouble.S
  x86/p256/p256_montjdouble_alt.S
  x86/p256/p256_montjmixadd.S
  x86/p256/p256_montjmixadd_alt.S
  x86/p256/p256_montjscalarmul.S
  x86/p256/p256_montjscalarmul_alt.S
  x86/p256/p256_scalarmulbase.S
  x86/p256/p256_scalarmulbase_alt.S
  x86/secp256k1/bignum_add_p256k1.S
  x86/secp256k1/bignum_demont_p256k1.S
  x86/secp256k1/bignum_double_p256k1.S
  x86/secp256k1/bignum_mod_n256k1_4.S
  x86/secp256k1/bignum_montmul_p256k1.S
  x86/secp256k1/bignum_montmul_p256k1_alt.S
  x86/secp256k1/bignum_montsqr_p256k1.S
  x86/secp256k1/bignum_montsqr_p256k1_alt.S
  x86/secp256k1/bignum_neg_p256k1.S
  x86/secp256k1/bignum_sub_p256k1.S
  x86/secp256k1/bignum_tomont_p256k1.S
  x86/secp256k1/bignum_tomont_p256k1_alt.S
  x86/secp256k1/bignum_triple_p256k1.S
  x86/secp256k1/bignum_triple_p256k1_alt.S
  x86/sha3/sha3_keccak_f1600.S
  arm/curve25519/curve25519_x25519_byte_alt.S
  arm/curve25519/curve25519_x25519base_byte_alt.S
  arm/fastmul/bignum_mul_4_8_alt.S
  arm/generic/bignum_demont.S
  arm/generic/bignum_modinv.S
  arm/generic/bignum_montmul.S
  arm/generic/bignum_sub.S
  arm/p256/bignum_add_p256.S
  arm/p256/bignum_demont_p256.S
  arm/p256/bignum_mod_n256.S
  arm/p256/bignum_mod_n256_4.S
  arm/p256/bignum_montinv_p256.S
  arm/p256/bignum_montmul_p256_alt.S
  arm/p256/bignum_montsqr_p256_alt.S
  arm/p256/bignum_optneg_p256.S
  arm/p256/bignum_tomont_p256.S
  arm/p256/p256_montjdouble_alt.S
  arm/p256/p256_montjmixadd_alt.S
  arm/p256/p256_montjscalarmul_alt.S
  arm/p256/p256_scalarmulbase_alt.S
  arm/secp256k1/bignum_add_p256k1.S
  arm/secp256k1/bignum_demont_p256k1.S
  arm/secp256k1/bignum_double_p256k1.S
  arm/secp256k1/bignum_mod_n256k1_4.S
  arm/secp256k1/bignum_montmul_p256k1_alt.S
  arm/secp256k1/bignum_montsqr_p256k1_alt.S
  arm/secp256k1/bignum_neg_p256k1.S
  arm/secp256k1/bignum_sub_p256k1.S
  arm/secp256k1/bignum_tomont_p256k1.S
  arm/secp256k1/bignum_triple_p256k1.S
  arm/sha3/sha3_keccak_f1600.S
)

tmp="$( mktemp -d "${TMPDIR:-/tmp}/fd-s2n-vendor.XXXXXX" )"
trap 'rm -rf "$tmp"' EXIT

git clone --filter=blob:none "$S2N_URL" "$tmp/s2n"
git -C "$tmp/s2n" checkout "$S2N_COMMIT"

cp "$tmp/s2n/LICENSE" LICENSE
for f in "${S2N_HDRS[@]}" "${S2N_FILES[@]}"; do
  mkdir -p "$( dirname "$f" )"
  cp "$tmp/s2n/$f" "$f"
done

echo "[+] Vendored s2n-bignum files from $S2N_COMMIT"
