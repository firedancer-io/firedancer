/*
  Generic poseidon implementation based on https://docs.rs/crate/light-poseidon/0.1.2/source/src/lib.rs
*/
  
extern "C" {
#include "fd_poseidon.h"
}
#include "fd_poseidon_params.hxx"
#include <libff/algebra/curves/alt_bn128/alt_bn128_init.hpp>

/*
static void
dump_state(const std::vector<fd_poseidon_field>& state) {
  uint j = 0;
  for (auto& i : state) {
    auto bi = i.as_bigint();
    FD_LOG_NOTICE(("%u: [%lu,%lu,%lu,%lu]", j++, bi.data[0], bi.data[1], bi.data[2], bi.data[3]));
  }
}
*/

/* Add constants to state */
static void
apply_ark(std::vector<fd_poseidon_field>& state, const fd_poseidon_params * params, ulong round) {
  for (ulong i = 0; i < params->width_; ++i)
    state[i] += params->ark_[round * params->width_ + i];
}

/* Raise all state fields to a power */
static void
apply_sbox_full(std::vector<fd_poseidon_field>& state, const fd_poseidon_params * params) {
  for (ulong i = 0; i < params->width_; ++i) {
    state[i] = libff::power(state[i], params->alpha_);
  }
}

/* Raise first state field to a power */
static void
apply_sbox_partial(std::vector<fd_poseidon_field>& state, const fd_poseidon_params * params) {
  state[0] = libff::power(state[0], params->alpha_);
}

/* Multiply state vector by a matrix */
static void
apply_mds(std::vector<fd_poseidon_field>& state, const fd_poseidon_params * params) {
  std::vector<fd_poseidon_field> tmp;
  tmp.resize(params->width_);
  for (ulong i = 0; i < params->width_; ++i) {
    fd_poseidon_field x(fd_poseidon_field::zero());
    for (ulong j = 0; j < params->width_; ++j) {
      x += state[j] * params->mds_[i*params->width_ + j];
    }
    tmp[i] = x;
  }
  for (ulong i = 0; i < params->width_; ++i)
    state[i] = tmp[i];
}

/* Swap bytes in a 32-byte big int */
static void
byte_swap_32(uchar * v) {
  for (ulong i = 0; i < FD_POSEIDON_HASH_SIZE/2; ++i) {
    uchar t = v[i];
    v[i] = v[FD_POSEIDON_HASH_SIZE-1U-i];
    v[FD_POSEIDON_HASH_SIZE-1U-i] = t;
  }
}

int
fd_poseidon_hash( const uchar * bytes, ulong bytes_len,
                  int big_endian, fd_poseidon_hash_result_t * result ) {
  static bool didinit = false;
  if (!didinit) {
    libff::init_alt_bn128_params();
    didinit = true;
  }

  // Round up. width is number of fields in the state vector.
  ulong width = 1U + (bytes_len + 31U)/32U;
  const fd_poseidon_params * params = fd_poseidon_params::getParams(width);
  if (params == NULL)
    return -1;

  // Create a vector of fields from the input bytes
  std::vector<fd_poseidon_field> state;
  state.resize(width);
  state[0] = fd_poseidon_field::zero(); // domain_tag, always zero for now
  for (ulong i = 1; i < width; ++i) {
    ulong j = fd_ulong_min(bytes_len, 32U);
    libff::bigint<libff::alt_bn128_r_limbs> bi;
    fd_memcpy(bi.data, bytes, j);
    if (big_endian) {
      byte_swap_32((uchar *)bi.data);
    }
    new (&state[i]) fd_poseidon_field(bi);
    bytes += j;
    bytes_len -= j;
  }

  // Mutate state vector
  auto all_rounds = params->full_rounds_ + params->partial_rounds_;
  auto half_rounds = params->full_rounds_ / 2;

  for (ulong round = 0; round < half_rounds; ++round) {
    apply_ark(state, params, round);
    apply_sbox_full(state, params);
    apply_mds(state, params);
  }

  for (ulong round = half_rounds; round < half_rounds + params->partial_rounds_; ++round) {
    apply_ark(state, params, round);
    apply_sbox_partial(state, params);
    apply_mds(state, params);
  }

  for (ulong round = half_rounds + params->partial_rounds_; round < all_rounds; ++round) {
    apply_ark(state, params, round);
    apply_sbox_full(state, params);
    apply_mds(state, params);
  }

  // The output hash is just the first element of the state vector
  auto bi = state[0].as_bigint();
  fd_memcpy(result->v, bi.data, FD_POSEIDON_HASH_SIZE);
  if (big_endian) {
    byte_swap_32(result->v);
  }

  return 0;
}
