/* Private header */

#include <vector>
#include <libff/algebra/curves/alt_bn128/alt_bn128_fields.hpp>
#include "../../util/fd_util.h"

/* Assume bn254 field */
typedef libff::alt_bn128_Fr fd_poseidon_field;

/* Parameters needed for the poseidon hash. See https://github.com/Lightprotocol/light-poseidon/blob/v0.1.2/light-poseidon/src/lib.rs#L170 */
class fd_poseidon_params {
  public:
    fd_poseidon_params() = default;
    ~fd_poseidon_params() = default;

    fd_poseidon_params(const fd_poseidon_params&) = delete;
    fd_poseidon_params(fd_poseidon_params&&) = delete;

    ulong width_;
    std::vector<fd_poseidon_field> ark_;
    std::vector<fd_poseidon_field> mds_;
    ulong full_rounds_;
    ulong partial_rounds_;
    ulong alpha_;

    /* Retrieve the parameters for a given input width (number of
       fields in the state). Returns NULL on failure. */
    static const fd_poseidon_params * getParams(ulong width);
};
