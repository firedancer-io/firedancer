#ifndef HEADER_test_fd_zktpp_ciphertext_commitment_equality_h
#define HEADER_test_fd_zktpp_ciphertext_commitment_equality_h

#include "../fd_zktpp_private.h"

static char *
tx_ciphertext_commitment_equality[] = {
  "02",
  "a5af6428daf1acce2f8bb8cd906cfce8e46f0000b4af0a6861666183e37c4b7a0b229079a76ac82d3ec05866b699f0d3a7beb8543b302bb4f7d835868d054007",
  "68cd264d2b7fa32eba645d25bc21e2e2960a7d752df9feddb26b20b4dee049561b4394912cd136733f59407098a589a60bd6a38198f37358d168ef91f71cdf0d",
  "02000204",
  "be5b54cdb01762497c7fd98bfcaaec1d2a2cad1c2bb5134857b68f0214935ebb",
  "3a118f2a5dc4e9c9088bc08cdb6a2086a8cbabff1e8d9b2234e408285c82d945",
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0863ba8dd9c4c2fb174a05cba27e2a2cd623573d79e90b35b579fc0d00000000",
  "02",
  "0202000134",
  "0000000030b11e0000000000a1000000000000000863ba8dd9c4c2fb174a05cba27e2a2cd623573d79e90b35b579fc0d00000000",
  "03020100c102",
  "0b", // VerifyCiphertextCommitmentEquality
  "a0d0383c8e276e1748ac744b7106b4ea8ae1de3fc3879e59a01124209f4a6c05", // context
  "26370b6a3cb238e3483f0ae28526a69178514b37d675b7b3de0f7165c4a2f040",
  "9c91115d5eb91344d9a258f90595e0b3b32dfe578f6cc7e16e6b5450178b7106",
  "eecdd95a6bb91e820534630df811fb98f9cccd092eb6fa96833a35e6564b844d",
  "6afb4b91508834684d8634dae7d95029ef3d3e8f3eb448268de63700c19d1e3a", // proof
  "5a9ef0175d505bd76f7a7f41d458168852aa19e7df1aa0683fa40f659967fd58",
  "f8735fa4d0248594caefa87c51c2d26db33751e8c621069cd06ee80e2324896f",
  "de908da115da638c68e8c23ff382c87f3690ec8cabbf30bb26ab27e22d8be301",
  "3553365bea7ae5dd426e918637cf5a11bd93db01b7c3acc042ff077da3c40407",
  "a61ca96ffb822eed2a0f00e5a16f448837bb2a9165d1ea431569a0936837bf0e",
};

const ulong instr_offset_ciphertext_commitment_equality = 325;
const ulong context_offset_ciphertext_commitment_equality = instr_offset_ciphertext_commitment_equality + 1;
const ulong proof_offset_ciphertext_commitment_equality = context_offset_ciphertext_commitment_equality + 4*32;

#endif /* HEADER_test_fd_zktpp_ciphertext_commitment_equality_h */
