#ifndef HEADER_fd_src_ballet_zksdk_instructions_test_fd_zksdk_pubkey_validity_h
#define HEADER_fd_src_ballet_zksdk_instructions_test_fd_zksdk_pubkey_validity_h

#include "../fd_zksdk_private.h"

static char *
tx_pubkey_validity =
  "01"
  "889db173f988ddec50c0a8e6a129cb0cac210d07cffec282059cb1a7f2ebc54b19e4a55d42894b57e1ac0e998c9e06082dfdd5312dc507946574f14d674e1202"
  "01000406"
  "be5b54cdb01762497c7fd98bfcaaec1d2a2cad1c2bb5134857b68f0214935ebb"
  "246965896e3577be29b6edcd2b9a986539ce7a5478e89a029067e3f999b23fb5"
  "06a7d517187bd16635dad40455fdc2c0c124c68f215675a5dbbacb5f08000000"
  "06ddf6e1ee758fde18425dbce46ccddab61afc4d83b90d27febdf928d8a18bfc"
  "086375ace2aeea281a6b374d681ba76a53ccf638c07455936c05d06540000000" // ZkE1Gama1Proof11111111111111111111111111111
  "cf7750285c0660c154942d49cf8934e2f40edd6778f5fca9cefb0bbb18724efd"
  "fb81cf5f4112351e362f0679316428eaa27425b807e8e7e72e904aa7f34b9f9b"
  "02"
  "0304010502002f"
  "1b0226176edc264a8784a31e4a515baf1c76986700606d1b2924f9dc4124b8bcc412f47d158f000001000000000001"
  "040061"
  "04" // VerifyPubkeyValidity
  "8e401e07ff61abd8236f4a086c1e46b9062bc0ba8e45628dce69371d9dd4a234" // context
  "bc7fe833f1b991b5344785ec2c6ab9f6fd984f4d1e5d0f0d2d5d6c1020449a7d" // proof
  "ac16dfe1e004a1039f55419289a783793556f27d627bfc0f1f46f9364cbba20e"
;

const ulong instr_offset_pubkey_validity = 351;

#endif /* HEADER_fd_src_ballet_zksdk_instructions_test_fd_zksdk_pubkey_validity_h */
