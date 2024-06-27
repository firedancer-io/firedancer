#ifndef HEADER_test_fd_zksdk_pubkey_validity_h
#define HEADER_test_fd_zksdk_pubkey_validity_h

#include "../fd_zksdk_private.h"

// TODO: redo valid tx
static char *
tx_pubkey_validity[] = {
  "01",
  "889db173f988ddec50c0a8e6a129cb0cac210d07cffec282059cb1a7f2ebc54b19e4a55d42894b57e1ac0e998c9e06082dfdd5312dc507946574f14d674e1202",
  "01000406",
  "be5b54cdb01762497c7fd98bfcaaec1d2a2cad1c2bb5134857b68f0214935ebb",
  "246965896e3577be29b6edcd2b9a986539ce7a5478e89a029067e3f999b23fb5",
  "06a7d517187bd16635dad40455fdc2c0c124c68f215675a5dbbacb5f08000000",
  "06ddf6e1ee758fde18425dbce46ccddab61afc4d83b90d27febdf928d8a18bfc",
  "086375ace2aeea281a6b374d681ba76a53ccf638c07455936c05d06540000000", // ZkE1Gama1Proof11111111111111111111111111111
  "cf7750285c0660c154942d49cf8934e2f40edd6778f5fca9cefb0bbb18724efd",
  "fb81cf5f4112351e362f0679316428eaa27425b807e8e7e72e904aa7f34b9f9b",
  "02",
  "0304010502002f",
  "1b0226176edc264a8784a31e4a515baf1c76986700606d1b2924f9dc4124b8bcc412f47d158f000001000000000001",
  "040061",
  "04", // VerifyPubkeyValidity
  "fa89ae0c8312aba69e727036a794b5add351b020e43c65ea94cdda8d8f8c2037", // context
  "80395515497f92fa09ebdb5f14b7f6b32ab8abc3bf7349394b538fb3959c8c4b", // proof
  "0e5cdb1f8f9aeb2fd374b89beafaf2f47a0b83558a7ef94629b07101f50b0007",
};

const ulong instr_offset_pubkey_validity = 351;

#endif /* HEADER_test_fd_zksdk_pubkey_validity_h */
