/* Precomputed base point table for secp256k1.
   Entry i = i*G in plain (non-Montgomery) Jacobian coordinates.
   z = {1,0,0,0} for entries 1..8; entry 0 is identity (z=0). */
static const fd_secp256k1_point_t fd_secp256k1_base_point_table[9] = {
  { {{{0,0,0,0}}}, {{{0,0,0,0}}}, {{{0,0,0,0}}} },
  { {{{ 0x59f2815b16f81798, 0x029bfcdb2dce28d9, 0x55a06295ce870b07, 0x79be667ef9dcbbac }}}, {{{ 0x9c47d08ffb10d4b8, 0xfd17b448a6855419, 0x5da4fbfc0e1108a8, 0x483ada7726a3c465 }}}, {{{1,0,0,0}}} },
  { {{{ 0xabac09b95c709ee5, 0x5c778e4b8cef3ca7, 0x3045406e95c07cd8, 0xc6047f9441ed7d6d }}}, {{{ 0x236431a950cfe52a, 0xf7f632653266d0e1, 0xa3c58419466ceaee, 0x1ae168fea63dc339 }}}, {{{1,0,0,0}}} },
  { {{{ 0x8601f113bce036f9, 0xb531c845836f99b0, 0x49344f85f89d5229, 0xf9308a019258c310 }}}, {{{ 0x6cb9fd7584b8e672, 0x6500a99934c2231b, 0x0fe337e62a37f356, 0x388f7b0f632de814 }}}, {{{1,0,0,0}}} },
  { {{{ 0x74fa94abe8c4cd13, 0xcc6c13900ee07584, 0x581e4904930b1404, 0xe493dbf1c10d80f3 }}}, {{{ 0xcfe97bdc47739922, 0xd967ae33bfbdfe40, 0x5642e2098ea51448, 0x51ed993ea0d455b7 }}}, {{{1,0,0,0}}} },
  { {{{ 0xcba8d569b240efe4, 0xe88b84bddc619ab7, 0x55b4a7250a5c5128, 0x2f8bde4d1a072093 }}}, {{{ 0xdca87d3aa6ac62d6, 0xf788271bab0d6840, 0xd4dba9dda6c9c426, 0xd8ac222636e5e3d6 }}}, {{{1,0,0,0}}} },
  { {{{ 0x2f057a1460297556, 0x82f6472f8568a18b, 0x20453a14355235d3, 0xfff97bd5755eeea4 }}}, {{{ 0x3c870c36b075f297, 0xde80f0f6518fe4a0, 0xf3be96017f45c560, 0xae12777aacfbb620 }}}, {{{1,0,0,0}}} },
  { {{{ 0xe92bddedcac4f9bc, 0x3d419b7e0330e39c, 0xa398f365f2ea7a0e, 0x5cbdf0646e5db4ea }}}, {{{ 0xa5082628087264da, 0xa813d0b813fde7b5, 0xa3178d6d861a54db, 0x6aebca40ba255960 }}}, {{{1,0,0,0}}} },
  { {{{ 0x67784ef3e10a2a01, 0x0a1bdd05e5af888a, 0xaff3843fb70f3c2f, 0x2f01e5e15cca351d }}}, {{{ 0xb5da2cb76cbde904, 0xc2e213d6ba5b7617, 0x293d082a132d13b4, 0x5c4da8a741539949 }}}, {{{1,0,0,0}}} },
};
