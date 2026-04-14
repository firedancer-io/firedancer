/* Precomputed base point table for secp256r1 (P-256).
   Entry i = i*G in Montgomery Jacobian coordinates.
   z = one_mont for entries 1..8; entry 0 is identity (z=0). */
static const fd_secp256r1_point_t fd_secp256r1_base_point_table[9] = {
  { {{{0,0,0,0}}}, {{{0,0,0,0}}}, {{{0,0,0,0}}} },
  { {{{ 0x79e730d418a9143c, 0x75ba95fc5fedb601, 0x79fb732b77622510, 0x18905f76a53755c6 }}}, {{{ 0xddf25357ce95560a, 0x8b4ab8e4ba19e45c, 0xd2e88688dd21f325, 0x8571ff1825885d85 }}}, {{{ 0x0000000000000001, 0xffffffff00000000, 0xffffffffffffffff, 0x00000000fffffffe }}} },
  { {{{ 0x850046d410ddd64d, 0xaa6ae3c1a433827d, 0x732205038d1490d9, 0xf6bb32e43dcf3a3b }}}, {{{ 0x2f3648d361bee1a5, 0x152cd7cbeb236ff8, 0x19a8fb0e92042dbe, 0x78c577510a5b8a3b }}}, {{{ 0x0000000000000001, 0xffffffff00000000, 0xffffffffffffffff, 0x00000000fffffffe }}} },
  { {{{ 0xffac3f904eebc127, 0xb027f84a087d81fb, 0x66ad77dd87cbbc98, 0x26936a3fb6ff747e }}}, {{{ 0xb04c5c1fc983a7eb, 0x583e47ad0861fe1a, 0x788208311a2ee98e, 0xd5f06a29e587cc07 }}}, {{{ 0x0000000000000001, 0xffffffff00000000, 0xffffffffffffffff, 0x00000000fffffffe }}} },
  { {{{ 0x74b0b50d46918dcc, 0x4650a6edc623c173, 0x0cdaacace8100af2, 0x577362f541b0176b }}}, {{{ 0x2d96f24ce4cbaba6, 0x17628471fad6f447, 0x6b6c36dee5ddd22e, 0x84b14c394c5ab863 }}}, {{{ 0x0000000000000001, 0xffffffff00000000, 0xffffffffffffffff, 0x00000000fffffffe }}} },
  { {{{ 0xbe1b8aaec45c61f5, 0x90ec649a94b9537d, 0x941cb5aad076c20c, 0xc9079605890523c8 }}}, {{{ 0xeb309b4ae7ba4f10, 0x73c568efe5eb882b, 0x3540a9877e7a1f68, 0x73a076bb2dd1e916 }}}, {{{ 0x0000000000000001, 0xffffffff00000000, 0xffffffffffffffff, 0x00000000fffffffe }}} },
  { {{{ 0x403947373e77664a, 0x55ae744f346cee3e, 0xd50a961a5b17a3ad, 0x13074b5954213673 }}}, {{{ 0x93d36220d377e44b, 0x299c2b53adff14b5, 0xf424d44cef639f11, 0xa4c9916d4a07f75f }}}, {{{ 0x0000000000000001, 0xffffffff00000000, 0xffffffffffffffff, 0x00000000fffffffe }}} },
  { {{{ 0x0746354ea0173b4f, 0x2bd20213d23c00f7, 0xf43eaab50c23bb08, 0x13ba5119c3123e03 }}}, {{{ 0x2847d0303f5b9d4d, 0x6742f2f25da67bdd, 0xef933bdc77c94195, 0xeaedd9156e240867 }}}, {{{ 0x0000000000000001, 0xffffffff00000000, 0xffffffffffffffff, 0x00000000fffffffe }}} },
  { {{{ 0x27f14cd19499a78f, 0x462ab5c56f9b3455, 0x8f90f02af02cfc6b, 0xb763891eb265230d }}}, {{{ 0xf59da3a9532d4977, 0x21e3327dcf9eba15, 0x123c7b84be60bbf0, 0x56ec12f27706df76 }}}, {{{ 0x0000000000000001, 0xffffffff00000000, 0xffffffffffffffff, 0x00000000fffffffe }}} },
};
