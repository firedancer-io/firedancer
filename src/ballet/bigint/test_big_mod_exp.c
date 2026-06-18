#include "fd_big_mod_exp.h"

#if !FD_HAS_S2NBIGNUM

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  FD_LOG_WARNING(( "skip: test requires s2n-bignum (FD_HAS_S2NBIGNUM)" ));
  fd_halt();
  return 0;
}

#else

/* hex -> bytes (lowercase or uppercase), returns byte count. */
static ulong
hex2buf( char const * hex,
         uchar *      out ) {
  ulong n = strlen( hex );
  FD_TEST( (n & 1UL)==0UL );
  ulong cnt = n/2UL;
  for( ulong i=0UL; i<cnt; i++ ) {
    char c0 = hex[2*i], c1 = hex[2*i+1];
    int v0 = (c0>='0'&&c0<='9')?(c0-'0'):((c0|32)-'a'+10);
    int v1 = (c1>='0'&&c1<='9')?(c1-'0'):((c1|32)-'a'+10);
    out[i] = (uchar)((v0<<4)|v1);
  }
  return cnt;
}

/* SUCCESS vectors, little-endian hex.  Computed with an independent
   reference (Python pow()); all moduli are odd and > 1 as required by
   SIMD-0529.  "solana-vec2" / "5^2 mod 7" are the two odd-modulus cases
   from the upstream solana-big-mod-exp test data (re-encoded to LE). */
static char const * const success_vec[][5] = {
  /* name, base, exponent, modulus, expected (all little-endian hex) */
  { "5^2 mod 7 (solana vec6)",
    "05", "02", "07", "04" },
  { "exp=0 -> 1",
    "87d61200", "00", "fbffffff", "01000000" },
  { "exp=1 reduction",
    "9a78563412000000", "01", "9b", "14" },
  { "base>modulus",
    "fecaefbeadde0000", "05", "0101", "1f00" },
  { "rsa-ish small",
    "01000100", "01000100", "01eeffc0", "61a7e295" },
  { "solana-vec2 (base=2*mod)",
    "2222222222222222222222222222222222222222222222222222222222222222",
    "2222222222222222222222222222222222222222222222222222222222222222",
    "1111111111111111111111111111111111111111111111111111111111111111",
    "0000000000000000000000000000000000000000000000000000000000000000" },
  { "exp_len>mod_len (64B exp, 8B mod)",
    "d11a6706fb40d6bd",
    "57526846903bb13ede562439e9c1b823a96089bca71f3d1a6d2d3cadb3669cbd50e165e434249d8b829f411669842a979911036cf3e822086ecaa0075a69fc17",
    "9d79b1a37f31801c",
    "66cca8e1d992f911" },
  { "base_len>mod_len (32B base, 4B mod)",
    "8ba8f83718aa8f3bd1f65e8144e61d9ab30fcb06a6c1ad8f2906e732b10f4db7",
    "3930", "89d35ea6", "d1444c99" },
  { "256-bit random",
    "f47e06e7d0ba020f88a8252ae361046127418d0048333dfc24aef263fc58e443",
    "cf4930edc6d9b8c8cd3cfec8ba6d7b74f2170649ea374a6c18d253b2c3c412f5",
    "776502bb7d05d4fe8e618ac834d5468ee16570a9ca9ae9b7797f967cd7c3a027",
    "055b32b7ff1b7669d1706adb98b2f77019c3466177de0618cab8a766fd911819" },
  { "max 512B operands",
    "8c088ab3f648818ba4a6656be0cb6e382a5dff72ac1dda96908137478bd536cf4b778ade1fe7a9010b3341c2bd2b4acec46edf287a43b9b21175306c76a81a57899322473081cd277bcd1e3763ea0bf5ee5974c3790f2b56ed732a1a1131be177dea42619767c2188e12e65b1364f5d8717b0d5803ca8d9aa6a3b7437ff59fce63911f0bd0b3cfba66de9c75853e4689789bf41f4c1d1ef9a18c1bec13a1e760e83f2c14f188528d41bb0d4b32dd53d4ae89eea07a4f579e2ff7ace2c1d298dcf01c945cbf59cd932cd33931f0d15eb4d25dce119925bb0b998d48a98e8a573a8acee7c54d54154a4c7a37fc313f6d14261af6daf82e983bb2dfd1ddd03adb19d7f34f613947294793b212742f37bca2de4288d541a4655de9b2a329082ec45e5305f35aae40a235a49990ab85a85844fe7eaab34998c8efd8fafcaeaba5e5a5576f47127302f09be3ef8da201becf2b0764bd88d40da8bacbedab3eefbed42972af5676f7fd2361f34c1b45e66651fda26fe6ec2806d7a3c4612bb03942948e26b338382fe142af7f310453a524c5d7cc32b0c439eea7c60df3510ef9e4a23aaba761d2a3b837084e7b17cefc87c1505bbcb2669eaa8a4481bcf110acf80236e049c3e9e48762f13eb63291eea059e0cf3ac9b7d7ba8e506fb16e3615d4caa7b19ecd7fd02148654d987ae265ca1feab2f091a4a9507775833b9324de2fcf43",
    "1dd0be23f8fa223f1999b7be7bd2b58f686afa89bc084343064c3cbf796da795c7d6ad6d75b8d7e5f0696295971c3f6697ccab5cb8672538e4bd50fff09f5eff84b56923a8507082df0d577ed8d645178af07ac195d10f0c963d71dc35f7111cdf9b2027c44da0a08194f4288cb6c5ca540434aee8ac126c3443ae98105a4310451c806222cdb161c9248c9899cf01ff021ed277a9097487ecac5c40b99798f85b36a08ded0e5cdc2f2643f1906bf002a70d27aeb93981b84b43531d179284aefd7e81e234e37689108739c0c8a74e44e3e2c2c4931216a46fbd1557e9ae8e1c08d3224b9ac64c6fca067d28a33c277459afd400cc472df47206dbb8ede537e00bfe3cb8e2766d438ba8cdf85f6926806ef40fc33421bc2d1c6df7816ffaa1e95cbd3d1b164edade6eac13a0a8e0664c77a477d7a73192a3d431f681c778e59b89d6eb327d7920276cd1b85f61e833c315475b2962be148a3f8f18f48f1054c7c5a324ec1e42c587dd6322ebd17a2500b46e54993be4fb528543157d826dfc04fb5ca31c3168d9edb54eec5cb0eaf3e08b053efc3908e8d42dcb88ceff3eb94e37bf4c3d1a2fd40ea9c2a93db83cc5e0e24d3e9176476bf2076c29146962ed15cf4b5ebbe1de697c60e6e6d048e9b71100315dfac5d2b6c2666e5f88b4b90dc450d731205d43de200c6ee5a81e1bac79ccac64f2b0edbf8cabc2452a43c0da43",
    "03a115879ac557df26bd499b9fc4526cc07ce0f6216838365e46cdedfb4e0f8a530f59c12ac3dcba5c2a9bb0dfa27e33e6d283b69aa3cc4ffa5b2466be1bc2fe39adf3ab8e685ea6717c985fa1532770cb1b4de6b4d97f848f9894739721fa1e1dbe763fcfc385395c0064109bc68c565980620562669b9603cdcd8d93cce83af202a496b62a60385642d701569a2c126e1035b5b6f68fa1e059120fd4ed9b3ac6254111269bc9e7fbad0a08c11011dc3cf6965413b5231250bc9f832ddfed3c3b494a47a72042abe71f447c3a39d836333c0b8a6f30df212ba22db976dc7def63dbe3e15ae12f92439b8293f9f700792811353e9fd1dcc820c114799d1fb8cef21435685fb4be3054bc25182b75d018fa17b3a8d35e596edf3eb35a11a66f6cbcff3d69b3ed8e77ac6724dd1ab7a4baa629de0d639e61accfdb48a75040f2fb41096ca5eee93119ef4f840f3a301267ab346cba0789dc5671a1f3cc5e9296dc270ef91b04f1a73f000c0c31ef87b130e4054a897d56d872b4fce223616f006c7612f92e19bc4e4715cb6e76bf50f33fbf4fdedf7c225bec926c4c1334047171bb8bdacee75f81dc6ea520dba31ee28ce58b1019585bf30cb8f7f2a6d5f9d0ff81f8638a70e705d6a82bc703832310f8b711e017e96226ed30abe9c0a51f44d9c05d833c625d932a7ac00a6817fa527c3e4e3a7b8124b83671ba59dd8593aa66",
    "f994e2bb9e974327cedbeae4fc8dda76420a80eb92324a834155f5c973e2cea326511d7fa11419757696370735c3b949c50c4b9398a3779027d9c209cb163d5195f0541a4a45bfe9d7a737cb34b77dd231b15b082a327f5c83f5b3d4f5f3286d9e15be87276eda38a966e382e328417eb1e9769c0f6a4d66cc8a6244cc9c6caa8648f7aed22c9ebc5c88418f70b38b9e8ee8f662f08fcad1a2121e6c744c40d48bfe5b3453dd2d8b381fa5393a456c43cbb8014616ae86376a5aa6e9c48c7527019068ca78849e5eb141958f8ffb30ff1d128ab2653e4b33d719ba384bc3bc493e4b51599cfa8803d9f5d762b8074dcb4ffbaffb46113b058cc016030db028fccef91037eb209b1733f44efb9bc064d266ebcf3da198dd029b4e67f4cda31b9bbfa95f8da3015b289d57b4a2c1a2b4f4bb57afd134b05a2f6ec49c0559644762e5adac2b6ccfaf94ba1237613f9275e2a1f4a2b229039c98b60e958e6898730832baba07130c23ba482578382ec144bafcaaf3546745265b1fd626bfd5ea08e43b84b188db7da12e88c404418bb0be71f1a1d9be9d311c9524d1acc333168a47a48d9893222e30ce7996e6fa389e7248cd4b7b62ecce343481021f3ed3b5c10672cd8e166f2dc300e3b2a772c8a82af47234d85a6f6811708244e7e02fb47b5f7267a8982b1486887d239725b2e2255f61f7689dc670682787558483f0a30244" },
};

static void
test_success( void ) {
  ulong n = sizeof(success_vec)/sizeof(success_vec[0]);
  for( ulong i=0UL; i<n; i++ ) {
    char const * name = success_vec[i][0];
    static uchar base[ FD_BIG_MOD_EXP_MAX_BYTES ];
    static uchar exp [ FD_BIG_MOD_EXP_MAX_BYTES ];
    static uchar mod [ FD_BIG_MOD_EXP_MAX_BYTES ];
    static uchar want[ FD_BIG_MOD_EXP_MAX_BYTES ];
    static uchar out [ FD_BIG_MOD_EXP_MAX_BYTES ];
    ulong base_len = hex2buf( success_vec[i][1], base );
    ulong exp_len  = hex2buf( success_vec[i][2], exp  );
    ulong mod_len  = hex2buf( success_vec[i][3], mod  );
    ulong want_len = hex2buf( success_vec[i][4], want );
    FD_TEST( want_len==mod_len );

    fd_memset( out, 0xcc, mod_len );
    int err = fd_big_mod_exp( out, base, base_len, exp, exp_len, mod, mod_len );
    FD_TEST( err==FD_BIG_MOD_EXP_SUCCESS );
    if( FD_UNLIKELY( memcmp( out, want, mod_len ) ) ) {
      FD_LOG_ERR(( "FAIL %s", name ));
    }
    FD_LOG_NOTICE(( "ok: %s", name ));
  }
}

/* Modulus validation: SIMD-0529 requires odd and > 1.  These exercise the
   even-modulus solana vectors (1,3,4,5,7) plus zero and one, which all
   abort under SIMD-0529 (unlike the legacy big-endian syscall, which
   returned zeros for modulus 0/1). */
static void
test_modulus_rejected( void ) {
  /* {modulus little-endian hex, should_be_valid} */
  struct { char const * mod; int valid; } cases[] = {
    { "07",   1 },                                          /* odd 7    */
    { "0101", 1 },                                          /* odd 257  */
    { "9b",   1 },                                          /* odd      */
    { "0a",   0 },                                          /* even 10 (solana vec1 lsb) */
    { "22",   0 },                                          /* even (vec3) */
    { "44",   0 },                                          /* even (vec4) */
    { "66",   0 },                                          /* even (vec5) */
    { "64",   0 },                                          /* even 100 (vec7) */
    { "00",   0 },                                          /* zero (vec8) */
    { "",     0 },                                          /* empty == zero */
    { "01",   0 },                                          /* one  (vec9) */
    { "0100000000000000", 0 },                              /* one, wide */
    { "0000000000000000", 0 },                              /* zero, wide */
    { "0300000000000000", 1 },                              /* odd 3, wide */
    { "fefefefefefefefe", 0 },                              /* even, wide */
  };
  ulong n = sizeof(cases)/sizeof(cases[0]);
  for( ulong i=0UL; i<n; i++ ) {
    static uchar mod[ FD_BIG_MOD_EXP_MAX_BYTES ];
    ulong mod_len = hex2buf( cases[i].mod, mod );
    int got = fd_big_mod_exp_modulus_is_valid( mod, mod_len );
    FD_TEST( got==cases[i].valid );

    if( !cases[i].valid ) {
      /* fd_big_mod_exp must refuse without writing out */
      static uchar base[1] = { 2 };
      static uchar exp [1] = { 3 };
      static uchar out [ FD_BIG_MOD_EXP_MAX_BYTES ];
      int err = fd_big_mod_exp( out, base, 1UL, exp, 1UL, mod, mod_len );
      FD_TEST( err==FD_BIG_MOD_EXP_ERR_MODULUS );
    }
  }
  FD_LOG_NOTICE(( "ok: modulus validation (odd && >1)" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_modulus_rejected();
  test_success();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

#endif
