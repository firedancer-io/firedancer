/* This just contains the #defines that are useful for the keyguard
   tile.  This is in line with our policy of ruthelessly minimizing the
   attack surface of the keyguard tile.  No need for an include guard
   because it's just #defines. */
#define FD_BUNDLE_CRANK_2_SZ 710UL
#define FD_BUNDLE_CRANK_3_SZ 857UL

#define FD_BUNDLE_CRANK_2_IX1_DISC_OFF 670UL
#define FD_BUNDLE_CRANK_2_IX2_DISC_OFF 694UL

#define FD_BUNDLE_CRANK_3_IX1_DISC_OFF 758UL
#define FD_BUNDLE_CRANK_3_IX2_DISC_OFF 817UL
#define FD_BUNDLE_CRANK_3_IX3_DISC_OFF 841UL

#define FD_BUNDLE_CRANK_DISC_INIT_TIP_DISTR 0x78, 0xbf, 0x19, 0xb6, 0x6f, 0x31, 0xb3, 0x37
#define FD_BUNDLE_CRANK_DISC_CHANGE_TIP_RCV 0x45, 0x63, 0x16, 0x47, 0x0b, 0xe7, 0x56, 0x8f
#define FD_BUNDLE_CRANK_DISC_CHANGE_BLK_BLD 0x86, 0x50, 0x26, 0x89, 0xa5, 0x15, 0x72, 0x7b
