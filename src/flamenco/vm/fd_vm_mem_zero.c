
/* Zeros memory from START_ADDR to [START_ADDR+SZ) based on the bitmap.
   Optimized for <= 4k pages and AVX512.  Does not handle
   FD_VM_MEM_IGNORE_HIGH, but handles other cases.  Depends on
   base_addr. */

do {

#if FD_HAS_AVX512
  wwb_t zero = wwb_zero();
#elif FD_HAS_AVX
  wb_t  zero = wb_zero();
#endif

  /* ZERO_PAGE(x) zeros at least the FD_VM_MEM_PAGE_SZ+7 bytes starting
     at haddr x (this is so that writes only need to set 1 bit even if
     they cross pages) */
#if FD_HAS_AVX512
#  define ZERO_64(x) wwb_stu( x, zero )
#  define ZERO_7(x)  wwb_stu( x, zero )
#elif FD_HAS_AVX
#  define ZERO_64(x) do{ wb_stu( x, zero ); wb_stu( (x)+32UL, zero ); } while( 0 )
#  define ZERO_7(x)  wb_stu( x, zero );
#else
#  define ZERO_64(x) memset( x, '\0', 64UL );
#  define ZERO_7(x)  memset( x, '\0',  7UL );
#endif

#if FD_VM_MEM_PAGE_SZ==64
#  define ZERO_PAGE_(x) do{ ZERO_64(x); ZERO_7( (x)+64UL ); } while( 0 )
#elif FD_VM_MEM_PAGE_SZ==128
#  define ZERO_PAGE_(x) do{ ZERO_64(x); ZERO_64( (x)+64UL ); ZERO_7( (x)+128UL ); } while( 0 )
#elif FD_VM_MEM_PAGE_SZ==256
#  define ZERO_PAGE_(x) do{ ZERO_64(x);           ZERO_64( (x)+ 64UL );                                   \
                            ZERO_64( (x)+128UL ); ZERO_64( (x)+192UL ); ZERO_7( (x)+256UL ); } while( 0 )
#else
#error "PAGE_SZ not configured"
#endif

#if !FD_VM_MEM_IGNORE_HIGH
#  define ZERO_PAGE(x) ZERO_PAGE_(x)
#else
#  define ZERO_PAGE(x) do { ZERO_PAGE_( (x)+0x200000000UL ); ZERO_PAGE_( (x)+0x300000000UL ); } while( 0 )
#endif


#define PAGE_CNT (SZ/FD_VM_MEM_PAGE_SZ)
#if PAGE_CNT % 512UL != 0UL
#error "This code requires SZ to be a multiple of 512*FD_VM_MEM_PAGE_SZ"
#endif


#if FD_HAS_AVX512 && !FD_VM_MEM_ONE_BYTE_PER_PAGE && (PAGE_CNT<=4096)
  /* Need to zero up to 4096 pages of memory, most of which is already
     zero, especially the high half of the stack, the stack gaps (for
     now), and anything past the default heap size.  We already have the
     dirty bitmap, which helps a lot.  We'll build a second layer bitmap
     to further accelerate skipping clean regions.

     The second layer bitmap can be at most 64 bits so that we can use
     find_lsb on it (it's a lot slower with uint128).   We can compress
     it by a factor of R (= 8, 16, 32, or 64) with
     _mm512_test_epi{R}_mask.  Each bit in the second layer bitmap then
     corresponds to R bits of the normal bitmap.  There's no benefit to
     compressing less than 32, but if we have to compress it more than
     32, we have to use the slightly slower expansion path. */
#  if PAGE_CNT<=32*64 /* <= 2k, R=32 */
  uint * u_bitmap  = (uint *)(base_addr + FD_VM_MEM_DIRTY_OFFSET + START_ADDR/(8*FD_VM_MEM_PAGE_SZ));
  ulong l2_bitmap = 0UL;
  for( ulong i=0UL; i<(PAGE_CNT/512UL); i++ ) { /* At most 4 iterations, known statically */
    /* Load 64 bytes (16 uints), compress to 16 bits */
    wwu_t bitmap = wwu_ldu( u_bitmap + 16UL*i );
    l2_butmap |= ((ulong)_mm512_test_epi32_mask( bitmap, bitmap ))<<(16UL*i);
  }

  static ushort const _ii[32] __attribute__((aligned(64))) = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,
                                                              16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31 };
  wwh_t ii          = wwh_ld( _ii );

#  else /* R=64 */
  ulong * u_bitmap = (ulong *)(base_addr + FD_VM_MEM_DIRTY_OFFSET + START_ADDR/(8*FD_VM_MEM_PAGE_SZ));
  for( ulong i=0UL; i<(PAGE_CNT/512UL); i++ ) { /* At most 8 iterations, known statically */
    /* Load 64 bytes (8 ulongs), compress to 8 bits */
    wwu_t bitmap = wwu_ldu( u_bitmap + 8UL*i );
    l2_butmap |= ((ulong)_mm512_test_epi64_mask( bitmap, bitmap ))<<( 8UL*i);
  }

  wwb_t ii = wwb(  0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,
                  16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,
                  32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,
                  48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63 );
#  endif

  ushort pages_to_zero[ PAGE_CNT + 32UL ] __attribute__((aligned(64)));
  ulong nz_page_cnt = 0UL;
  while( l2_bitmap ) {
    ulong l2_idx = (ulong)fd_ulong_find_lsb( l2_bitmap );
    l2_bitmap = fd_ulong_pop_lsb( l2_bitmap );

#  if PAGE_CNT<=32*64 /* <= 2k, R=32 */
    uint l1_word = u_bitmap[ l2_idx ]; /* the l2 bitmap ensures this is not 0 */
    wwh_t idx = wwh_add( ii, wwh_bcast( l2_idx*32UL ) ); /* Gives the page indices that correspond to the bits in l1_word */
    wwh_stu( pages_to_zero+nz_page_cnt, _mm512_maskz_compress_epi16( (__mmask32)l1_word, idx ) );
    ulong cnt = fd_uint_popcnt( l1_word );
#  else
    /* This is the trickier case.  We can't store the full page size in
       a uchar, but it's quite rare to have >32 dirty pages out of 64 on
       the stack. */
    ulong l1_word  = u_bitmap[ l2_idx ]; /* the l2 bitmap ensures this is not 0 */
    wwb_t selected = _mm512_maskz_compress_epi8( (__mmask64)l1_word, ii );
    wwh_t idx_lo   = wwh_add( _mm512_cvtepu8_epi16( _mm512_castsi512_si256( selected ) ), wwh_bcast( 64UL*i ) );
    wwh_stu( pages_to_zero+nz_page_cnt, idx_lo );
    ulong cnt = (ulong)fd_ulong_popcnt( l1_word );
    if( FD_UNLIKELY( cnt>32UL ) ) {
      wwh_t idx_hi = wwh_add( _mm512_cvtepu8_epi16( _mm512_extracti64x4_epi64( selected, 1 ) ), wwh_bcast( 64UL*i ) );
      wwh_stu( pages_to_zero+nz_page_cnt+32UL, idx_hi );
    }
#  endif

    nz_page_cnt += cnt;
  }

  memset( u_bitmap, '\0', PAGE_CNT/8UL );

  /* This branch is going to be tough to predict, but we're pretty much
     bound to have one somewhere. */
  for( ulong k=0UL; k<nz_page_cnt; k++ ) {
    uchar * p = (uchar *)(base_addr + START_ADDR + ((ulong)pages_to_zero[k]*FD_VM_MEM_PAGE_SZ));
    ZERO_PAGE( p );
  }

#elif FD_HAS_AVX512 && FD_VM_MEM_ONE_BYTE_PER_PAGE
  /* In the one byte per page mode, we need a slightly different (and
     sadly slower) approach.  This one omits the second layer bitmap. */

  wwb_t ii = wwb(  0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,
                  16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,
                  32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,
                  48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63 );

  ushort pages_to_zero[ PAGE_CNT + 32UL ] __attribute__((aligned(64)));
  ulong nz_page_cnt = 0UL;

  uchar * u_bitmap = (uchar *)(base_addr + FD_VM_MEM_DIRTY_OFFSET + START_ADDR/(FD_VM_MEM_PAGE_SZ));

  for( ulong i=0UL; i<PAGE_CNT/64UL; i++ ) {
    wwb_t     mask_vec = wwb_ldu( u_bitmap + 64UL*i );
    /* Compress 1 byte/page -> 1 bit/page in the mask register */
    __mmask64 k        = _mm512_test_epi8_mask( mask_vec, mask_vec );
    wwb_t     selected = _mm512_maskz_compress_epi8( k, ii );
    /* We can't represent the page index in a uchar, but it's highly
       unlikely that k had more than 32 bits set, so we take it as a
       predictable branch. */
    wwh_t    offset      = wwh_bcast( (ushort)(64UL*i) );
    wwh_t    selected_lo = wwh_add( _mm512_cvtepu8_epi16( _mm512_castsi512_si256( selected ) ), offset );
    wwh_stu( pages_to_zero+nz_page_cnt, selected_lo );

    ulong cnt = (ulong)fd_ulong_popcnt( (ulong)k );
    if( FD_UNLIKELY( cnt>32UL ) ) {
      wwh_t selected_hi = wwh_add( _mm512_cvtepu8_epi16( _mm512_extracti64x4_epi64( selected, 1 ) ), offset );
      wwh_stu( pages_to_zero+nz_page_cnt+32UL, selected_hi );
    }
    nz_page_cnt += cnt;
  }

  for( ulong k=0UL; k<nz_page_cnt; k++ ) {
    uchar * p = (uchar *)(base_addr + START_ADDR + ((ulong)pages_to_zero[k]*FD_VM_MEM_PAGE_SZ));
    ZERO_PAGE( p );
    u_bitmap[ pages_to_zero[ k ] ] = 0;
  }
#else
/* The generic implementation */
#  if FD_VM_MEM_ONE_BYTE_PER_PAGE
  ulong * u_bitmap  = (ulong *)(base_addr + FD_VM_MEM_DIRTY_OFFSET + START_ADDR/(    FD_VM_MEM_PAGE_SZ));
  /* Each iteration covers 64 pages */
  ulong   iters     = PAGE_CNT/64UL;
  int     bit_scale = 1;
#  else
  ulong * u_bitmap  = (ulong *)(base_addr + FD_VM_MEM_DIRTY_OFFSET + START_ADDR/(8UL*FD_VM_MEM_PAGE_SZ));
  /* Each iteration covers 8 pages */
  ulong   iters     = PAGE_CNT/8UL;
  int     bit_scale = 8;
#  endif

  for( ulong outer=0UL; outer<iters; outer++ ) {
    ulong word = u_bitmap[outer];
    while( word ) {
      int inner = fd_ulong_find_lsb( word )/bit_scale;
      ZERO_PAGE( (uchar *)(base_addr + START_ADDR + FD_VM_MEM_PAGE_SZ*(outer*(64UL/bit_scale)+inner)) );
      word = fd_ulong_pop_lsb( word );
    }
    u_bitmap[outer] = 0UL;
  }
#endif

} while( 0 );

#undef PAGE_CNT
#undef START_ADDR
#undef SZ

#undef ZERO_64
#undef ZERO_7
#undef ZERO_PAGE_
#undef ZERO_PAGE
