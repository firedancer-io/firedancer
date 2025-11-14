FD_STATIC_ASSERT( FD_VINYL_IO_FLAG_BLOCKING==1, unit_test );

#define BCACHE_LG_SZ 24
#define BCACHE_SZ    (1UL<<BCACHE_LG_SZ)

static ulong seq_ancient;
static ulong seq_past;
static ulong seq_present;
static ulong seq_future;

static uchar bcache[ BCACHE_SZ ];

static void
bcache_read( ulong seq0, void * _dst, ulong sz ) {
  if( !sz ) return;

  uchar * dst  = (uchar *)_dst;
  ulong   off  = seq0 & (BCACHE_SZ-1UL);
  ulong   rsz  = fd_ulong_min( sz, BCACHE_SZ - off );

  memcpy( dst, bcache + off, rsz );
  sz -= rsz;
  if( sz ) memcpy( dst + rsz, bcache, sz );
}

static ulong
bcache_append( void const * _src, ulong sz ) {
  ulong seq = seq_future; if( !sz ) return seq;
  seq_future = seq + sz;

  uchar * src  = (uchar *)_src;
  ulong   off  = seq & (BCACHE_SZ-1UL);
  ulong   wsz  = fd_ulong_min( sz, BCACHE_SZ - off );

  memcpy( bcache + off, src, wsz );
  sz -= wsz;
  if( sz ) memcpy( bcache, src + wsz, sz );

  return seq;
}

static ulong
bcache_copy( ulong seq_src0, ulong sz ) {
  ulong seq = seq_future; if( !sz ) return seq;
  seq_future = seq + sz;

  ulong seq_dst0 = seq;
  for(;;) {
    ulong off_src = seq_src0 & (BCACHE_SZ-1UL);
    ulong off_dst = seq_dst0 & (BCACHE_SZ-1UL);
    ulong csz     = fd_ulong_min( sz, BCACHE_SZ - fd_ulong_max( off_src, off_dst ) );
    memcpy( bcache + off_dst, bcache + off_src, csz );
    sz -= csz;
    if( !sz ) break;
    seq_src0 += csz;
    seq_dst0 += csz;
  }

  return seq;
}

static int
bcache_commit( void ) {
  seq_present = seq_future;
  return FD_VINYL_SUCCESS;
}

static ulong
bcache_hint( ulong sz ) {
  (void)sz;
  return seq_future;
}

static void
bcache_forget( ulong seq ) {
  seq_past = seq;
}

static void
bcache_rewind( ulong seq ) {
  seq_ancient = fd_vinyl_seq_lt( seq, seq_ancient ) ? seq : seq_ancient;
  seq_past    = fd_vinyl_seq_lt( seq, seq_past    ) ? seq : seq_past;
  seq_present = seq;
  seq_future  = seq;
}

static int
bcache_sync( void ) {
  seq_ancient = seq_past;
  return FD_VINYL_SUCCESS;
}

static void
test( fd_vinyl_io_t * io,
      fd_rng_t *      rng ) {

  for( ulong rem=1000000UL; rem; rem-- ) {
    FD_TEST( fd_vinyl_io_seq_ancient ( io )==seq_ancient );
    FD_TEST( fd_vinyl_io_seq_past    ( io )==seq_past    );
    FD_TEST( fd_vinyl_io_seq_present ( io )==seq_present );
    FD_TEST( fd_vinyl_io_seq_future  ( io )==seq_future  );

    ulong r = fd_rng_ulong( rng );

    int op = (int)(r & 15UL);
    switch( op ) {

    case 0: { /* append */
      ulong dev_free = BCACHE_SZ - (seq_future-seq_ancient);
      ulong sz       = fd_ulong_min( FD_VINYL_BSTREAM_BLOCK_SZ*fd_rng_coin_tosses( rng ), fd_ulong_min( dev_free, 16384UL ) );

      uchar buf[ 16384 ] __attribute__((aligned(FD_VINYL_BSTREAM_BLOCK_SZ)));

      void * src;
      if( !sz ) src = (void *)fd_rng_ulong( rng );
      else      src = buf, memset( buf, (int)(fd_rng_uint( rng ) & 255U), sz );

      ulong seq_ref  =      bcache_append(     src, sz );
      ulong seq_tst  = fd_vinyl_io_append( io, src, sz );
      FD_TEST( seq_ref==seq_tst );
      break;
    }

    case 1: { /* copy */
      ulong past_sz  = seq_present - seq_past;
      ulong dev_free = BCACHE_SZ - (seq_future-seq_ancient);
      ulong sz       = fd_ulong_min( FD_VINYL_BSTREAM_BLOCK_SZ*fd_rng_coin_tosses( rng ), fd_ulong_min( dev_free, past_sz ) );

      ulong seq;
      if     ( !sz         ) seq = fd_rng_ulong( rng );
      else if( past_sz==sz ) seq = seq_past;
      else seq = seq_past + FD_VINYL_BSTREAM_BLOCK_SZ*fd_rng_ulong_roll( rng, (past_sz-sz)/FD_VINYL_BSTREAM_BLOCK_SZ );

      ulong seq_ref =      bcache_copy(     seq, sz );
      ulong seq_tst = fd_vinyl_io_copy( io, seq, sz );
      FD_TEST( seq_ref==seq_tst );
      break;
    }

    case 2: { /* commit */
      int err_ref =      bcache_commit();
      int err_tst = fd_vinyl_io_commit( io, FD_VINYL_IO_FLAG_BLOCKING );
      FD_TEST( err_ref==err_tst );
      FD_TEST( !err_tst );
      break;
    }

    case 3: { /* hint */
      ulong dev_free = BCACHE_SZ - (seq_future-seq_ancient);
      ulong sz       = fd_ulong_min( FD_VINYL_BSTREAM_BLOCK_SZ*fd_rng_coin_tosses( rng ), dev_free );
      ulong seq_ref  =      bcache_hint(     sz );
      ulong seq_tst  = fd_vinyl_io_hint( io, sz );
      FD_TEST( seq_ref==seq_tst );
      break;
    }

    case 4: { /* forget */
      if( fd_vinyl_seq_ne( seq_present, seq_future ) ) break;
      ulong past_sz = seq_present - seq_past;
      ulong seq     = seq_past + FD_VINYL_BSTREAM_BLOCK_SZ*fd_rng_ulong_roll( rng, 1UL + (past_sz/FD_VINYL_BSTREAM_BLOCK_SZ) );
      /**/ bcache_forget(     seq );
      fd_vinyl_io_forget( io, seq );
      break;
    }

    case 5: { /* rewind */
      if( fd_vinyl_seq_ne( seq_present, seq_future ) ) break;
      ulong seq = seq_present - FD_VINYL_BSTREAM_BLOCK_SZ*fd_rng_coin_tosses( rng );
      /**/ bcache_rewind(     seq );
      fd_vinyl_io_rewind( io, seq );
      break;
    }

    case 6: { /* sync */
      int err_ref =      bcache_sync();
      int err_tst = fd_vinyl_io_sync( io, FD_VINYL_IO_FLAG_BLOCKING );
      FD_TEST( err_ref==err_tst );
      FD_TEST( !err_ref );
      break;
    }

    default: { /* read */
      uchar ref[ 16384 ] __attribute__((aligned(FD_VINYL_BSTREAM_BLOCK_SZ)));
      uchar tst[ 16384 ] __attribute__((aligned(FD_VINYL_BSTREAM_BLOCK_SZ)));

      ulong past_sz = seq_present - seq_past;
      ulong sz      = fd_ulong_min( FD_VINYL_BSTREAM_BLOCK_SZ*fd_rng_coin_tosses( rng ), past_sz );

      ulong seq;
      if     ( !sz         ) seq = fd_rng_ulong( rng );
      else if( past_sz==sz ) seq = seq_past;
      else seq = seq_past + FD_VINYL_BSTREAM_BLOCK_SZ*fd_rng_ulong_roll( rng, (past_sz-sz)/FD_VINYL_BSTREAM_BLOCK_SZ );

      bcache_read( seq, ref, sz );
      if( op>=12 ) fd_vinyl_io_read_imm( io, seq, tst, sz );
      else {
        fd_vinyl_io_rd_t rd[1];

        rd->ctx = r;
        rd->seq = seq;
        rd->dst = tst;
        rd->sz  = sz;

        fd_vinyl_io_read( io, rd );

        fd_vinyl_io_rd_t * _rd;
        FD_TEST( !fd_vinyl_io_poll( io, &_rd, FD_VINYL_IO_FLAG_BLOCKING ) );

        FD_TEST( _rd==rd );
        FD_TEST( rd->ctx==r    );
        FD_TEST( rd->seq==seq  );
        FD_TEST( rd->dst==tst  );
        FD_TEST( rd->sz ==sz   );

        FD_TEST( fd_vinyl_io_poll( io, &_rd, FD_VINYL_IO_FLAG_BLOCKING )==FD_VINYL_ERR_EMPTY );
        FD_TEST( !_rd );
      }
      FD_TEST( !memcmp( ref, tst, sz ) );
      break;
    }

    }
  }

  bcache_commit();
  FD_TEST( !fd_vinyl_io_commit( io, FD_VINYL_IO_FLAG_BLOCKING ) );

  bcache_sync();
  FD_TEST( !fd_vinyl_io_sync( io, FD_VINYL_IO_FLAG_BLOCKING ) );
}
