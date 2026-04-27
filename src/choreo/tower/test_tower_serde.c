#include "fd_tower_serde.h"
#include "fd_tower.h"

#include <string.h>

FD_IMPORT_BINARY( vote_acc_v2, "src/choreo/tower/fixtures/vote_acc_v2.bin" );
FD_IMPORT_BINARY( vote_acc_v3, "src/choreo/tower/fixtures/vote_acc_v3.bin" );
FD_IMPORT_BINARY( vote_acc_v4, "src/choreo/tower/fixtures/vote_acc_v4.bin" );

void
test_voter_v1_14_11( void ) {
  fd_vote_acc_t const * voter = (fd_vote_acc_t const *)fd_type_pun_const( vote_acc_v2 );
  FD_TEST( voter->kind == FD_VOTE_ACC_V2 );
  FD_TEST( fd_vote_acc_vote_cnt( vote_acc_v2 ) == 31 );
  FD_TEST( fd_vote_acc_vote_slot( vote_acc_v2 ) != ULONG_MAX );
  FD_TEST( fd_vote_acc_root_slot( vote_acc_v2 ) != ULONG_MAX );
}

void
test_voter_current( void ) {
  fd_vote_acc_t const * voter = (fd_vote_acc_t const *)fd_type_pun_const( vote_acc_v3 );
  FD_TEST( voter->kind == FD_VOTE_ACC_V3 );
  FD_TEST( fd_vote_acc_vote_cnt( vote_acc_v3 ) == 31 );
  FD_TEST( fd_vote_acc_vote_slot( vote_acc_v3 ) != ULONG_MAX );
  FD_TEST( fd_vote_acc_root_slot( vote_acc_v3 ) != ULONG_MAX );
}

/* Helper: serialize a valid CompactTowerSync into buf.  Returns the
   number of bytes written, or 0 on failure.  lockouts_cnt lockouts
   are generated with offset=1 and confirmation_count=cnt-i (cnt..1,
   strictly decreasing, all <= FD_TOWER_VOTE_MAX). */

static ulong
make_valid( uchar * buf, ulong buf_max, ushort lockouts_cnt, int with_timestamp ) {
  fd_compact_tower_sync_serde_t serde[1];
  memset( serde, 0, sizeof(*serde) );
  serde->root         = 42UL;
  serde->lockouts_cnt = lockouts_cnt;
  for( ushort i = 0; i < lockouts_cnt; i++ ) {
    serde->lockouts[i].offset             = 1;
    serde->lockouts[i].confirmation_count = (uchar)(lockouts_cnt - i);
  }
  memset( &serde->hash,     0xAA, sizeof(fd_hash_t) );
  serde->timestamp_option = (uchar)with_timestamp;
  serde->timestamp        = 1234567890L;
  memset( &serde->block_id, 0xBB, sizeof(fd_hash_t) );

  ulong sz = 0;
  if( FD_UNLIKELY( fd_compact_tower_sync_ser( serde, buf, buf_max, &sz ) ) ) return 0;
  return sz;
}

/* Attacker-style tests for fd_compact_tower_sync_de.  Each test crafts
   a specific malicious input and asserts the deserializer rejects it. */

static void
test_de_attacker( void ) {

  fd_compact_tower_sync_serde_t serde[1];
  uchar buf[1024];

  /* Sanity: a valid message round-trips. */

  {
    ulong sz = make_valid( buf, sizeof(buf), 3, 1 );
    FD_TEST( sz );
    FD_TEST( 0==fd_compact_tower_sync_de( serde, buf, sz ) );
    FD_TEST( serde->root==42UL );
    FD_TEST( serde->lockouts_cnt==3 );
  }

  /* Sanity: zero lockouts is valid. */

  {
    ulong sz = make_valid( buf, sizeof(buf), 0, 0 );
    FD_TEST( sz );
    FD_TEST( 0==fd_compact_tower_sync_de( serde, buf, sz ) );
    FD_TEST( serde->lockouts_cnt==0 );
  }

  /* Sanity: max lockouts (31) is valid.  make_valid generates
     confirmation counts descending from lockouts_cnt (first) to
     1 (last). */

  {
    ulong sz = make_valid( buf, sizeof(buf), FD_TOWER_VOTE_MAX, 1 );
    FD_TEST( sz );
    FD_TEST( 0==fd_compact_tower_sync_de( serde, buf, sz ) );
    FD_TEST( serde->lockouts_cnt==FD_TOWER_VOTE_MAX );
    FD_TEST( serde->lockouts[0].confirmation_count==FD_TOWER_VOTE_MAX );
    FD_TEST( serde->lockouts[FD_TOWER_VOTE_MAX-1].confirmation_count==1 );
  }

  /* 1. Empty buffer. */

  FD_TEST( -1==fd_compact_tower_sync_de( serde, buf, 0 ) );

  /* 2. Truncated root (only 7 of 8 bytes). */

  {
    ulong sz = make_valid( buf, sizeof(buf), 1, 0 );
    FD_TEST( sz );
    FD_TEST( -1==fd_compact_tower_sync_de( serde, buf, 7 ) );
  }

  /* 3. Truncated right after root (no lockouts_cnt). */

  {
    ulong sz = make_valid( buf, sizeof(buf), 1, 0 );
    FD_TEST( sz );
    FD_TEST( -1==fd_compact_tower_sync_de( serde, buf, 8 ) );
  }

  /* 4. lockouts_cnt > FD_TOWER_VOTE_MAX (32 encoded as ShortU16). */

  {
    ulong sz = make_valid( buf, sizeof(buf), 1, 0 );
    FD_TEST( sz );
    buf[8] = 32; /* overwrite lockouts_cnt to 32 */
    FD_TEST( -1==fd_compact_tower_sync_de( serde, buf, sz ) );
  }

  /* 5. lockouts_cnt = 0xFFFF (max ShortU16, way over 31). */

  {
    ulong sz = make_valid( buf, sizeof(buf), 1, 0 );
    FD_TEST( sz );
    buf[8] = 0xFF; buf[9] = 0xFF; buf[10] = 0x03;
    FD_TEST( -1==fd_compact_tower_sync_de( serde, buf, sz ) );
  }

  /* 6. Truncated mid-lockout: lockouts_cnt=1 but no offset bytes. */

  {
    ulong sz = make_valid( buf, sizeof(buf), 0, 0 );
    FD_TEST( sz );
    buf[8] = 1; /* overwrite lockouts_cnt to 1 */
    /* buffer ends after lockouts_cnt, no room for offset */
    FD_TEST( -1==fd_compact_tower_sync_de( serde, buf, 9 ) );
  }

  /* 7. timestamp_option = 2 (must be 0 or 1). */

  {
    ulong sz = make_valid( buf, sizeof(buf), 0, 0 );
    FD_TEST( sz );
    /* timestamp_option is right after hash (32 bytes) which is right
       after lockouts_cnt (1 byte for cnt=0) which is right after root
       (8 bytes).  So offset = 8 + 1 + 32 = 41. */
    buf[41] = 2;
    FD_TEST( -1==fd_compact_tower_sync_de( serde, buf, sz ) );
  }

  /* 8. timestamp_option = 0xFF. */

  {
    ulong sz = make_valid( buf, sizeof(buf), 0, 0 );
    FD_TEST( sz );
    buf[41] = 0xFF;
    FD_TEST( -1==fd_compact_tower_sync_de( serde, buf, sz ) );
  }

  /* 9. Truncated: timestamp_option=1 but no timestamp bytes. */

  {
    ulong sz = make_valid( buf, sizeof(buf), 0, 1 );
    FD_TEST( sz );
    /* Truncate right after timestamp_option (remove timestamp + block_id) */
    FD_TEST( -1==fd_compact_tower_sync_de( serde, buf, 42 ) );
  }

  /* 10. Truncated block_id: missing the last byte of block_id. */

  {
    ulong sz = make_valid( buf, sizeof(buf), 0, 0 );
    FD_TEST( sz );
    FD_TEST( -1==fd_compact_tower_sync_de( serde, buf, sz - 1 ) );
  }

  /* 11. VarInt with non-minimal encoding (leading zero continuation
         byte).  A valid VarInt for value 0 is a single 0x00 byte.
         0x80 0x00 is a non-minimal two-byte encoding of 0 which the
         VarInt decoder rejects as non-canonical. */

  {
    ulong sz = make_valid( buf, sizeof(buf), 1, 0 );
    FD_TEST( sz );
    /* Overwrite offset to non-minimal 0x80 0x00 (value 0).
       Need to shift everything after by 1 byte.  Easier to just craft
       the buffer manually after the root + lockouts_cnt. */
    uchar craft[1024];
    ulong off = 0;
    FD_STORE( ulong, craft, 42UL ); off += 8; /* root */
    craft[off++] = 1;                          /* lockouts_cnt = 1 */
    craft[off++] = 0x80;                       /* VarInt byte 0 (continuation) */
    craft[off++] = 0x00;                       /* VarInt byte 1 (value 0, non-minimal) */
    craft[off++] = 1;                          /* confirmation_count */
    memset( craft+off, 0xAA, 32 ); off += 32;  /* hash */
    craft[off++] = 0;                          /* timestamp_option */
    memset( craft+off, 0xBB, 32 ); off += 32;  /* block_id */
    FD_TEST( -1==fd_compact_tower_sync_de( serde, craft, off ) );
  }

  /* 12. VarInt overflow: 10 continuation bytes (forces > 64 bits of
         shift in the VarInt decoder). */

  {
    uchar craft[1024];
    ulong off = 0;
    FD_STORE( ulong, craft, 42UL ); off += 8;
    craft[off++] = 1; /* lockouts_cnt = 1 */
    for( int i = 0; i < 10; i++ ) craft[off++] = 0x80; /* 10 continuation bytes, no terminator */
    craft[off++] = 0x01;
    FD_TEST( -1==fd_compact_tower_sync_de( serde, craft, off ) );
  }

  /* 13. ShortU16 truncation: the first byte has continuation bit set
         but there's no second byte. */

  {
    uchar craft[9];
    FD_STORE( ulong, craft, 42UL ); /* root */
    craft[8] = 0x80; /* ShortU16 continuation bit set, but buffer ends */
    FD_TEST( -1==fd_compact_tower_sync_de( serde, craft, 9 ) );
  }

  /* 14. VarInt truncation: continuation bit set but buffer ends. */

  {
    uchar craft[1024];
    ulong off = 0;
    FD_STORE( ulong, craft, 42UL ); off += 8;
    craft[off++] = 1; /* lockouts_cnt = 1 */
    craft[off++] = 0x80; /* VarInt continuation bit, then EOF */
    FD_TEST( -1==fd_compact_tower_sync_de( serde, craft, off ) );
  }

  /* 15. Large valid VarInt offset (ULONG_MAX-1 fits in 10 VarInt bytes
         but is a valid nonzero offset).  The message should still parse
         if the rest of the payload is present. */

  {
    fd_compact_tower_sync_serde_t s[1];
    memset( s, 0, sizeof(*s) );
    s->root         = 0UL;
    s->lockouts_cnt = 1;
    s->lockouts[0].offset             = ULONG_MAX - 1;
    s->lockouts[0].confirmation_count = 1;
    memset( &s->hash,     0xCC, sizeof(fd_hash_t) );
    memset( &s->block_id, 0xDD, sizeof(fd_hash_t) );
    ulong sz = 0;
    FD_TEST( 0==fd_compact_tower_sync_ser( s, buf, sizeof(buf), &sz ) );
    FD_TEST( 0==fd_compact_tower_sync_de( serde, buf, sz ) );
    FD_TEST( serde->lockouts[0].offset == ULONG_MAX - 1 );
  }

  /* 16. Exactly 1 byte short everywhere: test progressive truncation
         of a valid 0-lockout message. */

  {
    ulong sz = make_valid( buf, sizeof(buf), 0, 0 );
    FD_TEST( sz );
    for( ulong trunc = 0; trunc < sz; trunc++ ) {
      FD_TEST( -1==fd_compact_tower_sync_de( serde, buf, trunc ) );
    }
    FD_TEST( 0==fd_compact_tower_sync_de( serde, buf, sz ) );
  }

  /* 17. Progressive truncation of a valid 1-lockout message with
         timestamp. */

  {
    ulong sz = make_valid( buf, sizeof(buf), 1, 1 );
    FD_TEST( sz );
    for( ulong trunc = 0; trunc < sz; trunc++ ) {
      FD_TEST( -1==fd_compact_tower_sync_de( serde, buf, trunc ) );
    }
    FD_TEST( 0==fd_compact_tower_sync_de( serde, buf, sz ) );
  }

  FD_LOG_NOTICE(( "pass: test_de_attacker" ));
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  fd_vote_acc_t const * voter = (fd_vote_acc_t const *)fd_type_pun_const( vote_acc_v4 );
  FD_TEST( voter );
  FD_TEST( voter->kind==FD_VOTE_ACC_V4 );
  FD_TEST( fd_vote_acc_vote_slot( vote_acc_v4 )==699 );
  FD_TEST( fd_vote_acc_root_slot( vote_acc_v4 )==668 );

  test_voter_v1_14_11();
  test_voter_current();
  test_de_attacker();
  fd_halt();
}
