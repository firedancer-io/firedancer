#include "../../util/fd_util.h"
#include "fd_gossip_message.h"

#include <string.h>

/* BP707 — flate2: deser_epoch_slots (fd_gossip_message.c:244-272) must
   reject a malformed Flate2-compressed EpochSlots payload at the
   wire-format boundary.

   This test FAILS while the bug is present and PASSES once the fix
   lands.  Today's behaviour (the bug): the deserializer SKIP_BYTES-es
   the compressed payload without inflating or validating it, returns
   success, and the gossip relay path forwards the unchanged value
   (fd_gossip.c:647 / fd_gossip.c:659) — see audit BP707 §3.1 and §4.

   Expected behaviour after the fix (audit §6.1, "validate but don't
   consume"): a malformed DEFLATE stream is detected and the
   deserializer returns 0.  Agave's `Flate2::inflate`
   (agave/gossip/src/epoch_slots.rs:146-160) rejects the same bytes
   today.

   Build a Push packet whose sole CRDS value is an EpochSlots with a
   Flate2 slot range whose compressed bytes are pure garbage (not a
   valid DEFLATE stream), then assert that fd_gossip_message_deserialize
   rejects it. */

static fd_gossip_message_t msg;

#define GARBAGE_LEN (8UL)

static uchar const GARBAGE[ GARBAGE_LEN ] = {
  0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE
};

void
test_epoch_slots_flate2_rejects_garbage( void ) {
  uchar buf[ 1232UL ];
  ulong off = 0UL;

  /* Push header: tag, from, values_len. */
  FD_STORE( uint,  buf+off, FD_GOSSIP_MESSAGE_PUSH ); off += 4UL;
  for( ulong i=0UL; i<32UL; i++ ) buf[ off+i ] = (uchar)i;
  off += 32UL;
  FD_STORE( ulong, buf+off, 1UL ); off += 8UL;

  /* CRDS value: signature + enum tag. */
  for( ulong i=0UL; i<64UL; i++ ) buf[ off+i ] = (uchar)(0xA0U + i);
  off += 64UL;
  FD_STORE( uint, buf+off, FD_GOSSIP_VALUE_EPOCH_SLOTS ); off += 4UL;

  /* EpochSlots header: index, origin, slots_len=1. */
  buf[ off ] = 0;                                                off += 1UL;
  for( ulong i=0UL; i<32UL; i++ ) buf[ off+i ] = (uchar)(0x50U + i);
  off += 32UL;
  FD_STORE( ulong, buf+off, 1UL ); off += 8UL;

  /* One slot range, Flate2 variant, with a malformed compressed
     payload — not a valid DEFLATE stream. */
  FD_STORE( uint,  buf+off, 0U   ); off += 4UL;  /* is_uncompressed = 0 -> Flate2 */
  FD_STORE( ulong, buf+off, 0UL  ); off += 8UL;  /* first_slot */
  FD_STORE( ulong, buf+off, 1UL  ); off += 8UL;  /* num */
  FD_STORE( ulong, buf+off, GARBAGE_LEN ); off += 8UL; /* compressed_len */
  fd_memcpy( buf+off, GARBAGE, GARBAGE_LEN ); off += GARBAGE_LEN;

  /* Wallclock (ms). */
  FD_STORE( ulong, buf+off, 12345UL ); off += 8UL;

  ulong const total_sz = off;

  memset( &msg, 0, sizeof(msg) );
  int decoded = fd_gossip_message_deserialize( &msg, buf, total_sz );

  /* Once the fix lands, the deserializer rejects the malformed DEFLATE
     stream and returns 0.  Until then, it returns 1 and the relay path
     forwards the unchanged compressed bytes to peers — this test
     fails on the unpatched tree. */
  if( FD_UNLIKELY( decoded ) ) {
    FD_LOG_ERR(( "BP707: fd_gossip_message_deserialize accepted a malformed "
                 "Flate2 EpochSlots payload.  deser_epoch_slots "
                 "(fd_gossip_message.c:244-272) must validate the DEFLATE "
                 "stream instead of SKIP_BYTES-ing it." ));
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_epoch_slots_flate2_rejects_garbage();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
