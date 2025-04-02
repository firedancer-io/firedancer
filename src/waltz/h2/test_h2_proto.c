#include "fd_h2_proto.h"
#include "../../util/log/fd_log.h"

/* https://www.iana.org/assignments/http2-parameters/http2-parameters.xhtml */

static void
test_h2_enum( void ) {

  /* Frame types */

  FD_TEST( !strcmp( fd_h2_frame_name( 0x00u ), "DATA"            ) );
  FD_TEST( !strcmp( fd_h2_frame_name( 0x01u ), "HEADERS"         ) );
  FD_TEST( !strcmp( fd_h2_frame_name( 0x02u ), "PRIORITY"        ) );
  FD_TEST( !strcmp( fd_h2_frame_name( 0x03u ), "RST_STREAM"      ) );
  FD_TEST( !strcmp( fd_h2_frame_name( 0x04u ), "SETTINGS"        ) );
  FD_TEST( !strcmp( fd_h2_frame_name( 0x05u ), "PUSH_PROMISE"    ) );
  FD_TEST( !strcmp( fd_h2_frame_name( 0x06u ), "PING"            ) );
  FD_TEST( !strcmp( fd_h2_frame_name( 0x07u ), "GOAWAY"          ) );
  FD_TEST( !strcmp( fd_h2_frame_name( 0x08u ), "WINDOW_UPDATE"   ) );
  FD_TEST( !strcmp( fd_h2_frame_name( 0x09u ), "CONTINUATION"    ) );
  FD_TEST( !strcmp( fd_h2_frame_name( 0x0au ), "ALTSVC"          ) );
  FD_TEST( !strcmp( fd_h2_frame_name( 0x0bu ), "unknown"         ) );
  FD_TEST( !strcmp( fd_h2_frame_name( 0x0cu ), "ORIGIN"          ) );
  FD_TEST( !strcmp( fd_h2_frame_name( 0x0du ), "unknown"         ) );
  FD_TEST( !strcmp( fd_h2_frame_name( 0x0eu ), "unknown"         ) );
  FD_TEST( !strcmp( fd_h2_frame_name( 0x0fu ), "unknown"         ) );
  FD_TEST( !strcmp( fd_h2_frame_name( 0x10u ), "PRIORITY_UPDATE" ) );
  for( uint i=0x11u; i<=0xffu; i++ ) {
    FD_TEST( !strcmp( fd_h2_frame_name( i ), "unknown" ) );
  }

  /* Settings */

  FD_TEST( !strcmp( fd_h2_setting_name( 0x00 ), "reserved"               ) );
  FD_TEST( !strcmp( fd_h2_setting_name( 0x01 ), "HEADER_TABLE_SIZE"      ) );
  FD_TEST( !strcmp( fd_h2_setting_name( 0x02 ), "ENABLE_PUSH"            ) );
  FD_TEST( !strcmp( fd_h2_setting_name( 0x03 ), "MAX_CONCURRENT_STREAMS" ) );
  FD_TEST( !strcmp( fd_h2_setting_name( 0x04 ), "INITIAL_WINDOW_SIZE"    ) );
  FD_TEST( !strcmp( fd_h2_setting_name( 0x05 ), "MAX_FRAME_SIZE"         ) );
  FD_TEST( !strcmp( fd_h2_setting_name( 0x06 ), "MAX_HEADER_LIST_SIZE"   ) );
  FD_TEST( !strcmp( fd_h2_setting_name( 0x07 ), "unknown"                ) );

}

static void
test_h2_proto( void ) {
  test_h2_enum();
}
