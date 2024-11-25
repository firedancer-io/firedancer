#include "fd_stub_to_json.h"
#include "../../ballet/base58/fd_base58.h"

/* STATE_{...} identify the state of the JSON writer.  This is used
   because assembling the JSON stream requires different combinations
   of print operations depending on the sequence of AST nodes. */

#define STATE_NULL         (0)  /* Sentinel value */
#define STATE_OBJECT_BEGIN (2)  /* Writing object, ==0 elems so far */
#define STATE_OBJECT       (3)  /* Writing object,  >0 elems so far */
#define STATE_ARRAY_BEGIN  (4)  /* Writing array,  ==0 elems so far */
#define STATE_ARRAY        (5)  /* Writing array,   >0 elems so far */
#define STATE_ENUM_BEGIN   (6)  /* Writing enum,  ==0 elems so far */
#define STATE_ENUM         (7)  /* Writing enum,   >0 elems so far */
#define STATE_OPTION_BEGIN (8)  /* Writing nullable, waiting for elem */

#define STACK_HEIGHT 64U
struct fd_rpc_json {
  fd_webserver_t * ws;
  int stack[ STACK_HEIGHT ];
};


ulong
fd_rpc_json_align( void ) {
  return alignof(fd_rpc_json_t);
}

ulong
fd_rpc_json_footprint( void ) {
  return sizeof(fd_rpc_json_t);
}

fd_rpc_json_t *
fd_rpc_json_new( void * mem ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  fd_rpc_json_t * json = (fd_rpc_json_t *)mem;
  memset( json,         0,   sizeof(*json)        );
  return (fd_rpc_json_t *)mem;
}

void *
fd_rpc_json_delete( fd_rpc_json_t * json ) {
  return json;
}

fd_rpc_json_t *
fd_rpc_json_init( fd_rpc_json_t * self, fd_webserver_t * ws ) {

  if( FD_UNLIKELY( !self ) ) {
    FD_LOG_WARNING(( "NULL self" ));
    return NULL;
  }
  self->ws = ws;

  return self;
}

void
fd_rpc_json_walk( void *       _self,
                  void const * arg,
                  char const * name,
                  int          type,
                  char const * type_name,
                  uint         level ) {
  (void)type_name;

  if( level>=STACK_HEIGHT-1 ) {
    FD_LOG_WARNING(( "level %u exceeds max %u", level, STACK_HEIGHT));
    return;
  }

  /* Check if we are at the beginning of a collection */
  fd_rpc_json_t * self = (fd_rpc_json_t *)_self;
  if( (self->stack[ level ] & 1)==0 ) {

    /* Collection is empty -- print inline */
    if( fd_flamenco_type_is_collection_end( type ) ) {
      if( name )
        fd_web_reply_sprintf( self->ws, "\"%s\":", name );
      switch( type ) {
      case FD_FLAMENCO_TYPE_MAP_END:
      case FD_FLAMENCO_TYPE_ENUM_END:
        fd_web_reply_sprintf( self->ws, "{}" );
        break;
      case FD_FLAMENCO_TYPE_ARR_END:
        fd_web_reply_sprintf( self->ws, "[]" );
        break;
      }
      self->stack[ level ] = STATE_NULL;
      return;
    }

  } else {
    if( fd_flamenco_type_is_collection_end( type ) ) {
      switch( type ) {
      case FD_FLAMENCO_TYPE_MAP_END:
        fd_web_reply_sprintf( self->ws, "}" );
        break;
      case FD_FLAMENCO_TYPE_ENUM_END:
        fd_web_reply_sprintf( self->ws, "}" );
        break;
      case FD_FLAMENCO_TYPE_ARR_END:
        fd_web_reply_sprintf( self->ws, "]" );
        break;
      }
      self->stack[ level ] = STATE_NULL;
      return;
    }
    fd_web_reply_sprintf( self->ws, "," );
  }

  /* Print node tag */
  switch( self->stack[ level ] ) {
  case STATE_OBJECT_BEGIN:
  case STATE_OBJECT:
    if( name ) {
      fd_web_reply_sprintf( self->ws, "\"%s\":", name );
    }
    break;

  case STATE_ENUM_BEGIN:
  case STATE_ENUM:
    if( type == FD_FLAMENCO_TYPE_ENUM_DISC ) break;
    if( type != FD_FLAMENCO_TYPE_MAP ) {
      if( name ) {
        fd_web_reply_sprintf( self->ws, "\"%s\":", name );
      }
    } else {
      fd_web_reply_sprintf( self->ws, "\"info\":" );
    }
    break;
  }

  /* Print node value */
  switch( type ) {
  case FD_FLAMENCO_TYPE_MAP:
    self->stack[ level+1 ] = STATE_OBJECT_BEGIN;
    fd_web_reply_sprintf( self->ws, "{" );
    break;
  case FD_FLAMENCO_TYPE_ENUM:
    self->stack[ level+1 ] = STATE_ENUM_BEGIN;
    fd_web_reply_sprintf( self->ws, "{" );
    break;
  case FD_FLAMENCO_TYPE_ARR:
    self->stack[ level+1 ] = STATE_ARRAY_BEGIN;
    fd_web_reply_sprintf( self->ws, "[" );
    break;

  case FD_FLAMENCO_TYPE_NULL:
    fd_web_reply_sprintf( self->ws, "null" );
    break;
  case FD_FLAMENCO_TYPE_BOOL:
    fd_web_reply_sprintf( self->ws, "%s", (*(uchar const *)arg) ? "true" : "false" );
    break;
  case FD_FLAMENCO_TYPE_UCHAR:
    fd_web_reply_sprintf( self->ws, "%u", *(uchar const *)arg );
    break;
  case FD_FLAMENCO_TYPE_SCHAR:
    fd_web_reply_sprintf( self->ws, "%d", *(schar const *)arg );
    break;
  case FD_FLAMENCO_TYPE_USHORT:
    fd_web_reply_sprintf( self->ws, "%u", *(ushort const *)arg );
    break;
  case FD_FLAMENCO_TYPE_SSHORT:
    fd_web_reply_sprintf( self->ws, "%d", *(short const *)arg );
    break;
  case FD_FLAMENCO_TYPE_UINT:
    fd_web_reply_sprintf( self->ws, "%u", *(uint const *)arg );
    break;
  case FD_FLAMENCO_TYPE_SINT:
    fd_web_reply_sprintf( self->ws, "%d", *(int const *)arg );
    break;
  case FD_FLAMENCO_TYPE_ULONG:
    fd_web_reply_sprintf( self->ws, "%lu", *(ulong const *)arg );
    break;
  case FD_FLAMENCO_TYPE_SLONG:
    fd_web_reply_sprintf( self->ws, "%ld", *(long const *)arg );
    break;
# if FD_HAS_INT128
  case FD_FLAMENCO_TYPE_UINT128:
  case FD_FLAMENCO_TYPE_SINT128: {
    uint128 v = *(uint128 const *)arg;
    fd_web_reply_sprintf( self->ws, "%s: 0x%016lx%016lx", name,
              (ulong)(v>>64), (ulong)v );
    break;
  }
# endif
  case FD_FLAMENCO_TYPE_FLOAT:
    fd_web_reply_sprintf( self->ws, "%f", (double)( *(float const *)arg ) );
    break;
  case FD_FLAMENCO_TYPE_DOUBLE:
    fd_web_reply_sprintf( self->ws, "%f", *(double const *)arg );
    break;
  case FD_FLAMENCO_TYPE_HASH256: {
    char buf[ FD_BASE58_ENCODED_32_SZ ];
    fd_base58_encode_32( arg, NULL, buf );
    fd_web_reply_sprintf( self->ws, "\"%s\"", buf );
    break;
  }
  case FD_FLAMENCO_TYPE_SIG512: {
    char buf[ FD_BASE58_ENCODED_64_SZ ];
    fd_base58_encode_64( arg, NULL, buf );
    fd_web_reply_sprintf( self->ws, "\"%s\"", buf );
    break;
  }
  case FD_FLAMENCO_TYPE_CSTR:
    fd_web_reply_sprintf( self->ws, "\"%s\"", (char const *)arg );
    break;

  case FD_FLAMENCO_TYPE_ENUM_DISC:
    fd_web_reply_sprintf( self->ws, "\"type\":\"%s\"", name );
    break;

  default:
    FD_LOG_CRIT(( "unknown type %#x", (uint)type ));
    break;
  }

  /* Remember that we processed an element in the current level */
  self->stack[ level ] |= 1;
}
