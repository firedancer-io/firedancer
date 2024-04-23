#include "fd_types_yaml.h"
#include "fd_types_meta.h"
#include "../../ballet/base58/fd_base58.h"

#include <ctype.h>
#include <stdio.h>

#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"

#define FD_FLAMENCO_YAML_INDENT_BUFSZ (2UL*FD_FLAMENCO_YAML_MAX_INDENT+1UL)

/* STATE_{...} identify the state of the YAML writer.  This is used
   because assembling the YAML stream requires different combinations
   of print operations depending on the sequence of AST nodes. */

#define STATE_NULL         (0)  /* Sentinel value */
#define STATE_OBJECT_BEGIN (2)  /* Writing object, ==0 elems so far */
#define STATE_OBJECT       (3)  /* Writing object,  >0 elems so far */
#define STATE_ARRAY_BEGIN  (4)  /* Writing array,  ==0 elems so far */
#define STATE_ARRAY        (5)  /* Writing array,   >0 elems so far */
#define STATE_OPTION_BEGIN (6)  /* Writing nullable, waiting for elem */

/* fd_flamenco_yaml provides methods for converting a bincode-like AST of
   nodes into a YAML text stream.

   indent is a string containing the prefix suitable for the current
   indent level.  indent_stack[ i ] is the number of chars in indent
   level i.

   For example, the following structure

     my_object:
       key0: 34
       key1:
       - 128
       - 129
       key2: true
       key3: null

   Results in the following walk:

     [LEVEL] [TYPE]  [NAME]    [VALUE]
          0  MAP
          1  MAP     my_object
          2  SINT    key0       34
          2  ARR     key1
          3  SINT              128
          3  SINT              129
          3  ARR_END
          2  BOOL    key2      true
          2  MAP_END
          2  OPT     key3
          3  OPT_END
          1  MAP_END
          0  MAP_END

   After the start node of a collection types (arrays, maps, options),
   the walk level may increment.  The subsequent nodes in this
   incremented level then belong to the collection.  The last node in
   the incremented level is always the collection's corresponding end
   node.

   Finally, we support option types.  During walk, these are presented
   as a separate  */

struct fd_flamenco_yaml {
  void * file;   /* (FILE *) or platform equivalent */

  int  stack [ FD_FLAMENCO_YAML_MAX_INDENT   ];
  char indent[ FD_FLAMENCO_YAML_INDENT_BUFSZ ];
};


ulong
fd_flamenco_yaml_align( void ) {
  return alignof(fd_flamenco_yaml_t);
}

ulong
fd_flamenco_yaml_footprint( void ) {
  return sizeof(fd_flamenco_yaml_t);
}

fd_flamenco_yaml_t *
fd_flamenco_yaml_new( void * mem ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  fd_flamenco_yaml_t * yaml = (fd_flamenco_yaml_t *)mem;
  memset( yaml,         0,   sizeof(*yaml)        );
  memset( yaml->indent, ' ', sizeof(yaml->indent) );
  return (fd_flamenco_yaml_t *)mem;
}

void *
fd_flamenco_yaml_delete( fd_flamenco_yaml_t * yaml ) {
  return yaml;
}

fd_flamenco_yaml_t *
fd_flamenco_yaml_init( fd_flamenco_yaml_t * self,
                       void *               _file ) {

  if( FD_UNLIKELY( !self ) ) {
    FD_LOG_WARNING(( "NULL self" ));
    return NULL;
  }
  if( FD_UNLIKELY( !_file ) ) {
    FD_LOG_WARNING(( "NULL file" ));
    return NULL;
  }

  self->file = _file;

  return self;
}

void *
fd_flamenco_yaml_file( fd_flamenco_yaml_t * self ) {
  return self->file;
}

/* fd_flamenco_yaml_walk iteratively serializes YAML while keeping
   minimal state.

   Throughout this function, serialization state is illustrated using
   code comments.  The '$' symbol symbolizes the current stream cursor. */

void
fd_flamenco_yaml_walk( void *       _self,
                       void const * arg,
                       char const * name,
                       int          type,
                       char const * type_name,
                       uint         level ) {

  (void)type_name;

  if( level>=FD_FLAMENCO_YAML_MAX_INDENT-1 ) {
    FD_LOG_WARNING(( "indent level %d exceeds max %lu",
                     level, FD_FLAMENCO_YAML_MAX_INDENT ));
    return;
  }

  fd_flamenco_yaml_t * self = (fd_flamenco_yaml_t *)_self;
  FILE *               file = self->file;

  /* On entry, there are either two cursor states:

     At the beginning of a line, if there is at least one predecessor
     in the current collection:

       ...
       object:
         - foo
         - bar
       $
       ...

     Or, at the beginning of the line, if we are serializing the first
     element.  We handle this as a special case, because we don't know
     whether the subsequent content can be printed inline, or needs a
     new line.

       ...
       object: $
       ...

     For example, an empty array is the following:

       ...
       object: []
       ...                                                            */

  /* Check if we are at the beginning of a collection */
  if( (self->stack[ level ] & 1)==0 ) {

    /* Collection is empty -- print inline */
    if( fd_flamenco_type_is_collection_end( type ) ) {
      if( name )
        fprintf( file, "%s: ", name );

      switch( type ) {
      case FD_FLAMENCO_TYPE_MAP_END:
        fprintf( file, "{}\n" );
        break;
      case FD_FLAMENCO_TYPE_ARR_END:
        fprintf( file, "[]\n" );
        break;
      }

      return;
    }

    /* Check if we should split off into a separate line */
    int split = 0;
    switch( self->stack[ level ] ) {
    case STATE_OBJECT_BEGIN:
      /* Objects nested in objects go on a separate line:

           ...
           a:          <---
             b:        <---
               c: {}
           ...                                                        */

      split = ( level>1 )
           && ( ( (self->stack[ level-1 ])==STATE_OBJECT ) );
      break;
    case STATE_ARRAY_BEGIN:
      /* Arrays nested in arrays or objects go on a separate line:

           ...              |      ...
           -         <---   |      a:          <---
             -       <---   |        - a: 3
               - []         |          b: 4
           ...              |      ...                                */

      split = ( level>1 )
           && ( ( (self->stack[ level-1 ])==STATE_OBJECT )
              | ( (self->stack[ level-1 ])==STATE_ARRAY  ) );
      break;
    }

    if( split ) {
      fprintf( file, "\n" );
      fwrite( self->indent, 2, (ulong)level-1, file );
    }

  } else {

    /* Nothing to do if collection ends, but at least one item printed */

    if( fd_flamenco_type_is_collection_end( type ) )
      return;

    /* We are at the beginning of a line.

       Indent according to current level.
       If just started an object or array, inhibit indent. */

    long indent = (long)level-1L;
    fwrite( self->indent, 2, (ulong)indent, file );

  }

  /* Print node tag */
  switch( self->stack[ level ] ) {
  case STATE_OBJECT_BEGIN:
  case STATE_OBJECT:
    fprintf( file, "%s: ", name );
    break;

  case STATE_ARRAY_BEGIN:
  case STATE_ARRAY:
    fprintf( file, "- " );
    break;
  }

  /* Print node value */
  switch( type ) {
  case FD_FLAMENCO_TYPE_MAP:
    self->stack[ level+1 ] = STATE_OBJECT_BEGIN;
    break;
  case FD_FLAMENCO_TYPE_ARR:
    self->stack[ level+1 ] = STATE_ARRAY_BEGIN;
    break;

  case FD_FLAMENCO_TYPE_NULL:
    fprintf( file, "null\n" );
    break;
  case FD_FLAMENCO_TYPE_BOOL:
    fprintf( file, "%s\n", (*(uchar const *)arg) ? "true" : "false" );
    break;
  case FD_FLAMENCO_TYPE_UCHAR:
    fprintf( file, "%u\n", *(uchar const *)arg );
    break;
  case FD_FLAMENCO_TYPE_SCHAR:
    fprintf( file, "%d\n", *(schar const *)arg );
    break;
  case FD_FLAMENCO_TYPE_USHORT:
    fprintf( file, "%u\n", *(ushort const *)arg );
    break;
  case FD_FLAMENCO_TYPE_SSHORT:
    fprintf( file, "%d\n", *(short const *)arg );
    break;
  case FD_FLAMENCO_TYPE_UINT:
    fprintf( file, "%u\n", *(uint const *)arg );
    break;
  case FD_FLAMENCO_TYPE_SINT:
    fprintf( file, "%d\n", *(int const *)arg );
    break;
  case FD_FLAMENCO_TYPE_ULONG:
    fprintf( file, "%lu\n", *(ulong const *)arg );
    break;
  case FD_FLAMENCO_TYPE_SLONG:
    fprintf( file, "%ld\n", *(long const *)arg );
    break;
# if FD_HAS_INT128
  case FD_FLAMENCO_TYPE_UINT128:
  case FD_FLAMENCO_TYPE_SINT128: {
    uint128 v = *(uint128 const *)arg;
    fprintf( file, "%s: 0x%016lx%016lx\n", name,
              (ulong)(v>>64), (ulong)v );
    break;
  }
# endif
  case FD_FLAMENCO_TYPE_FLOAT:
    fprintf( file, "%f\n", (double)( *(float const *)arg ) );
    break;
  case FD_FLAMENCO_TYPE_DOUBLE:
    fprintf( file, "%f\n", *(double const *)arg );
    break;
  case FD_FLAMENCO_TYPE_HASH256: {
    char buf[ FD_BASE58_ENCODED_32_SZ ];
    fd_base58_encode_32( arg, NULL, buf );
    fprintf( file, "'%s'\n", buf );
    break;
  }
  case FD_FLAMENCO_TYPE_HASH1024:
    fprintf( file, "'%32J%32J%32J%32J'\n", arg, ((uchar *) arg)+32, ((uchar *) arg)+64, ((uchar *) arg)+96 );
    break;
  case FD_FLAMENCO_TYPE_SIG512: {
    char buf[ FD_BASE58_ENCODED_64_SZ ];
    fd_base58_encode_64( arg, NULL, buf );
    fprintf( file, "'%s'\n", buf );
    break;
  }
  case FD_FLAMENCO_TYPE_CSTR:
    fprintf( file, "'%s'\n", (char const *)arg );
    break;
  default:
    FD_LOG_CRIT(( "unknown type %#x", type ));
    break;
  }

  /* Remember that we processed an element in the current level */
  self->stack[ level ] |= 1;
}
