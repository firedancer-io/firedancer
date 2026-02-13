#ifndef HEADER_fd_src_ballet_pb_fd_pb_less_h
#define HEADER_fd_src_ballet_pb_fd_pb_less_h

/* fd_pb_less.h provides APIs for schema-less parsing of Protobuf
   messages.  These allow accessing Protobuf fields by field IDs.

   At a high-level, pb_less lazily parses Protobuf (sub-)messages as the
   user accesses fields.  Parsing only stores offsets to fields but does
   not copy field data.  The pb_less instance requires access to the
   original serialized message during its lifetime.

   pb_less is backed by a single contiguous memory region.  The size of
   this region is proportional to the field count of the root message,
   plus the number of fields in each submessage accessed.  This means
   that pb_less allocates additional memory (out of its backing memory)
   whenever a new submessage is parsed.

   Typical usage is as follows:

     ... FIXME usage example ...

   The name was inspired by the less(1) unix command, which allows you
   to hop around lines in a file. */

#include "fd_pb_base.h"

/* pb_less is an opaque handle to a Protobuf message.  It stores an
   offset table for each Protobuf field internally, allowing for
   efficient random access to fields. */

struct fd_pb_less;
typedef struct fd_pb_less fd_pb_less_t;

FD_PROTOTYPES_BEGIN

/* fd_pb_less_align returns the required alignment of an fd_pb_less.
   (Alignment of the 'scratch' argument provided to fd_pb_less_parse) */

#define FD_PB_LESS_ALIGN (16UL)

FD_FN_CONST ulong
fd_pb_less_align( void );

/* fd_pb_less_footprint returns the minimum required footprint of a
   memory region suitable to back a pb_less object. */

ulong
fd_pb_less_footprint( void );

/* fd_pb_less_parse lazily parses a Protobuf message. */

fd_pb_less_t *
fd_pb_less_parse( void *        scratch,
                  ulong         scratch_sz,
                  uchar const * msg,
                  ulong         msg_sz );

/* Accessors */

/* fd_pb_less_get_submsg returns a less object describing the Protobuf
   submessage at the given field_id.  Returns NULL if no submessage was
   found (returns non-NULL if the submessage exists and is empty). */

fd_pb_less_t *
fd_pb_less_get_submsg( fd_pb_less_t * less,
                       uint           field_id );

/* fd_pb_less_get_repeated returns a less object describing a repeated
   Protobuf field.  When using accessors on the returned object, specify
   the index of the repeated field in field_id (field_id==0 gives the
   first element, field_id==1 gives the second, and so on) */

fd_pb_less_t *
fd_pb_less_get_repeated( fd_pb_less_t * less,
                         uint           field_id );

/* fd_pb_get_[type] queries for the [type] in less at field_id.  Returns
   the query result on success or def on failure. */

int
fd_pb_get_bool( fd_pb_less_t const * less,
                uint                 field_id,
                int                  def );

int
fd_pb_get_int32( fd_pb_less_t const * less,
                 uint                 field_id,
                 int                  def );

long
fd_pb_get_int64( fd_pb_less_t const * less,
                 uint                 field_id,
                 long                 def );

uint
fd_pb_get_uint32( fd_pb_less_t const * less,
                  uint                 field_id,
                  uint                 def );

ulong
fd_pb_get_uint64( fd_pb_less_t const * less,
                  uint                 field_id,
                  ulong                def );

int
fd_pb_get_sint32( fd_pb_less_t const * less,
                  uint                 field_id,
                  int                  def );

long
fd_pb_get_sint64( fd_pb_less_t const * less,
                  uint                 field_id,
                  long                 def );

uint
fd_pb_get_fixed32( fd_pb_less_t const * less,
                   uint                 field_id,
                   uint                 def );

ulong
fd_pb_get_fixed64( fd_pb_less_t const * less,
                   uint                 field_id,
                   ulong                def );

static inline int
fd_pb_get_sfixed32( fd_pb_less_t const * less,
                    uint                 field_id,
                    int                  def ) {
  return (int)fd_pb_get_fixed32( less, field_id, (uint)def );
}

static inline long
fd_pb_get_sfixed64( fd_pb_less_t const * less,
                    uint                 field_id,
                    long                 def ) {
  return (long)fd_pb_get_fixed64( less, field_id, (ulong)def );
}

float
fd_pb_get_float( fd_pb_less_t const * less,
                 uint                 field_id,
                 float                def );

#if FD_HAS_DOUBLE
double
fd_pb_get_double( fd_pb_less_t const * less,
                  uint                 field_id,
                  double               def );
#endif

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_pb_fd_pb_less_h */
