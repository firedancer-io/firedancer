#!/usr/bin/env python3
"""
fd_pb_gen.py generates C structs and fd_pb based (de)serializers from
proto3 schemas.

Usage:

  protoc -I<dir> --include_imports --descriptor_set_out=<fds> <protos>
  fd_pb_gen.py --fds <fds> --options <dir> --out <dir> --prefix fd_exec_test

The generated code keeps the in-memory layout conventions that callers
expect from nanopb (which this replaces):

- Scalars are stored inline.  proto3 'optional' scalars and singular
  submessages carry a has_<field> flag.
- 'bytes' and 'string' fields are pointers to fd_pb_bytes_array_t
  (NULL==absent), unless the .options file gives the field a
  'max_size'.  'fixed_length:true' fields become uchar[max_size],
  other 'max_size' fields become inline FD_PB_BYTES_ARRAY_T(max_size).
  'max_length' strings become char[max_length+1].
- Repeated fields are a <field>_count and a pointer to the elements.
- oneof members share a union and a which_<oneof> tag.

Decoded pointer fields are allocated with malloc and freed by
fd_pb_release.  Encoding always writes fields in field number
order, skipping proto3 default values, packing repeated scalars. """

import argparse
import os
import re
import sys

from google.protobuf import descriptor_pb2

FT = descriptor_pb2.FieldDescriptorProto

SCALAR = {
    # proto type: (ctype, fd_pb_push_* suffix, FD_PB_GEN_* type)
    FT.TYPE_DOUBLE:   ('double', 'double',  'FIXED64'),
    FT.TYPE_FLOAT:    ('float',  'float',   'FIXED32'),
    FT.TYPE_INT64:    ('long',   'int64',   'INT64'  ),
    FT.TYPE_UINT64:   ('ulong',  'uint64',  'UINT64' ),
    FT.TYPE_INT32:    ('int',    'int32',   'INT32'  ),
    FT.TYPE_FIXED64:  ('ulong',  'fixed64', 'FIXED64'),
    FT.TYPE_FIXED32:  ('uint',   'fixed32', 'FIXED32'),
    FT.TYPE_BOOL:     ('bool',   'bool',    'BOOL'   ),
    FT.TYPE_UINT32:   ('uint',   'uint32',  'UINT32' ),
    FT.TYPE_SFIXED32: ('int',    'fixed32', 'FIXED32'),
    FT.TYPE_SFIXED64: ('long',   'fixed64', 'FIXED64'),
    FT.TYPE_SINT32:   ('int',    'sint32',  'SINT32' ),
    FT.TYPE_SINT64:   ('long',   'sint64',  'SINT64' ),
}

# FD_PB_GEN_* type -> (fd_pb_dec_* suffix, decoded ctype)
DEC = {
    'BOOL':    ('bool',    'bool' ),
    'INT32':   ('int32',   'int'  ),
    'UINT32':  ('uint32',  'uint' ),
    'SINT32':  ('sint32',  'int'  ),
    'INT64':   ('int64',   'long' ),
    'UINT64':  ('uint64',  'ulong'),
    'SINT64':  ('sint64',  'long' ),
    'FIXED32': ('fixed32', 'uint' ),
    'FIXED64': ('fixed64', 'ulong'),
}

def snake(name):
    name = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\1_\2', name)
    name = re.sub(r'([a-z\d])([A-Z])', r'\1_\2', name)
    return name.lower()

def parse_options(path):
    """Parses the subset of nanopb .options syntax used by protosol.
    Returns {'Msg.field': {key: value}}."""
    opts = {}
    with open(path) as f:
        for line in f:
            line = line.split('#', 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            target = parts[0]
            if target.endswith('.proto'):
                continue
            target = target.split('.', 1)[1] if target.count('.') >= 2 else target
            d = opts.setdefault(target, {})
            for kv in parts[1:]:
                k, v = kv.split(':', 1)
                d[k] = v.strip('"')
    return opts

class Gen:

    def __init__(self, fds, opts, prefix):
        self.fds    = fds
        self.opts   = opts
        self.prefix = prefix
        self.msgs   = {}  # '.pkg.Name' -> (file, DescriptorProto)
        self.enums  = {}  # '.pkg.Name' -> (file, EnumDescriptorProto)
        for f in fds.file:
            for m in f.message_type:
                self.msgs['.%s.%s' % (f.package, m.name)] = (f, m)
            for e in f.enum_type:
                self.enums['.%s.%s' % (f.package, e.name)] = (f, e)

    def cname(self, full):
        return '%s_%s' % (self.prefix, snake(full.rsplit('.', 1)[1]))

    def CNAME(self, full):
        return self.cname(full).upper()

    def fopt(self, msg, field):
        return self.opts.get('%s.%s' % (msg.name, field.name), {})

    # Field classification

    def kind(self, msg, field):
        """Returns one of: scalar, enum, msg, bytes_ptr, bytes_fixed,
        bytes_static, string_static"""
        t = field.type
        if t == FT.TYPE_MESSAGE:
            return 'msg'
        if t == FT.TYPE_ENUM:
            return 'enum'
        if t in (FT.TYPE_BYTES, FT.TYPE_STRING):
            o = self.fopt(msg, field)
            if field.label == FT.LABEL_REPEATED:
                return 'bytes_ptr'
            if 'max_length' in o:
                return 'string_static'
            if 'max_size' in o:
                if o.get('fixed_length') == 'true':
                    return 'bytes_fixed'
                return 'bytes_static'
            return 'bytes_ptr'
        return 'scalar'

    def is_repeated(self, field):
        return field.label == FT.LABEL_REPEATED

    def oneof_of(self, msg, field):
        if field.HasField('oneof_index') and not field.proto3_optional:
            return msg.oneof_decl[field.oneof_index].name
        return None

    def has_flag(self, msg, field):
        if self.is_repeated(field) or self.oneof_of(msg, field):
            return False
        if field.proto3_optional:
            return True
        return field.type == FT.TYPE_MESSAGE

    def elem_ctype(self, msg, field):
        k = self.kind(msg, field)
        if k == 'scalar':
            return SCALAR[field.type][0]
        if k == 'enum':
            return self.cname(field.type_name) + '_t'
        if k == 'msg':
            return self.cname(field.type_name) + '_t'
        if k == 'bytes_ptr':
            return 'fd_pb_bytes_array_t *'
        raise ValueError(k)

    def static_size(self, msg, field):
        o = self.fopt(msg, field)
        if 'max_length' in o:
            return int(o['max_length'])
        return int(o['max_size'])

    def tag_macro(self, msg_full, field):
        return '%s_%s_TAG' % (self.CNAME(msg_full), field.name.upper())

    # Topological order of messages in a file

    def ordered_msgs(self, f):
        local = ['.%s.%s' % (f.package, m.name) for m in f.message_type]
        done, out = set(), []
        def visit(full):
            if full in done or full not in local:
                return
            done.add(full)
            _, m = self.msgs[full]
            for fld in m.field:
                if fld.type == FT.TYPE_MESSAGE:
                    visit(fld.type_name)
            out.append(full)
        for full in local:
            visit(full)
        return out

    # Header

    def gen_header(self, f, base):
        guard = 'HEADER_fd_src_flamenco_runtime_tests_generated_%s_pb_h' % base
        o = []
        o.append('/* Automatically generated by fd_pb_gen.py.  Do not edit. */\n')
        o.append('#ifndef %s' % guard)
        o.append('#define %s\n' % guard)
        o.append('#include "../../../../ballet/pb/fd_pb_gen.h"')
        for dep in f.dependency:
            o.append('#include "%s.pb.h"' % os.path.splitext(dep)[0])
        o.append('')

        for e in f.enum_type:
            full = '.%s.%s' % (f.package, e.name)
            cn = self.cname(full)
            o.append('typedef enum %s {' % cn)
            vals = []
            for v in e.value:
                vals.append('  %s_%s = %d' % (cn.upper(), v.name, v.number))
            o.append(',\n'.join(vals))
            o.append('} %s_t;\n' % cn)
            o.append('#define _%s_MIN %s_%s' % (cn.upper(), cn.upper(), min(e.value, key=lambda v: v.number).name))
            o.append('#define _%s_MAX %s_%s\n' % (cn.upper(), cn.upper(), max(e.value, key=lambda v: v.number).name))

        for full in self.ordered_msgs(f):
            _, m = self.msgs[full]
            cn = self.cname(full)
            o.append('typedef struct %s {' % cn)
            emitted_oneofs = set()
            for fld in m.field:
                oneof = self.oneof_of(m, fld)
                if oneof:
                    if oneof in emitted_oneofs:
                        continue
                    emitted_oneofs.add(oneof)
                    o.append('  uint which_%s;' % oneof)
                    o.append('  union {')
                    for fld2 in m.field:
                        if self.oneof_of(m, fld2) == oneof:
                            o.append('    %s;' % self.field_decl(m, fld2))
                    o.append('  } %s;' % oneof)
                    continue
                if self.has_flag(m, fld):
                    o.append('  bool has_%s;' % fld.name)
                if self.is_repeated(fld):
                    o.append('  uint %s_count;' % fld.name)
                o.append('  %s;' % self.field_decl(m, fld))
            if not m.field:
                o.append('  uchar dummy_field;')
            o.append('} %s_t;\n' % cn)

        for full in self.ordered_msgs(f):
            _, m = self.msgs[full]
            for fld in m.field:
                o.append('#define %s %d' % (self.tag_macro(full, fld), fld.number))
        o.append('')

        o.append('FD_PROTOTYPES_BEGIN\n')
        for full in self.ordered_msgs(f):
            cn = self.cname(full)
            o.append('extern fd_pb_msgdesc_t const %s_t_msg;' % cn)
        o.append('')
        o.append('FD_PROTOTYPES_END\n')
        o.append('#endif /* %s */' % guard)
        return '\n'.join(o) + '\n'

    def field_decl(self, m, fld):
        k = self.kind(m, fld)
        if self.is_repeated(fld):
            et = self.elem_ctype(m, fld)
            if et.endswith('*'):
                return '%s* %s' % (et, fld.name)
            return '%s * %s' % (et, fld.name)
        if k == 'scalar':
            return '%s %s' % (SCALAR[fld.type][0], fld.name)
        if k in ('enum', 'msg'):
            return '%s %s' % (self.elem_ctype(m, fld), fld.name)
        if k == 'bytes_ptr':
            return 'fd_pb_bytes_array_t * %s' % fld.name
        if k == 'bytes_fixed':
            return 'uchar %s[%d]' % (fld.name, self.static_size(m, fld))
        if k == 'bytes_static':
            return 'FD_PB_BYTES_ARRAY_T(%d) %s' % (self.static_size(m, fld), fld.name)
        if k == 'string_static':
            return 'char %s[%d]' % (fld.name, self.static_size(m, fld) + 1)
        raise ValueError(k)

    # Source

    def gen_source(self, f, base):
        o = []
        o.append('/* Automatically generated by fd_pb_gen.py.  Do not edit. */\n')
        o.append('#include "%s.pb.h"\n' % base)
        o.append('#include <stdlib.h>\n')
        for full in self.ordered_msgs(f):
            o.extend(self.gen_oneof_release(full))
            o.extend(self.gen_msg_funcs(full))
        return '\n'.join(o) + '\n'

    def gen_msg_funcs(self, full):
        self.cur_full = full
        _, m = self.msgs[full]
        cn = self.cname(full)
        o = []

        o.append('static int')
        o.append('%s_encode( fd_pb_encoder_t * enc,' % cn)
        o.append('%s void const *      msg_ ) {' % (' ' * (len(cn) + 8)))
        o.append('  %s_t const * msg = msg_;' % cn)
        o.append('  (void)enc; (void)msg;')
        for fld in sorted(m.field, key=lambda x: x.number):
            o.extend('  ' + l for l in self.gen_encode_field(m, fld))
        o.append('  return 1;')
        o.append('}\n')

        o.append('static int')
        o.append('%s_decode( fd_pb_inbuf_t * in,' % cn)
        o.append('%s void *          msg_ ) {' % (' ' * (len(cn) + 8)))
        o.append('  %s_t * msg = msg_;' % cn)
        o.append('  (void)msg;')
        o.append('  while( fd_pb_inbuf_sz( in ) ) {')
        o.append('    fd_pb_tlv_t tlv[1];')
        o.append('    if( FD_UNLIKELY( !fd_pb_dec_tlv( in, tlv ) ) ) return 0;')
        o.append('    switch( tlv->field_id ) {')
        for fld in m.field:
            o.append('    case %d:' % fld.number)
            o.extend('      ' + l for l in self.gen_decode_field(m, fld))
            o.append('      break;')
        o.append('    default:')
        o.append('      if( FD_UNLIKELY( !fd_pb_dec_skip( in, tlv ) ) ) return 0;')
        o.append('      break;')
        o.append('    }')
        o.append('  }')
        o.append('  return 1;')
        o.append('}\n')

        o.append('static void')
        o.append('%s_release( void * msg_ ) {' % cn)
        o.append('  %s_t * msg = msg_;' % cn)
        o.append('  (void)msg;')
        for fld in m.field:
            o.extend('  ' + l for l in self.gen_release_field(m, fld))
        o.append('}\n')

        o.append('fd_pb_msgdesc_t const %s_t_msg = {' % cn)
        o.append('  .name    = "%s",' % full[1:])
        o.append('  .size    = sizeof(%s_t),' % cn)
        o.append('  .encode  = %s_encode,' % cn)
        o.append('  .decode  = %s_decode,' % cn)
        o.append('  .release = %s_release' % cn)
        o.append('};\n')
        return o

    def access(self, m, fld):
        oneof = self.oneof_of(m, fld)
        if oneof:
            return 'msg->%s.%s' % (oneof, fld.name)
        return 'msg->%s' % fld.name

    def gen_type(self, m, fld):
        if self.kind(m, fld) == 'enum':
            return 'INT32'
        return SCALAR[fld.type][2]

    def gen_encode_field(self, m, fld):
        n     = fld.number
        a     = self.access(m, fld)
        k     = self.kind(m, fld)
        oneof = self.oneof_of(m, fld)
        out   = []

        if self.is_repeated(fld):
            cnt = 'msg->%s_count' % fld.name
            if k in ('scalar', 'enum'):
                out.append('if( FD_UNLIKELY( !fd_pb_enc_packed( enc, %dU, FD_PB_GEN_%s, %s, %s ) ) ) return 0;' % (n, self.gen_type(m, fld), a, cnt))
            elif k == 'msg':
                sub = self.cname(fld.type_name)
                out.append('for( ulong i=0UL; i<%s; i++ ) {' % cnt)
                out.append('  if( FD_UNLIKELY( !fd_pb_enc_submsg( enc, %dU, &%s_t_msg, &%s[ i ] ) ) ) return 0;' % (n, sub, a))
                out.append('}')
            elif k == 'bytes_ptr':
                out.append('for( ulong i=0UL; i<%s; i++ ) {' % cnt)
                out.append('  if( FD_UNLIKELY( !fd_pb_enc_bytes_ptr( enc, %dU, %s[ i ] ) ) ) return 0;' % (n, a))
                out.append('}')
            else:
                raise ValueError(k)
            return out

        if oneof:
            cond = 'msg->which_%s==%d' % (oneof, n)
        elif self.has_flag(m, fld):
            cond = 'msg->has_%s' % fld.name
        else:
            cond = None  # proto3 implicit presence: skip default values

        def emit(c, call):
            if c:
                out.append('if( %s && FD_UNLIKELY( !%s ) ) return 0;' % (c, call))
            else:
                out.append('if( FD_UNLIKELY( !%s ) ) return 0;' % call)

        if k == 'scalar':
            push = SCALAR[fld.type][1]
            val  = a
            if fld.type == FT.TYPE_SFIXED32: val = '(uint)%s' % a
            if fld.type == FT.TYPE_SFIXED64: val = '(ulong)%s' % a
            if cond is None:
                if fld.type in (FT.TYPE_DOUBLE, FT.TYPE_FLOAT):
                    cond = 'fd_pb_enc_nonzero( &%s, sizeof(%s) )' % (a, a)
                else:
                    cond = '%s' % a
            emit(cond, 'fd_pb_push_%s( enc, %dU, %s )' % (push, n, val))
        elif k == 'enum':
            if cond is None:
                cond = '%s' % a
            emit(cond, 'fd_pb_push_int64( enc, %dU, (long)%s )' % (n, a))
        elif k == 'msg':
            sub = self.cname(fld.type_name)
            emit(cond, 'fd_pb_enc_submsg( enc, %dU, &%s_t_msg, &%s )' % (n, sub, a))
        elif k == 'bytes_ptr':
            if oneof:
                emit(cond, 'fd_pb_enc_bytes_ptr( enc, %dU, %s )' % (n, a))
            else:
                c = '%s && %s->size' % (a, a)
                emit(c, 'fd_pb_push_bytes( enc, %dU, %s->bytes, %s->size )' % (n, a, a))
        elif k == 'bytes_fixed':
            emit(cond, 'fd_pb_push_bytes( enc, %dU, %s, %dUL )' % (n, a, self.static_size(m, fld)))
        elif k == 'bytes_static':
            sz = self.static_size(m, fld)
            out.append('if( FD_UNLIKELY( %s.size>%dU ) ) return 0;' % (a, sz))
            c = '%s.size' % a
            if cond: c = '%s && %s' % (cond, c)
            emit(c, 'fd_pb_push_bytes( enc, %dU, %s.bytes, %s.size )' % (n, a, a))
        elif k == 'string_static':
            sz = self.static_size(m, fld)
            c = '%s[0]' % a
            if cond: c = '%s && %s' % (cond, c)
            emit(c, 'fd_pb_push_string( enc, %dU, %s, strnlen( %s, %dUL ) )' % (n, a, a, sz))
        return out

    def gen_decode_field(self, m, fld):
        n     = fld.number
        a     = self.access(m, fld)
        k     = self.kind(m, fld)
        oneof = self.oneof_of(m, fld)
        out   = []

        if self.is_repeated(fld):
            cnt = 'msg->%s_count' % fld.name
            et  = self.elem_ctype(m, fld)
            if k in ('scalar', 'enum'):
                out.append('if( FD_UNLIKELY( !fd_pb_dec_repeated( in, tlv, FD_PB_GEN_%s, (void **)&%s, &%s ) ) ) return 0;' % (self.gen_type(m, fld), a, cnt))
            elif k == 'msg':
                sub = self.cname(fld.type_name)
                out.append('{')
                out.append('  void * ele = fd_pb_dec_grow( (void **)&%s, &%s, sizeof(%s) );' % (a, cnt, et))
                out.append('  if( FD_UNLIKELY( !ele ) ) return 0;')
                out.append('  if( FD_UNLIKELY( !fd_pb_dec_submsg( in, tlv, &%s_t_msg, ele ) ) ) return 0;' % sub)
                out.append('}')
            elif k == 'bytes_ptr':
                out.append('{')
                out.append('  fd_pb_bytes_array_t ** ele = fd_pb_dec_grow( (void **)&%s, &%s, sizeof(fd_pb_bytes_array_t *) );' % (a, cnt))
                out.append('  if( FD_UNLIKELY( !ele ) ) return 0;')
                out.append('  if( FD_UNLIKELY( !fd_pb_dec_bytes_ptr( in, tlv, ele ) ) ) return 0;')
                out.append('}')
            return out

        if oneof:
            # Switching oneof members discards the previous member
            out.append('if( msg->which_%s!=%d ) {' % (oneof, n))
            out.append('  %s_release_oneof_%s( msg );' % (self.cname(self.cur_full), oneof))
            out.append('  fd_memset( &msg->%s, 0, sizeof(msg->%s) );' % (oneof, oneof))
            out.append('}')

        if k == 'scalar':
            dec, ct = DEC[SCALAR[fld.type][2]]
            if ct == SCALAR[fld.type][0]:
                out.append('if( FD_UNLIKELY( !fd_pb_dec_%s( in, tlv, &%s ) ) ) return 0;' % (dec, a))
            else:
                out.append('if( FD_UNLIKELY( !fd_pb_dec_%s( in, tlv, (%s *)&%s ) ) ) return 0;' % (dec, ct, a))
        elif k == 'enum':
            out.append('if( FD_UNLIKELY( !fd_pb_dec_int32( in, tlv, (int *)&%s ) ) ) return 0;' % a)
        elif k == 'msg':
            sub = self.cname(fld.type_name)
            out.append('if( FD_UNLIKELY( !fd_pb_dec_submsg( in, tlv, &%s_t_msg, &%s ) ) ) return 0;' % (sub, a))
        elif k == 'bytes_ptr':
            out.append('if( FD_UNLIKELY( !fd_pb_dec_bytes_ptr( in, tlv, &%s ) ) ) return 0;' % a)
        elif k == 'bytes_fixed':
            out.append('if( FD_UNLIKELY( !fd_pb_dec_bytes_fixed( in, tlv, %s, %dUL ) ) ) return 0;' % (a, self.static_size(m, fld)))
        elif k == 'bytes_static':
            out.append('if( FD_UNLIKELY( !fd_pb_dec_bytes_static( in, tlv, %s.bytes, &%s.size, %dUL ) ) ) return 0;' % (a, a, self.static_size(m, fld)))
        elif k == 'string_static':
            out.append('if( FD_UNLIKELY( !fd_pb_dec_string_static( in, tlv, %s, %dUL ) ) ) return 0;' % (a, self.static_size(m, fld) + 1))

        if oneof:
            out.append('msg->which_%s = %d;' % (oneof, n))
        elif self.has_flag(m, fld):
            out.append('msg->has_%s = 1;' % fld.name)
        return out

    def release_lines(self, m, fld):
        a = self.access(m, fld)
        k = self.kind(m, fld)
        out = []
        if self.is_repeated(fld):
            cnt = 'msg->%s_count' % fld.name
            if k == 'msg':
                sub = self.cname(fld.type_name)
                out.append('for( ulong i=0UL; i<%s; i++ ) fd_pb_release( &%s_t_msg, &%s[ i ] );' % (cnt, sub, a))
            elif k == 'bytes_ptr':
                out.append('for( ulong i=0UL; i<%s; i++ ) free( %s[ i ] );' % (cnt, a))
            out.append('free( %s ); %s = NULL; %s = 0U;' % (a, a, cnt))
        elif k == 'msg':
            sub = self.cname(fld.type_name)
            out.append('fd_pb_release( &%s_t_msg, &%s );' % (sub, a))
        elif k == 'bytes_ptr':
            out.append('free( %s ); %s = NULL;' % (a, a))
        return out

    def gen_release_field(self, m, fld):
        oneof = self.oneof_of(m, fld)
        if oneof:
            # Released via fd_pb_release_oneof_*, once per oneof
            first = [f for f in m.field if self.oneof_of(m, f) == oneof][0]
            if first is not fld:
                return []
            return ['%s_release_oneof_%s( msg );' % (self.cname(self.cur_full), oneof)]
        return self.release_lines(m, fld)

    def gen_oneof_release(self, full):
        _, m = self.msgs[full]
        cn = self.cname(full)
        o = []
        seen = []
        for fld in m.field:
            oneof = self.oneof_of(m, fld)
            if oneof and oneof not in seen:
                seen.append(oneof)
        for oneof in seen:
            o.append('static void')
            o.append('%s_release_oneof_%s( %s_t * msg ) {' % (cn, oneof, cn))
            o.append('  switch( msg->which_%s ) {' % oneof)
            for fld in m.field:
                if self.oneof_of(m, fld) != oneof:
                    continue
                lines = self.release_lines(m, fld)
                if lines:
                    o.append('  case %d:' % fld.number)
                    o.extend('    ' + l for l in lines)
                    o.append('    break;')
            o.append('  default:')
            o.append('    break;')
            o.append('  }')
            o.append('  msg->which_%s = 0U;' % oneof)
            o.append('}\n')
        return o

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--fds',     required=True)
    ap.add_argument('--options', required=True)
    ap.add_argument('--out',     required=True)
    ap.add_argument('--prefix',  required=True)
    ap.add_argument('protos', nargs='+')
    args = ap.parse_args()

    fds = descriptor_pb2.FileDescriptorSet()
    with open(args.fds, 'rb') as f:
        fds.ParseFromString(f.read())

    opts = {}
    for name in os.listdir(args.options):
        if name.endswith('.options'):
            opts.update(parse_options(os.path.join(args.options, name)))

    gen = Gen(fds, opts, args.prefix)
    for f in fds.file:
        if f.name not in args.protos:
            continue
        if f.syntax != 'proto3':
            sys.exit('%s: only proto3 is supported' % f.name)
        base = os.path.splitext(f.name)[0]
        with open(os.path.join(args.out, base + '.pb.h'), 'w') as out:
            out.write(gen.gen_header(f, base))
        with open(os.path.join(args.out, base + '.pb.c'), 'w') as out:
            out.write(gen.gen_source(f, base))

if __name__ == '__main__':
    main()
