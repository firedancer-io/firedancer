import os
from pathlib import Path
import textwrap
from typing import Dict, List, TextIO
from .event_types import ClickHouseType, Field, Event


def generate_header(events: Dict[str, Event]):
    os.makedirs(Path(__file__).parent.parent / 'generated', exist_ok=True)

    with open(Path(__file__).parent.parent / 'generated' / 'fd_event.h', 'w') as f:
        f.write('#ifndef HEADER_fd_src_disco_events_generated_fd_event_h\n')
        f.write('#define HEADER_fd_src_disco_events_generated_fd_event_h\n\n')

        f.write('#include "../../fd_disco_base.h"\n\n')

        max_name_length = max([len(f'FD_EVENT_{event.name}') for event in events.values()])
        for event in events.values():
            if event.name == 'common':
                continue

            name = f'FD_EVENT_{event.name.upper()}'.ljust(max_name_length)
            f.write(f'#define {name} ({event.id}UL)\n')
        f.write('\n')

        f.write('static inline char const *\n')
        f.write('fd_event_type_str( ulong event_type ) {\n')
        f.write('  switch( event_type ) {\n')

        for event in events.values():
            if event.name == 'common':
                continue

            name = f'FD_EVENT_{event.name.upper()}'.ljust(max_name_length)
            f.write(f'    case {name}: return "{event.name}";\n')
        f.write('    default: return "unknown";\n')
        f.write('  }\n')
        f.write('}\n\n')

        for event in events.values():
            for field in event.fields.values():
                if field.deprecated or field.server_only:
                    continue

                if field.type == ClickHouseType.ENUM_8:
                    max_variant_length = max([len(f'FD_EVENT_{event.name}_{field.name}_{variant}') for variant in field.variants])
                    for (variant, value) in field.variants.items():
                        name = f'FD_EVENT_{event.name.upper()}_{field.name.upper()}_{variant.upper()}'.ljust(max_variant_length)
                        f.write(f'#define {name} ({value})\n')
                    f.write('\n')

                    f.write('static inline char const *\n')
                    f.write(f'fd_event_{event.name}_{field.name}_str( uchar value ) {{\n')
                    f.write(f'  switch( value ) {{\n')
                    for (variant, value) in field.variants.items():
                        f.write(f'    case FD_EVENT_{event.name.upper()}_{field.name.upper()}_{variant.upper()}: return "{variant}";\n')
                    f.write('    default: return "unknown";\n')
                    f.write('  }\n')
                    f.write('}\n\n')

                elif field.type == ClickHouseType.NESTED:
                    for sub_field in field.sub_fields.values():
                        if sub_field.type == ClickHouseType.ENUM_8:
                            max_variant_length = max([len(f'FD_EVENT_{event.name}_{field.name}_{sub_field.name}_{variant}') for variant in sub_field.variants])
                            for (variant, value) in sub_field.variants.items():
                                name = f'FD_EVENT_{event.name.upper()}_{field.name.upper()}_{sub_field.name.upper()}_{variant.upper()}'.ljust(max_variant_length)
                                f.write(f'#define {name} ({value})\n')
                            f.write('\n')

                            f.write('static inline char const *\n')
                            f.write(f'fd_event_{event.name}_{field.name}_{sub_field.name}_str( uchar value ) {{\n')
                            f.write(f'  switch( value ) {{\n')
                            for (variant, value) in sub_field.variants.items():
                                f.write(f'    case FD_EVENT_{event.name.upper()}_{field.name.upper()}_{sub_field.name.upper()}_{variant.upper()}: return "{variant}";\n')
                            f.write('    default: return "unknown";\n')
                            f.write('  }\n')
                            f.write('}\n\n')

        for event in events.values():
            for field in event.fields.values():
                if field.type == ClickHouseType.NESTED:
                    f.write(f'struct fd_event_{event.name}_{field.name} {{\n')
                    for sub_field in field.sub_fields.values():
                        if sub_field.type == ClickHouseType.DATETIME_64_9:
                            f.write(f'  /* {textwrap.fill(sub_field.description, width=72, subsequent_indent="     ")} */\n')
                            f.write(f'  long {sub_field.name};\n\n')
                        elif sub_field.type == ClickHouseType.ENUM_8:
                            description = sub_field.description + " Must be one of FD_EVENT_" + event.name.upper() + "_" + field.name.upper() + "_" + sub_field.name.upper() + "_*"
                            f.write(f'  /* {textwrap.fill(description, width=72, subsequent_indent="     ")} */\n')
                            f.write(f'  uchar {sub_field.name};\n\n')
                        elif sub_field.type == ClickHouseType.LOW_CARDINALITY_STRING or sub_field.type == ClickHouseType.STRING:
                            if sub_field.max_length is None:
                                description = f'{sub_field.description} Fields of this type are arbitrary length strings ' + \
                                    f'and are not guaranteed to be null-terminated. {sub_field.name}_off is an offset from ' + \
                                    f'the beginning of the event to the start of the string, and {sub_field.name}_len is the ' + \
                                    'length of the string in bytes.'
                                f.write(f'  /* {textwrap.fill(description, width=72, subsequent_indent="     ")} */\n')
                                f.write(f'  ulong {sub_field.name}_off;\n')
                                f.write(f'  ulong {sub_field.name}_len;\n\n')
                                continue
                            else:
                                f.write(f'  /* {textwrap.fill(sub_field.description, width=72, subsequent_indent="     ")} */\n')
                                f.write(f'  char {sub_field.name}[{sub_field.max_length + 1}];\n\n')
                        elif sub_field.type == ClickHouseType.UINT16:
                            f.write(f'  /* {textwrap.fill(sub_field.description, width=72, subsequent_indent="     ")} */\n')
                            f.write(f'  ushort {sub_field.name};\n\n')
                        elif sub_field.type == ClickHouseType.UINT32:
                            f.write(f'  /* {textwrap.fill(sub_field.description, width=72, subsequent_indent="     ")} */\n')
                            f.write(f'  uint {sub_field.name};\n\n')
                        elif sub_field.type == ClickHouseType.UINT64:
                            f.write(f'  /* {textwrap.fill(sub_field.description, width=72, subsequent_indent="     ")} */\n')
                            f.write(f'  ulong {sub_field.name};\n\n')
                        elif sub_field.type == ClickHouseType.TUPLE:
                            f.write(f'  /* {textwrap.fill(sub_field.description, width=72, subsequent_indent="     ")} */\n')
                            f.write(f'  struct {{\n')
                            for tuple_field in sub_field.sub_fields.values():
                                if tuple_field.type == ClickHouseType.DATETIME_64_9:
                                    f.write(f'    long {tuple_field.name}; /* {tuple_field.description} */ \n')
                                elif tuple_field.type == ClickHouseType.ENUM_8:
                                    description = tuple_field.description + " Must be one of FD_EVENT_" + event.name.upper() + "_" + field.name.upper() + "_" + sub_field.name.upper() + "_" + tuple_field.name.upper() + "_*"
                                    f.write(f'    uchar {tuple_field.name}; /* {tuple_field.description} */ \n')
                                elif tuple_field.type == ClickHouseType.LOW_CARDINALITY_STRING or tuple_field.type == ClickHouseType.STRING:
                                    if tuple_field.max_length is None:
                                        description = f'{tuple_field.description} Fields of this type are arbitrary length strings ' + \
                                            f'and are not guaranteed to be null-terminated. {tuple_field.name}_off is an offset from ' + \
                                            f'the beginning of the event to the start of the string, and {tuple_field.name}_len is the ' + \
                                            'length of the string in bytes.'
                                        f.write(f'    ulong {tuple_field.name}_off;\n')
                                        f.write(f'    ulong {tuple_field.name}_len;\n')
                                        continue
                                    else:
                                        f.write(f'    char {tuple_field.name}[{tuple_field.max_length + 1}];\n')
                                elif tuple_field.type == ClickHouseType.UINT16:
                                    f.write(f'    ushort {tuple_field.name}; /* {tuple_field.description} */ \n')
                                elif tuple_field.type == ClickHouseType.UINT32:
                                    f.write(f'    uint {tuple_field.name}; /* {tuple_field.description} */ \n')
                                elif tuple_field.type == ClickHouseType.UINT64:
                                    f.write(f'    ulong {tuple_field.name}; /* {tuple_field.description} */ \n')
                                else:
                                    raise ValueError(f"Unknown field type {tuple_field.type}")
                            f.write(f'  }} {sub_field.name};\n\n')
                        else:
                            raise ValueError(f"Unknown field type {sub_field.type}")
                    f.write('};\n\n')

                    f.write(f'typedef struct fd_event_{event.name}_{field.name} fd_event_{event.name}_{field.name}_t;\n\n')

            f.write(f'/* {textwrap.fill(event.description, width=72, subsequent_indent="   ")} */\n')
            f.write(f'struct fd_event_{event.name} {{\n')
            for field in event.fields.values():
                if field.deprecated or field.server_only:
                    continue

                if field.type == ClickHouseType.DATETIME_64_9:
                    f.write(f'  /* {textwrap.fill(field.description, width=72, subsequent_indent="     ")} */\n')
                    f.write(f'  long {field.name};\n\n')
                elif field.type == ClickHouseType.ENUM_8:
                    description = field.description + " Must be one of FD_EVENT_" + event.name.upper() + "_" + field.name.upper() + "_*"
                    f.write(f'  /* {textwrap.fill(description, width=72, subsequent_indent="     ")} */\n')
                    f.write(f'  uchar {field.name};\n\n')
                elif field.type == ClickHouseType.LOW_CARDINALITY_STRING or field.type == ClickHouseType.STRING:
                    if field.max_length is None:
                        description = f'{field.description} Fields of this type are arbitrary length strings ' + \
                            f'and are not guaranteed to be null-terminated. {field.name}_off is an offset from ' + \
                            f'the beginning of the event to the start of the string, and {field.name}_len is the ' + \
                            'length of the string in bytes.'
                        f.write(f'  /* {textwrap.fill(description, width=72, subsequent_indent="     ")} */\n')
                        f.write(f'  ulong {field.name}_off;\n')
                        f.write(f'  ulong {field.name}_len;\n\n')
                        continue
                    else:
                        f.write(f'  /* {textwrap.fill(field.description, width=72, subsequent_indent="     ")} */\n')
                        f.write(f'  char {field.name}[{field.max_length + 1}];\n\n')
                elif field.type == ClickHouseType.UINT16:
                    f.write(f'  /* {textwrap.fill(field.description, width=72, subsequent_indent="     ")} */\n')
                    f.write(f'  ushort {field.name};\n\n')
                elif field.type == ClickHouseType.UINT32:
                    f.write(f'  /* {textwrap.fill(field.description, width=72, subsequent_indent="     ")} */\n')
                    f.write(f'  uint {field.name};\n\n')
                elif field.type == ClickHouseType.UINT64:
                    f.write(f'  /* {textwrap.fill(field.description, width=72, subsequent_indent="     ")} */\n')
                    f.write(f'  ulong {field.name};\n\n')
                elif field.type == ClickHouseType.NESTED:
                    f.write(f'  /* {textwrap.fill(field.description, width=72, subsequent_indent="     ")} */\n')
                    f.write(f'  ulong {field.name}_off;\n')
                    f.write(f'  ulong {field.name}_len;\n\n')
                else:
                    raise ValueError(f"Unknown field type {field.type}")
            f.write('};\n\n')

            f.write(f'typedef struct fd_event_{event.name} fd_event_{event.name}_t;\n\n')

        f.write('struct fd_event {\n')
        f.write('  union {\n')
        for event in events.values():
            if event.name == 'common':
                continue

            f.write(f'    fd_event_{event.name}_t {event.name};\n')
        f.write('  };\n')
        f.write('};\n\n')

        f.write('typedef struct fd_event fd_event_t;\n\n')

        f.write('#define FD_EVENT_FORMAT_OVERFLOW (-1)\n')
        f.write('#define FD_EVENT_FORMAT_INVALID  (-2)\n\n')

        f.write('long\n')
        f.write('fd_event_format( fd_event_common_t const * common,\n')
        f.write('                 ulong                     event_type,\n')
        f.write('                 fd_event_t const *        event,\n')
        f.write('                 ulong                     event_len,\n')
        f.write('                 char *                    buffer,\n')
        f.write('                 ulong                     buffer_len );\n\n')

        f.write('#endif /* HEADER_fd_src_disco_events_generated_fd_event_h */\n')

    with open(Path(__file__).parent.parent / 'generated' / 'fd_event_metrics.h', 'w') as f:
        f.write('#ifndef HEADER_fd_src_disco_events_generated_fd_event_metrics_h\n')
        f.write('#define HEADER_fd_src_disco_events_generated_fd_event_metrics_h\n\n')

        f.write('#include "fd_event.h"\n')
        f.write('#include "../../metrics/fd_metrics.h"\n\n')
        f.write('#include "../../topo/fd_topo.h"\n\n')

        f.write('ulong\n')
        f.write('fd_event_metrics_footprint( fd_topo_t const * topo ) {\n')
        f.write('  ulong l = FD_LAYOUT_INIT;')
        f.write('  l = FD_LAYOUT_APPEND( l, alignof( fd_event_metrics_sample_t ),      sizeof( fd_event_metrics_sample_t ) );\n')
        f.write('  l = FD_LAYOUT_APPEND( l, alignof( fd_event_metrics_sample_tile_t ), topo->tile_cnt*sizeof( fd_event_metrics_sample_tile_t ) );\n')
        f.write('  l = FD_LAYOUT_APPEND( l, alignof( fd_event_metrics_sample_link_t ), fd_topo_polled_in_cnt( topo )*sizeof( fd_event_metrics_sample_link_t ) );\n')
        for field in events['metrics_sample'].fields.values():
            if field.deprecated or field.server_only:
                continue

            if field.type != ClickHouseType.NESTED or field.name == 'common' or field.name == 'link':
                continue

            f.write(f'  l = FD_LAYOUT_APPEND( l, alignof( fd_event_metrics_sample_{field.name}_t ), fd_topo_tile_name_cnt( topo, "{field.name}" )*sizeof( fd_event_metrics_sample_{field.name}_t ) );\n')

        f.write('  return l;\n')
        f.write('}\n\n')

        f.write('void\n')
        f.write('fd_event_metrics_layout( fd_topo_t const * topo,\n')
        f.write('                         uchar *           buffer ) {\n')
        f.write('  ulong off = 0UL;\n\n')
        f.write('  fd_event_metrics_sample_t * metrics = (fd_event_metrics_sample_t *)(buffer+off);\n')
        f.write('  off += sizeof( fd_event_metrics_sample_t );\n\n')

        for field in events['metrics_sample'].fields.values():
            if field.deprecated or field.server_only:
                continue

            if field.type != ClickHouseType.NESTED:
                continue

            f.write(f'  off = fd_ulong_align_up( off, alignof( fd_event_metrics_sample_{field.name}_t ) );\n')
            f.write(f'  metrics->{field.name}_off = off;\n')
            if field.name == 'common':
                cnt = 'topo->tile_cnt'
            elif field.name == 'link':
                cnt = 'fd_topo_polled_in_cnt( topo )'
            else:
                cnt = f'fd_topo_tile_name_cnt( topo, "{field.name}" )'
            f.write(f'  metrics->{field.name}_len = {cnt};\n')
            f.write(f'  off += {cnt}*sizeof( fd_event_metrics_sample_{field.name}_t );\n\n')

        f.write('  ulong link_idx = 0UL;\n')
        f.write('  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {\n')
        f.write('    fd_event_metrics_sample_tile_t * tile = (fd_event_metrics_sample_tile_t *)(buffer+((fd_event_metrics_sample_t*)buffer)->tile_off)+i;\n')
        f.write('    strncpy( tile->kind, topo->tiles[ i ].name, sizeof( tile->kind ) );\n')
        f.write('    tile->kind_id = (ushort)topo->tiles[ i ].kind_id;\n\n')
        f.write('    for( ulong j=0UL; j<topo->tiles[ i ].in_cnt; j++ ) {\n')
        f.write('      if( FD_UNLIKELY( !topo->tiles[ i ].in_link_poll[ j ] ) ) continue;\n')
        f.write('      fd_event_metrics_sample_link_t * link = (fd_event_metrics_sample_link_t *)(buffer+((fd_event_metrics_sample_t*)buffer)->link_off)+link_idx;\n')
        f.write('      strncpy( link->kind, topo->tiles[ i ].name, sizeof( link->kind ) );\n')
        f.write('      link->kind_id = (ushort)topo->tiles[ i ].kind_id;\n')
        f.write('      strncpy( link->link_kind, topo->links[ topo->tiles[ i ].in_link_id[ j ] ].name, sizeof( link->link_kind ) );\n')
        f.write('      link->link_kind_id = (ushort)topo->links[ topo->tiles[ i ].in_link_id[ j ] ].kind_id;\n')
        f.write('      link_idx++;\n')
        f.write('    }\n')
        f.write('  }\n')
        f.write('}\n\n')

        f.write('#endif /* HEADER_fd_src_disco_events_generated_fd_event_metrics_h */\n')

def write_fields(f: TextIO, indent: int, name: str, prefix: str, fields: Dict[str, Field]):
    f.write(''.ljust(indent) + 'success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed,\n')
    f.write(''.ljust(indent) + '  "{"\n')
    
    for (i, field) in enumerate(fields.values()):
        if field.deprecated or field.server_only:
            continue

        if field.type == ClickHouseType.DATETIME_64_9:
            f.write(''.ljust(indent) + f'    "\\"{field.name}\\":%ld')
        elif field.type == ClickHouseType.ENUM_8:
            f.write(''.ljust(indent) + f'    "\\"{field.name}\\":\\"%s\\"')
        elif field.type == ClickHouseType.LOW_CARDINALITY_STRING or field.type == ClickHouseType.STRING:
            if field.max_length is None:
                f.write(''.ljust(indent) + f'    "\\"{field.name}\\":\\"%.*s\\"')
            else:
                f.write(''.ljust(indent) + f'    "\\"{field.name}\\":\\"%.{field.max_length}s\\"')
        elif field.type == ClickHouseType.UINT16:
            f.write(''.ljust(indent) + f'    "\\"{field.name}\\":%hu')
        elif field.type == ClickHouseType.UINT32:
            f.write(''.ljust(indent) + f'    "\\"{field.name}\\":%u')
        elif field.type == ClickHouseType.UINT64:
            f.write(''.ljust(indent) + f'    "\\"{field.name}\\":%lu')
        elif field.type == ClickHouseType.TUPLE:
            f.write(''.ljust(indent) + f'    "\\"{field.name}\\":{{"\n')
            for (j, tuple_field) in enumerate(field.sub_fields.values()):
                if tuple_field.type == ClickHouseType.DATETIME_64_9:
                    f.write(''.ljust(indent) + f'      "\\"{tuple_field.name}\\":\\"%ld\\"')
                elif tuple_field.type == ClickHouseType.ENUM_8:
                    f.write(''.ljust(indent) + f'      "\\"{tuple_field.name}\\":\\"%s\\"')
                elif tuple_field.type == ClickHouseType.LOW_CARDINALITY_STRING or tuple_field.type == ClickHouseType.STRING:
                    if tuple_field.max_length is None:
                        f.write(''.ljust(indent) + f'      "\\"{tuple_field.name}\\":\\"%.*s\\"')
                    else:
                        f.write(''.ljust(indent) + f'      "\\"{tuple_field.name}\\":\\"%.{tuple_field.max_length}s\\"')
                elif tuple_field.type == ClickHouseType.UINT16:
                    f.write(''.ljust(indent) + f'      "\\"{tuple_field.name}\\":%hu')
                elif tuple_field.type == ClickHouseType.UINT32:
                    f.write(''.ljust(indent) + f'      "\\"{tuple_field.name}\\":%u')
                elif tuple_field.type == ClickHouseType.UINT64:
                    f.write(''.ljust(indent) + f'      "\\"{tuple_field.name}\\":%lu')
                else:
                    raise ValueError(f"Unknown field type {tuple_field.type}")

                if j < len(field.sub_fields) - 1:
                    f.write(',"\n')
                else:
                    f.write('"\n')
            f.write(''.ljust(indent) + f'    "}}')
        elif field.type == ClickHouseType.NESTED:
            pass

        if i < len(fields) - 1:
            f.write(',"\n')
        else:
            f.write('"\n')

    f.write(''.ljust(indent) + '  "}",\n')
    active_fields: List[Field] = [field for field in fields.values() if not field.deprecated and not field.server_only]
    for (i, field) in enumerate(active_fields):
        if field.type == ClickHouseType.DATETIME_64_9:
            f.write(''.ljust(indent) + f'  {name}->{field.name}')
        elif field.type == ClickHouseType.ENUM_8:
            f.write(''.ljust(indent) + f'  fd_event_{prefix}_{field.name}_str( {name}->{field.name} )')
        elif field.type == ClickHouseType.LOW_CARDINALITY_STRING or field.type == ClickHouseType.STRING:
            if field.max_length is None:
                f.write(''.ljust(indent) + f'  (int){name}->{field.name}_len, ((char*){name})+{name}->{field.name}_off')
            else:
                f.write(''.ljust(indent) + f'  {name}->{field.name}')
        elif field.type == ClickHouseType.UINT16:
            f.write(''.ljust(indent) + f'  {name}->{field.name}')
        elif field.type == ClickHouseType.UINT32:
            f.write(''.ljust(indent) + f'  {name}->{field.name}')
        elif field.type == ClickHouseType.UINT64:
            f.write(''.ljust(indent) + f'  {name}->{field.name}')
        elif field.type == ClickHouseType.TUPLE:
            sub_fields = [field for field in field.sub_fields.values() if not field.deprecated and not field.server_only]
            for (j, tuple_field) in enumerate(sub_fields):
                if tuple_field.type == ClickHouseType.DATETIME_64_9:
                    f.write(''.ljust(indent) + f'  {name}->{field.name}.{tuple_field.name}')
                elif tuple_field.type == ClickHouseType.ENUM_8:
                    f.write(''.ljust(indent) + f'  fd_event_{prefix}_{field.name}_{tuple_field.name}_str( {name}->{field.name}.{tuple_field.name} )')
                elif tuple_field.type == ClickHouseType.LOW_CARDINALITY_STRING or tuple_field.type == ClickHouseType.STRING:
                    if tuple_field.max_length is None:
                        f.write(''.ljust(indent) + f'  (int){name}->{field.name}.{tuple_field.name}_len, ((char*){name})+{name}->{field.name}.{tuple_field.name}_off')
                    else:
                        f.write(''.ljust(indent) + f'  {name}->{field.name}.{tuple_field.name}')
                elif tuple_field.type == ClickHouseType.UINT16:
                    f.write(''.ljust(indent) + f'  {name}->{field.name}.{tuple_field.name}')
                elif tuple_field.type == ClickHouseType.UINT32:
                    f.write(''.ljust(indent) + f'  {name}->{field.name}.{tuple_field.name}')
                elif tuple_field.type == ClickHouseType.UINT64:
                    f.write(''.ljust(indent) + f'  {name}->{field.name}.{tuple_field.name}')
                else:
                    raise ValueError(f"Unknown field type {tuple_field.type}")

                if j < len(sub_fields) - 1:
                    f.write(',\n')
        else:
            raise ValueError(f"Unknown field type {field.type}")

        if i < len(active_fields) - 1:
            f.write(',\n')
        else:
            f.write(' );\n')

    f.write('\n')
    f.write(''.ljust(indent) + 'if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;\n')
    f.write(''.ljust(indent) + 'off += printed;\n')

def write_event(f: TextIO, name: str, event: Event):
    has_complex = [field for field in event.fields.values() if field.type == ClickHouseType.NESTED]

    if not has_complex:
        write_fields(f, 2, name, event.name, event.fields)
    else:
        for (i, field) in enumerate(event.fields.values()):
            if field.deprecated or field.server_only:
                continue

            comma = ',' if i < len(event.fields) - 1 else ''
            if field.type == ClickHouseType.DATETIME_64_9:
                f.write(f'  success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, "\\"{field.name}\\":%ld,", {name}->{field.name} );\n')
                f.write('  if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;\n')
                f.write('  off += printed;\n\n')
            elif field.type == ClickHouseType.ENUM_8:
                f.write(f'  success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, "\\"{field.name}\\":\\"%s\\",", fd_event_{event.name}_{field.name}_str( {name}->{field.name} ) );\n')
                f.write('  if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;\n')
                f.write('  off += printed;\n\n')
            elif field.type == ClickHouseType.LOW_CARDINALITY_STRING or field.type == ClickHouseType.STRING:
                if field.max_length is None:
                    f.write(f'  success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, "\\"{field.name}\\":%.*s{comma}", (int){name}->{field.name}_len, ((char*)event)+event->{field.name}_off );\n')
                else:
                    f.write(f'  success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, "\\"{field.name}\\":%.*s{comma}", {field.max_length}, {name}->{field.name} );\n')
                f.write('  if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;\n')
                f.write('  off += printed;\n\n')
            elif field.type == ClickHouseType.UINT16:
                f.write(f'  success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, "\\"{field.name}\\":%hu{comma}", {name}->{field.name} );\n')
                f.write('  if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;\n')
                f.write('  off += printed;\n\n')
            elif field.type == ClickHouseType.UINT32:
                f.write(f'  success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, "\\"{field.name}\\":%u{comma}", {name}->{field.name} );\n')
                f.write('  if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;\n')
                f.write('  off += printed;\n\n')
            elif field.type == ClickHouseType.UINT64:
                f.write(f'  success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, "\\"{field.name}\\":%lu{comma}", {name}->{field.name} );\n')
                f.write('  if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;\n')
                f.write('  off += printed;\n\n')
            elif field.type == ClickHouseType.NESTED:
                f.write(f'  success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, "\\"{field.name}\\":[" );\n')
                f.write(f'  if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;\n')
                f.write(f'  off += printed;\n\n')
                f.write(f'  if( FD_UNLIKELY( event->{field.name}_off+event->{field.name}_len*sizeof(fd_event_{event.name}_{field.name}_t)>event_len ) ) return FD_EVENT_FORMAT_INVALID;\n')
                f.write(f'  for( ulong i=0UL; i<event->{field.name}_len; i++ ) {{\n')
                f.write(f'    fd_event_{event.name}_{field.name}_t const * {field.name} = ((fd_event_{event.name}_{field.name}_t const *)(((char*)event)+{name}->{field.name}_off))+i;\n\n')

                write_fields(f, 4, field.name, f'{event.name}_{field.name}', field.sub_fields)

                f.write(f'\n    if( FD_LIKELY( i!=event->{field.name}_len-1UL ) ) {{\n' );
                f.write('      success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, ",");\n')
                f.write('      if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;\n')
                f.write('      off += printed;\n')
                f.write('    }\n')

                f.write(f'  }}\n\n')
                f.write(f'  success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, "]{comma}");\n')
                f.write(f'  if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;\n')
                f.write(f'  off += printed;\n\n')

def generate_impl(events: Dict[str, Event]):
    os.makedirs(Path(__file__).parent.parent / 'generated', exist_ok=True)

    with open(Path(__file__).parent.parent / 'generated' / 'fd_event.c', 'w') as f:
        f.write('#include "fd_event.h"\n\n')

        f.write('#pragma GCC diagnostic ignored "-Woverlength-strings"\n\n')

        for event in events.values():
            f.write(f'static long\n')
            if event.name != 'common':
                f.write(f'format_{event.name}( fd_event_{event.name}_t const * event,\n')
                f.write(f'                     ulong                           event_len,\n')
            else:
                f.write(f'format_common( fd_event_common_t const * event,\n')
            f.write(f'                     char *                          buffer,\n')
            f.write(f'                     ulong                           buffer_len ) {{\n')

            for field in event.fields.values():
                if field.deprecated or field.server_only:
                    continue

                if field.type == ClickHouseType.LOW_CARDINALITY_STRING or field.type == ClickHouseType.STRING:
                    if field.max_length is None:
                        f.write(f'  if( FD_UNLIKELY( event->{field.name}_off+event->{field.name}_len>event_len ) ) return FD_EVENT_FORMAT_INVALID;\n')

            f.write('\n')

            f.write('  ulong off = 0UL;\n')
            f.write('  ulong printed;\n')
            f.write('  int success;\n\n')

            write_event(f, 'event', event)

            f.write('\n  return (long)off;\n')
            f.write('}\n\n')

        f.write('long\n')
        f.write('fd_event_format( fd_event_common_t const * common,\n')
        f.write('                 ulong                     event_type,\n')
        f.write('                 fd_event_t const *        event,\n')
        f.write('                 ulong                     event_len,\n')
        f.write('                 char *                    buffer,\n')
        f.write('                 ulong                     buffer_len ) {\n')
        f.write('  ulong off = 0UL;\n')
        f.write('  ulong printed;\n')
        f.write('  int success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, "{\\"kind\\":\\"%s\\",\\"common\\":", fd_event_type_str( event_type ) );\n')
        f.write('  if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;\n')
        f.write('  off += printed;\n\n')

        f.write('  long printed2 = format_common( common, buffer+off, buffer_len-off );\n')
        f.write('  if( FD_UNLIKELY( printed2<0 ) ) return printed2;\n')
        f.write('  off += (ulong)printed2;\n\n')

        f.write('  success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, ",\\"event\\":{" );\n')
        f.write('  if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;\n')
        f.write('  off += printed;\n\n')

        f.write('  switch( event_type ) {\n')

        for event in events.values():
            if event.name == 'common':
                continue

            f.write(f'    case FD_EVENT_{event.name.upper()}:\n')
            f.write(f'      printed2 = format_{event.name}( &event->{event.name}, event_len, buffer+off, buffer_len-off );\n')
            f.write('      break;\n')

        f.write('    default:\n')
        f.write('      return FD_EVENT_FORMAT_INVALID;\n')
        f.write('  }\n\n')
        f.write('  if( FD_UNLIKELY( printed2<0 ) ) return printed2;\n')
        f.write('  off += (ulong)printed2;\n\n')
        f.write('  success = fd_cstr_printf_check( buffer+off, buffer_len-off, &printed, "}}" );\n')
        f.write('  if( FD_UNLIKELY( !success ) ) return FD_EVENT_FORMAT_OVERFLOW;\n')
        f.write('  off += printed;\n\n')
        f.write('  return (long)off;\n')
        f.write('}\n')

def write_event_formatter(events: Dict[str, Event]):
    generate_header(events)
    generate_impl(events)

    print(f'Wrote {len(events)} events to src/disco/metrics/generated')
