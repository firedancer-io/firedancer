"""Field tables the event tile walks to encode metrics_<tile> and
metrics_link rows (generated/fd_metrics_sample_gen.{h,c}).  One entry per
encoded field, in schema order, numbered from the committed schema file,
so the tables always match the proto."""

from .types import *
from .write_schemas import snake, SCHEMA_DIR
from .write_codegen import camel2snake
from pathlib import Path
import json

def _numbered(fields: dict) -> dict:
    """{name: (field number, subfields, variants)}: positional unless an
    explicit provisional field_number is given."""
    return { k: ( v.get('field_number', i), _numbered(v['fields']) if 'fields' in v else None, list(v.get('variants', {})) )
             for i, (k, v) in enumerate(fields.items(), 1) }

def _state_map(states: MetricEnum, variants: list) -> list:
    """Raw gauge value -> proto enum number (0 for a value the schema lacks)."""
    raw = { snake(v.name): v.value for v in states.values }
    out = [ 0 ] * ( max(v.value for v in states.values) + 1 )
    for i, n in enumerate(variants, 1): out[ raw[n] ] = i
    return out

def _entries(ms: List[Metric], fields: dict, maps: dict, prefix: str, group: str) -> list:
    """(offset expr, field number, kind, map name) per encoded field;
    offsets are the generated _OFF names into the tile metrics area
    (fd_metrics_tile) or one link-in area."""
    out = []
    for m in ms:
        if not m.telemetry: continue
        num, sub, variants = fields[snake(m.name)]
        base = f'FD_METRICS_{m.type.name.upper()}_{group}_{camel2snake(m.name)}'
        off  = f'{base}_OFF'
        ns  = getattr(m, 'converter', None) == HistogramConverter.NANOSECONDS
        if isinstance(m, HistogramMetric):
            out.append((off, num, 'OPEN', None))
            out += [ (f'{off}+{i}', sub[f'b{i}'][0], 'U64', None) for i in range(16) ]
            out.append((f'{off}+16', sub['sum'][0], 'NS' if ns else 'U64', None))
            out.append(('0', 0, 'CLOSE', None))
        elif isinstance(m, (CounterEnumMetric, GaugeEnumMetric)):
            k = 'BOOL' if getattr(m, 'is_bool', False) else ( 'NS' if ns else 'U64' )
            out.append((off, num, 'OPEN', None))
            out += [ (f'{base}_{camel2snake(v.name)}_OFF', sub[snake(v.name)][0], k, None) for v in m.enum.values if not v.deprecated ]
            out.append(('0', 0, 'CLOSE', None))
        elif isinstance(m, GaugeMetric) and m.states:
            name = f'state_{prefix}_{snake(m.name)}'
            maps[name] = _state_map(m.states, variants)
            out.append((off, num, 'STATE', name))
        elif isinstance(m, GaugeMetric) and m.is_bool:
            out.append((off, num, 'BOOL', None))
        else:
            out.append((off, num, 'NS' if ns else 'U64', None))
    return out

def _tag_sz(num: int) -> int:
    """Bytes of a protobuf tag (field number, wire type) varint."""
    v, n = num << 3, 1
    while v >= 0x80: v >>= 7; n += 1
    return n

# Worst-case value bytes per kind: varint64, bool, enum varint, LEN prefix
# (fd_pb_lp_open reserves 5) for a Tuple open; a close adds nothing
VALUE_SZ = { 'U64': 10, 'NS': 10, 'BOOL': 1, 'STATE': 5, 'OPEN': 5, 'CLOSE': 0 }

def _fields_max(entries: list) -> int:
    return sum(0 if kind == 'CLOSE' else _tag_sz(num) + VALUE_SZ[kind] for _, num, kind, _ in entries)

def _event_max(sid: int, entries: list, nums: dict, link: bool) -> int:
    """Worst-case encoded event: envelope (nonce, event_id, link_seq,
    timestamp), Event and schema submessage opens, the sample header the
    event tile writes, every field, and the encoder's 32-byte slack."""
    envelope = sum(_tag_sz(n) + 10 for n in (1, 2, 3, 4)) + _tag_sz(5) + 5 + _tag_sz(sid) + 5
    header   = sum(_tag_sz(nums[k]) + 10 for k in ('sample_id', 'sample_slot', 'sample_tile_cnt', 'kind_id'))
    header  += _tag_sz(nums['sample_reason']) + 5 + _tag_sz(nums['sample_snapct_state']) + 5 + _tag_sz(nums['sample_caught_up']) + 1
    if link:  # tile name (6) and link name (13) strings, link_idx
        header += _tag_sz(nums['tile']) + 1 + 6 + _tag_sz(nums['link']) + 1 + 13 + _tag_sz(nums['link_idx']) + 10
    return envelope + header + _fields_max(entries) + 32

# Sample fields every metrics schema starts with, encoded by the event tile
SAMPLE_FIELDS = ( 'sample_id', 'sample_reason', 'sample_slot', 'sample_snapct_state', 'sample_caught_up', 'sample_tile_cnt', 'kind_id' )
LINK_FIELDS   = ( 'tile', 'link', 'link_idx' )

def write_sample(metrics: Metrics):
    out    = Path(__file__).parent / '../generated'
    shared = json.loads((SCHEMA_DIR / 'shared.json').read_text())
    tiles  = [ t for t in metrics.tiles if t not in metrics.tiles_no_telemetry ]
    docs   = { t.name.lower(): json.loads((SCHEMA_DIR / f'metrics_{t.name.lower()}.json').read_text()) for t in tiles }
    link   = json.loads((SCHEMA_DIR / 'metrics_link.json').read_text())

    # The sample fields are inlined in every schema from one source; check
    # they kept the same numbers so the event tile can encode them once
    nums = None
    for name, doc in list(docs.items()) + [ ('link', link) ]:
        n = _numbered(doc['fields'])
        got = { k: n[k][0] for k in SAMPLE_FIELDS }
        if nums is None: nums = got
        elif got != nums: raise SystemExit(f'metrics_{name}: sample fields numbered {got}, others {nums}')
    lnum = _numbered(link['fields'])

    maps = {}
    tables = {}
    for name, doc in docs.items():
        f = _numbered(doc['fields'])
        tables[name] = _entries(metrics.common, f, maps, name, 'TILE') + _entries(metrics.tiles[Tile[name.upper()]], f, maps, name, name.upper())
    tables['link'] = _entries(metrics.link_in, lnum, maps, 'link', 'LINK')

    with open(out / 'fd_metrics_sample_gen.h', 'w') as f:
        f.write('#ifndef HEADER_fd_src_disco_metrics_generated_fd_metrics_sample_gen_h\n')
        f.write('#define HEADER_fd_src_disco_metrics_generated_fd_metrics_sample_gen_h\n\n')
        f.write('/* THIS FILE IS GENERATED BY gen_metrics.py. DO NOT HAND EDIT. */\n\n')
        f.write('#include "../../../util/fd_util_base.h"\n\n')
        f.write('/* How a metric slot is encoded */\n\n')
        f.write('#define FD_METRICS_SAMPLE_U64   (0) /* uint64 */\n')
        f.write('#define FD_METRICS_SAMPLE_NS    (1) /* ticks, as uint64 nanoseconds */\n')
        f.write('#define FD_METRICS_SAMPLE_BOOL  (2) /* bool */\n')
        f.write('#define FD_METRICS_SAMPLE_STATE (3) /* raw state, as its proto enum number via map */\n')
        f.write('#define FD_METRICS_SAMPLE_OPEN  (4) /* opens the Tuple submessage num */\n')
        f.write('#define FD_METRICS_SAMPLE_CLOSE (5) /* closes it */\n\n')
        f.write('/* Field numbers of the sample fields, the same in every metrics schema */\n\n')
        for k in SAMPLE_FIELDS: f.write(f'#define FD_METRICS_SAMPLE_F_{k.upper()} ({nums[k]}U)\n')
        for k in LINK_FIELDS:   f.write(f'#define FD_METRICS_SAMPLE_F_{k.upper()} ({lnum[k][0]}U)\n')
        f.write('\n/* MetricsSampleReason proto enum numbers */\n\n')
        for i, v in enumerate(shared['MetricsSampleReason']['variants'], 1):
            f.write(f'#define FD_METRICS_SAMPLE_REASON_{v.upper()} ({i}U)\n')
        f.write('\nstruct fd_metrics_sample_field {\n  ulong        off;     /* metrics slot */\n  uint         num;     /* proto field number */\n  uint         kind;    /* FD_METRICS_SAMPLE_* */\n  uint const * map;     /* STATE: raw value -> proto enum number */\n  ulong        map_cnt;\n};\n\n')
        f.write('typedef struct fd_metrics_sample_field fd_metrics_sample_field_t;\n\n')
        f.write('struct fd_metrics_sample_schema {\n  char const *                      tile;      /* tile name, NULL ends the list */\n  uint                              id;        /* Event oneof field number */\n  fd_metrics_sample_field_t const * field;\n  ulong                             field_cnt;\n  ulong                             buf_max;   /* worst-case encoded event */\n};\n\n')
        f.write('typedef struct fd_metrics_sample_schema fd_metrics_sample_schema_t;\n\n')
        f.write('/* One schema per telemetry tile kind, NULL-terminated */\n\n')
        f.write('extern fd_metrics_sample_schema_t const fd_metrics_sample_tiles[];\n')
        f.write('\n/* Tile kinds with telemetry="false": not sampled on purpose, NULL-terminated */\n\n')
        f.write('extern char const * const fd_metrics_sample_skip[];\n')
        f.write('extern fd_metrics_sample_schema_t const fd_metrics_sample_link;\n\n')
        snapct = shared['MetricsSnapctLoadState']['variants']
        f.write('/* Raw snapct LoadState -> MetricsSnapctLoadState proto enum number */\n\n')
        f.write(f'#define FD_METRICS_SAMPLE_SNAPCT_STATE_CNT ({len(_state_map(metrics.enums["SnapctLoadState"], list(snapct)))}UL)\n')
        f.write('extern uint const fd_metrics_sample_snapct_state[ FD_METRICS_SAMPLE_SNAPCT_STATE_CNT ];\n\n')
        f.write('#endif /* HEADER_fd_src_disco_metrics_generated_fd_metrics_sample_gen_h */\n')

    with open(out / 'fd_metrics_sample_gen.c', 'w') as f:
        f.write('/* THIS FILE IS GENERATED BY gen_metrics.py. DO NOT HAND EDIT. */\n\n')
        f.write('#include "fd_metrics_sample_gen.h"\n#include "fd_metrics_all.h"\n\n')
        sm = _state_map(metrics.enums['SnapctLoadState'], list(shared['MetricsSnapctLoadState']['variants']))
        f.write(f'uint const fd_metrics_sample_snapct_state[ FD_METRICS_SAMPLE_SNAPCT_STATE_CNT ] = {{ {", ".join(map(str, sm))} }};\n\n')
        for name, m in maps.items():
            f.write(f'static uint const {name}[ {len(m)} ] = {{ {", ".join(map(str, m))} }};\n')
        f.write('\n')
        for name, e in tables.items():
            f.write(f'static fd_metrics_sample_field_t const fields_{name}[ {len(e)} ] = {{\n')
            for off, num, kind, mp in e:
                tail = f', {mp}, {len(maps[mp])}UL' if mp else ', NULL, 0UL'
                f.write(f'  {{ {off}, {num}U, FD_METRICS_SAMPLE_{kind}{tail} }},\n')
            f.write('};\n\n')
        f.write('fd_metrics_sample_schema_t const fd_metrics_sample_tiles[] = {\n')
        for name, doc in docs.items():
            f.write(f'  {{ "{name}", {doc["id"]}U, fields_{name}, {len(tables[name])}UL, {_event_max(doc["id"], tables[name], nums, False)}UL }},\n')
        f.write('  { NULL, 0U, NULL, 0UL, 0UL }\n};\n\n')
        skip = sorted(t.name.lower() for t in metrics.tiles_no_telemetry)
        f.write('char const * const fd_metrics_sample_skip[] = { ' + ''.join(f'"{t}", ' for t in skip) + 'NULL };\n\n')
        lnums = { **nums, **{ k: lnum[k][0] for k in LINK_FIELDS } }
        f.write(f'fd_metrics_sample_schema_t const fd_metrics_sample_link = {{ "link", {link["id"]}U, fields_link, {len(tables["link"])}UL, {_event_max(link["id"], tables["link"], lnums, True)}UL }};\n')
