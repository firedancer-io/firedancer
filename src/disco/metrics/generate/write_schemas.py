"""Event schemas for metrics samples: one metrics_<tile>.json per telemetry
tile plus metrics_link.json, written next to the other event schemas.

Field numbers are positional, like every other event schema.  Fields,
enum values and states are written in their committed order (the schema
file on disk), with additions at the end, so reordering metrics.xml never
renumbers anything.  An addition to a committed message gets an explicit
provisional field_number at or above EVENT_ID_PROVISIONAL, a hash of its
name, so a fork's additions never collide with the next position upstream
assigns.  A new schema gets a provisional id.  Before landing,
`make -C src/disco/metrics metrics-assign` drops the provisional numbers
(the fields keep their place at the end) and assigns the next free id;
gen_events.py --no-provisional enforces it."""

from .types import *
import copy
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'events'))
from gen_events import PB_FIELD_NUMBER_MAX, PB_RESERVED, EVENT_ID_PROVISIONAL

SCHEMA_DIR = Path(__file__).parent.parent.parent / 'events' / 'schema'

def snake(name: str) -> str:
    return re.sub(r'(?<!^)(?=[A-Z])', '_', name).lower()

def _hash(name: str, lo: int, hi: int) -> int:
    """Stable hash of name into [lo, hi), skipping the reserved range."""
    span = hi - lo - len(PB_RESERVED)
    n = lo + int.from_bytes(hashlib.sha256(name.encode()).digest()[:8], 'little') % span
    return n + len(PB_RESERVED) if n >= PB_RESERVED.start else n

def provisional(name: str) -> int:
    return _hash(name, EVENT_ID_PROVISIONAL, PB_FIELD_NUMBER_MAX+1)

def _description(metric: Metric, el: ET.Element) -> str:
    d = ' '.join(line.strip() for line in metric.description.split('\n')).strip()
    if el.attrib.get('ambiguous-kind') == 'true':
        d = ('counter: cumulative since tile start, query deltas. ' if el.tag == 'counter' else 'gauge: current value, do not sum over time. ') + d
    return d

def _histogram_buckets(metric: HistogramMetric) -> dict:
    from .write_codegen import _histogram_edges
    unit = { 'Nanos': 'nanos', 'Bytes': 'bytes', 'Lamports': 'lamports', 'Pct': 'pct' }.get(re.findall(r'[A-Z][a-z0-9]*', metric.name)[-1], '')
    bounds = [0] + _histogram_edges(metric)   # left edge of each of the 16 buckets
    fields = {}
    for i in range(16):
        hi = f'{bounds[i+1]})' if i < 15 else 'inf)'
        fields[f'b{i}'] = { 'type': 'UInt64', 'compression': 'DoubleDelta, ZSTD', 'description': f'[{bounds[i]}, {hi} {unit}'.rstrip() }
    fields['sum'] = { 'type': 'UInt64', 'compression': 'DoubleDelta, ZSTD', 'description': f'Sum of samples{" (" + unit + ")" if unit else ""}' }
    return fields

def _variants(e: MetricEnum) -> dict:
    """LowCardinality variants of an enum; '_from' carries renamed_from."""
    out = {}
    for v in e.values:
        d = { 'description': v.label }
        if v.deprecated:   d['deprecated'] = True
        if v.renamed_from: d['_from'] = snake(v.renamed_from)
        out[snake(v.name)] = d
    return out

def metric_field(metric: Metric, el: ET.Element) -> dict:
    """Schema field for one metric.  '_from' carries renamed_from so the
    ordering pass can find the committed entry."""
    desc  = _description(metric, el)
    codec = 'DoubleDelta, ZSTD' if metric.type == MetricType.COUNTER else 'T64, ZSTD'
    if isinstance(metric, HistogramMetric):
        f = { 'type': 'Tuple', 'description': desc, 'fields': _histogram_buckets(metric), '_positional': True }
    elif isinstance(metric, (CounterEnumMetric, GaugeEnumMetric)):
        t = 'Bool' if getattr(metric, 'is_bool', False) else 'UInt64'
        sub = {}
        for v in metric.enum.values:
            e = { 'type': t, 'description': v.label }
            if t == 'UInt64': e['compression'] = codec
            if v.deprecated: e['deprecated'] = True
            if v.renamed_from: e['_from'] = snake(v.renamed_from)
            sub[snake(v.name)] = e
        f = { 'type': 'Tuple', 'description': desc, 'fields': sub }
    elif isinstance(metric, GaugeMetric) and metric.states:
        f = { 'type': 'LowCardinality(String)', 'description': desc, 'variants': _variants(metric.states) }
    elif isinstance(metric, GaugeMetric) and metric.is_bool:
        f = { 'type': 'Bool', 'description': desc }
    elif isinstance(metric, GaugeMetric) and metric.is_time:
        f = { 'type': 'DateTime64(9)', 'compression': 'Delta, ZSTD', 'description': desc }
    else:
        f = { 'type': 'UInt64', 'compression': codec, 'description': desc }
    if 'renamed_from' in el.attrib: f['_from'] = snake(el.attrib['renamed_from'])
    return f

def _shared_types(snapct_states: MetricEnum) -> dict:
    """Enums every metrics schema uses, defined once in shared.json and
    referenced with ref: (one proto enum instead of one per schema)."""
    return {
        'MetricsSampleReason': { 'type': 'LowCardinality(String)', 'description': 'Why a metrics sweep was taken', 'variants': {
            'periodic':         { 'description': 'Periodic sweep' },
            'leader_start':     { 'description': 'Our leader slot started' },
            'leader_end':       { 'description': 'Our leader slot ended' },
            'leader_end_start': { 'description': 'Our leader slot ended and the next one started' },
            'snapct_state':     { 'description': 'Snapshot load changed state' },
            'replay_ready':     { 'description': 'Replay finished loading and started processing' },
            'caught_up':        { 'description': 'Replay caught up to the cluster tip' } } },
        'MetricsSnapctLoadState': { 'type': 'LowCardinality(String)', 'description': 'Snapshot load state',
                                    'variants': _variants(snapct_states) },
    }

def _sample_fields(link: bool) -> dict:
    f = {
        'sample_id':     { 'type': 'UInt64', 'description': 'Identifier shared by every row of one sweep' },
        'sample_reason': { 'type': 'ref:MetricsSampleReason', 'description': 'Why the sweep was taken' },
        'sample_slot':      { 'type': 'UInt64', 'description': 'Slot that triggered the sweep, 0 for periodic sweeps' },
        'sample_snapct_state': { 'type': 'ref:MetricsSnapctLoadState', 'description': 'Snapshot load state entered, for snapct_state sweeps; unknown otherwise' },
        'sample_caught_up':    { 'type': 'Bool', 'description': 'Whether replay had caught up to the cluster tip when the sweep was taken (replay IsCaughtUp); set once per run, never cleared' },
        'sample_tile_cnt':  { 'type': 'UInt64', 'description': 'Tile instances in the sweep, to detect partial sweeps' },
        'kind_id':          { 'type': 'UInt64', 'description': 'Index of this tile instance among tiles of its kind' },
    }
    if link:
        f['tile']     = { 'type': 'LowCardinality(String)', 'description': 'Consumer tile kind' }
        f['link']     = { 'type': 'LowCardinality(String)', 'description': 'Input link name' }
        f['link_idx'] = { 'type': 'UInt64', 'description': 'Index of the input link on the consumer tile' }
    return f

def _read(fields: dict) -> list:
    """Committed message as [(name, field_number, subfields, variants, deprecated, type)];
    variants are [(name, deprecated)]."""
    return [ ( k, v.get('field_number'), _read(v['fields']) if 'fields' in v else None,
               [ ( n, bool(d.get('deprecated')) ) for n, d in v['variants'].items() ] if 'variants' in v else None,
               bool(v.get('deprecated')), v['type'] )
             for k, v in fields.items() ]

def _committed() -> dict:
    """{schema name: (id, committed fields, deprecated)} from the schema
    files on disk."""
    out = {}
    for p in SCHEMA_DIR.glob('*.json'):
        if p.name == 'shared.json': continue
        d = json.loads(p.read_text())
        out[d['name']] = (d['id'], _read(d['fields']), bool(d.get('deprecated')))
    return out

def _order(where: str, fields: dict, committed: Optional[list], assign: bool) -> dict:
    """Orders fields: committed ones in committed order, then additions.
    committed is None when the message itself is new, so everything in it
    is positional.  An addition to a committed message gets a provisional
    field_number unless assign."""
    for v in fields.values():
        if v.pop('_positional', False): v['_keep'] = True
    if committed is None:
        out = { k: v for k, v in fields.items() if not v.get('deprecated') }   # never landed: just gone
        csubs = {}
    else:
        by_from = { v['_from']: k for k, v in fields.items() if '_from' in v }
        out, csubs = {}, {}
        for cname, cnum, cfields, cvariants, cdep, ctype in committed:
            if cnum is not None: continue   # a provisional entry is an addition
            k = cname if cname in fields else by_from.get(cname)
            if k is None:
                raise SystemExit(f'{where}.{cname}: committed field is gone; removing it would shift every later field number.  Mark it deprecated="true" in metrics.xml (or rename with renamed_from)')
            if fields[k]['type'] != ctype:
                # buf breaking misses changes that keep the proto type (UInt64
                # vs DateTime64(9)), and the server refuses a column type change
                raise SystemExit(f'{where}.{cname}: committed as {ctype}, now {fields[k]["type"]}; a column type never changes, deprecate it and add a new metric')
            if cdep and not fields[k].get('deprecated'):
                raise SystemExit(f'{where}.{cname}: committed as deprecated; a tombstone is permanent, add a new metric with a new name instead')
            out[k] = fields[k]
            csubs[k] = ( cfields, cvariants )
        for k, v in fields.items():
            if k in out or v.get('deprecated'): continue   # a tombstone that never landed is dropped
            if not assign: v['field_number'] = provisional(f'{where}.{k}')
            out[k] = v
    for k, v in out.items():
        v.pop('_from', None)
        cfields, cvariants = csubs.get(k, ( None, None ))
        if v.pop('_keep', False): continue
        if 'fields' in v:
            v['fields'] = _order(f'{where}.{k}', v['fields'], cfields, assign)
        if 'variants' in v:
            v['variants'] = _order_variants(f'{where}.{k}', v['variants'], cvariants)
    return out

def _order_variants(where: str, variants: dict, committed: Optional[list]) -> dict:
    """Variants in committed order (renamed ones found by renamed_from), then
    additions; enum values are numbered by position, so nothing committed
    may disappear."""
    if committed is None:
        out = { n: d for n, d in variants.items() if not d.get('deprecated') }
    else:
        by_from = { d['_from']: n for n, d in variants.items() if '_from' in d }
        out = {}
        for c, cdep in committed:
            n = c if c in variants else by_from.get(c)
            if n is None:
                raise SystemExit(f'{where}: committed value {c} is gone; removing one would renumber the rest.  Mark it deprecated="true" in metrics.xml (or rename with renamed_from)')
            if cdep and not variants[n].get('deprecated'):
                raise SystemExit(f'{where}: committed value {c} is deprecated; a tombstone is permanent, add a new value with a new name instead')
            out[n] = variants[n]
        out.update({ n: d for n, d in variants.items() if n not in out and not d.get('deprecated') })
    for d in out.values(): d.pop('_from', None)
    return out

def write_schemas(metrics: Metrics, root: ET.Element, assign: bool = False) -> dict:
    """The sample and <common> fields are inlined in every tile schema
    (the server generates nested types per schema, so a shared ref with
    nested Tuples does not build), generated from one source so they
    stay identical."""
    els, tombs = {}, {}
    for sec in root:
        if sec.tag in ('tile', 'common', 'linkin'):
            section = sec.attrib.get('name', sec.tag)
            for el in sec:
                if el.tag not in ('counter', 'gauge', 'histogram', 'bool', 'time'): continue
                if is_deprecated(el):
                    m = parse_metric(None, el, metrics.enums)
                    tombs.setdefault(section, {})[snake(m.name)] = { **metric_field(m, el), 'deprecated': True }
                else:
                    els[(section, el.attrib['name'])] = el

    committed = _committed()
    next_id   = max((i for i, _, _ in committed.values() if i < EVENT_ID_PROVISIONAL), default=0) + 1
    def fields_of(section: str, ms: List[Metric]) -> dict:
        out = { snake(m.name): metric_field(m, els[(section, m.name)]) for m in ms if m.telemetry }
        for k, f in tombs.get(section, {}).items():
            if k in out: raise SystemExit(f'{section}.{k}: name of a deprecated metric is reused; pick a new name')
            out[k] = f
        return out

    def schema(name: str, description: str, fields: dict) -> dict:
        nonlocal next_id
        cid, cfields, cdep = committed.get(name, ( None, None, False ))
        if cdep:
            raise SystemExit(f'{name}: committed as deprecated; a schema tombstone is permanent, a reintroduced tile needs a new tile name')
        final = cid is not None and cid < EVENT_ID_PROVISIONAL
        if final:      sid = cid
        elif assign:   sid = next_id; next_id += 1
        else:          sid = provisional(name)
        return { 'name': name, 'id': sid, 'description': description, 'local': True,
                 'fields': _order(name, fields, cfields if final else None, assign) }

    common = fields_of('common', metrics.common)
    out = {}
    for tile, tile_metrics in metrics.tiles.items():
        if tile in metrics.tiles_no_telemetry: continue
        t = tile.name.lower()
        out[f'metrics_{t}'] = schema(f'metrics_{t}', f'Metrics of one {t} tile instance, one row per sweep',
                                     { **_sample_fields(False), **copy.deepcopy(common), **fields_of(t, tile_metrics) })
    out['metrics_link'] = schema('metrics_link', 'Input link metrics of one consumer tile instance, one row per link per sweep',
                                 { **_sample_fields(True), **fields_of('linkin', metrics.link_in) })
    return out

def write_schema_files(metrics: Metrics, root: ET.Element, assign: bool = False):
    from fmt_schema import render, block
    shared_path = SCHEMA_DIR / 'shared.json'
    shared = json.loads(shared_path.read_text()) if shared_path.exists() else {}
    for name, t in _shared_types(metrics.enums['SnapctLoadState']).items():
        # Variants keep their committed order (the shared enum's numbering)
        committed = _read({ name: shared[name] }) if name in shared else None
        shared[name] = _order('shared', { name: t }, committed, assign)[name]
    shared_path.write_text('\n'.join([ '{' ] + block( shared, 1 ) + [ '}' ]) + '\n')
    out = write_schemas(metrics, root, assign)
    for name, doc in out.items():
        (SCHEMA_DIR / f'{name}.json').write_text(render(doc))
    stale = sorted(p.stem for p in SCHEMA_DIR.glob('metrics_*.json')
                   if p.stem not in out and not json.loads(p.read_text()).get('deprecated'))
    if stale:
        raise SystemExit(f'metrics schemas with no telemetry tile: {stale}; add "deprecated": true to a schema that landed, delete one that never did')
    print(f'Wrote {len(out)} metrics schemas to {SCHEMA_DIR}')
