import re
from enum import Enum
from typing import Dict, List, Optional
import xml.etree.ElementTree as ET

class Tile(Enum):
    GENESI = 1
    IPECHO = 2

    SNAPCT = 3
    SNAPLD = 4
    SNAPDC = 5
    SNAPIN = 6
    SNAPWR = 7

    ADMIN = 8

    NETLNK = 14
    NET = 15
    SOCK = 16
    QUIC = 17
    BUNDLE = 18
    VERIFY = 19
    DEDUP = 20
    RESOLV = 21
    PACK = 22
    EXECLE = 23
    POH = 24
    SIGN = 25
    SHRED = 26

    GOSSVF = 27
    GOSSIP = 28
    REPAIR = 29
    RSERVE = 30
    REPLAY = 31
    EXECRP = 32
    ACCDB = 33
    TOWER = 34
    TXSEND = 35

    DIAG = 36
    EVENT = 37
    GUI = 38
    METRIC = 39
    RPC = 40
    MLX5 = 41
    WAKER = 42
    MWAITX = 43
    IAVF = 44

    SNAPMK = 50
    SNAPZP = 51
    SNAPRD = 52
    SNAPSV = 53

    BACKT = 105
    BENCHS = 106

    ROTOR = 108
    VOTOR = 109
    MOTOR = 110
    SOLCAP = 111

class MetricType(Enum):
    COUNTER = 0
    GAUGE = 1
    HISTOGRAM = 2

class HistogramConverter(Enum):
    NONE = 0
    NANOSECONDS = 2

def _source_converter(metric: ET.Element) -> 'HistogramConverter':
    """source="ticks": the tile stores fd_tickcount() deltas, converted to
    nanoseconds on export."""
    name = metric.attrib['name']
    source = metric.attrib.get('source')
    if source is None: return HistogramConverter.NONE
    if source != 'ticks': raise Exception(f'{name}: unknown source "{source}"')
    if not name.endswith('Nanos'): raise Exception(f'{name}: source="ticks" needs a *Nanos name')
    return HistogramConverter.NANOSECONDS

class EnumValue:
    def __init__(self, value: int, name: str, label: str, renamed_from: Optional[str] = None, deprecated: bool = False):
        self.value = value
        self.name = name
        self.label = label
        self.renamed_from = renamed_from
        self.deprecated = deprecated

class EnumGroup:
    def __init__(self, name: str, values: List[EnumValue]):
        self.name = name
        self.values = values

class MetricEnum:
    def __init__(self, name: str, values: List[EnumValue], groups: Optional[List[EnumGroup]] = None):
        self.name = name
        self.values = values
        self.groups = groups or []

    def live(self) -> List[EnumValue]:
        return [ v for v in self.values if not v.deprecated ]

    def group_mask(self, group: EnumGroup) -> int:
        return sum(1 << self.values.index(v) for v in group.values)

class Metric:
    def __init__(self, type: MetricType, name: str, tile: Optional[Tile], description: str):
        self.type = type
        self.name = name
        self.tile = tile
        self.description = description
        self.offset = 0
        self.telemetry = True

    def footprint(self) -> int:
        return 8

    def count(self) -> int:
        return 1

class CounterMetric(Metric):
    def __init__(self, name: str, tile: Optional[Tile], description: str, converter: HistogramConverter = HistogramConverter.NONE):
        super().__init__(MetricType.COUNTER, name, tile, description)
        self.converter = converter

class GaugeMetric(Metric):
    def __init__(self, name: str, tile: Optional[Tile], description: str, states: Optional['MetricEnum'] = None, is_bool: bool = False, is_time: bool = False):
        super().__init__(MetricType.GAUGE, name, tile, description)
        self.states  = states  # gauge holds one value of this enum (ClickHouse LowCardinality(String))
        self.is_bool = is_bool # <bool>: always 0 or 1 (ClickHouse Bool)
        self.is_time = is_time # <time>: wall-clock UNIX nanoseconds, 0 if never (ClickHouse DateTime64(9))

class HistogramMetric(Metric):
    def __init__(self, name: str, tile: Optional[Tile], description: str, converter: HistogramConverter, min: str, max: str):
        super().__init__(MetricType.HISTOGRAM, name, tile, description)

        self.converter = converter
        self.min = min
        self.max = max

    def footprint(self) -> int:
        return 136

class CounterEnumMetric(Metric):
    def __init__(self, name: str, tile: Optional[Tile], description: str, enum: MetricEnum, converter: HistogramConverter = HistogramConverter.NONE):
        super().__init__(MetricType.COUNTER, name, tile, description)
        self.type = MetricType.COUNTER
        self.enum = enum
        self.converter = converter

    def footprint(self) -> int:
        return 8 * len(self.enum.values)

    def count(self) -> int:
        return len(self.enum.live())

class GaugeEnumMetric(Metric):
    def __init__(self, name: str, tile: Optional[Tile], description: str, enum: MetricEnum, is_bool: bool = False):
        super().__init__(MetricType.GAUGE, name, tile, description)

        self.enum    = enum
        self.is_bool = is_bool # <bool enum=...>: each value is 0 or 1

    def footprint(self) -> int:
        return 8 * len(self.enum.values)

    def count(self) -> int:
        return len(self.enum.live())

class Metrics:
    def __init__(self, common: List[Metric], tiles: Dict[Tile, List[Metric]], link_in: List[Metric], enums: List[MetricEnum], tiles_no_telemetry: set = None):
        self.common = common
        self.tiles = tiles
        self.link_in = link_in
        self.enums = enums
        self.tiles_no_telemetry = tiles_no_telemetry or set()

    def count(self):
        return sum([metric.count() for metric in self.common]) + \
            sum([sum([metric.count() for metric in tile_metrics]) for tile_metrics in self.tiles.values()]) + \
            sum([metric.count() for metric in self.link_in])

    def layout(self):
        offset: int = 0
        for metric in self.link_in:
            metric.offset = offset
            offset += int(metric.footprint() / 8)

        offset: int = 0
        for metric in self.common:
            metric.offset = offset
            offset += int(metric.footprint() / 8)

        for tile_metrics in self.tiles.values():
            tile_offset = offset
            for metric in tile_metrics:
                metric.offset = tile_offset
                tile_offset += int(metric.footprint() / 8)

def parse_metric(tile: Optional[Tile], metric: ET.Element, enums: Dict[str, MetricEnum]) -> Metric:
    name = metric.attrib['name']
    description = ""

    summary_ele = metric.find('summary')
    if summary_ele is not None and summary_ele.text is not None:
        description = summary_ele.text
    elif 'summary' in metric.attrib:
        description = metric.attrib['summary']

    if metric.attrib.get('telemetry', 'false') != 'false':
        raise Exception(f'{name}: telemetry= only takes "false"')

    if 'ambiguous-kind' in metric.attrib and ( metric.tag not in ( 'counter', 'gauge' ) or metric.attrib['ambiguous-kind']!='true' ):
        raise Exception(f'{name}: ambiguous-kind="true" is only for <counter> and <gauge>')

    if metric.tag == 'counter':
        converter = _source_converter(metric)
        if 'enum' in metric.attrib:
            return CounterEnumMetric(name, tile, description, enums[metric.attrib['enum']], converter)
        else:
            return CounterMetric(name, tile, description, converter)
    elif metric.tag in ('gauge', 'bool', 'time') and 'source' in metric.attrib:
        raise Exception(f'{name}: source= is only supported on <counter> and <histogram>')
    elif metric.tag == 'gauge':
        if 'enum' in metric.attrib:
            return GaugeEnumMetric(name, tile, description, enums[metric.attrib['enum']])
        elif 'states' in metric.attrib:
            states = enums[metric.attrib['states']]
            def state_str(v):
                tag = re.sub(r'(?<!^)(?=[A-Z])', '_', v.name).lower()
                return f'{v.value}={tag}' if v.label.lower() == tag.replace('_', ' ') else f'{v.value}={tag} ({v.label})'
            description += ': ' + ', '.join(state_str(v) for v in states.live())
            return GaugeMetric(name, tile, description, states=states)
        else:
            return GaugeMetric(name, tile, description)
    elif metric.tag == 'bool':
        if 'enum' in metric.attrib:
            return GaugeEnumMetric(name, tile, description, enums[metric.attrib['enum']], is_bool=True)
        return GaugeMetric(name, tile, description, is_bool=True)
    elif metric.tag == 'time':
        return GaugeMetric(name, tile, description, is_time=True)
    elif metric.tag == 'histogram':
        converter = _source_converter(metric)

        min = metric.attrib['min']
        max = metric.attrib['max']

        return HistogramMetric(name, tile, description, converter, min, max)
    else:
        raise Exception(f'Unknown metric type: {metric.tag}')

def is_deprecated(el: ET.Element) -> bool:
    """deprecated="true" removes a metric or enum value everywhere except the
    ClickHouse schema, which keeps it as a tombstone so later field
    positions never shift."""
    d = el.attrib.get('deprecated')
    if d not in (None, 'true'): raise Exception(f'{el.attrib.get("name")}: deprecated= only takes "true"')
    return d == 'true'

def _parse_enum(enum: ET.Element) -> MetricEnum:
    values = [
        EnumValue(
            value=int(value.attrib['value']),
            name=value.attrib['name'],
            label=value.attrib['label'],
            renamed_from=value.attrib.get('renamed_from'),
            deprecated=is_deprecated(value),
        )
        for value in enum.findall('int')
    ]
    by_name = { v.name: v for v in values if not v.deprecated }
    groups = []
    for g in enum.findall('group'):
        gname = g.attrib['name']
        if gname in by_name: raise Exception(f'{enum.attrib["name"]}: group {gname} collides with a value')
        if gname=='All': raise Exception(f'{enum.attrib["name"]}: group All is implicit')
        members = g.attrib['values'].split()
        for m in members:
            if m not in by_name:
                if m in { v.name for v in values }: raise Exception(f'{enum.attrib["name"]}: group {gname} names deprecated value {m}; drop it from the group')
                raise Exception(f'{enum.attrib["name"]}: group {gname} names unknown value {m}')
        groups.append(EnumGroup(gname, [by_name[m] for m in members]))
    if groups and len(values) > 64: raise Exception(f'{enum.attrib["name"]}: groups need at most 64 values')
    return MetricEnum(name=enum.attrib['name'], values=values, groups=groups)

def _parse_section(tile: Optional[Tile], section: ET.Element, enums: Dict[str, MetricEnum]) -> List[Metric]:
    """Live metrics of a <tile>, <common> or <linkin>, with telemetry= applied."""
    out = []
    for el in section:
        if is_deprecated(el): continue
        m = parse_metric(tile, el, enums)
        m.telemetry = el.attrib.get('telemetry') != 'false'
        out.append(m)
    return out

def parse_metrics(xml_data: str) -> Metrics:
    root = ET.fromstring(xml_data)

    enums = {
        enum.attrib['name']: _parse_enum(enum)
        for enum in root.findall('enum')
    }

    common = root.find('common')
    assert common is not None
    common = _parse_section(None, common, enums)

    tiles = {}
    tiles_no_telemetry = set()
    for tile in root.findall('tile'):
        tile_enum = Tile[tile.attrib['name'].upper()]
        tiles[tile_enum] = _parse_section(tile_enum, tile, enums)
        if tile.attrib.get('telemetry', 'false') != 'false':
            raise Exception(f'tile {tile.attrib["name"]}: telemetry= only takes "false"')
        if tile.attrib.get('telemetry') == 'false':
            tiles_no_telemetry.add(tile_enum)

    link_in = root.find('linkin')
    assert link_in is not None
    link_in = _parse_section(None, link_in, enums)

    return Metrics(common=common, tiles=tiles, link_in=link_in, enums=enums, tiles_no_telemetry=tiles_no_telemetry)
