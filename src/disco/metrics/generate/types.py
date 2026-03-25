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
    SNAPWH = 8
    SNAPLA = 9
    SNAPLS = 10
    SNAPWM = 11
    SNAPLH = 12
    SNAPLV = 13

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
    REPLAY = 30
    EXECRP = 31
    ACCDB = 32
    TOWER = 33
    TXSEND = 34

    DIAG = 35
    EVENT = 36
    GUI = 37
    METRIC = 38
    RPC = 39

    RESOLH = 100
    BANK = 101
    POHH = 102
    STORE = 103
    PLUGIN = 104
    BACKT = 105
    BENCHS = 106

class MetricType(Enum):
    COUNTER = 0
    GAUGE = 1
    HISTOGRAM = 2

class HistogramConverter(Enum):
    NONE = 0
    SECONDS = 1
    NANOSECONDS = 2

class EnumValue:
    def __init__(self, value: int, name: str, label: str):
        self.value = value
        self.name = name
        self.label = label

class MetricEnum:
    def __init__(self, name: str, values: List[EnumValue]):
        self.name = name
        self.values = values

class Metric:
    def __init__(self, type: MetricType, name: str, tile: Optional[Tile], description: str):
        self.type = type
        self.name = name
        self.tile = tile
        self.description = description
        self.offset = 0

    def footprint(self) -> int:
        return 8

    def count(self) -> int:
        return 1

class CounterMetric(Metric):
    def __init__(self, name: str, tile: Optional[Tile], description: str, converter: HistogramConverter = HistogramConverter.NONE):
        super().__init__(MetricType.COUNTER, name, tile, description)
        self.converter = converter

class GaugeMetric(Metric):
    def __init__(self, name: str, tile: Optional[Tile], description: str):
        super().__init__(MetricType.GAUGE, name, tile, description)

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
        return len(self.enum.values)

class GaugeEnumMetric(Metric):
    def __init__(self, name: str, tile: Optional[Tile], description: str, enum: MetricEnum):
        super().__init__(MetricType.GAUGE, name, tile, description)

        self.enum = enum

    def footprint(self) -> int:
        return 8 * len(self.enum.values)

    def count(self) -> int:
        return len(self.enum.values)

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

    if metric.tag == 'counter':
        converter = HistogramConverter.NONE
        if 'converter' in metric.attrib:
            converter_str = metric.attrib['converter'].upper()
            if converter_str in HistogramConverter.__members__:
                converter = HistogramConverter[converter_str]

        if 'enum' in metric.attrib:
            return CounterEnumMetric(name, tile, description, enums[metric.attrib['enum']], converter)
        else:
            return CounterMetric(name, tile, description, converter)
    elif metric.tag == 'gauge':
        if 'enum' in metric.attrib:
            return GaugeEnumMetric(name, tile, description, enums[metric.attrib['enum']])
        else:
            return GaugeMetric(name, tile, description)
    elif metric.tag == 'histogram':
        converter = None
        if 'converter' in metric.attrib:
            converter = HistogramConverter[metric.attrib['converter'].upper()]
        else:
            converter = HistogramConverter.NONE

        min = metric.attrib['min']
        max = metric.attrib['max']

        return HistogramMetric(name, tile, description, converter, min, max)
    else:
        raise Exception(f'Unknown metric type: {metric.tag}')

def parse_metrics(xml_data: str) -> Metrics:
    root = ET.fromstring(xml_data)

    enums = {
        enum.attrib['name']: MetricEnum(
            name=enum.attrib['name'],
            values=[
                EnumValue(
                    value=int(value.attrib['value']),
                    name=value.attrib['name'],
                    label=value.attrib['label']
                )
                for value in enum.findall('int')
            ]
        )
        for enum in root.findall('enum')
    }

    common = root.find('common')
    assert common is not None
    common = [parse_metric(None, metric, enums) for metric in common]

    tiles = {}
    tiles_no_telemetry = set()
    for tile in root.findall('tile'):
        tile_enum = Tile[tile.attrib['name'].upper()]
        tiles[tile_enum] = [parse_metric(tile_enum, metric, enums) for metric in tile]
        if tile.attrib.get('telemetry') == 'false':
            tiles_no_telemetry.add(tile_enum)

    link_in = root.find('linkin')
    assert link_in is not None
    link_in = [parse_metric(None, metric, enums) for metric in link_in]

    return Metrics(common=common, tiles=tiles, link_in=link_in, enums=enums, tiles_no_telemetry=tiles_no_telemetry)
