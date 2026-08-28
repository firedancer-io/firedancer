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

    SNAPMK = 50
    SNAPZP = 51
    SNAPRD = 52
    SNAPSV = 53

    RESOLH = 100
    BANK = 101
    POHH = 102
    STORE = 103
    PLUGIN = 104
    BACKT = 105
    BENCHS = 106
    GUIH = 107

    ROTOR = 108

class MetricType(Enum):
    COUNTER = 0
    GAUGE = 1
    HISTOGRAM = 2

class HistogramConverter(Enum):
    NONE = 0
    SECONDS = 1
    NANOSECONDS = 2

class EnumValue:
    def __init__(self, value: int, name: str, label: str, normalize: bool = True):
        self.value = value
        self.name = name
        self.label = label
        self.normalize = normalize

class MetricEnum:
    def __init__(self, name: str, values: List[EnumValue]):
        self.name = name
        self.values = values

class Metric:
    def __init__(self, type: MetricType, name: str, tile: Optional[Tile], description: str, optional: bool = False):
        self.type = type
        self.name = name
        self.tile = tile
        self.description = description
        self.optional = optional
        self.offset = 0
        self.availability_offset = 0
        self.availability_word = 0
        self.availability_bit = 0

    def footprint(self) -> int:
        return 8

    def count(self) -> int:
        return 1

class CounterMetric(Metric):
    def __init__(self, name: str, tile: Optional[Tile], description: str, converter: HistogramConverter = HistogramConverter.NONE, optional: bool = False):
        super().__init__(MetricType.COUNTER, name, tile, description, optional)
        self.converter = converter

class GaugeMetric(Metric):
    def __init__(self, name: str, tile: Optional[Tile], description: str, optional: bool = False):
        super().__init__(MetricType.GAUGE, name, tile, description, optional)

class HistogramMetric(Metric):
    def __init__(self, name: str, tile: Optional[Tile], description: str, converter: HistogramConverter, min: str, max: str):
        super().__init__(MetricType.HISTOGRAM, name, tile, description)

        self.converter = converter
        self.min = min
        self.max = max

    def footprint(self) -> int:
        return 136

class CounterEnumMetric(Metric):
    def __init__(self, name: str, tile: Optional[Tile], description: str, enum: MetricEnum, converter: HistogramConverter = HistogramConverter.NONE, optional: bool = False):
        super().__init__(MetricType.COUNTER, name, tile, description, optional)
        self.type = MetricType.COUNTER
        self.enum = enum
        self.converter = converter

    def footprint(self) -> int:
        return 8 * len(self.enum.values)

    def count(self) -> int:
        return len(self.enum.values)

class GaugeEnumMetric(Metric):
    def __init__(self, name: str, tile: Optional[Tile], description: str, enum: MetricEnum, optional: bool = False):
        super().__init__(MetricType.GAUGE, name, tile, description, optional)

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
        self.link_in_footprint = 0
        self.common_footprint = 0
        self.tile_footprints = {}

    def count(self):
        return sum([metric.count() for metric in self.common]) + \
            sum([sum([metric.count() for metric in tile_metrics]) for tile_metrics in self.tiles.values()]) + \
            sum([metric.count() for metric in self.link_in])

    @staticmethod
    def layout_group(metrics: List[Metric], start_offset: int) -> int:
        offset = start_offset
        for metric in metrics:
            metric.offset = offset
            offset += int(metric.footprint() / 8)

        optional_metrics = [metric for metric in metrics if metric.optional]
        for idx, metric in enumerate(optional_metrics):
            metric.availability_offset = offset + idx // 64
            metric.availability_word = idx // 64
            metric.availability_bit = idx % 64

        return offset + (len(optional_metrics) + 63) // 64

    def layout(self):
        self.link_in_footprint = self.layout_group(self.link_in, 0)
        self.common_footprint = self.layout_group(self.common, 0)

        for tile, tile_metrics in self.tiles.items():
            self.tile_footprints[tile] = self.layout_group(tile_metrics, self.common_footprint)

def parse_metric(tile: Optional[Tile], metric: ET.Element, enums: Dict[str, MetricEnum]) -> Metric:
    name = metric.attrib['name']
    description = ""
    optional = metric.attrib.get('optional', 'false').lower() == 'true'

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
            return CounterEnumMetric(name, tile, description, enums[metric.attrib['enum']], converter, optional)
        else:
            return CounterMetric(name, tile, description, converter, optional)
    elif metric.tag == 'gauge':
        if 'enum' in metric.attrib:
            return GaugeEnumMetric(name, tile, description, enums[metric.attrib['enum']], optional)
        else:
            return GaugeMetric(name, tile, description, optional)
    elif metric.tag == 'histogram':
        if optional:
            raise ValueError(f'Histogram metric {name} cannot be optional')
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
                    label=value.attrib['label'],
                    normalize=(enum.attrib.get('normalize', 'true').lower() == 'true')
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
