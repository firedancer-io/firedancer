from enum import Enum
from typing import Dict, List, Optional
import xml.etree.ElementTree as ET

class Tile(Enum):
    NET = 0
    QUIC = 1
    BUNDLE = 2
    VERIFY = 3
    DEDUP = 4
    RESOLV = 5
    PACK = 6
    BANK = 7
    POH = 8
    SHRED = 9
    STORE = 10
    SIGN = 11
    METRIC = 12
    CSWTCH = 13
    EVENT = 14
    PLUGIN = 15
    GUI = 16

class MetricType(Enum):
    COUNTER = 0
    GAUGE = 1
    HISTOGRAM = 2

class HistogramConverter(Enum):
    NONE = 0
    SECONDS = 1

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
    def __init__(self, type: MetricType, name: str, tile: Optional[Tile], description: str, clickhouse_exclude: bool):
        self.type = type
        self.name = name
        self.tile = tile
        self.description = description
        self.clickhouse_exclude = clickhouse_exclude
        self.offset = 0

    def footprint(self) -> int:
        return 8
    
    def count(self) -> int:
        return 1

class CounterMetric(Metric):
    def __init__(self, name: str, tile: Optional[Tile], description: str, clickhouse_exclude: bool):
        super().__init__(MetricType.COUNTER, name, tile, description, clickhouse_exclude)

class GaugeMetric(Metric):
    def __init__(self, name: str, tile: Optional[Tile], description: str, clickhouse_exclude: bool):
        super().__init__(MetricType.GAUGE, name, tile, description, clickhouse_exclude)

class HistogramMetric(Metric):
    def __init__(self, name: str, tile: Optional[Tile], description: str, clickhouse_exclude: bool, converter: HistogramConverter, min: str, max: str):
        super().__init__(MetricType.HISTOGRAM, name, tile, description, clickhouse_exclude)

        self.converter = converter
        self.min = min
        self.max = max

    def footprint(self) -> int:
        return 136

class CounterEnumMetric(Metric):
    def __init__(self, name: str, tile: Optional[Tile], description: str, clickhouse_exclude: bool, enum: MetricEnum):
        super().__init__(MetricType.COUNTER, name, tile, description, clickhouse_exclude)

        self.enum = enum

    def footprint(self) -> int:
        return 8 * len(self.enum.values)
    
    def count(self) -> int:
        return len(self.enum.values)

class GaugeEnumMetric(Metric):
    def __init__(self, name: str, tile: Optional[Tile], description: str, clickhouse_exclude: bool, enum: MetricEnum):
        super().__init__(MetricType.GAUGE, name, tile, description, clickhouse_exclude)

        self.enum = enum

    def footprint(self) -> int:
        return 8 * len(self.enum.values)
    
    def count(self) -> int:
        return len(self.enum.values)

class Metrics:
    def __init__(self, common: List[Metric], tiles: Dict[Tile, List[Metric]], link_in: List[Metric], link_out: List[Metric], enums: List[MetricEnum]):
        self.common = common
        self.tiles = tiles
        self.link_in = link_in
        self.link_out = link_out
        self.enums = enums

    def count(self):
        return sum([metric.count() for metric in self.common]) + \
            sum([sum([metric.count() for metric in tile_metrics]) for tile_metrics in self.tiles.values()]) + \
            sum([metric.count() for metric in self.link_in]) + \
            sum([metric.count() for metric in self.link_out])

    def layout(self):
        offset: int = 0
        for metric in self.link_in:
            metric.offset = offset
            offset += int(metric.footprint() / 8)

        offset: int = 0
        for metric in self.link_out:
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

    clickhouse_exclude = False
    if 'clickhouse_exclude' in metric.attrib:
        clickhouse_exclude = metric.attrib['clickhouse_exclude'] == 'true'

    if metric.tag == 'counter':
        if 'enum' in metric.attrib:
            return CounterEnumMetric(name, tile, description, clickhouse_exclude, enums[metric.attrib['enum']])
        else:
            return CounterMetric(name, tile, description, clickhouse_exclude)
    elif metric.tag == 'gauge':
        if 'enum' in metric.attrib:
            return GaugeEnumMetric(name, tile, description, clickhouse_exclude, enums[metric.attrib['enum']])
        else:
            return GaugeMetric(name, tile, description, clickhouse_exclude)
    elif metric.tag == 'histogram':
        converter = None
        if 'converter' in metric.attrib:
            converter = HistogramConverter[metric.attrib['converter'].upper()]
        else:
            converter = HistogramConverter.NONE

        min = metric.attrib['min']
        max = metric.attrib['max']

        return HistogramMetric(name, tile, description, clickhouse_exclude, converter, min, max)
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

    tiles = {
        Tile[tile.attrib['name'].upper()]: [
            parse_metric(Tile[tile.attrib['name'].upper()], metric, enums)
            for metric in tile
        ]    
        for tile in root.findall('tile')
    }

    link_in = root.find('linkin')
    assert link_in is not None
    link_in = [parse_metric(None, metric, enums) for metric in link_in]

    link_out = root.find('linkout')
    assert link_out is not None
    link_out = [parse_metric(None, metric, enums) for metric in link_out]
        
    return Metrics(common=common, tiles=tiles, link_in=link_in, link_out=link_out, enums=enums)