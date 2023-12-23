import xml.etree.ElementTree as ET
from collections import defaultdict
import re
import os

class EnumValue:
    def __init__(self, value, name, label):
        self.value = value
        self.name = name
        self.label = label

class Enum:
    def __init__(self, name, values):
        self.name = name
        self.values = values

class Metric:
    def __init__(self, _type, link, linkside, group_id, group_name, enum, enum_idx, enum_cnt, tile, shortname, name, summary, min, max, converter):
        self.type = _type
        self.link = link
        self.linkside = linkside
        self.group_name = re.sub(r'(?<!^)(?=[A-Z])', '_', group_name).upper()
        self.group_id = group_id
        self.enum = enum
        self.enum_idx = enum_idx
        self.enum_cnt = enum_cnt
        self.tile = tile
        self.shortname = re.sub(r'(?<!^)(?=[A-Z])', '_', shortname).upper()
        self.name = re.sub(r'(?<!^)(?=[A-Z])', '_', name).upper()
        self.summary = ' '.join([line.strip() for line in summary.split('\n')]).strip()
        self.min = min
        self.max = max
        self.cvt = converter

    def type_str(self):
        if self.type == 'gauge':
            return 'FD_METRICS_TYPE_GAUGE'
        elif self.type == 'counter':
            return 'FD_METRICS_TYPE_COUNTER'
        elif self.type == 'histogram':
            return 'FD_METRICS_TYPE_HISTOGRAM'
        raise Exception(f'Unknown metric type: `{self.type}`')

    def full_name(self):
        return f'{self.group_name}_{self.name}'

    def declare(self):
        if self.type == 'gauge':
            return 'DECLARE_METRIC_GAUGE'
        elif self.type == 'counter':
            return 'DECLARE_METRIC_COUNTER'
        elif self.type == 'histogram':
            if self.cvt == 'seconds':
                return 'DECLARE_METRIC_HISTOGRAM_SECONDS'
            elif self.cvt == 'none':
                return 'DECLARE_METRIC_HISTOGRAM_NONE'
            else:
                raise Exception(f'Unknown histogram converter: `{self.cvt}`')
        raise Exception(f'Unknown metric type: `{self.type}`')


def parse_metrics(xml_data):
    root = ET.fromstring(xml_data)
    enums = {}
    metrics = []
    group_id = 0
    for enum_element in root.findall('enum'):
        values = []
        name = enum_element.attrib['name']
        for value in enum_element.findall('int'):
            values.append(EnumValue(value=int(value.attrib['value']), name=value.attrib['name'], label=value.attrib['label']))
        enums[name] = Enum(name=name, values=values)
    for group_element in root.findall('group'):
        group_id += 1
        for metric_element in group_element:
            converter = metric_element.attrib['converter'] if 'converter' in metric_element.attrib else 'none'
            if converter == 'seconds':
                minval = float(metric_element.attrib['min'])
                maxval = float(metric_element.attrib['max'])
            else:
                minval = str(int(metric_element.attrib['min']) if 'min' in metric_element.attrib else 0) + "UL"
                maxval = str(int(metric_element.attrib['max']) if 'max' in metric_element.attrib else 0) + "UL"

            enum=metric_element.attrib['enum'] if 'enum' in metric_element.attrib else None
            if enum:
                enum = enums[enum]
                for (i, value) in enumerate(enum.values):
                    summary = metric_element.find('summary').text if metric_element.find('summary') is not None else metric_element.attrib['summary']
                    metrics.append(Metric(_type=metric_element.tag,
                                        link='link' in group_element.attrib,
                                        linkside=group_element.attrib['linkside'] if 'linkside' in group_element.attrib else None,
                                        group_id=group_id,
                                        group_name=group_element.attrib['name'],
                                        enum=enum,
                                        enum_idx=i,
                                        enum_cnt=len(enum.values),
                                        tile=group_element.attrib['tile'] if 'link' not in group_element.attrib else 'all',
                                        shortname=metric_element.attrib["name"],
                                        name=f'{metric_element.attrib["name"]}{value.name}',
                                        summary=f'{summary} ({value.label})',
                                        min=minval,
                                        max=maxval,
                                        converter=converter))
            else:
                metrics.append(Metric(_type=metric_element.tag,
                                    link='link' in group_element.attrib,
                                    linkside=group_element.attrib['linkside'] if 'linkside' in group_element.attrib else None,
                                    group_id=group_id,
                                    group_name=group_element.attrib['name'],
                                    enum=None,
                                    enum_idx=0,
                                    enum_cnt=0,
                                    tile=group_element.attrib['tile'] if 'link' not in group_element.attrib else 'all',
                                    shortname="",
                                    name=metric_element.attrib['name'],
                                    summary=metric_element.find('summary').text if metric_element.find('summary') is not None else metric_element.attrib['summary'],
                                    min=minval,
                                    max=maxval,
                                    converter=converter))
    return (enums, metrics)


OFFSETS = {
    'counter': 1,
    'gauge': 1,
    'histogram': 17, # 16 buckets + 1 for the sum
}


if __name__ == '__main__':
    with open('metrics.xml', 'r') as f:
        xml_data = f.read()

    (enums, metrics) = parse_metrics(xml_data)
    os.makedirs('generated', exist_ok=True)  # Ensure the directory exists

    max_offset = 0
    for tile in ['all', 'quic']:
        tile_metrics = [x for x in metrics if x.tile == tile]
        max_offset = max(max_offset, sum([OFFSETS[x.type] for x in metrics if x.tile == 'all' or x.tile == tile]))

        with open(f'generated/fd_metrics_{tile}.h', 'w') as f:
            f.write('/* THIS FILE IS GENERATED BY gen_metrics.py. DO NOT HAND EDIT. */\n\n')
            f.write('#include "../fd_metrics_base.h"\n\n')

            if tile == 'all':
                offset = 0
            else:
                # Tiles have their tile specific metrics placed after the 'all' section
                offset = sum([OFFSETS[x.type] for x in metrics if x.tile == 'all' and not x.link])

            just = max([len(x.full_name()) for x in tile_metrics])
            prior_group_link = tile == 'all'
            prior_group_id = None
            for metric in tile_metrics:
                if metric.group_id != prior_group_id and prior_group_link:
                    prior_group_id = metric.group_id
                    prior_group_link = metric.link
                    offset = 0

                    if not metric.linkside:
                        f.write('/* Start of TILE metrics */\n\n')
                    elif metric.linkside == 'in':
                        f.write('/* Start of LINK IN metrics */\n\n')
                    elif metric.linkside == 'out':
                        f.write('/* Start of LINK OUT metrics */\n\n')

                if metric.enum and metric.enum_idx == 0:
                    f.write(f'#define FD_METRICS_{metric.type.upper()}_{metric.group_name}_{metric.shortname}_OFF  ({offset}UL)\n')
                    f.write(f'#define FD_METRICS_{metric.type.upper()}_{metric.group_name}_{metric.shortname}_CNT  ({metric.enum_cnt}UL)\n\n')

                f.write(f'#define FD_METRICS_{metric.type.upper()}_{metric.full_name()}_OFF  ({offset}UL)\n')
                f.write(f'#define FD_METRICS_{metric.type.upper()}_{metric.full_name()}_NAME "{metric.full_name().lower()}"\n')
                f.write(f'#define FD_METRICS_{metric.type.upper()}_{metric.full_name()}_TYPE ({metric.type_str()})\n')
                f.write(f'#define FD_METRICS_{metric.type.upper()}_{metric.full_name()}_DESC "{metric.summary}"\n')
                if metric.type == 'histogram':
                    f.write(f'#define FD_METRICS_{metric.type.upper()}_{metric.full_name()}_MIN  ({metric.min})\n')
                    f.write(f'#define FD_METRICS_{metric.type.upper()}_{metric.full_name()}_MAX  ({metric.max})\n')
                    if metric.cvt == 'none':
                        converter = 'FD_METRICS_CONVERTER_NONE'
                    elif metric.cvt == 'seconds':
                        converter = 'FD_METRICS_CONVERTER_SECONDS'
                    f.write(f'#define FD_METRICS_{metric.type.upper()}_{metric.full_name()}_CVT  ({converter})\n\n')
                else:
                    f.write('\n')
                offset += OFFSETS[metric.type]

            f.write(f'\n#define FD_METRICS_{tile.upper()}_TOTAL ({len([x for x in tile_metrics if not x.link])}UL)\n')
            f.write(f'extern const fd_metrics_meta_t FD_METRICS_{tile.upper()}[FD_METRICS_{tile.upper()}_TOTAL];\n')
            if tile == 'all':
                f.write(f'\n#define FD_METRICS_{tile.upper()}_LINK_IN_TOTAL ({len([x for x in tile_metrics if x.link and x.linkside == "in"])}UL)\n')
                f.write(f'extern const fd_metrics_meta_t FD_METRICS_{tile.upper()}_LINK_IN[FD_METRICS_{tile.upper()}_LINK_IN_TOTAL];\n')
                f.write(f'\n#define FD_METRICS_{tile.upper()}_LINK_OUT_TOTAL ({len([x for x in tile_metrics if x.link and x.linkside == "out"])}UL)\n')
                f.write(f'extern const fd_metrics_meta_t FD_METRICS_{tile.upper()}_LINK_OUT[FD_METRICS_{tile.upper()}_LINK_OUT_TOTAL];\n')

        with open(f'generated/fd_metrics_{tile}.c', 'w') as f:
            f.write('/* THIS FILE IS GENERATED BY gen_metrics.py. DO NOT HAND EDIT. */\n')
            f.write(f'#include "fd_metrics_{tile}.h"\n\n')

            f.write(f'const fd_metrics_meta_t FD_METRICS_{tile.upper()}[FD_METRICS_{tile.upper()}_TOTAL] = {{\n')
            for metric in tile_metrics:
                if metric.link:
                    continue
                f.write(f'    {metric.declare()}( {metric.group_name}, {metric.name} ),\n')
            f.write('};\n')

            if tile == 'all':
                f.write(f'const fd_metrics_meta_t FD_METRICS_{tile.upper()}_LINK_IN[FD_METRICS_{tile.upper()}_LINK_IN_TOTAL] = {{\n')
                for metric in tile_metrics:
                    if not metric.link or metric.linkside != "in":
                        continue
                    f.write(f'    {metric.declare()}( {metric.group_name}, {metric.name} ),\n')
                f.write('};\n')

                f.write(f'const fd_metrics_meta_t FD_METRICS_{tile.upper()}_LINK_OUT[FD_METRICS_{tile.upper()}_LINK_OUT_TOTAL] = {{\n')
                for metric in tile_metrics:
                    if not metric.link or metric.linkside != "out":
                        continue
                    f.write(f'    {metric.declare()}( {metric.group_name}, {metric.name} ),\n')
                f.write('};\n')

    with open('generated/fd_metrics_all.h', 'a') as f:
        # Kind of a hack for now.  Different tiles should get a different size.
        f.write(f'\n#define FD_METRICS_TOTAL_SZ (8UL*{max_offset}UL)\n')
