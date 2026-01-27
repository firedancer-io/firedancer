from .types import *
from typing import TextIO
import re

def camel2snake(str):
    return re.sub(r'(?<!^)(?=[A-Z])', '_', str).lower()

def _write_metric(f: TextIO, metric: Metric, prefix: str):
    if isinstance(metric, CounterEnumMetric) or isinstance(metric, GaugeEnumMetric):
        for value in metric.enum.values:
            full_name = prefix + "_" + camel2snake(metric.name)
            tag = camel2snake(value.name)
            tag = '<span class="metrics-enum">' + tag + '</span>'
            full_tag = "{" + camel2snake(metric.enum.name) + "=\"" + tag + "\"}"
            full_tag = full_tag.replace("_", "_&#8203;")
            full_name = '<span class="metrics-name">' + full_name.replace("_", "_&#8203;") + '</span>'
            f.write(f'| {full_name}<br/>{full_tag} | {metric.type.name.lower()} | {metric.description} ({value.label}) |\n')
    else:
        full_name = prefix + "_" + camel2snake(metric.name)
        full_name = '<span class="metrics-name">' + full_name.replace("_", "_&#8203;") + '</span>'
        f.write(f'| {full_name} | {metric.type.name.lower()} | {metric.description} |\n')

def write_docs(metrics: Metrics):
    with open('../../../book/api/metrics-generated.md', 'w') as f:
        f.write('\n## All Links\n<!--@include: ./metrics-link-preamble.md-->\n')
        f.write('\n<div class="metrics">\n\n')
        f.write('| Metric | Type | Description |\n')
        f.write('|--------|------|-------------|\n')
        for metric in metrics.link_in:
            _write_metric(f, metric, "link")
        f.write('</div>\n')

        f.write('\n## All Tiles\n<!--@include: ./metrics-tile-preamble.md-->\n')
        f.write('\n<div class="metrics">\n\n')
        f.write('| Metric | Type | Description |\n')
        f.write('|--------|------|-------------|\n')
        for metric in metrics.common:
            _write_metric(f, metric, "tile")
        f.write('\n</div>\n')

        for tile in Tile:
            if tile in metrics.tiles:
                f.write(f'\n## {tile.name.capitalize()} Tile\n')
                f.write('\n<div class="metrics">\n\n')
                f.write('| Metric | Type | Description |\n')
                f.write('|--------|------|-------------|\n')
                for metric in metrics.tiles[tile]:
                    _write_metric(f, metric, tile.name.lower())
                f.write('\n</div>\n')

    print(f"Wrote {metrics.count()} metrics to book/api/metrics-generated.md")
