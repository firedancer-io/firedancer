from .types import *
from typing import TextIO
import re

def _write_metric(f: TextIO, metric: Metric, prefix: str):
    if isinstance(metric, CounterEnumMetric) or isinstance(metric, GaugeEnumMetric):
        for value in metric.enum.values:
            full_name = prefix + "_" + re.sub(r'(?<!^)(?=[A-Z])', '_', metric.name).lower() + "_" + re.sub(r'(?<!^)(?=[A-Z])', '_', value.name).lower()
            full_name = full_name.replace("_", "_&#8203;")
            f.write(f'| {full_name} | `{metric.type.name.lower()}` | {metric.description} ({value.label}) |\n')
    else:
        full_name = prefix + "_" + re.sub(r'(?<!^)(?=[A-Z])', '_', metric.name).lower()
        full_name = full_name.replace("_", "_&#8203;")
        f.write(f'| {full_name} | `{metric.type.name.lower()}` | {metric.description} |\n')

def write_docs(metrics: Metrics):
    with open('../../../book/api/metrics-generated.md', 'w') as f:
        f.write('\n## All Links\n<!--@include: ./metrics-link-preamble.md-->\n')
        f.write('| Metric | Type | Description |\n')
        f.write('|--------|------|-------------|\n')
        for metric in metrics.link_out:
            _write_metric(f, metric, "link")
        for metric in metrics.link_in:
            _write_metric(f, metric, "link")

        f.write('\n## All Tiles\n<!--@include: ./metrics-tile-preamble.md-->\n')
        f.write('| Metric | Type | Description |\n')
        f.write('|--------|------|-------------|\n')
        for metric in metrics.common:
            _write_metric(f, metric, "tile")

        for tile in Tile:
            if tile in metrics.tiles:
                f.write(f'\n## {tile.name.capitalize()} Tile\n')
                f.write('| Metric | Type | Description |\n')
                f.write('|--------|------|-------------|\n')
                for metric in metrics.tiles[tile]:
                    _write_metric(f, metric, tile.name.lower())

    print(f"Wrote {metrics.count()} metrics to book/api/metrics-generated.md")
