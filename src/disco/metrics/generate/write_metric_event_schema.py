from typing import TextIO
from .metric_types import *
import re

def name(name: str):
    return re.sub(r'(?<!^)(?=[A-Z])', '_', name).lower()

def write_metrics_sample_schema(metrics: Metrics, f: TextIO):
    f.write('{\n')
    f.write('    "name": "metrics_sample",\n')
    f.write('    "id": 2,\n')
    f.write('    "description": "Metric data periodically sampled by the application.",\n')
    f.write('    "fields": {\n')
    f.write('        "reason": {\n')
    f.write('            "type": "Enum8",\n')
    f.write('            "description": "Reason the metrics snapshot was sampled.",\n')
    f.write('            "variants": {\n')
    f.write('                "periodic": 1,\n')
    f.write('                "leader_start": 2,\n')
    f.write('                "leader_end_start": 3,\n')
    f.write('                "leader_end": 4\n')
    f.write('            }\n')
    f.write('        },\n')
    f.write('        "slot": { "type": "UInt64", "description": "If the reason the sample was taken is because a leader was starting or ending, this is the slot that was starting (or ending). If a leader slot is both ending and starting (leader_end_start), this is the slot which is starting." },\n')

    tiles: List[Tile] = []
    for tile in Tile:
        if tile in metrics.tiles:
            for metric in metrics.tiles[tile]:
                if not metric.clickhouse_exclude and not isinstance(metric, HistogramMetric):
                    tiles.append(tile)
                    break

    f.write('        "tile": {\n')
    f.write('            "type": "Nested",\n')
    f.write('            "description": "Common metrics shared by all tiles",\n')
    f.write('            "fields": {\n')

    max_name_len = max([len(name(metric.name)) for metric in metrics.common if not metric.clickhouse_exclude])
    f.write(f'                "kind":{"".rjust(max_name_len-4)} {{ "type": "LowCardinality(String)", "max_length": 20, "description": "Tile type." }},\n')
    f.write(f'                "kind_id":{"".rjust(max_name_len-7)} {{ "type": "UInt16", "description": "ID of the tile within the type." }},\n')
    for (i, metric) in enumerate(metrics.common):
        if metric.clickhouse_exclude or isinstance(metric, HistogramMetric):
            continue

        if isinstance(metric, CounterEnumMetric) or isinstance(metric, GaugeEnumMetric):
            f.write(f'                "{name(metric.name)}": {{\n')
            f.write('                    "type": "Tuple",\n')
            f.write(f'                    "description": "{metric.description}",\n')
            f.write('                    "fields": {\n')
            for (k, value) in enumerate(metric.enum.values):
                f.write(f'                        "{name(value.name)}": {{ "type": "UInt64", "description": "{value.label}" }}')
                if k < len(metric.enum.values) - 1:
                    f.write(',')
                f.write('\n')
            f.write('                    }\n')
            f.write('                }')
        else:
            f.write(f'                "{name(metric.name)}":{"".rjust(max_name_len-len(name(metric.name)))} {{')
            f.write(' "type": "UInt64",')
            f.write(f' "description": "{metric.description}"')
            f.write(' }')

        if i < len(metrics.common) - 1:
            f.write(',')
        f.write('\n')

    f.write('            }\n')
    f.write('        },\n')

    f.write('        "link": {\n')
    f.write('            "type": "Nested",\n')
    f.write('            "description": "Metrics for links between tiles.",\n')
    f.write('            "fields": {\n')

    max_name_len = max([len(name(metric.name)) for metric in metrics.link_in + metrics.link_out if not metric.clickhouse_exclude])
    f.write(f'                "kind":{"".rjust(max_name_len-4)} {{ "type": "LowCardinality(String)", "max_length": 20, "description": "Tile type." }},\n')
    f.write(f'                "kind_id":{"".rjust(max_name_len-7)} {{ "type": "UInt16", "description": "ID of the tile within the type." }},\n')
    f.write(f'                "link_kind":{"".rjust(max_name_len-9)} {{ "type": "LowCardinality(String)", "max_length": 20, "description": "Link type." }},\n')
    f.write(f'                "link_kind_id":{"".rjust(max_name_len-12)} {{ "type": "UInt16", "description": "ID of the link within the link kind." }},\n')

    for (i, metric) in enumerate(metrics.link_in + metrics.link_out):
        if metric.clickhouse_exclude or isinstance(metric, HistogramMetric):
            continue

        f.write(f'                "{name(metric.name)}":{"".rjust(max_name_len-len(name(metric.name)))} {{')
        f.write(' "type": "UInt64",')
        f.write(f' "description": "{metric.description}"')
        f.write(' }')

        if i < len(metrics.link_in + metrics.link_out) - 1:
            f.write(',')
        f.write('\n')

    f.write('            }\n')
    f.write('        },\n')

    for (i, tile) in enumerate(tiles):
        tile_metrics = metrics.tiles[tile]

        f.write(f'        "{tile.name.lower()}": {{\n')
        f.write('            "type": "Nested",\n')
        f.write(f'            "description": "Metrics for {tile.name.lower()} tiles.",\n')
        f.write('            "fields": {\n')
        
        max_name_len = max([len(name(metric.name)) for metric in tile_metrics if not metric.clickhouse_exclude])
        for (j, metric) in enumerate(tile_metrics):
            if metric.clickhouse_exclude or isinstance(metric, HistogramMetric):
                continue
            
            if isinstance(metric, CounterEnumMetric) or isinstance(metric, GaugeEnumMetric):
                f.write(f'                "{name(metric.name)}": {{\n')
                f.write('                    "type": "Tuple",\n')
                f.write(f'                    "description": "{metric.description}",\n')
                f.write('                    "fields": {\n')
                for (k, value) in enumerate(metric.enum.values):
                    f.write(f'                        "{name(value.name)}": {{ "type": "UInt64", "description": "{value.label}" }}')
                    if k < len(metric.enum.values) - 1:
                        f.write(',')
                    f.write('\n')
                f.write('                    }\n')
                f.write('                }')
            else:
                f.write(f'                "{name(metric.name)}":{"".rjust(max_name_len-len(name(metric.name)))} {{')
                f.write(' "type": "UInt64",')
                f.write(f' "description": "{metric.description}"')
                f.write(' }')

            if j < len(tile_metrics) - 1:
                f.write(',')
            f.write('\n')

        f.write('            }\n')
        f.write('        }')

        if i < len(tiles) - 1:
            f.write(',')
        f.write('\n')

    f.write('    }\n')
    f.write('}\n')


