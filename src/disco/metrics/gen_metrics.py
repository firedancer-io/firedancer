from generate.types import *
from generate.write_codegen import write_codegen
from generate.write_docs import write_docs
from pathlib import Path
import json
import re
import subprocess
import sys

def to_snake_case(name: str) -> str:
    """Convert PascalCase/camelCase to snake_case."""
    return re.sub(r'(?<!^)(?=[A-Z])', '_', name).lower()

def expand_metric_to_fields(metric: Metric) -> list:
    """Expand a metric into one or more (name, description) tuples.
    
    For enum metrics (CounterEnumMetric, GaugeEnumMetric), this expands to
    one field per enum value. For regular metrics, returns a single field.
    """
    base_name = to_snake_case(metric.name)
    base_desc = metric.description or f"Metric: {metric.name}"
    
    if isinstance(metric, (CounterEnumMetric, GaugeEnumMetric)):
        # Expand to one field per enum value
        fields = []
        for enum_val in metric.enum.values:
            field_name = f"{base_name}_{to_snake_case(enum_val.name)}"
            field_desc = f"{base_desc} ({enum_val.label})"
            fields.append((field_name, field_desc))
        return fields
    else:
        return [(base_name, base_desc)]

def metric_to_flatten_sum(metric: Metric) -> dict:
    """Convert an enum metric to a FlattenSum field definition.
    
    Returns a dict with type="FlattenSum", description, and nested fields.
    """
    base_name = to_snake_case(metric.name)
    base_desc = metric.description or f"Metric: {metric.name}"
    
    nested_fields = {}
    for enum_val in metric.enum.values:
        field_name = f"{base_name}_{to_snake_case(enum_val.name)}"
        nested_fields[field_name] = {
            "type": "UInt64",
            "description": enum_val.label
        }
    
    return {
        "type": "FlattenSum",
        "description": base_desc,
        "fields": nested_fields
    }

def metric_to_clickhouse_type(metric: Metric) -> str:
    if isinstance(metric, HistogramMetric):
        return "String"  # Histograms serialized as JSON or similar
    return "UInt64"  # Counters and gauges are all uint64


def format_fields_json(fields: dict, indent: int = 8) -> List[str]:
    """Format fields as JSON lines, recursively handling Flatten and FlattenSum types."""
    lines = []
    pad = " " * indent
    max_name_len = max(len(name) for name in fields) if fields else 0
    field_items = list(fields.items())

    for i, (name, field) in enumerate(field_items):
        padding = " " * (max_name_len - len(name))
        comma = "," if i < len(field_items) - 1 else ""
        
        if field.get("type") in ("Flatten", "FlattenSum") and "fields" in field:
            # Multi-line format for Flatten/FlattenSum fields with nested fields
            lines.append(f'{pad}"{name}":{padding} {{')
            lines.append(f'{pad}    "type": "{field["type"]}",')
            lines.append(f'{pad}    "description": "{field["description"]}",')
            lines.append(f'{pad}    "fields": {{')
            nested_lines = format_fields_json(field["fields"], indent + 8)
            lines.extend(nested_lines)
            lines.append(f'{pad}    }}')
            lines.append(f'{pad}}}{comma}')
        elif "variants" in field:
            # Multi-line format for fields with variants
            lines.append(f'{pad}"{name}":{padding} {{')
            lines.append(f'{pad}    "type": "{field["type"]}",')
            lines.append(f'{pad}    "description": "{field["description"]}",')
            lines.append(f'{pad}    "variants": {{')
            variant_items = list(field["variants"].items())
            for j, (vname, vdata) in enumerate(variant_items):
                vcomma = "," if j < len(variant_items) - 1 else ""
                lines.append(f'{pad}        "{vname}": {{ "description": "{vdata["description"]}" }}{vcomma}')
            lines.append(f'{pad}    }}')
            lines.append(f'{pad}}}{comma}')
        else:
            lines.append(f'{pad}"{name}":{padding} {{ "type": "{field["type"]}", "description": "{field["description"]}" }}{comma}')
    
    return lines


def format_schema_json(schema: dict) -> str:
    """Format schema JSON with aligned single-line fields."""
    lines = ["{"]
    lines.append(f'    "name": "{schema["name"]}",')
    lines.append(f'    "id": {schema["id"]},')
    lines.append(f'    "description": "{schema["description"]}",')
    lines.append('    "fields": {')
    lines.extend(format_fields_json(schema["fields"], indent=8))

    lines.append("    }")
    lines.append("}")
    return "\n".join(lines)

def generate_event_schemas(metrics: Metrics, schema_dir: Path) -> int:
    """Generate schema/metrics_<tile>.json for each tile. Returns next available event ID."""
    # Event IDs are derived from Tile enum values with a fixed offset to avoid
    # conflicts with non-metrics events (txn=1, shred=2, etc.)
    EVENT_ID_OFFSET = 100

    for tile, tile_metrics in metrics.tiles.items():
        # Skip tiles with telemetry disabled
        if tile in metrics.tiles_no_telemetry:
            continue

        tile_name = tile.name.lower()

        # Derive stable event ID from Tile enum value
        event_id = EVENT_ID_OFFSET + tile.value

        fields = {}

        # Meta fields in a nested "meta" message (kind_id first, then sample fields)
        fields["meta"] = {
            "type": "Flatten",
            "description": "Metadata about this metrics sample",
            "fields": {
                "kind_id": {
                    "type": "UInt64",
                    "description": "The kind_id of this tile instance within its type (e.g., 0, 1, 2 for multiple tiles of same type)"
                },
                "sample_id": {
                    "type": "UInt64",
                    "description": "Unique identifier correlating samples taken at the same time across tiles"
                },
                "sample_reason": {
                    "type": "LowCardinality(String)",
                    "description": "Reason for taking this sample",
                    "variants": {
                        "Periodic": {"description": "Periodic sampling at regular intervals"},
                        "LeaderStarted": {"description": "Sampled because this validator started leading a slot"},
                        "LeaderEnded": {"description": "Sampled because this validator finished leading a slot"}
                    }
                },
                "sample_slot": {
                    "type": "UInt64",
                    "description": "The slot number for which this sample was taken, if applicable"
                }
            }
        }

        # Tile metrics in a nested "tile" message (skip histograms - not supported yet)
        tile_fields = {}
        for metric in metrics.common:
            if isinstance(metric, HistogramMetric):
                continue
            
            if isinstance(metric, (CounterEnumMetric, GaugeEnumMetric)):
                # Enum metrics become FlattenSum nested messages
                base_name = to_snake_case(metric.name)
                tile_fields[base_name] = metric_to_flatten_sum(metric)
            else:
                # Regular metrics become simple UInt64 fields
                for field_name, field_desc in expand_metric_to_fields(metric):
                    tile_fields[field_name] = {
                        "type": "UInt64",
                        "description": field_desc
                    }
        
        if tile_fields:
            fields["tile"] = {
                "type": "Flatten",
                "description": "Common tile metrics shared by all tiles",
                "fields": tile_fields
            }

        # Tile-specific fields (skip histograms - not supported yet)
        for metric in tile_metrics:
            if isinstance(metric, HistogramMetric):
                continue
            
            if isinstance(metric, (CounterEnumMetric, GaugeEnumMetric)):
                # Enum metrics become FlattenSum nested messages
                base_name = to_snake_case(metric.name)
                fields[base_name] = metric_to_flatten_sum(metric)
            else:
                # Regular metrics become simple UInt64 fields
                for field_name, field_desc in expand_metric_to_fields(metric):
                    fields[field_name] = {
                        "type": "UInt64",
                        "description": field_desc
                    }

        if not fields:
            continue

        schema = {
            "name": f"metrics_{tile_name}",
            "id": event_id,
            "description": f"Metrics snapshot for the {tile_name} tile",
            "fields": fields
        }

        schema_path = schema_dir / f"metrics_{tile_name}.json"
        schema_path.write_text(format_schema_json(schema) + "\n")
        print(f"✓ Generated {schema_path.name} (id: {event_id}, fields: {len(fields)})")

    return EVENT_ID_OFFSET + len(Tile)

def main():
    metrics = parse_metrics(Path('metrics.xml').read_text())
    metrics.layout()

    write_codegen(metrics)
    write_docs(metrics)

    # Generate event schemas for metrics
    schema_dir = Path(__file__).parent.parent / "events" / "schema"
    if schema_dir.exists():
        print("\nGenerating metrics event schemas...")
        generate_event_schemas(metrics, schema_dir)

        # Run gen_events to regenerate protobufs
        print("\nRegenerating protobufs...")
        gen_events = Path(__file__).parent.parent / "events" / "gen_events.py"
        subprocess.run([sys.executable, str(gen_events)], check=True)

if __name__ == '__main__':
    main()
