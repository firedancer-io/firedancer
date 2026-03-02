from .types import *
import json
import re
import sys
from typing import Dict, Union
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "events"))
from gen_events import Field, Variant, ClickHouseType, main as gen_events_main

def to_snake_case(name: str) -> str:
    """Convert PascalCase/camelCase to snake_case."""
    return re.sub(r'(?<!^)(?=[A-Z])', '_', name).lower()

def ch_type_name(field: Field) -> str:
    if field.chtype == ClickHouseType.LowCardinalityString:
        return "LowCardinality(String)"
    return field.chtype.name

def format_fields_json(fields: Dict[str, Union[Field, str]], indent: int = 8) -> List[str]:
    lines = []
    pad = " " * indent
    max_name_len = max(len(name) for name in fields) if fields else 0
    field_items = list(fields.items())

    for i, (name, field) in enumerate(field_items):
        padding = " " * (max_name_len - len(name))
        comma = "," if i < len(field_items) - 1 else ""
        
        if isinstance(field, str):
            lines.append(f'{pad}"{name}":{padding} {{ "type": "{field}" }}{comma}')
            continue
        
        type_name = ch_type_name(field)
        
        if field.chtype == ClickHouseType.Flatten and field.fields:
            lines.append(f'{pad}"{name}":{padding} {{')
            lines.append(f'{pad}    "type": "{type_name}",')
            lines.append(f'{pad}    "description": "{field.description}",')
            lines.append(f'{pad}    "fields": {{')
            nested_lines = format_fields_json(field.fields, indent + 8)
            lines.extend(nested_lines)
            lines.append(f'{pad}    }}')
            lines.append(f'{pad}}}{comma}')
        elif field.variants:
            lines.append(f'{pad}"{name}":{padding} {{')
            lines.append(f'{pad}    "type": "{type_name}",')
            lines.append(f'{pad}    "description": "{field.description}",')
            lines.append(f'{pad}    "variants": {{')
            variant_items = list(field.variants.items())
            for j, (vname, vdata) in enumerate(variant_items):
                vcomma = "," if j < len(variant_items) - 1 else ""
                lines.append(f'{pad}        "{vname}": {{ "description": "{vdata.description}" }}{vcomma}')
            lines.append(f'{pad}    }}')
            lines.append(f'{pad}}}{comma}')
        else:
            lines.append(f'{pad}"{name}":{padding} {{ "type": "{type_name}", "description": "{field.description}" }}{comma}')
    
    return lines

def format_schema_json(schema: dict) -> str:
    lines = ["{"]
    lines.append(f'    "name": "{schema["name"]}",')
    lines.append(f'    "id": {schema["id"]},')
    lines.append(f'    "description": "{schema["description"]}",')
    lines.append('    "fields": {')
    lines.extend(format_fields_json(schema["fields"], indent=8))
    lines.append("    }")
    lines.append("}")
    return "\n".join(lines)

def metric_enum_to_schema_flatten(metric: Metric) -> Field:
    nested_fields = {}
    for enum_val in metric.enum.values:
        field_name = f"{to_snake_case(metric.name)}_{to_snake_case(enum_val.name)}"
        nested_fields[field_name] = Field(
            chtype=ClickHouseType.UInt64,
            description=enum_val.label
        )
    
    return Field(
        chtype=ClickHouseType.Flatten,
        description=metric.description,
        fields=nested_fields
    )

def generate_event_schemas(metrics: Metrics, schema_dir: Path) -> int:
    count = 0
    for tile, tile_metrics in metrics.tiles.items():
        if tile in metrics.tiles_no_telemetry:
            continue

        count += 1
        tile_name = tile.name.lower()

        fields: Dict[str, Union[Field, str]] = {}
        fields["meta"] = "ref:MetricMeta"
        fields["tile"] = "ref:MetricTile"

        for metric in tile_metrics:
            if isinstance(metric, HistogramMetric):
                continue
            
            if isinstance(metric, (CounterEnumMetric, GaugeEnumMetric)):
                fields[to_snake_case(metric.name)] = metric_enum_to_schema_flatten(metric)
            else:
                fields[to_snake_case(metric.name)] = Field(
                    chtype=ClickHouseType.UInt64,
                    description=metric.description
                )

        event_id = 1000 + tile.value
        schema = {
            "name": f"metrics_{tile_name}",
            "id": event_id,
            "description": f"Metrics snapshot for the {tile_name} tile",
            "fields": fields
        }

        schema_path = schema_dir / f"metrics_{tile_name}.json"
        schema_path.write_text(format_schema_json(schema) + "\n")
    
    return count

def write_schemas(metrics: Metrics):
    schema_dir = Path(__file__).parent.parent.parent / "events" / "schema"
    count = generate_event_schemas(metrics, schema_dir)

    print(f"Wrote {count} metric schemas to {schema_dir}")

    gen_events_main()
