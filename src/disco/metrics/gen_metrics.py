import copy
import io
import os

from generate.metric_types import *
from generate.event_types import *
from generate.write_codegen import write_codegen, write_event_snap_codegen
from generate.write_docs import write_docs
from generate.write_metric_event_schema import write_metrics_sample_schema
from generate.write_events_codegen import write_event_formatter
from pathlib import Path

def main():
    metrics = parse_metrics(Path('metrics.xml').read_text())
    metrics.layout()

    schema_before: Dict[str, Any] = {}
    for file in os.listdir(Path(__file__).parent / 'schema'):
        if file.endswith('.json'):
            with open(Path(__file__).parent / 'schema' / file, 'r') as f:
                data = json.load(f)

            schema_before[file[:-5]] = Event(data)

    # Check that metrics event schema which goes up to clickhouse is
    # still backwards compatible.
    event_new = io.StringIO()
    write_metrics_sample_schema(metrics, event_new)
    schema_after = copy.deepcopy(schema_before)
    schema_after['metrics_sample'] = Event(json.loads(event_new.getvalue()))

    check_schema(schema_before)
    check_schema(schema_after)
    validate_compatability(schema_before, schema_after)

    with open(Path(__file__).parent / 'schema/metrics_sample.json', 'w') as f:
        f.write(event_new.getvalue())

    # Now code generate the metrics structs and accessors.
    write_codegen(metrics)

    # Now code generate documentation of the metrics.
    write_docs(metrics)

    # Now code generate the transformer that turns the metrics structs
    # into a metrics event for remote reporting.
    write_event_snap_codegen(metrics)

    # Now code generate a JSON formatter for generic event types.
    write_event_formatter(schema_after)

if __name__ == '__main__':
    main()
