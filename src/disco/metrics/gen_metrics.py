import os

from generate.types import *
from generate.write_codegen import write_codegen, write_event_snap_codegen
from generate.write_docs import write_docs
from generate.write_events import write_events
from pathlib import Path

def main():
    metrics = parse_metrics(Path('metrics.xml').read_text())
    metrics.layout()

    write_codegen(metrics)
    write_event_snap_codegen(metrics)
    write_docs(metrics)
    write_events(metrics)

    import subprocess
    os.environ['PYTHONPATH'] = str(Path(__file__).resolve().parent.parent / 'events')
    subprocess.run(['python3', '../events/gen_events.py'], cwd='../events', check=True)

if __name__ == '__main__':
    main()
