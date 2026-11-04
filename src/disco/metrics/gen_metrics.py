from generate.types import *
from generate.write_codegen import write_codegen
from generate.write_docs import write_docs
from generate.write_schemas import write_schema_files
from generate.write_sample import write_sample
from pathlib import Path
import sys

def main():
    assign = '--assign' in sys.argv[1:]   # replace provisional schema numbers with the next free ones
    xml = Path('metrics.xml').read_text()
    metrics = parse_metrics(xml)
    metrics.layout()

    write_codegen(metrics)
    write_docs(metrics)
    write_schema_files(metrics, ET.fromstring(xml), assign)
    write_sample(metrics)

if __name__ == '__main__':
    main()
