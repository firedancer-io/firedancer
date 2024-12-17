from generate.types import *
from generate.write_codegen import write_codegen
from generate.write_docs import write_docs
from pathlib import Path

def main():
    metrics = parse_metrics(Path('metrics.xml').read_text())
    metrics.layout()

    write_codegen(metrics)
    write_docs(metrics)

if __name__ == '__main__':
    main()
