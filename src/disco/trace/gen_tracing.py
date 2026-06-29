from generate.types import *
from generate.codegen import write_codegen
from generate.strings import generate_string_table, write_string_table
from pathlib import Path


def main():
    out_dir = Path(__file__).parent / "generated"
    out_dir.mkdir(exist_ok=True)
    traces = parse_traces(Path("tracing.xml").read_text())
    strings = generate_string_table(traces)
    write_string_table(strings, out_dir / "fd_trace_strings.c")
    write_codegen(traces, strings, out_dir)


if __name__ == "__main__":
    main()
