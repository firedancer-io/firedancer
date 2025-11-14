#!/usr/bin/env python3

import pathlib


def inject_pragmas(header_path: pathlib.Path) -> bool:
    """Ensure the header is wrapped in GCC diagnostic pragmas."""
    text = header_path.read_text()
    updated = False

    if "#pragma GCC diagnostic push" not in text:
        text = (
            "#pragma GCC diagnostic push\n"
            '#pragma GCC diagnostic ignored "-Wmisleading-indentation"\n\n'
            + text
        )
        updated = True

    if "#pragma GCC diagnostic pop" not in text:
        text = text.rstrip() + "\n\n#pragma GCC diagnostic pop\n"
        updated = True

    if updated:
        header_path.write_text(text)

    return updated


def main() -> None:
    script_dir = pathlib.Path(__file__).resolve().parent
    headers_dir = script_dir / "flatbuffers" / "generated"

    if not headers_dir.is_dir():
        raise SystemExit(f"Missing generated headers directory: {headers_dir}")

    for header in sorted(headers_dir.glob("*.h")):
        changed = inject_pragmas(header)
        action = "updated" if changed else "skipped"
        print(f"{action}: {header}")


if __name__ == "__main__":
    main()

