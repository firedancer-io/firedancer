"""
Silly tool that verifies whether C/C++ header include guards match
Firedancer code style.
"""

from pathlib import Path
import os


def check_file(path):
    guard_name = "HEADER_fd_" + str(path).replace(".", "_").replace("/", "_").replace("-", "_")
    with open(path, "r") as f:
        # Skip whitespace lines
        while True:
            line0 = f.readline()
            if not line0.startswith("/* ") and not line0.startswith("// ") and line0.strip():
                break
        line1 = f.readline()
        if not line0.startswith("#ifndef ") and not line1.startswith("#define "):
            print(f"{path}: include guard missing")
        if line0[8:] != line1[8:]:
            return
        if line0[8:].strip() != guard_name:
            print(f"{path}: include guard name '{line0[8:].strip()}' does not match expected '{guard_name}'")


def main():
    # Recursive find .h files
    for path in Path("./src").rglob("*.h"):
        if ".pb.h" in path.name:
            continue
        try:
            check_file(path)
        except IOError:
            print(f"Error reading file: {path}")


if __name__ == "__main__":
    os.chdir(Path(__file__).parents[2])
    main()
