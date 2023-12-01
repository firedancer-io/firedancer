#!/usr/bin/env python3

# run this script from the top of the repository

from collections import defaultdict
import functools
import os
import subprocess
import sys


canary_canary_path = 'src/util/sanitize/test_fuzz_canary_canary.c'

def main(lcov_files):
    canaries = find_canaries()

    # turn canaries into map of (file_name -> {linum, ...})
    def add(a, c):
        a[c.file].add(c.linum)
        return a
    files_to_lines = functools.reduce(add, canaries, defaultdict(set))

    print(f"canaries found in source ({len(canaries)}):")
    for entry in files_to_lines.items():
        print(f"\t{entry}")

    for lcov_path in lcov_files:
        files_to_lines = eliminate_canaries_with_lcov(lcov_path, files_to_lines)

    live_canaries = files_to_lines
    print("live canaries", live_canaries)

    # check for canary canary - if absent, this tool has failed.
    if len(live_canaries[canary_canary_path]) != 1:
        print(f"the canary in {canary_canary_path} hasn't been found as uncovered - the tool is faulty", file=sys.stderr)
        os.exit(1)

    # remove the canary canary from the the findings
    del live_canaries[canary_canary_path]

    live_canaries = list(filter(lambda item: len(item[1]) != 0, live_canaries.items()))

    if not live_canaries:
        print("no uncovered canaries")

    else:
        for (canary_file, linums) in live_canaries:
            for linum in linums:
                print(f"::warning file={canary_file},line={linum}::\"Canary not yet covered by fuzzing\"")


class Canary:
    def __init__(self, file, linum):
        self.file = file
        self.linum = linum

def find_canaries():
    # define the command to be executed
    cmd = ["grep", "-Hn", "-r", "--exclude=fd_fuzz.h", "FD_FUZZ_MUST_BE_COVERED", "src/"]
    try:
        # execute the command
        result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, text=True)

        # split the output into an array, one element per line
        output_lines = result.stdout.strip().split('\n')

        output_tokens = []
        for line in output_lines:
            raw_canary = line.split(":", 2)
            output_tokens.append(Canary(raw_canary[0], raw_canary[1]))

        return output_tokens

    except subprocess.CalledProcessError as e:
        # Handle errors such as directory not found or grep command failure
        return ["Error: " + str(e)]

# eliminate_canaries_with_lcov reads an lcov file at the specified path
# and returns all of the canaries that were not covered
def eliminate_canaries_with_lcov(path_to_lcov, canaries):
    print(f"processing file: {path_to_lcov}")
    cwd = os.getcwd()
    with open(path_to_lcov) as lcov:

        # loop state
        node_of_interest = None
        source_path = None
        while True: # go over every line in the lcov
            line = lcov.readline()
            if line == "":
                break

            if line.startswith("SF:"): # new source file context: track node if applicable
                source_path = line[len(f"SF:{cwd}/"):].strip() # make path relative
                node_of_interest = canaries.get(source_path, None)

            elif line.startswith("end_of_context"):
                source_path = None
                node_of_interest = None

            elif line.startswith("DA:"):
                if node_of_interest is not None:
                    linum, hits = line[3:].split(",", 1)

                    if hits.strip() == "0": # lcov line has no hits thus is uncovered
                        continue

                    node_of_interest.discard(linum)
        return canaries


if __name__ == '__main__':
    print("using lcov files:", sys.argv[1:])
    main(sys.argv[1:])
