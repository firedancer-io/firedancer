# Builds a time-proportional flame graph from perf samples.  Each
# sample is weighted by its period rather than counted once, so with
# task-clock and offcpu-time events (both report nanoseconds) on-CPU
# and off-CPU time share one scale.
#
# Run via `perf script -s`.  Reads the d3-flame-graph HTML template
# from the path in FD_FLAMEGRAPH_TEMPLATE and writes flamegraph.html
# to the current directory.

import json
import os
import sys


class Node:
    def __init__(self, name, libtype):
        self.name = name
        self.libtype = libtype  # "root" | "kernel" | ""
        self.value = 0
        self.children = []

    def to_json(self):
        return {
            "n": self.name,
            "l": self.libtype,
            "v": self.value,
            "c": self.children,
        }


root = Node("all", "root")


def libtype_from_dso(dso):
    if dso and (dso == "[kernel.kallsyms]" or dso.endswith("/vmlinux")):
        return "kernel"
    return ""


def child(node, name, libtype):
    for c in node.children:
        if c.name == name:
            return c
    c = Node(name, libtype)
    node.children.append(c)
    return c


def process_event(event):
    sample = event.get("sample", {})
    period = sample.get("period", 0)
    if not period:
        return

    pid = sample.get("pid", 0)
    if pid == 0:
        node = child(root, event["comm"], "kernel")
    else:
        node = child(root, "{} ({})".format(event["comm"], pid), "")

    for entry in reversed(event.get("callchain", [])):
        name = entry.get("sym", {}).get("name", "[unknown]")
        node = child(node, name, libtype_from_dso(entry.get("dso")))

    node.value += period


def trace_end():
    template_path = os.environ["FD_FLAMEGRAPH_TEMPLATE"]
    with open(template_path, "r", encoding="utf-8") as f:
        template = f.read()

    stacks_json = json.dumps(root, default=lambda x: x.to_json())
    options_json = json.dumps({
        "colorscheme": "blue-green",
        "context": "",
    })

    output = template.replace("/** @options_json **/", options_json)
    output = output.replace("/** @flamegraph_json **/", stacks_json)

    with open("flamegraph.html", "w", encoding="utf-8") as f:
        f.write(output)
