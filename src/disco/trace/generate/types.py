from enum import Enum
from typing import Dict, List
import xml.etree.ElementTree as ET


class EventType(Enum):
    INSTANT = 0
    COUNTER = 1
    DURATION = 2
    ASYNC = 3
    FLOW = 4

    def min_size(self):
        return {
            EventType.INSTANT: 16,
            EventType.COUNTER: 24,
            EventType.DURATION: 16,  # +8 for "duration complete" event
            EventType.ASYNC: 24,
            EventType.FLOW: 24,
        }[self]


class ArgType(Enum):
    NULL = 0
    S32 = 1
    U32 = 2
    S64 = 3
    U64 = 4
    F64 = 5
    STRING = 6
    POINTER = 7
    KOID = 8
    BOOL = 9
    BLOB = 10

    def c_type(self):
        return {
            ArgType.S32: "int",
            ArgType.U32: "uint",
            ArgType.S64: "long",
            ArgType.U64: "ulong",
            ArgType.F64: "double",
            ArgType.POINTER: "void const *",
            ArgType.KOID: "ulong",
            ArgType.BOOL: "_Bool",
        }[self]

    def c_enum(self):
        return {
            ArgType.NULL: "FD_FXT_ARG_NULL",
            ArgType.S32: "FD_FXT_ARG_S32",
            ArgType.U32: "FD_FXT_ARG_U32",
            ArgType.S64: "FD_FXT_ARG_S64",
            ArgType.U64: "FD_FXT_ARG_U64",
            ArgType.F64: "FD_FXT_ARG_F64",
            ArgType.STRING: "FD_FXT_ARG_STR",
            ArgType.POINTER: "FD_FXT_ARG_PTR",
            ArgType.KOID: "FD_FXT_ARG_KOID",
            ArgType.BOOL: "FD_FXT_ARG_BOOL",
            ArgType.BLOB: "FD_FXT_ARG_BLOB",
        }[self]

    def size(self):
        return {
            ArgType.NULL: 0,
            ArgType.S32: 8,
            ArgType.U32: 8,
            ArgType.S64: 16,
            ArgType.U64: 16,
            ArgType.F64: 16,
            ArgType.STRING: None,
            ArgType.POINTER: 16,
            ArgType.KOID: 16,
            ArgType.BOOL: 8,
            ArgType.BLOB: None,
        }[self]


class Arg:
    def __init__(self, type: ArgType, name: str):
        self.type = type
        self.name = name

    def size(self):
        return self.type.size()


class Event:
    def __init__(self, name: str, type: EventType, args: List[Arg]):
        self.name = name
        self.type = type
        self.args = args

    def size(self):
        sz = self.type.min_size()
        for arg in self.args:
            arg_sz = arg.size()
            if arg_sz is None:
                return None
            sz += arg_sz
        return sz


class Category:
    def __init__(self, name: str, events: Dict[str, Event]):
        self.name = name
        self.events = events


class Traces:
    def __init__(self, categories: Dict[str, Category]):
        self.categories = categories


def parse_arg(arg: ET.Element) -> Arg:
    type = ArgType[arg.attrib["type"]]
    name = arg.attrib["name"]
    return Arg(type, name)


def parse_event(event: ET.Element) -> Event:
    name = event.attrib["name"]
    type = EventType[event.attrib["type"]]
    args = [parse_arg(arg) for arg in event.findall("arg")]
    return Event(name, type, args)


def parse_category(category: ET.Element) -> Category:
    name = category.attrib["name"]
    events = {ev.attrib["name"]: parse_event(ev) for ev in category.findall("event")}
    return Category(name, events)


def parse_traces(xml_data: str) -> Traces:
    root = ET.fromstring(xml_data)
    categories = {
        cat.attrib["name"]: parse_category(cat) for cat in root.findall("category")
    }
    return Traces(categories)


class StringTable:
    def __init__(self):
        self.str2idx = {}
        self.idx2str = []

    def push(self, s: str) -> int:
        if s in self.str2idx:
            return self.str2idx[s]
        idx = len(self.idx2str)
        self.str2idx[s] = idx
        self.idx2str.append(s)
        return idx

    def __getitem__(self, key) -> str:
        if isinstance(key, int):
            return self.idx2str[key]
        return self.str2idx[key]

    def __len__(self) -> int:
        return len(self.strings)
