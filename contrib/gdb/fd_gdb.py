import gdb.printing

class fd_hash_printer:
    def __init__(self, val):
        self.__val = bytes([int(val["uc"][i]) for i in range(32)])

    def to_string(self):
        if all(v == 0 for v in self.__val):
            return ("0000...")
        return ("0x" + self.__val.hex())

class fd_signature_printer:
    def __init__(self, val):
        self.__val = bytes([int(val["uc"][i]) for i in range(64)])

    def to_string(self):
        if all(v == 0 for v in self.__val):
            return ("0000...")
        return ("0x" + self.__val.hex())

def build_pretty_printer():
    pp = gdb.printing.RegexpCollectionPrettyPrinter("Firedancer")
    pp.add_printer("fd_hash", "^fd_hash$", fd_hash_printer)
    pp.add_printer("fd_signature", "^fd_signature$", fd_hash_printer)
    return pp

gdb.printing.register_pretty_printer(
    gdb.current_objfile(),
    build_pretty_printer()
)
