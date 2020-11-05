from unicorn import *


class MemoryViewer:
    def __init__(self):

        # Dict: key - address, value - [size, pointer of calling, type]
        self.memory_map = {}

    def add_memory(self, address: int, size: int, type_: bool, pointer: int, value):
        values = self.memory_map.get(address, None)
        if values is not None:
            values.append((size, pointer, type_, value))
        else:
            self.memory_map[address] = [(size, pointer, type_, value)]

    def print_access(self):
        for address, info_list in sorted(self.memory_map.items()):
            for info in info_list:
                print("{:08x} - size: {:02x}, pointer: {:08x}, access: {}, value: {:08x}".format(address,
                                                                                             info[0], info[1], "R" if info[2] else "W",
                                                                                             info[3]))
