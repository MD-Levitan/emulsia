from unicorn import *
from enum import Enum
from termcolor import colored, cprint

class MemoryType(Enum):
    STACK_MEMORY = 0
    HEAP_MEMORY = 1

    TEXT_MEMORY = 2
    USER_MEMORY = 3

    UNMAPPED_MEMORY = 4
    UNDEFINED_MEMORY = 5


class MemoryAccess(Enum):
    READ = 0
    WRITE = 1


class MemoryViewer:

    def __init__(self):

        self.memory_access_map = {}
        self.memory_map = {}

        self.start_addr = 0
        self.end_addr = 0

    def map_memory(self, start_address: int, size: int):
        self.start_addr = start_address
        self.end_addr = start_address + size

    def init_memory(self, address: int, size: int, init_type: MemoryType, value: bytearray):
        for size_iter in range(0, size):
            self.memory_map[address + size_iter] = (value[size_iter], init_type)

    def check_memory(self, address: int, size: int) -> list:
        type_list = []
        for size_iter in range(0, size):
            mem_addr = address + size_iter
            type_list.append(self.memory_map.get(mem_addr, MemoryType.UNDEFINED_MEMORY if self.start_addr <=
                                                 mem_addr <= self.end_addr else MemoryType.UNMAPPED_MEMORY))

        return type_list

    def access_memory(self, address: int, size: int, access_type: MemoryAccess, pointer: int, value):
        """ Add info about access to memory.

        """
        types = self.check_memory(address, size)
        for i in range(0, len(types)):
            type_ = types[i]
            if type_ == MemoryType.UNDEFINED_MEMORY or type_ == MemoryType.UNMAPPED_MEMORY:
                # TODO: add execption
                cprint("Trying access to INVALID memory {:08x}".format(address + i), "red")

        values = self.memory_access_map.get(address, None)
        if values is not None:
            values.append((size, pointer, access_type, value))
        else:
            self.memory_access_map[address] = [
                (size, pointer, access_type, value)]

    def print_access(self):
        for address, info_list in sorted(self.memory_access_map.items()):
            for info in info_list:
                print("{:08x} - size: {:02x}, pointer: {:08x}, access: {}, value: {:08x}".format(address,
                                                                                                 info[0], info[1], "R" if info[2] == MemoryAccess.READ else "W",
                                                                                                 info[3]))
