from unicorn import *
from enum import Enum
from termcolor import colored, cprint

from .utils import dict_add


class MemoryType(Enum):
    STACK_MEMORY = 0
    HEAP_MEMORY = 1

    TEXT_MEMORY = 2
    USER_MEMORY = 3

    UNMAPPED_MEMORY = 4
    UNDEFINED_MEMORY = 5

    UNINITIALIZED_STACK_MEMORY = 6
    UNINITIALIZED_HEAP_MEMORY = 7


class MemoryAccess(Enum):
    READ = 0
    WRITE = 1
    READ_WRITE = 2

    @staticmethod
    def from_str(str):
        if str == "r":
            return MemoryAccess.READ
        if str == "w":
            return MemoryAccess.WRITE
        return MemoryAccess.READ_WRITE


class MemoryViewer:
    def __init__(self, stack_start, heap_start):

        # Dict with memory that were accessed
        self.memory_access_map = {}
        # Dict with memory that were accessed but invalid
        self.invalid_access = {}
        # Dict with all memory that were initialized
        self.memory_map = {}

        self.start_addr = 0
        self.end_addr = 0

        # Start address of stack and heap
        self.stack_start = stack_start
        self.heap_start = heap_start
        
        # Current address of stack and heap
        self.stack_address = stack_start
        self.heap_address = heap_start

        # TODO: rewrite heap. free doesn;t work at all
        # Dict of heap allocations
        self.heap_dict = {}
        # List with all allocations fro debug and rev
        self.heap_allocations = list()

    @property
    def stack(self):
        return self.stack_address

    @stack.setter
    def stack(self, address: int):
        self.stack_address = address

    @property
    def heap(self):
        return self.heap

    @heap.setter
    def heap(self, address: int):
        self.heap_address = address


    def malloc(self, size: int):
        address = self.heap_address
        self.heap_dict[address] = size
        self.heap_allocations.append({address: [size, "malloc"]}) 
        self.heap_address += size
        return address

    def alloca(self, size: int):
        """! Doesn't work yet . !"""
        address = self.stack_address 
        self.stack_address += size
        return address


    def free(self, address: int):
        entry = self.heap_dict.get(address, None)
        if entry is None:
            print("Double free")
            self.heap_allocations.append({address: [-1, "double freee"]}) 
        else:
            self.heap_dict[address] = None
            self.heap_allocations.append({address: [-1, "free"]}) 
        

    def map_memory(self, start_address: int, size: int):
        """! Map memory(just define memory space suitable for binary file).

        @param start_address    base address of mapped memory
        @param size             size of memory space
        """
        self.start_addr = start_address
        self.end_addr = start_address + size

    def init_memory(self, address: int, size: int, init_type: MemoryType, value: bytearray):
        """! Initialized a part of memory.
        
        @param address          address of memory
        @param size             size of memory
        @param init_type        type of memory: STACK, HEAP, TEXT
        @param value            value of memory
        """

        for size_iter in range(0, size):
            self.memory_map[address + size_iter] = (value[size_iter], init_type)

    def check_memory(self, address: int, size: int) -> list:
        """! Check memory in map if it was initialized.
        
        @param address          address of memory
        @param size             size of memory

        @return list            list of MemoryTypes. Use list for situation when we try to access to different types of memory
        """
        type_list = []
        for size_iter in range(0, size):
            mem_addr = address + size_iter
            # Check if this memory is in memory_map
            enter = self.memory_map.get(mem_addr, None)
            if enter is not None:
                type_list.append(enter)
            else:
                # Check if this memory in stack
                if self.stack_address != -1 and mem_addr < self.stack_address:
                    type_list.append(MemoryType.UNINITIALIZED_STACK_MEMORY)
                # Otherwise it's invalid map
                else:
                    type_list.append(MemoryType.UNDEFINED_MEMORY if self.start_addr <= mem_addr <=
                                     self.end_addr else MemoryType.UNMAPPED_MEMORY)

        return type_list

    def memory_type(self, address: int):
        if self.stack_address != -1 and address < self.stack_address:
            return MemoryType.STACK_MEMORY

        # TODO: add heap
        if self.start_addr > address > self.end_addr:
            return MemoryType.UNMAPPED_MEMORY

        if address in self.memory_map:
            return self.memory_map[address][1]

        return MemoryType.UNDEFINED_MEMORY

    def access_memory(self,
                      address: int,
                      size: int,
                      access_type: MemoryAccess,
                      pointer: int,
                      value):
        """! Add access to memory.

        @param address      address of memory
        @param size         size of memory
        @param access_type  type of accesing: Read, Write
        @param pointer      address from where access to memory
        @param value        value on address
        """
        # Should check if emulator tries to access(read!!) in invalid memory.
        # If it's trying to write in invalid memory all will be fine because @hook_invalid_mem will be raised.
        if access_type == MemoryAccess.READ:
            types = self.check_memory(address, size)

            for i in range(0, len(types)):
                type_ = types[i]

            if type_ == MemoryType.UNDEFINED_MEMORY or type_ == MemoryType.UNMAPPED_MEMORY or type_ == MemoryType.UNINITIALIZED_STACK_MEMORY:
                cprint("Trying access to INVALID memory {:08x}".format(address + i), "red")
                dict_add(self.invalid_access, address, (size, pointer, access_type, value, type_))

        dict_add(self.memory_access_map, address, (size, pointer, access_type, value))

        data = int.to_bytes(value, size, byteorder="little")
        if access_type == MemoryAccess.WRITE:
            for size_iter in range(0, size):
                self.memory_map[address + size_iter] = (data[size_iter],
                                                        self.memory_type(address + size_iter))

    def print_access(self, type_: str = "rw"):
        """! Print inforamtion about all access tries."""
        print()
        print("===              Access Memory Map              ===")
        print("Address:   Size:  Pointer:   Access: Value:")

        type_ = MemoryAccess.from_str(type_)
        for address, info_list in sorted(self.memory_access_map.items()):
            for info in info_list:
                if type_ != MemoryAccess.READ_WRITE and type_ != info[2]:
                    continue
                print("{:08x} | {:02x}   | {:08x} | {}      | {:08x}".format(
                    address,
                    info[0],
                    info[1],
                    "R" if info[2] == MemoryAccess.READ else "W",
                    info[3]))

    def print_invlaid_memory(self, type_: str = "rw"):
        """! Print access tries to invalid memory."""
        print()
        print("===            Invalid Memory Map           ===")
        print("Address:   Size:  Pointer:   Access: Value:")

        type_ = MemoryAccess.from_str(type_)
        for address, info_list in sorted(self.invalid_access.items()):
            for info in info_list:
                if type_ != MemoryAccess.READ_WRITE and type_ != info[2]:
                    continue
                print("{:08x} | {:02x}   | {:08x} | {}      | {:08x}".format(
                    address,
                    info[0],
                    info[1],
                    "R" if info[2] == MemoryAccess.READ else "W",
                    info[3]))
