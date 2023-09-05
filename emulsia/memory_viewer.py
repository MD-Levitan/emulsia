from unicorn import *
from enum import IntEnum
from termcolor import colored, cprint

from emulsia.utils import dict_add, logger


class MemoryType(IntEnum):
    STACK_MEMORY = 0
    HEAP_MEMORY = 1

    TEXT_MEMORY = 2
    USER_MEMORY = 3

    UNMAPPED_MEMORY = 4
    UNDEFINED_MEMORY = 5

    UNINITIALIZED_STACK_MEMORY = 6
    UNINITIALIZED_HEAP_MEMORY = 7
    UNINITIALIZED_MEMORY = 8


class MemoryAccess(IntEnum):
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


def justify(size):
    return size + 0x1000 - size % 0x1000


class MemoryViewer:
    """
    #TODO: add stack, heap size
    """

    def __init__(
        self,
        stack_start: int,
        heap_start: int,
        stack_max_size: int,
        heap_max_size: int,
    ):
        # Dict with memory that were accessed
        self.memory_access_map = {}
        # Dict with memory that were accessed but invalid
        self.invalid_access = {}
        # Dict with all memory that were initialized
        self.memory_map = {}

        # Start address of stack and heap
        self.stack_start = stack_start
        self.heap_start = heap_start
        self.stack_max_size = stack_max_size
        self.heap_max_size = heap_max_size

        # Current address of stack and heap
        self.stack_address = stack_start
        self.heap_address = heap_start

        # Mapped areas of memory
        self.areas = []

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

    def map_memory(self, address: int, size: int):
        """! Define/map a part of memory.

        @param address          address of memory
        @param size             size of memory
        @param value            value of memory
        """

        for area_i in range(0, len(self.areas)):
            area_start, area_end = self.areas[area_i]
            if (
                area_start <= address <= area_end
                or area_start <= address + size <= area_end
            ):
                self.areas[area_i] = (
                    min(area_start, address),
                    max(area_start, address + size),
                )
                return

        self.areas.append((address, address + size))

        for size_iter in range(0, size):
            self.memory_map[address + size_iter] = (0, MemoryType.UNINITIALIZED_MEMORY)

    def init_memory(self, address: int, value: bytes, init_type: MemoryType):
        """! Initialized a part of memory.

        @param address          address of memory
        @param value            value of memory
        @param init_type        type of memory: STACK, HEAP, TEXT(BASE)
        """

        for size_iter in range(0, len(value)):
            self.memory_map[address + size_iter] = (value[size_iter], init_type)

    def init_uc_memory(self, uc: Uc):
        # Map stack
        uc.mem_map(self.stack_start, self.stack_max_size)
        # Map heap
        uc.mem_map(self.heap_start, self.heap_max_size)
        # Map memory
        for area_start, area_end in self.areas:
            logger.debug(
                "uc map: addr - 0x%x, size - 0x%x",
                area_start,
                justify(area_end - area_start),
            )
            uc.mem_map(area_start, justify(area_end - area_start))

        for addr, value in self.memory_map.items():
            if MemoryType.STACK_MEMORY <= value[1] <= MemoryType.USER_MEMORY:
                try:
                    uc.mem_write(addr, bytes([value[0]]))
                except Exception as e:
                    logger.error("uc write failed: addr - %x", addr)
                    raise e

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
                    type_list.append(MemoryType.UNMAPPED_MEMORY)

        return type_list

    def memory_type(self, address: int):
        if self.stack_address != -1 and address < self.stack_address:
            return MemoryType.STACK_MEMORY

        if self.heap_address != -1 and address < self.stack_address:
            return MemoryType.HEAP_MEMORY

        if address in self.memory_map:
            return self.memory_map[address][1]

        return MemoryType.UNDEFINED_MEMORY

    def access_memory(
        self, address: int, size: int, access_type: MemoryAccess, pointer: int, value
    ):
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
            print("HERE")
            types = self.check_memory(address, size)

            for i in range(0, len(types)):
                type_ = types[i]

                if (
                    type_ == MemoryType.UNDEFINED_MEMORY
                    or type_ == MemoryType.UNMAPPED_MEMORY
                    or type_ == MemoryType.UNINITIALIZED_STACK_MEMORY
                ):
                    logger.warn(
                        "Trying access to INVALID memory {:08x}".format(address + i),
                    )

                    dict_add(
                        self.invalid_access,
                        address,
                        (size, pointer, access_type, value, type_),
                    )

                    break

        dict_add(self.memory_access_map, address, (size, pointer, access_type, value))

        data = int.to_bytes(value, size, byteorder="little")
        if access_type == MemoryAccess.WRITE:
            for size_iter in range(0, size):
                self.memory_map[address + size_iter] = (
                    data[size_iter],
                    self.memory_type(address + size_iter),
                )

    def print_access(self, type_: str = "rw"):
        """! Print inforamtion about all access tries."""
        logger.info("")
        logger.info("===              Access Memory Map              ===")
        logger.info("Address:   Size:  Pointer:   Access: Value:")

        mem_type = MemoryAccess.from_str(type_)
        for address, info_list in sorted(self.memory_access_map.items()):
            for info in info_list:
                if mem_type != MemoryAccess.READ_WRITE and mem_type != info[2]:
                    continue
                logger.info(
                    "0x{:08x} | 0x{:02x}   | 0x{:08x} | {}      | 0x{:08x}".format(
                        address,
                        info[0],
                        info[1],
                        "R" if info[2] == MemoryAccess.READ else "W",
                        info[3],
                    )
                )

    def print_invlaid_memory(self, type_: str = "rw"):
        """! Print access tries to invalid memory."""
        print()
        print("===            Invalid Memory Map           ===")
        print("Address:   Size:  Pointer:   Access: Value:")

        mem_type = MemoryAccess.from_str(type_)
        for address, info_list in sorted(self.invalid_access.items()):
            for info in info_list:
                if mem_type != MemoryAccess.READ_WRITE and mem_type != info[2]:
                    continue
                print(
                    "0x{:08x} | 0x{:02x}   | 0x{:08x} | {}      | 0x{:08x}".format(
                        address,
                        info[0],
                        info[1],
                        "R" if info[2] == MemoryAccess.READ else "W",
                        info[3],
                    )
                )
