from unicorn import *
from capstone import *
from unicorn.arm_const import *
from unicorn.arm64_const import *

from enum import IntEnum
from typing import Optional

from emulsia.memory_viewer import MemoryViewer, MemoryType, MemoryAccess
from emulsia.call_viewer import CallViewer
from emulsia.exported import ExportedManager
from emulsia.utils import modes, archs, logger, get_special_regs
from emulsia.emulator_hooker import EmulatorHooker
from emulsia.emulator_config import (
    EmulatorConfig,
    VerboseEmulatorConfig,
    SilentEmulatorConfig,
)


class Arch(IntEnum):
    """Copy of supported UC arch"""

    ARCH_ARM = 1
    ARCH_ARM64 = 2


class Mode(IntEnum):
    """Copy of supported UC modes"""

    MODE_ARM = 0
    MODE_THUMB = 16


class Emulator:
    """! Main Class. Use Unicorn to emulate and capstone to display instructions."""

    def __init__(
        self,
        config: EmulatorConfig = VerboseEmulatorConfig,
        arch: Arch = Arch.ARCH_ARM64,
        mode: Mode = Mode.MODE_ARM,
        stack_start: int = 0xD0000000,
        heap_start: int = 0xB0000000,
        stack_max_size: int = 0x1000,
        heap_max_size: int = 0x1000,
        exp_manager=ExportedManager(),
    ):
        self.arch = arch
        self.mode = mode

        self.uc = Uc(arch, mode)
        self.cs_arch = archs(arch)[1]
        self.cs_mode = modes(mode)[1]

        if self.cs_arch == CS_ARCH_ARM:
            self.cs_thumb = Cs(self.cs_arch, CS_MODE_THUMB)
            self.cs_arm = Cs(self.cs_arch, CS_MODE_ARM)

            self.cs_arm.detail = True
            self.cs_thumb.detail = True
        else:
            self.cs = Cs(self.cs_arch, self.cs_mode)
            self.cs.detail = True

        self._export_manager = exp_manager
        self._mem_view = MemoryViewer(
            stack_start, heap_start, stack_max_size, heap_max_size
        )
        self._call_view = CallViewer()
        self.emhook = EmulatorHooker(self.uc, self._mem_view)

        self.hook_functions_before = {}
        self.hook_functions_after = {}
        self.config = config

        self.prepared_for_emulation = False

    def map_data(
        self, pointer: int, size: int, mem_type: MemoryType = MemoryType.TEXT_MEMORY
    ):
        """! Mam block of memory.

        @param pointer          pointer to block of memory
        @param size             size of memory
        @param mem_type         type of memory
        """
        logger.debug(
            "Map memory: addr - 0x%x, size - 0x%x, type - 0x%x",
            pointer,
            size,
            mem_type,
        )

        # self.uc.mem_map(pointer, 0x200000)
        self._mem_view.map_memory(pointer, size)

    def init_data(self, pointer: int, data: bytes):
        """! Init block of memory.

        @param pointer          pointer to block of memory
        @param data             data to init
        """

        logger.debug(
            "Init memory: addr - 0x%x, size - 0x%x",
            pointer,
            len(data),
        )

        # self.uc.mem_map(pointer, 0x200000)
        # self.uc.mem_write(pointer, data)
        self._mem_view.init_memory(pointer, data, MemoryType.TEXT_MEMORY)

    def init_data_file(self, filename: str, start: int, size: int, address=None):
        """! Init block of memory from file.

        @param  filename            name of file with data
        @param  start               offset to read from file
        @param  size                size of data to read from file
        @param  address             address to place in memory, is None it'll place by @start
        """
        address = address if address is not None else start
        self.init_data(address, open(filename, "br").read()[start : start + size])

    def init_binary(self, filename: str, base_addres: int = 0x00):
        """! Init memory by full file. Doesn't work good.
        TODO: Add memory map creating anf placing by map.
        """
        data = open(filename, "br").read()
        self.map_data(base_addres, len(data))
        self.init_data(base_addres, data)

    def init_args(self, args: list):
        """!  Init arguments of function.
        1. Add support of placing to stack
        """
        for i, argument in enumerate(args):
            self.uc.reg_write(
                UC_ARM_REG_R0 if self.arch == UC_ARCH_ARM else UC_ARM64_REG_X0 + i,
                argument,
            )

    def init_heap_data(self, pointer: int, data: bytes):
        """! Init block of memory in heap.

        @param pointer          pointer to block of memory
        @param data             data to init
        """

        logger.debug(
            "Init heap memory: addr - 0x%x, size - 0x%x",
            pointer,
            len(data),
        )

        # self.uc.mem_map(pointer, 0x200000)
        # self.uc.mem_write(pointer, data)
        self._mem_view.init_memory(pointer, data, MemoryType.HEAP_MEMORY)

    def init_stack_data(self, pointer: int, data: bytes):
        """! Init block of memory in stack.

        @param pointer          pointer to block of memory
        @param data             data to init
        """

        logger.debug(
            "Init heap memory: addr - 0x%x, size - 0x%x",
            pointer,
            len(data),
        )

        # self.uc.mem_map(pointer, 0x200000)
        # self.uc.mem_write(pointer, data)
        self._mem_view.init_memory(pointer, data, MemoryType.STACK_MEMORY)

    def init_function_stack(
        self,
        stack_address: int,
        stack_size_top: int = 0x300,
        stack_size_bottom: int = 0x300,
        stack_data: Optional[bytes] = None,
    ):
        """! Prepare stack of emulator. As it emulates function stack has to have free memory at top and bottom.

        @param stack_address        adrress of current stack
        @param stack_size_top       size of free memory at top of stack
        @param stack_size_bottom    size of free memory at bottom of stack
        @param stack_data           value of stack
        """
        self.stack_address = stack_address
        if stack_data is None:
            stack_data = b"\xff" * (stack_size_top + stack_size_bottom)
        if len(stack_data) < stack_size_top + stack_size_bottom:
            stack_data = (
                b"\xff" * stack_size_top
                + stack_data
                + b"\xff" * (stack_size_bottom - len(stack_data))
            )

        # self.uc.mem_map(stack_address, stack_address - stack_size_top)
        # self.uc.mem_write(stack_address - stack_size_top, stack_data)
        self._mem_view.init_memory(
            stack_address - stack_size_top,
            stack_data,
            MemoryType.STACK_MEMORY,
        )
        self.uc.reg_write(UC_ARM64_REG_TPIDR_EL0, 0x7b67774020)
        self.uc.reg_write(UC_ARM_REG_SP if self.arch == UC_ARCH_ARM else UC_ARM64_REG_SP, stack_address)

    def prepare_emulate(self):
        if not self.prepared_for_emulation:
            self.__init_hooks__()
            self._mem_view.init_uc_memory(self.uc)
            self.prepared_for_emulation = True

    def emulate(self, begin: int, until: int, count: int = 0):
        """! Start emulation."""
        if not self.prepared_for_emulation:
            self.__init_hooks__()
            self._mem_view.init_uc_memory(self.uc)
            self.prepared_for_emulation = True

        self.uc.emu_start(
            begin=begin + (0x01 if self.mode == UC_MODE_THUMB else 0x00),
            until=until,
            count=count,
        )

    def create_binary(self, start: int, end: int, count: int, file: str):
        """! TODO Rework"""
        assert start <= end
        output = open(file, "wb")
        output.write(b"\x00\x00\x00\x00" * (self.bin_range // 0x04))

        def hook_code_writeable(uc: Uc, address, size, user_data):
            data = uc.mem_read(address, size)
            output.seek(address)
            output.write(data)

        self.uc.hook_add(UC_HOOK_CODE, hook_code_writeable)

        self.uc.emu_start(
            self.base_address + start + (0x01 if self.mode == UC_MODE_THUMB else 0x00),
            end,
            count=count,
        )

    def add_function_hook(self, address: int, func, place="before"):
        """! Add function hook by address.

        @param address      address of fucntion
        @param func         function that will emulate function using unicorn
        @param place        place of hook: hook intruction "before" @hook_code or "after"
                            NOTE: As emulator call @hook_code from @EmulatorConfig, sometimes it's
                            matter when your hook(@func) will work before or after @hook_code.
        """
        if place == "before":
            self.hook_functions_before[address] = func
        elif place == "after":
            self.hook_functions_after[address] = func
        else:
            print("Failed to add hook")

    def read_stack(self, size=0x400, offset=0x200):
        """! Read data in stack.

        @param size         size of stack
        @param offset       offset of stack to read
        """
        return self.read_memory(self.stack_address - offset, size)

    def read_memory(self, address: int, size=0x100):
        """! Read data at address.

        @address            address of memory
        @size               size of memory to readd
        """
        return self.uc.mem_read(address, size)

    def __init_hooks__(self):
        def emulator_decorator(func):
            def emulator_wrap(uc, interupt, user_data):
                return func(self.emhook, interupt, user_data)

            return emulator_wrap

        def mem_decorator(func):
            def mem_wrap(uc, access, address, size, value, user_data):
                try:
                    self._mem_view.access_memory(
                    address,
                    size,
                    MemoryAccess.READ if access == UC_MEM_READ else MemoryAccess.WRITE,
                    uc.reg_read(get_special_regs(uc)[0]),
                    value
                    if access == UC_MEM_WRITE
                    else int.from_bytes(uc.mem_read(address, size), byteorder="little"),
                    )
                except Exception as e:
                    logger.fatal(f"error: {e}")

                return func(self.emhook, access, address, size, value, user_data)

            return mem_wrap

        def code_decorator(func):
            def code_wrap(uc, address, size, user_data):
                # TODO: fix this trash
                if address in self.hook_functions_before:
                    self.hook_functions_before[address](self.emhook)

                if uc._arch == UC_ARCH_ARM:
                    if uc._mode == UC_MODE_THUMB:
                        disasm = list(
                            self.cs_thumb.disasm(uc.mem_read(address, size), address)
                        )
                        if len(disasm) != 1:
                            disasm = list(
                                self.cs_arm.disasm(uc.mem_read(address, size), address)
                            )
                    elif uc._mode == UC_MODE_ARM:
                        disasm = list(
                            self.cs_arm.disasm(uc.mem_read(address, size), address)
                        )
                        if len(disasm) != 1:
                            disasm = list(
                                self.cs_thumb.disasm(
                                    uc.mem_read(address, size), address
                                )
                            )
                else:
                    disasm = list(self.cs.disasm(uc.mem_read(address, size), address))
                self._call_view.add_call(disasm[0])

                func(self.emhook, address, size, user_data, disasm[0])

                if address in self.hook_functions_after:
                    self.hook_functions_after[address](self.emhook)

                return

            return code_wrap

        @mem_decorator
        def hook_mem(emhook, access, address, size, value, user_data):
            return self.config.hook_mem(emhook, access, address, size, value, user_data)

        @code_decorator
        def hook_code(emhook, address, size, user_data, instruction):
            return self.config.hook_code(emhook, address, size, user_data, instruction)

        @emulator_decorator
        def hook_inter(emhook, interupt, user_data):
            return self.config.hook_inter(emhook, interupt, user_data)

        for address, func in self._export_manager.iter():
            self.add_function_hook(address, func.hook)

        # Add logging insted of print
        print(self.hook_functions_before)
        print(self.hook_functions_after)

        self.uc.hook_add(UC_HOOK_CODE, hook_code)
        self.uc.hook_add(UC_HOOK_INTR, hook_inter)
        self.uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_mem)

        # self.uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED,
        #                  self.config.hook_mem_invalid)
        # self.uc.hook_add(
        #     UC_HOOK_MEM_FETCH | UC_HOOK_MEM_FETCH_INVALID
        #     | UC_HOOK_MEM_FETCH_UNMAPPED | UC_HOOK_MEM_FETCH_PROT
        #     | UC_HOOK_MEM_PROT | UC_HOOK_MEM_PROT,
        #     self.config.hook_fetch)

    @property
    def mem_view(self):
        return self._mem_view

    @property
    def call_view(self):
        return self._call_view
