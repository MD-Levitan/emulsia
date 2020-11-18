from unicorn import *
from capstone import *

from unicorn.arm_const import *

from colorama import init
from termcolor import colored, cprint
from typing import Callable

from .memory_viewer import MemoryViewer, MemoryType, MemoryAccess
from .call_viewer import CallViewer
from .exported import ExportedManager

Hook = Callable[[], None ]


class EmulatorConfig:
    def __init__(self,
                 hook_code: Hook,
                 hook_inter: Hook,
                 hook_mem: Hook,
                 hook_mem_invalid: Hook,
                 hook_fetch: Hook):
        self._hook_code = hook_code
        self._hook_inter = hook_inter
        self._hook_mem = hook_mem
        self._hook_mem_invalid = hook_mem_invalid
        self._hook_fetch = hook_fetch

    def __str__(self):
        return "Hooks configuaration: code - {}, interupt - {}, memory - {}, invalid memory - {}, fetch - {}".format(
            self._hook_code,
            self._hook_inter,
            self._hook_mem,
            self._hook_mem_invalid,
            self._hook_fetch)

    @property
    def hook_code(self):
        return self._hook_code

    @property
    def hook_inter(self):
        return self._hook_inter

    @property
    def hook_mem_invalid(self):
        return self._hook_mem_invalid

    @property
    def hook_mem(self):
        return self._hook_mem

    @property
    def hook_fetch(self):
        return self._hook_fetch


def __hook_code__(uc, address, size, user_data, instruction):

    print()
    cprint(">>> Tracing instruction at 0x{:x}, instruction size = 0x{:x}".format(address, size),
           'green')
    print(
        "Registers: r0 - {}, r1 - {}, r2 - {}, r3 - {}, r4 - {}, r5 - {}, r6 - {}, r7 - {}, r8 - {} sb - {}, pc - {}, lr - {}, sp - {}"
        .format(hex(uc.reg_read(UC_ARM_REG_R0)),
                hex(uc.reg_read(UC_ARM_REG_R1)),
                hex(uc.reg_read(UC_ARM_REG_R2)),
                hex(uc.reg_read(UC_ARM_REG_R3)),
                hex(uc.reg_read(UC_ARM_REG_R4)),
                hex(uc.reg_read(UC_ARM_REG_R5)),
                hex(uc.reg_read(UC_ARM_REG_R6)),
                hex(uc.reg_read(UC_ARM_REG_R7)),
                hex(uc.reg_read(UC_ARM_REG_R8)),
                hex(uc.reg_read(UC_ARM_REG_SB)),
                hex(uc.reg_read(UC_ARM_REG_PC)),
                hex(uc.reg_read(UC_ARM_REG_LR)),
                hex(uc.reg_read(UC_ARM_REG_SP))))

    print("0x%x:\t%s\t%s" % (instruction.address, instruction.mnemonic, instruction.op_str))


def __hook_intr__(uc, intno, user_data):
    if intno != 0x80:
        print("got interrupt {:8x}".format(intno))


def __hook_mem_invalid__(uc, access, address, size, value, user_data):
    if access == UC_MEM_WRITE_UNMAPPED:
        print(">>> Missing memory is being WRITE at 0x%x, data size = %u, data value = 0x%x" %
              (address, size, value))
        return False
    else:
        print(">>> Missing memory is being READ at 0x%x, data size = %u, data value = 0x%x" %
              (address, size, value))
        return False


def __hook_mem__(uc, access, address, size, value, user_data):
    pass


def __hook_fetch__(uc, access, address, size, value, user_data):
    print("UC_MEM_FETCH of 0x%x, data size = %u" % (address, size))


def __silent_hook__(uc, *args):
    pass


VerboseEmulatorConfig = EmulatorConfig(__hook_code__,
                                       __hook_intr__,
                                       __hook_mem__,
                                       __hook_mem_invalid__,
                                       __hook_fetch__)
SilentEmulatorConfig = EmulatorConfig(__silent_hook__,
                                      __silent_hook__,
                                      __silent_hook__,
                                      __silent_hook__,
                                      __silent_hook__)


class Emulator:
    def __init_hooks__(self):
        def mem_decorator(func):
            def mem_wrap(uc, access, address, size, value, user_data):
                self._mem_view.access_memory(
                    address,
                    size,
                    MemoryAccess.READ if access == UC_MEM_READ else MemoryAccess.WRITE,
                    uc.reg_read(UC_ARM_REG_PC),
                    value if access == UC_MEM_WRITE else int.from_bytes(
                        uc.mem_read(address, size), byteorder='little'))

                return func(uc, access, address, size, value, user_data)

            return mem_wrap

        def code_decorator(func):
            def code_wrap(uc, address, size, user_data):
                # TODO: fix this trash
                if address in self.hook_functions_before:
                    self.hook_functions_before[address](uc)
                
                if uc._arch == UC_ARCH_ARM:
                    if uc._mode == UC_MODE_THUMB:
                        disasm = list(self.md_thumb.disasm(uc.mem_read(address, size), address))
                        if len(disasm) != 1:
                            disasm = list(self.md_arm.disasm(uc.mem_read(address, size), address))
                    elif uc._mode == UC_MODE_ARM:
                        disasm = list(self.md_arm.disasm(uc.mem_read(address, size), address))
                        if len(disasm) != 1:
                            disasm = list(
                                self.md_thumb.disasm(uc.mem_read(address, size), address))
                else:
                    disasm = list(self.md.disasm(uc.mem_read(address, size), address))
                self._call_view.add_call(disasm[0])

                func(uc, address, size, user_data, disasm[0])
                
                if address in self.hook_functions_after:
                    self.hook_functions_after[address](uc)

                return
            return code_wrap

        @mem_decorator
        def hook_mem(uc, access, address, size, value, user_data):
            return self.config.hook_mem(uc, access, address, size, value, user_data)

        @code_decorator
        def hook_code(uc, address, size, user_data, instruction):
            return self.config.hook_code(uc, address, size, user_data, instruction)

        for address, func in self._export_manager.iter():
            self.add_function_hook(address, func.hook)

        print(self.hook_functions_before)
        print(self.hook_functions_after)

        self.mu.hook_add(UC_HOOK_CODE, hook_code)
        self.mu.hook_add(UC_HOOK_INTR, self.config.hook_inter)
        self.mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_mem)
        self.mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED,
                         self.config.hook_mem_invalid)
        self.mu.hook_add(
            UC_HOOK_MEM_FETCH | UC_HOOK_MEM_FETCH_INVALID
            | UC_HOOK_MEM_FETCH_UNMAPPED | UC_HOOK_MEM_FETCH_PROT
            | UC_HOOK_MEM_PROT | UC_HOOK_MEM_PROT,
            self.config.hook_fetch)

    def __init__(self,
                 config: EmulatorConfig = VerboseEmulatorConfig,
                 arch=UC_ARCH_ARM,
                 mode=UC_MODE_THUMB,
                 arch_md=CS_ARCH_ARM,
                 mode_md=CS_MODE_THUMB,
                 base_address=0x0000,
                 exp_manager=ExportedManager()):

        self.arch = arch
        self.mode = mode

        self.mu = Uc(arch, mode)

        if arch_md == CS_ARCH_ARM:
            self.md_thumb = Cs(arch_md, CS_MODE_THUMB)
            self.md_arm = Cs(arch_md, CS_MODE_ARM)

            self.md_arm.detail = True
            self.md_thumb.detail = True
        else:
            self.md = Cs(arch_md, mode)
            self.md.detail = True

        if mode_md == CS_MODE_THUMB:
            self.arm_mode = True
        else:
            self.arm_mode = False

        self._export_manager = exp_manager
        self._mem_view = MemoryViewer()
        self._call_view = CallViewer()
        
        self.hook_functions_before = {}
        self.hook_functions_after = {}


        self.config = config
        self.base_address = base_address

        self.mem_range = 8000 * 1024 * 1024
        self.bin_range = 4000 * 1024

        self.mu.mem_map(base_address, self.mem_range)
        self._mem_view.map_memory(base_address, self.mem_range)

    def init_data(self, pointer: int, data: bytes):
        self.mu.mem_write(self.base_address + pointer, data)
        self._mem_view.init_memory(pointer, len(data), MemoryType.TEXT_MEMORY, data)

    def init_data_file(self, filename: str, start: int, size: int, address=None):
        address = address if address is not None else start
        self.init_data(address, open(filename, 'br').read()[start:start + size])

    def init_binary(self, filename: str):
        self.init_data(0, open(filename, 'br').read())

    def init_reg(self, reg_type: int, reg_value):
        self.mu.reg_write(reg_type, reg_value)

    def init_args(self, args: list):
        # TODO: add different regs
        regs = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3]

        for i_arg in range(0, len(args)):
            arg = args[i_arg]
            if i_arg < 4:
                self.mu.reg_write(regs[i_arg], arg)
            else:
                pass

    def init_stack(self,
                   stack_address: int,
                   stack_size_top: int = 0x300,
                   stack_size_bottom: int = 0x300,
                   stack_data: bytes = None):
        """! Prepare stack of emulator. As it emulate function stack has to have free memory at top and bottom.

        @param stack_address        adrress of current stack
        @param stack_size_top       size of free memory at top of stack
        @param stack_size_bottom    size of free memory at bottom of stack
        @param stack_data           value of stack
        """
        self.stack_address = stack_address
        if stack_data is None:
            stack_data = b'\xff' * (stack_size_top + stack_size_bottom)
        if len(stack_data) < stack_size_top + stack_size_bottom:
            stack_data = b'\xff' * stack_size_top + stack_data + b'\xff' * (stack_size_bottom -
                                                                            len(stack_data))

        self.mu.mem_write(self.base_address + stack_address - stack_size_top, stack_data)
        self._mem_view.init_memory(self.base_address + stack_address - stack_size_top,
                                   len(stack_data),
                                   MemoryType.STACK_MEMORY,
                                   stack_data)
        self.mu.reg_write(UC_ARM_REG_SP, stack_address)

    def emulate(self, begin: int, until: int, count: int = 0):
        """! Start emulation. """
        self.__init_hooks__()

        self.mu.emu_start(begin=self.base_address + begin +
                          (0x01 if self.mode == UC_MODE_THUMB else 0x00),
                          until=until,
                          count=count)

    def create_binary(self, start: int, end: int, count: int, file: str):
        assert start <= end
        output = open(file, "wb")
        output.write(b'\x00\x00\x00\x00' * (self.bin_range // 0x04))

        def hook_code_writeable(uc: Uc, address, size, user_data):
            data = uc.mem_read(address, size)
            output.seek(address)
            output.write(data)

        self.mu.hook_add(UC_HOOK_CODE, hook_code_writeable)

        self.mu.emu_start(self.base_address + start +
                          (0x01 if self.mode == UC_MODE_THUMB else 0x00),
                          end,
                          count=count)

    def add_function_hook(self, address: int, func, place="before"):
        """! Add function hook by address.
        
        @param address      address of fucntion
        @param func         function that will emulate function using unicorn
        @param place        place of hook: hook intruction "before" @hook_code or "after" 
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
        return self.mu.mem_read(self.base_address + address, size)

    @property
    def mem_view(self):
        return self._mem_view

    @property
    def call_view(self):
        return self._call_view
