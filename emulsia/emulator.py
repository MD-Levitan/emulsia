from unicorn import *
from capstone import *

from unicorn.arm_const import *

from colorama import init
from termcolor import colored, cprint
from typing import Callable, Any

from .memory_viewer import MemoryViewer, MemoryType, MemoryAccess
from .call_viewer import CallViewer
from .exported import ExportedManager
from .utils import modes, archs
from .emulator_hooker import EmulatorHooker

# /*
#   Callback function for tracing code (UC_HOOK_CODE & UC_HOOK_BLOCK)
#   @address: address where the code is being executed
#   @size: size of machine instruction(s) being executed, or 0 when size is unknown
#   @user_data: user data passed to tracing APIs.
# */
# typedef void (*uc_cb_hookcode_t)(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);

# /*
#   Callback function for tracing interrupts (for uc_hook_intr())
#   @intno: interrupt number
#   @user_data: user data passed to tracing APIs.
# */
# typedef void (*uc_cb_hookintr_t)(uc_engine *uc, uint32_t intno, void *user_data);

# /*
#   Callback function for tracing invalid instructions
#   @user_data: user data passed to tracing APIs.
#   @return: return true to continue, or false to stop program (due to invalid instruction).
# */
# typedef bool (*uc_cb_hookinsn_invalid_t)(uc_engine *uc, void *user_data);

# /*
#   Callback function for tracing IN instruction of X86
#   @port: port number
#   @size: data size (1/2/4) to be read from this port
#   @user_data: user data passed to tracing APIs.
# */
# typedef uint32_t (*uc_cb_insn_in_t)(uc_engine *uc, uint32_t port, int size, void *user_data);

# /*
#   Callback function for OUT instruction of X86
#   @port: port number
#   @size: data size (1/2/4) to be written to this port
#   @value: data value to be written to this port
# */
# typedef void (*uc_cb_insn_out_t)(uc_engine *uc, uint32_t port, int size, uint32_t value, void *user_data);
# *
#   Callback function for hooking memory (READ, WRITE & FETCH)
#   @type: this memory is being READ, or WRITE
#   @address: address where the code is being executed
#   @size: size of data being read or written
#   @value: value of data being written to memory, or irrelevant if type = READ.
#   @user_data: user data passed to tracing APIs
# */
# typedef void (*uc_cb_hookmem_t)(uc_engine *uc, uc_mem_type type,
#         uint64_t address, int size, int64_t value, void *user_data);

# /*
#   Callback function for handling invalid memory access events (UNMAPPED and
#     PROT events)
#   @type: this memory is being READ, or WRITE
#   @address: address where the code is being executed
#   @size: size of data being read or written
#   @value: value of data being written to memory, or irrelevant if type = READ.
#   @user_data: user data passed to tracing APIs
#   @return: return true to continue, or false to stop program (due to invalid memory).
#            NOTE: returning true to continue execution will only work if the accessed
#            memory is made accessible with the correct permissions during the hook.

#            In the event of a UC_MEM_READ_UNMAPPED or UC_MEM_WRITE_UNMAPPED callback,
#            the memory should be uc_mem_map()-ed with the correct permissions, and the
#            instruction will then read or write to the address as it was supposed to.

#            In the event of a UC_MEM_FETCH_UNMAPPED callback, the memory can be mapped
#            in as executable, in which case execution will resume from the fetched address.
#            The instruction pointer may be written to in order to change where execution resumes,
#            but the fetch must succeed if execution is to resume.
# */
# typedef bool (*uc_cb_eventmem_t)(uc_engine *uc, uc_mem_type type,
#         uint64_t address, int size, int64_t value, void *user_data);

uc_cb_hookcode_t = Callable[[Uc, int, int, Any], None]
uc_cb_hookintr_t = Callable[[Uc, int, Any], None]
uc_cb_hookinsn_invalid_t = Callable[[Uc, int, Any], None]
uc_cb_hookmem_t = Callable[[Uc, int, int, int, int, Any], None]

em_cb_hookcode_t = Callable[[EmulatorHooker, int, int, Any], None]
em_cb_hookintr_t = Callable[[EmulatorHooker, int, Any], None]
em_cb_hookinsn_invalid_t = Callable[[EmulatorHooker, int, Any], None]
em_cb_hookmem_t = Callable[[EmulatorHooker, int, int, int, int, Any], None]


class EmulatorConfig:
    def __init__(self,
                 hook_code: em_cb_hookcode_t,
                 hook_inter: em_cb_hookintr_t,
                 hook_mem: em_cb_hookmem_t,
                 hook_mem_invalid: em_cb_hookmem_t,
                 hook_fetch: em_cb_hookmem_t):
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


def __hook_code__(emhook, address, size, user_data, instruction):
    uc = emhook.uc

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


def __hook_intr__(emhook, intno, user_data):
    uc = emhook.uc
    
    if intno != 0x80:
        print("got interrupt {:8x}".format(intno))


def __hook_mem_invalid__(emhook, access, address, size, value, user_data):
    uc = emhook.uc

    if access == UC_MEM_WRITE_UNMAPPED:
        print(">>> Missing memory is being WRITE at 0x%x, data size = %u, data value = 0x%x" %
              (address, size, value))
        return False
    else:
        print(">>> Missing memory is being READ at 0x%x, data size = %u, data value = 0x%x" %
              (address, size, value))
        return False


def __hook_mem__(emhook, access, address, size, value, user_data):
    uc = emhook.uc
    pass


def __hook_fetch__(emhook, access, address, size, value, user_data):
    uc = emhook.uc

    print("UC_MEM_FETCH of 0x%x, data size = %u" % (address, size))


def __silent_hook__(emhook, *args):
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
    """! Main Class. Use Unicorn to emulate and capstone to display instructions."""
    def __init__(self,
                 config: EmulatorConfig = VerboseEmulatorConfig,
                 arch=UC_ARCH_ARM,
                 mode=UC_MODE_THUMB,
                 base_address=0x0000,
                 exp_manager=ExportedManager()):

        self.arch = arch
        self.mode = mode

        self.uc = Uc(arch, mode)
        self.cs_arch = archs(arch)[1]
        self.cs_mode = modes(mode)[1]

        if self.cs_arch == CS_ARCH_ARM:
            # As in arm32 it's normal to switch from arm to thumb,
            # we have to have 2 Cs
            self.cs_thumb = Cs(self.cs_arch, CS_MODE_THUMB)
            self.cs_arm = Cs(self.cs_arch, CS_MODE_ARM)

            self.cs_arm.detail = True
            self.cs_thumb.detail = True
        else:
            self.cs = Cs(self.cs_arch, self.cs_mode)
            self.cs.detail = True

        if self.cs_mode == CS_MODE_THUMB:
            self.arm_mode = True
        else:
            self.arm_mode = False

        self.emhook = EmulatorHooker(self.uc)
        self._export_manager = exp_manager
        self._mem_view = MemoryViewer()
        self._call_view = CallViewer()

        self.hook_functions_before = {}
        self.hook_functions_after = {}

        self.config = config
        self.base_address = base_address

        self.mem_range = 8000 * 1024 * 1024
        self.bin_range = 4000 * 1024

        self.uc.mem_map(base_address, self.mem_range)
        self._mem_view.map_memory(base_address, self.mem_range)

    def init_data(self, pointer: int, data: bytes):
        """! Init block of memory.
        
        @param pointer          pointer to block of memory
        @param data             data to init
        """
        self.uc.mem_write(self.base_address + pointer, data)
        self._mem_view.init_memory(pointer, len(data), MemoryType.TEXT_MEMORY, data)

    def init_data_file(self, filename: str, start: int, size: int, address=None):
        """! Init block of memory from file.
        
        @param  filename            name of file with data
        @param  start               offset to read from file
        @param  size                size of data to read from file
        @param  address             address to place in memory, is None it'll place by @start
        """
        address = address if address is not None else start
        self.init_data(address, open(filename, 'br').read()[start:start + size])

    def init_binary(self, filename: str):
        """! Init memory by full file. Doesn't work good.
        TODO: Add memory map creating anf placing by map.
        """
        self.init_data(0, open(filename, 'br').read())

    
    def init_args(self, args: list):
        """!  Init arguments of function.
        TODO: 1. Different types of regs.
              2. Add support of placing to stack
        """
        regs = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3]

        for i_arg in range(0, len(args)):
            arg = args[i_arg]
            if i_arg < 4:
                self.uc.reg_write(regs[i_arg], arg)
            else:
                pass

    def init_stack(self,
                   stack_address: int,
                   stack_size_top: int = 0x300,
                   stack_size_bottom: int = 0x300,
                   stack_data: bytes = None):
        """! Prepare stack of emulator. As it emulates function stack has to have free memory at top and bottom.

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

        self.uc.mem_write(self.base_address + stack_address - stack_size_top, stack_data)
        self._mem_view.init_memory(self.base_address + stack_address - stack_size_top,
                                   len(stack_data),
                                   MemoryType.STACK_MEMORY,
                                   stack_data)
        self.uc.reg_write(UC_ARM_REG_SP, stack_address)

    def emulate(self, begin: int, until: int, count: int = 0):
        """! Start emulation. """
        self.__init_hooks__()

        self.uc.emu_start(begin=self.base_address + begin +
                          (0x01 if self.mode == UC_MODE_THUMB else 0x00),
                          until=until,
                          count=count)

    def create_binary(self, start: int, end: int, count: int, file: str):
        """! TODO Rework """
        assert start <= end
        output = open(file, "wb")
        output.write(b'\x00\x00\x00\x00' * (self.bin_range // 0x04))

        def hook_code_writeable(uc: Uc, address, size, user_data):
            data = uc.mem_read(address, size)
            output.seek(address)
            output.write(data)

        self.uc.hook_add(UC_HOOK_CODE, hook_code_writeable)

        self.uc.emu_start(self.base_address + start +
                          (0x01 if self.mode == UC_MODE_THUMB else 0x00),
                          end,
                          count=count)

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
        return self.uc.mem_read(self.base_address + address, size)

    def __init_hooks__(self):
        def emulator_decorator(func):
            def emulator_wrap(uc, *args):
                return func(self.emhook, args)
            return emulator_wrap

        def mem_decorator(func):
            def mem_wrap(uc, access, address, size, value, user_data):
                self._mem_view.access_memory(
                    address,
                    size,
                    MemoryAccess.READ if access == UC_MEM_READ else MemoryAccess.WRITE,
                    uc.reg_read(UC_ARM_REG_PC),
                    value if access == UC_MEM_WRITE else int.from_bytes(
                        uc.mem_read(address, size), byteorder='little'))

                return func(self, access, address, size, value, user_data)

            return mem_wrap

        def code_decorator(func):
            def code_wrap(uc, address, size, user_data):
                # TODO: fix this trash
                if address in self.hook_functions_before:
                    self.hook_functions_before[address](self)

                if uc._arch == UC_ARCH_ARM:
                    if uc._mode == UC_MODE_THUMB:
                        disasm = list(self.cs_thumb.disasm(uc.mem_read(address, size), address))
                        if len(disasm) != 1:
                            disasm = list(self.cs_arm.disasm(uc.mem_read(address, size), address))
                    elif uc._mode == UC_MODE_ARM:
                        disasm = list(self.cs_arm.disasm(uc.mem_read(address, size), address))
                        if len(disasm) != 1:
                            disasm = list(
                                self.cs_thumb.disasm(uc.mem_read(address, size), address))
                else:
                    disasm = list(self.cs.disasm(uc.mem_read(address, size), address))
                self._call_view.add_call(disasm[0])

                func(self, address, size, user_data, disasm[0])

                if address in self.hook_functions_after:
                    self.hook_functions_after[address](self)

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
            return self.config.hook_code(emhook, interupt, user_data)


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
