from unicorn import *
from capstone import *

from unicorn.arm_const import *

from .memory_viewer import MemoryViewer
from .call_viewer import CallViewer


class EmulatorConfig:
    def __init__(self, hook_code: bool, hook_inter: bool, hook_mem: bool, hook_mem_invalid: bool, hook_fetch):
        self._hook_code = hook_code
        self._hook_inter = hook_inter
        self._hook_mem = hook_mem
        self._hook_mem_invalid = hook_mem_invalid
        self._hook_fetch = hook_fetch

    def __str__(self):
        return "Hooks configuaration: code - {}, interupt - {}, memory - {}, invalid memory - {}, fetch - {}".format(self._hook_code,
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


VerboseEmulatorConfig = EmulatorConfig(True, True, True, True, True)

SilentEmulatorConfig = EmulatorConfig(False, False, False, False, False)


class Emulator:
    def __init_hooks__(self):
        def hook_code(uc: Uc, address, size, user_data):
            print()
            print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %
                  (address, size))
            print("Registers: r0 - {}, r1 - {}, r2 - {}, r3 - {}, r4 - {}, r5 - {}, r6 - {}, r7 - {}, r8 - {} sb - {}, pc - {}, lr - {}, sp - {}".format(
                hex(uc.reg_read(UC_ARM_REG_R0)),
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

            if self.arch == UC_ARCH_ARM:
                disasm_thumb = list(self.md_thumb.disasm(
                    uc.mem_read(address, size), address))
                disasm_arm = list(self.md_arm.disasm(
                    uc.mem_read(address, size), address))

                if len(disasm_thumb) == 2 and len(disasm_arm) == 1 and self.arm_mode == True:
                    self.arm_mode = False

                if len(disasm_thumb) == 1 and len(disasm_arm) != 1 and self.arm_mode == False:
                    self.arm_mode = True

                print("Arm mode: {}".format(
                    "THUMB2" if self.arm_mode == True else "ARM"))
                for i in disasm_thumb if self.arm_mode == 1 else disasm_arm:
                    print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
                    self._call_view.add_call(i.op_str, i.address, i)

            else:
                for i in self.md.disasm(uc.mem_read(address, size), address):
                    print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))

        def hook_intr(uc, intno, user_data):
            if intno != 0x80:
                print("got interrupt %x ???" % intno)
                uc.emu_stop()
                return

        def hook_mem_invalid(uc, access, address, size, value, user_data):
            if access == UC_MEM_WRITE_UNMAPPED:
                print(">>> Missing memory is being WRITE at 0x%x, data size = %u, data value = 0x%x" % (
                    address, size, value))
                return False
            else:
                print(">>> Missing memory is being READ at 0x%x, data size = %u, data value = 0x%x" % (
                    address, size, value))
                return False

        def hook_mem(uc, access, address, size, value, user_data):
            self._mem_view.add_memory(
                address, size,
                access == UC_MEM_READ,
                uc.reg_read(UC_ARM_REG_PC),
                value if access == UC_MEM_WRITE else int.from_bytes(
                    uc.mem_read(address, size), byteorder='little')
            )

        def hook_fetch(uc, access, address, size, value, user_data):
            print("UC_MEM_FETCH of 0x%x, data size = %u" %
                  (address, size))

        if self.config.hook_code == True:
            self.mu.hook_add(UC_HOOK_CODE, hook_code)

        if self.config.hook_inter == True:
            self.mu.hook_add(UC_HOOK_INTR, hook_intr)

        if self.config.hook_mem == True:
            self.mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_mem)

        if self.config.hook_mem_invalid == True:
            self.mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED |
                             UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid)

        if self.config.hook_fetch == True:
            self.mu.hook_add(UC_HOOK_MEM_FETCH | UC_HOOK_MEM_FETCH_INVALID |
                             UC_HOOK_MEM_FETCH_UNMAPPED | UC_HOOK_MEM_FETCH_PROT |
                             UC_HOOK_MEM_PROT | UC_HOOK_MEM_PROT, hook_fetch)

    def __init__(self, config: EmulatorConfig = VerboseEmulatorConfig, arch=UC_ARCH_ARM, mode=UC_MODE_THUMB,
                 arch_md=CS_ARCH_ARM, mode_md=CS_MODE_THUMB, base_address=0x0000):

        self.arch = arch
        self.mode = mode

        self.mu = Uc(arch, mode)
        if arch_md == CS_ARCH_ARM:
            # Special classes for disassm
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

        self._mem_view = MemoryViewer()
        self._call_view = CallViewer()

        self.config = config
        self.base_address = base_address

        self.mu.mem_map(base_address, 4000 * 1024 * 1024)
        self.__init_hooks__()

    def init_data(self, pointer: int, data: bytes):
        self.mu.mem_write(self.base_address + pointer, data)

    def init_data_file(self, filename: str, start: int, size: int, address=None):
        address = address if address is not None else start
        self.mu.mem_write(self.base_address + address,
                          open(filename, 'br').read()
                          [start: start + size])

    def init_reg(self, reg_type: int, reg_value):
        self.mu.reg_write(reg_type, reg_value)

    def prepare_args(self, args: list):
        # TODO: add different regs
        regs = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3]

        for i_arg in range(0, len(args)):
            arg = args[i_arg]
            if i_arg < 4:
                self.mu.reg_write(regs[i_arg], arg)
            else:
                pass

    def prepare_stack(self, stack_address: int, stack_data: bytes):
        self.stack_address = stack_address
        self.mu.mem_write(self.base_address + stack_address, stack_data)
        # Fill empty stack
        self.mu.mem_write(self.base_address +
                          stack_address - 0x100, b'\xff' * 0x100)

        self.mu.reg_write(UC_ARM_REG_SP, stack_address)

    def emulate(self, start: int, end: int, count: int):
        assert start <= end
        self.mu.emu_start(self.base_address + start + (0x01 if self.mode ==
                                                       UC_MODE_THUMB else 0x00), end, count=count)

    def read_stack(self, size=0x100):
        return self.read_memory(self.stack_address, size)

    def read_memory(self, address: int, size=0x100):
        return self.mu.mem_read(self.base_address + address, size)

    @property
    def mem_view(self):
        return self._mem_view

    @property
    def call_view(self):
        return self._call_view
