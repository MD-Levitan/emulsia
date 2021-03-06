from unicorn import *
from unicorn.arm_const import *
import struct

from .emulator_hooker import EmulatorHooker


class ExportedFunction:
    def __init__(self, name: str, hook, attr=None):
        self._name = name
        self._hook = hook
        self._attr = attr

    def __str__(self):
        return "libc function: {}, function {}".format(self._name, self._hook)

    @property
    def hook(self):
        return self._hook


def __memset__(emhook: EmulatorHooker):
    uc = emhook.uc
    print("memset hook")
    value = uc.reg_read(UC_ARM_REG_R1)
    size = uc.reg_read(UC_ARM_REG_R2)

    uc.mem_write(uc.reg_read(UC_ARM_REG_R0), bytes([value] * size))
    uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))


def __memclr__(emhook: EmulatorHooker):
    print("memclr hook")
    uc = emhook.uc
    size = uc.reg_read(UC_ARM_REG_R1)

    uc.mem_write(uc.reg_read(UC_ARM_REG_R0), b"\x00" * size)
    uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))


def __free__(emhook: EmulatorHooker):
    print("free hook")
    uc = emhook.uc
    #TODO: add clear from heap

    uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))


def __malloc__(emhook: EmulatorHooker):
    uc = emhook.uc
    mem = emhook.mem

    size = uc.reg_read(UC_ARM_REG_R0)
    address = mem.malloc(size=size)

    print("HOOK malloc({:8x}) -> {:8x}".format(size, address))
    
    uc.reg_write(UC_ARM_REG_R0, address)
    uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))


def __strlen__(emhook: EmulatorHooker):
    print("strlen hook")
    uc = emhook.uc
    i = 0
    while True:
        symb = uc.mem_read(uc.reg_read(UC_ARM_REG_R0) + i, 0x1)
        if symb == 0x00:
            break
        i += 1

    uc.reg_write(UC_ARM_REG_R0, i)
    uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))


EXPORT_STRLEN = ExportedFunction("strlen", __strlen__)
EXPORT_MEMSET = ExportedFunction("memset", __memset__)
EXPORT_FREE = ExportedFunction("free", __free__)
EXPORT_MALLOC = ExportedFunction("malloc", __malloc__)
EXPORT_MEMCLR = ExportedFunction("memclr", __memclr__)

# DEFAULT_EXPORTED = (
#     ExportedFunction("memset", __memset__),
#     ,
# )


class ExportedManager:
    def __init__(self):
        self.exported_map = dict()

    def export(self, address: int, export: ExportedFunction):
        self.exported_map[address] = export

    def iter(self):
        for address, func in self.exported_map.items():
            yield address, func
