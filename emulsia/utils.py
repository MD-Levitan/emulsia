from unicorn import *
from capstone import *
from capstone.arm import *

from typing import Optional


def read_string(uc: Uc, address: int):
    string = b""
    i = 0

    while True:
        symb = uc.mem_read(address + i, 0x1)
        if symb == 0x00:
            break
        string += symb
        i += 1

    return string


def get_call(instruction):
    operand = instruction.operands[0]

    # if operand.type == ARM_OP_REG:
    #     print("\t\toperands[%u].type: REG = %s" % (c, instruction.reg_name(i.reg)))

    if operand.type in (ARM_OP_IMM, ARM_OP_PIMM, ARM_OP_CIMM):
        return operand.imm
    return -1


def dict_add(map_: dict, key, values):
    if key not in map_:
        map_[key] = [values]
    else:
        map_[key].append(values)


def archs(uc: Optional[int]=None, cs: Optional[int]=None) -> (Optional[int], Optional[int]):
    ucs = (UC_ARCH_ARM,
           UC_ARCH_ARM64,
           UC_ARCH_MIPS,
           UC_ARCH_X86,
           UC_ARCH_PPC,
           UC_ARCH_SPARC,
           UC_ARCH_M68K,
           None,
           None,
           UC_ARCH_MAX)
    css = (CS_ARCH_ARM,
           CS_ARCH_ARM64,
           CS_ARCH_MIPS,
           CS_ARCH_X86,
           CS_ARCH_PPC,
           CS_ARCH_SPARC,
           None,
           CS_ARCH_SYSZ,
           CS_ARCH_XCORE,
           None) #CS_ARCH_MAX

    if uc is not None:
        return uc, css[ucs.index(uc)]
    if cs is not None:
        return cs, ucs[css.index(cs)]
    return None, None

def modes(uc: Optional[int]=None, cs: Optional[int]=None) -> (Optional[int], Optional[int]):
    ucs = (UC_MODE_ARM, UC_MODE_THUMB, UC_MODE_MCLASS, UC_MODE_V8)
    css = (CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_MCLASS, CS_MODE_V8)

    if uc is not None:
        return uc, css[ucs.index(uc)]
    if cs is not None:
        return cs, ucs[css.index(cs)]
    return None, None