from unicorn import *
from capstone import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from capstone.arm_const import *

from typing import Optional, List

import logging

logger = logging.getLogger(__name__)


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


def archs(
    uc: Optional[int] = None, cs: Optional[int] = None
) -> (Optional[int], Optional[int]):
    ucs = (
        UC_ARCH_ARM,
        UC_ARCH_ARM64,
        UC_ARCH_MIPS,
        UC_ARCH_X86,
        UC_ARCH_PPC,
        UC_ARCH_SPARC,
        UC_ARCH_M68K,
        None,
        None,
        UC_ARCH_MAX,
    )
    css = (
        CS_ARCH_ARM,
        CS_ARCH_ARM64,
        CS_ARCH_MIPS,
        CS_ARCH_X86,
        CS_ARCH_PPC,
        CS_ARCH_SPARC,
        None,
        CS_ARCH_SYSZ,
        CS_ARCH_XCORE,
        None,
    )  # CS_ARCH_MAX

    if uc is not None:
        return uc, css[ucs.index(uc)]
    if cs is not None:
        return cs, ucs[css.index(cs)]
    return None, None


def modes(
    uc: Optional[int] = None, cs: Optional[int] = None
) -> (Optional[int], Optional[int]):
    ucs = (UC_MODE_ARM, UC_MODE_THUMB, UC_MODE_MCLASS, UC_MODE_V8)
    css = (CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_MCLASS, CS_MODE_V8)

    if uc is not None:
        return uc, css[ucs.index(uc)]
    if cs is not None:
        return cs, ucs[css.index(cs)]
    return None, None


def get_general_regs(uc: Uc) -> List[int]:
    if uc._arch == UC_ARCH_ARM:
        return list(range(UC_ARM_REG_R0, UC_ARM_REG_R12))
    elif uc._arch == UC_ARCH_ARM64:
        return list(range(UC_ARM64_REG_X0, UC_ARM64_REG_X28))

    raise Exception


def get_special_regs(uc: Uc) -> (int, int, int):
    """PC, SP, LR"""
    if uc._arch == UC_ARCH_ARM:
        return (UC_ARM_REG_PC, ARM_REG_SP, ARM_REG_LR)
    elif uc._arch == UC_ARCH_ARM64:
        return (UC_ARM64_REG_PC, UC_ARM64_REG_SP, UC_ARM64_REG_LR)

    raise Exception
