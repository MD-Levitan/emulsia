from unicorn import *
from capstone import *
from capstone.arm import *

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