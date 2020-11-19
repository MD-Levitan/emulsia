from unicorn import *
from capstone import *
from capstone.arm import *

from .utils import *


def valid_call(instruction) -> bool:
    if instruction.mnemonic not in ("push", "stmdb"):
        return False
    operands = instruction.operands
    for operand in operands:
        if operand.type == ARM_OP_REG and instruction.reg_name(operand.reg) == "lr":
            return True

    return False


class CallStorage:
    CALL_TYPE = 1
    JUMP_TYPE = 2
    ANY_TYPE = 3

    def __init__(self, address: int, pointer: int, _type: int, level: int = 0):
        self.address = address
        self.pointer = pointer
        self.type = _type
        self.level = level

    @classmethod
    def create_storage(cls, instruction):
        """! Create storage from instruction. """
        # Using capstone let's try to identify GRPOUP.
        # But it doesn't work good, so after that will check better group.
        _type = CallStorage.CALL_TYPE if instruction.group(CS_GRP_CALL) else 0
        _type = CallStorage.JUMP_TYPE if instruction.group(CS_GRP_JUMP) else 0

        if _type == 0:
            return None

        pointer = instruction.address
        address = get_call(instruction)

        return cls(address=address, pointer=pointer, _type=_type)

    def check_call(self, instruction) -> bool:
        """! Check using new instruction after storage if storage is valid call. """
        pointer = instruction.address
        
        # By default type is jump.
        # So check all instruction until new jump fro looking
        # "push lr" - that should means that's call.  
        if self.type != CallStorage.CALL_TYPE:
            if valid_call(instruction):
                self.type = CallStorage.CALL_TYPE

        # If storage has invalid address
        if self.address == -1:
            self.address = pointer
            return True
        elif self.address == pointer:
            return True
        else:
            return False

    @staticmethod
    def type_from_str(type_str: str):
        if type_str == 'c':
            return CallStorage.CALL_TYPE
        if type_str == 'j':
            return CallStorage.JUMP_TYPE
        return CallStorage.ANY_TYPE


class CallViewer:
    def __init__(self):
        """! Manager that stores all calls and jumps instructions. """

        # List: (key - address to call, value - pointer of calling)
        self.call_map = list()
        self.call_stack = list()

        self.prev_storage = None
        self.current_level = 0

    def add_call(self, instruction):
        """! TODO: Needs upgrade. """
        pointer = instruction.address
        
        if len(self.call_stack) != 0:
            ret_addr = self.call_stack[-1]
            if ret_addr < pointer < ret_addr + 8:
                self.current_level -= 1
                self.call_stack.pop()

        if self.prev_storage is not None and self.prev_storage.check_call(instruction):
            self.call_map.append(self.prev_storage)
            if self.prev_storage.type == CallStorage.CALL_TYPE:
                self.current_level += 1
                self.prev_storage.level = self.current_level
                self.call_stack.append(self.prev_storage.pointer)

        storage = CallStorage.create_storage(instruction)
        if storage is not None:
            self.prev_storage = storage 

    def print_tree(self, _type: str = "a"):
        """!Print call tree.
        
        @param type     type of calls - 'a' - all, 'j' - JUMP, 'c' - CALL.
        """
        print()
        print("===        Jump/Call Tree        ===")
        print("Address:   Pointer:   Type:")
        _type = CallStorage.type_from_str(_type)
        for storage in self.call_map:
            if _type != CallStorage.ANY_TYPE and _type != storage.type:
                continue
            print("{:8x} {:8x} {}".format(
                storage.address,
                storage.pointer,
                "JUMP" if storage.type == CallStorage.JUMP_TYPE else "CALL"))

    def print_call_tree(self):
        print()
        print("===         Call Tree         ===")
        print("Address:   Pointer: Level:")
        for storage in self.call_map:
            if storage.type != CallStorage.CALL_TYPE:
                continue
            print("{:8x} {:8x} {:8x}".format(storage.address, storage.pointer, storage.level))