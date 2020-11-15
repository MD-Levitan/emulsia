from unicorn import *
from capstone import *
from capstone.arm import *

from .utils import *

class CallViewer:
    CALL_TYPE = 1
    JUMP_TYPE = 2

    def __init__(self):

        # List: (key - address to call, value - pointer of calling)
        self.call_map = list()

        self.prev_address = None
        self.prev_storage = None
   
    @staticmethod
    def create_storage(instruction):
        """! Create temporary storage for data. """
        _type = CallViewer.CALL_TYPE if instruction.group(CS_GRP_CALL) else 0 
        _type |= CallViewer.JUMP_TYPE if instruction.group(CS_GRP_JUMP) else 0 

        if _type == 0:
            return None

        if len(instruction.operands) != 0:
            print("Problem")

        pointer = instruction.address
        address = get_call(instruction)

        return [address, pointer, _type]

    def add_call(self, instruction):
        pointer = instruction.address
        
        if self.prev_storage is not None:
            if self.prev_storage[0] == -1:
                self.prev_storage[0] = pointer
                self.call_map.append(self.prev_storage)
            
            if self.prev_storage[0] == pointer:
                self.call_map.append(self.prev_storage)

        self.prev_storage = CallViewer.create_storage(instruction)


    def print_tree(self):
        for address, pointer, _type in self.call_map:
            print("{:8x} at {:8x} {}".format(address, pointer, "JUMP" if _type == self.JUMP_TYPE else "CALL"))
