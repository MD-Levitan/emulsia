from unicorn import *
from capstone import *

def near(a1, a2):
    if abs(a1 - a2) < 0x4:
        return True
    else:
        return False

class CallViewer:
    CALL_TYPE = 1
    JUMP_TYPE = 2

    def __init__(self):

        # List: (key - address to call, value - pointer of calling)
        self.call_map = list()

        self.prev_address = None
        self.prev_storage = None
   
    @staticmethod
    def create_storage(address: int, pointer: int, instruction):
        _type = CallViewer.CALL_TYPE if instruction.group(CS_GRP_CALL) else 0 
        _type |= CallViewer.JUMP_TYPE if instruction.group(CS_GRP_JUMP) else 0 

        try:
            address = int(address[3:], 16)
        except Exception as _e:
            address = -1

        if _type != 0:
            return [address, pointer, _type]
        else:
            return None

    def add_call(self, address: int, pointer: int, instruction):
        if self.prev_storage is not None:
            if self.prev_storage[0] == -1:
                self.prev_storage[0] = pointer
                self.call_map.append(self.prev_storage)
            if near(self.prev_storage[0], pointer):
                self.call_map.append(self.prev_storage)

        self.prev_storage = CallViewer.create_storage(address, pointer, instruction)


    def print_tree(self):
        for address, pointer, _type in self.call_map:
            print("{:8x} at {:8x} {}".format(address, pointer, "JUMP" if _type == self.JUMP_TYPE else "CALL"))
