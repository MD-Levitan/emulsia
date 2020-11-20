from unicorn import *
from capstone import *

from unicorn.arm_const import *
from .memory_viewer import MemoryViewer

class EmulatorHooker:
    def __init__(self, uc: Uc, mem: MemoryViewer):
        self.uc = uc
        self.mem = mem