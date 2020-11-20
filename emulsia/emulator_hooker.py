from unicorn import *
from capstone import *

from unicorn.arm_const import *

class EmulatorHooker:
    def __init__(self, uc: Uc):
        self.uc = uc