# from unicorn import *
# from capstone import *

# from unicorn.arm_const import *

# from .utils import read_string

# class SysCallHook:
#     ###!

#     ###
#     def __init__(self, id, hook, annotation):
#         self.id = id
#         self._hook = hook

    

# OpenatCall = SysCallHook(0x142, hook=)


# def openat_annotation(uc: UC):
#     """! Annotation of system call openat.
#     """
#     dirfd = uc.reg_read(UC_ARM_REG_R0)
#     filename_ptr = uc.reg_read(UC_ARM_REG_R1)
#     filename = read_string(uc, filename_ptr)
#     flags = uc.reg_read(UC_ARM_REG_R2)
#     mode = uc.reg_read(UC_ARM_REG_R3)

#     print("System Call: openat(int dirfd, const char *filename, int flags, umode_t mode) = (0x{:x}, {:s}, 0x{:x}, 0x{:x})".format(dirfd, filename, flags, mode))


# def openat_hook(uc: Uc, annotation: None):
#     if annotation is not None:
#         annotation(uc)

#     dirfd = uc.reg_read(UC_ARM_REG_R0)
#     filename_ptr = uc.reg_read(UC_ARM_REG_R1)
#     filename = read_string(uc, filename_ptr)
#     flags = uc.reg_read(UC_ARM_REG_R2)
#     mode = uc.reg_read(UC_ARM_REG_R3)

#     file = open(filename_ptr, )