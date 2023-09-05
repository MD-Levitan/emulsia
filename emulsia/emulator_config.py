from unicorn import *
from capstone import *

from unicorn.arm_const import *
from unicorn.arm64_const import *

from typing import Callable, Any

from emulsia.emulator_hooker import EmulatorHooker
from emulsia.utils import logger

# /*
#   Callback function for tracing code (UC_HOOK_CODE & UC_HOOK_BLOCK)
#   @address: address where the code is being executed
#   @size: size of machine instruction(s) being executed, or 0 when size is unknown
#   @user_data: user data passed to tracing APIs.
# */
# typedef void (*uc_cb_hookcode_t)(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);

# /*
#   Callback function for tracing interrupts (for uc_hook_intr())
#   @intno: interrupt number
#   @user_data: user data passed to tracing APIs.
# */
# typedef void (*uc_cb_hookintr_t)(uc_engine *uc, uint32_t intno, void *user_data);

# /*
#   Callback function for tracing invalid instructions
#   @user_data: user data passed to tracing APIs.
#   @return: return true to continue, or false to stop program (due to invalid instruction).
# */
# typedef bool (*uc_cb_hookinsn_invalid_t)(uc_engine *uc, void *user_data);

# /*
#   Callback function for tracing IN instruction of X86
#   @port: port number
#   @size: data size (1/2/4) to be read from this port
#   @user_data: user data passed to tracing APIs.
# */
# typedef uint32_t (*uc_cb_insn_in_t)(uc_engine *uc, uint32_t port, int size, void *user_data);

# /*
#   Callback function for OUT instruction of X86
#   @port: port number
#   @size: data size (1/2/4) to be written to this port
#   @value: data value to be written to this port
# */
# typedef void (*uc_cb_insn_out_t)(uc_engine *uc, uint32_t port, int size, uint32_t value, void *user_data);
# *
#   Callback function for hooking memory (READ, WRITE & FETCH)
#   @type: this memory is being READ, or WRITE
#   @address: address where the code is being executed
#   @size: size of data being read or written
#   @value: value of data being written to memory, or irrelevant if type = READ.
#   @user_data: user data passed to tracing APIs
# */
# typedef void (*uc_cb_hookmem_t)(uc_engine *uc, uc_mem_type type,
#         uint64_t address, int size, int64_t value, void *user_data);

# /*
#   Callback function for handling invalid memory access events (UNMAPPED and
#     PROT events)
#   @type: this memory is being READ, or WRITE
#   @address: address where the code is being executed
#   @size: size of data being read or written
#   @value: value of data being written to memory, or irrelevant if type = READ.
#   @user_data: user data passed to tracing APIs
#   @return: return true to continue, or false to stop program (due to invalid memory).
#            NOTE: returning true to continue execution will only work if the accessed
#            memory is made accessible with the correct permissions during the hook.

#            In the event of a UC_MEM_READ_UNMAPPED or UC_MEM_WRITE_UNMAPPED callback,
#            the memory should be uc_mem_map()-ed with the correct permissions, and the
#            instruction will then read or write to the address as it was supposed to.

#            In the event of a UC_MEM_FETCH_UNMAPPED callback, the memory can be mapped
#            in as executable, in which case execution will resume from the fetched address.
#            The instruction pointer may be written to in order to change where execution resumes,
#            but the fetch must succeed if execution is to resume.
# */
# typedef bool (*uc_cb_eventmem_t)(uc_engine *uc, uc_mem_type type,
#         uint64_t address, int size, int64_t value, void *user_data);

uc_cb_hookcode_t = Callable[[Uc, int, int, Any], None]
uc_cb_hookintr_t = Callable[[Uc, int, Any], None]
uc_cb_hookinsn_invalid_t = Callable[[Uc, int, Any], None]
uc_cb_hookmem_t = Callable[[Uc, int, int, int, int, Any], None]

em_cb_hookcode_t = Callable[[EmulatorHooker, int, int, Any], None]
em_cb_hookintr_t = Callable[[EmulatorHooker, int, Any], None]
em_cb_hookinsn_invalid_t = Callable[[EmulatorHooker, int, Any], None]
em_cb_hookmem_t = Callable[[EmulatorHooker, int, int, int, int, Any], None]


class EmulatorConfig:
    def __init__(
        self,
        hook_code: em_cb_hookcode_t,
        hook_inter: em_cb_hookintr_t,
        hook_mem: em_cb_hookmem_t,
        hook_mem_invalid: em_cb_hookmem_t,
        hook_fetch: em_cb_hookmem_t,
    ):
        self._hook_code = hook_code
        self._hook_inter = hook_inter
        self._hook_mem = hook_mem
        self._hook_mem_invalid = hook_mem_invalid
        self._hook_fetch = hook_fetch

    def __str__(self):
        return (
            f"Hooks configuaration: code - {self._hook_code},"
            f" interupt - {self._hook_inter}, memory - {self._hook_mem},"
            f" invalid memory - {self._hook_mem_invalid}, fetch - {self._hook_fetch}"
        )

    @property
    def hook_code(self):
        return self._hook_code

    @property
    def hook_inter(self):
        return self._hook_inter

    @property
    def hook_mem_invalid(self):
        return self._hook_mem_invalid

    @property
    def hook_mem(self):
        return self._hook_mem

    @property
    def hook_fetch(self):
        return self._hook_fetch


def __hook_code__(emhook, address, size, user_data, instruction):
    uc = emhook.uc

    logger.info("Tracing instruction at 0x%x, instruction size = 0x%x", address, size)
    # logger.info(
    #     "Registers: r0 - {}, r1 - {}, r2 - {}, r3 - {}, r4 - {}, r5 - {}, r6 - {}, r7 - {}, r8 - {} sb - {}, pc - {}, lr - {}, sp - {}".format(
    #         hex(uc.reg_read(UC_ARM_REG_R0)),
    #         hex(uc.reg_read(UC_ARM_REG_R1)),
    #         hex(uc.reg_read(UC_ARM_REG_R2)),
    #         hex(uc.reg_read(UC_ARM_REG_R3)),
    #         hex(uc.reg_read(UC_ARM_REG_R4)),
    #         hex(uc.reg_read(UC_ARM_REG_R5)),
    #         hex(uc.reg_read(UC_ARM_REG_R6)),
    #         hex(uc.reg_read(UC_ARM_REG_R7)),
    #         hex(uc.reg_read(UC_ARM_REG_R8)),
    #         hex(uc.reg_read(UC_ARM_REG_SB)),
    #         hex(uc.reg_read(UC_ARM_REG_PC)),
    #         hex(uc.reg_read(UC_ARM_REG_LR)),
    #         hex(uc.reg_read(UC_ARM_REG_SP)),
    #     )
    # )

    logger.info(
        "Registers: r0 - {}, r1 - {}, r2 - {}, r3 - {}, r4 - {}, r5 - {}, r6 - {}, r7 - {}, r8 - {}, r9 - {}, r10 - {}, r11 - {}, r12 - {}, r13 - {}, r14 - {}, r15 - {}, r16 - {}, r17 - {}, r18 - {}, r19 - {}, r20 - {}, r21 - {}, r22 - {}, r23 - {}, r24 - {}, r25 - {}, r26 - {}, r27 - {}, r28 - {}, r29 - {}, r30 - {}, sb - {}, pc - {}, lr - {}, sp - {}".format(
            hex(uc.reg_read(UC_ARM64_REG_X0)),
            hex(uc.reg_read(UC_ARM64_REG_X1)),
            hex(uc.reg_read(UC_ARM64_REG_X2)),
            hex(uc.reg_read(UC_ARM64_REG_X3)),
            hex(uc.reg_read(UC_ARM64_REG_X4)),
            hex(uc.reg_read(UC_ARM64_REG_X5)),
            hex(uc.reg_read(UC_ARM64_REG_X6)),
            hex(uc.reg_read(UC_ARM64_REG_X7)),
            hex(uc.reg_read(UC_ARM64_REG_X8)),
            hex(uc.reg_read(UC_ARM64_REG_X9)),
            hex(uc.reg_read(UC_ARM64_REG_X10)),
            hex(uc.reg_read(UC_ARM64_REG_X11)),
            hex(uc.reg_read(UC_ARM64_REG_X12)),
            hex(uc.reg_read(UC_ARM64_REG_X13)),
            hex(uc.reg_read(UC_ARM64_REG_X14)),
            hex(uc.reg_read(UC_ARM64_REG_X15)),
            hex(uc.reg_read(UC_ARM64_REG_X16)),
            hex(uc.reg_read(UC_ARM64_REG_X17)),
            hex(uc.reg_read(UC_ARM64_REG_X18)),
            hex(uc.reg_read(UC_ARM64_REG_X18)),
            hex(uc.reg_read(UC_ARM64_REG_X19)),
            hex(uc.reg_read(UC_ARM64_REG_X20)),
            hex(uc.reg_read(UC_ARM64_REG_X21)),
            hex(uc.reg_read(UC_ARM64_REG_X22)),
            hex(uc.reg_read(UC_ARM64_REG_X23)),
            hex(uc.reg_read(UC_ARM64_REG_X24)),
            hex(uc.reg_read(UC_ARM64_REG_X25)),
            hex(uc.reg_read(UC_ARM64_REG_X26)),
            hex(uc.reg_read(UC_ARM64_REG_X27)),
            hex(uc.reg_read(UC_ARM64_REG_X28)),
            hex(uc.reg_read(UC_ARM64_REG_X29)),
            hex(uc.reg_read(UC_ARM64_REG_X30)),
            hex(uc.reg_read(UC_ARM64_REG_NZCV)),
            hex(uc.reg_read(UC_ARM64_REG_PC)),
            hex(uc.reg_read(UC_ARM64_REG_LR)),
            hex(uc.reg_read(UC_ARM64_REG_SP)),
        )
    )

    logger.info(
        "0x%x:\t%s\t%s"
        % (instruction.address, instruction.mnemonic, instruction.op_str)
    )


def __hook_intr__(emhook, intno, user_data):
    uc = emhook.uc

    if intno != 0x80:
        logger.info("got interrupt {:8x}".format(intno))


def __hook_mem_invalid__(emhook, access, address, size, value, user_data):
    uc = emhook.uc

    if access == UC_MEM_WRITE_UNMAPPED:
        logger.info(
            ">>> Missing memory is being WRITE at 0x%x, data size = %u, data value = 0x%x"
            % (address, size, value)
        )
        return False
    else:
        logger.info(
            ">>> Missing memory is being READ at 0x%x, data size = %u, data value = 0x%x"
            % (address, size, value)
        )
        return False


def __hook_mem__(emhook, access, address, size, value, user_data):
    uc = emhook.uc
    logger.debug("accees to %x", address)


def __hook_fetch__(emhook, access, address, size, value, user_data):
    uc = emhook.uc

    logger.info("UC_MEM_FETCH of 0x%x, data size = %u" % (address, size))


def __silent_hook__(emhook, *args):
    pass


VerboseEmulatorConfig = EmulatorConfig(
    __hook_code__, __hook_intr__, __hook_mem__, __hook_mem_invalid__, __hook_fetch__
)
SilentEmulatorConfig = EmulatorConfig(
    __silent_hook__, __silent_hook__, __silent_hook__, __silent_hook__, __silent_hook__
)
