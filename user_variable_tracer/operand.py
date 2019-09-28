from enum import Enum


class OperandType(Enum):
    Register = 1
    Immediate = 2
    Memory = 3


class Operand:

    def __init__(self, cs_operand, reg_name_fn):
        self._type = OperandType(cs_operand.type)
        self._cs_operand = cs_operand
        self._reg_name_fn = reg_name_fn

    @property
    def type(self):
        return self._type

    @property
    def register(self):
        if self._type == OperandType.Register:
            return self._reg_name_fn(self._cs_operand.reg)
        elif self._type == OperandType.Memory:
            return self._reg_name_fn(self._cs_operand.mem.base)
        return None

    @property
    def has_immediate_instruction_offset(self):
        return self._type == OperandType.Immediate

    def get_immediate_instruction_offset(self):
        if not self.has_immediate_instruction_offset:
            return 0
        return self._cs_operand.imm

    @property
    def has_base_instruction_offset(self):
        if not self._type == OperandType.Memory:
            return False
        return (self.register == 'rip' or
                self.register == 'eip' or
                self.register == 'ip')

    def get_base_instruction_offset(self):
        if not self.has_base_instruction_offset:
            return 0
        return self._cs_operand.mem.disp
