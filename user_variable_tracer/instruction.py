from .operand import Operand


class Instruction:
    def __init__(self, cs_instruction, section):
        self._address = cs_instruction.address
        self._size = cs_instruction.size
        self._mnemonic = cs_instruction.mnemonic
        self._op_str = cs_instruction.op_str
        self._operands = [
            Operand(operand, cs_instruction.reg_name)
            for operand in cs_instruction.operands
        ]
        self._section = section
        self._relocation = None
        self._xrefs = []

    def __str__(self):
        ret = f"0x{self._address:x}\t{self._mnemonic}\t"
        if self.has_relocation and self._relocation.name:
            if "call" in self._mnemonic:
                ret += f"{self._relocation.name}"
            else:
                ret += f"{self._op_str}; {self._relocation.name}"
        else:
            ret += f"{self._op_str}"
        return ret

    @property
    def address(self):
        return self._address

    @property
    def size(self):
        return self._size

    @property
    def mnemonic(self):
        return self._mnemonic

    @property
    def op_str(self):
        return self._op_str

    @property
    def operands(self):
        return self._operands

    @property
    def section(self):
        return self._section

    @property
    def has_instruction_offset(self):
        for operand in self._operands:
            if (
                operand.has_base_instruction_offset
                or operand.has_immediate_instruction_offset
            ):
                return True
        return False

    def get_instruction_offset(self):
        for operand in self._operands:
            if operand.has_base_instruction_offset:
                return (
                    self._address
                    + self._size
                    + operand.get_base_instruction_offset()
                )
            elif (
                operand.has_immediate_instruction_offset
                and "call" in self._mnemonic
            ):
                return operand.get_immediate_instruction_offset()
        return 0

    @property
    def has_relocation(self):
        return self._relocation is not None

    @property
    def relocation(self):
        return self._relocation

    @relocation.setter
    def relocation(self, value):
        self._relocation = value

    @property
    def xrefs(self):
        return self._xrefs

    def add_xref(self, xref):
        self._xrefs.append(xref)
