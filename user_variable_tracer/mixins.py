from capstone import *
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

from .instruction import Instruction
from .section import Section
from .relocation import Relocation


class CsMixin:

    @classmethod
    def get_instructions(cls, arch, section):
        cs = cls._get_cs(arch)
        return [
            Instruction(instruction, section)
            for instruction in cs.disasm(section.data, section.address)
        ]

    @staticmethod
    def _get_cs(arch):
        cs = None
        if arch == 'x64':
            cs = Cs(CS_ARCH_X86, CS_MODE_64)
        if cs:
            cs.detail = True
        return cs


class ElfMixin:

    @staticmethod
    def get_elf_file(open_file):
        return ELFFile(open_file)

    @staticmethod
    def get_sections(elf_file):
        return [
            Section(section)
            for section in elf_file.iter_sections()
        ]

    @staticmethod
    def get_relocations(elf_file, sections):
        relocations = []
        for section in sections:
            if section.is_relocation_section:
                symbol_table = elf_file.get_section(section.link)
                relocations.extend([
                    Relocation(
                        relocation,
                        symbol_table.get_symbol(relocation['r_info_sym']),
                        section
                    )
                    for relocation in section.iter_cs_relocations()
                ])
        return relocations
