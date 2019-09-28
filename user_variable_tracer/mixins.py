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
        instructions = []
        for instruction in cs.disasm(section.data, section.address):
            instructions.append(Instruction(instruction, section))
        return instructions

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
        sections = []
        for section in elf_file.iter_sections():
            sections.append(Section(section))
        return sections

    @staticmethod
    def get_relocations(elf_file, sections):
        relocations = []
        for section in sections:
            if section.is_relocation_section:
                symbol_table = elf_file.get_section(section.link)
                for relocation in section.iter_cs_relocations():
                    symbol = symbol_table.get_symbol(relocation['r_info_sym'])
                    relocations.append(Relocation(
                        relocation,
                        symbol,
                        section
                    ))
        return relocations
