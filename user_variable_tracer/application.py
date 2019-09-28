from .analyzers import run_analyzers
from .mixins import *


class Application(CsMixin, ElfMixin):

    def __init__(self, application_file):
        self._file = open(application_file, 'rb')
        self._elf_file = self.get_elf_file(self._file)
        self._sections = self.get_sections(self._elf_file)
        self._relocations = self.get_relocations(self._elf_file, self._sections)
        self._set_section_instructions()
        self._entrypoint = None

        # run_analyzers(self)

    def __del__(self):
        if self._file:
            self._file.close()

    def __str__(self):
        ret = ""
        for section in self._sections:
            ret += f"{section}\n"
        return ret

    def _set_section_instructions(self):
        for section in self._sections:
            section.instructions = self.get_instructions(
                self._elf_file.get_machine_arch(),
                section,
            )

    @property
    def sections(self):
        return self._sections

    @property
    def relocations(self):
        return self._relocations

    @property
    def entrypoint(self):
        return self._entrypoint

    @entrypoint.setter
    def entrypoint(self, value):
        self._entrypoint = value

    def get_instruction_for_address(self, addr):
        for section in self._sections:
            for instruction in section.instructions:
                if instruction.address == addr:
                    return instruction
        return None

    def get_section_for_name(self, name):
        for section in self._sections:
            if section.name == name:
                return section
        return None

    def get_section_for_address(self, addr):
        for section in self._sections:
            if section.address == addr:
                return section
        return None

    def get_relocation_for_name(self, name):
        for relocation in self._relocations:
            if relocation.name == name:
                return relocation
        return None

    def get_relocation_for_address(self, addr):
        for relocation in self._relocations:
            if relocation.address == addr:
                return relocation
        return None
