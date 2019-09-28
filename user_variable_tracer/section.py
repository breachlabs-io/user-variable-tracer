from elftools.elf.relocation import RelocationSection


class Section:

    def __init__(self, cs_section):
        self._name = cs_section.name
        self._address = cs_section['sh_addr']
        self._link = cs_section['sh_link']
        self._data = cs_section.data()
        self._instructions = []
        self._cs_section = cs_section

    def __str__(self):
        ret = f"Section: {self._name}\n"
        for instruction in self._instructions:
            ret += f"{instruction}\n"
        return ret

    @property
    def name(self):
        return self._name

    @property
    def address(self):
        return self._address

    @property
    def link(self):
        return self._link

    @property
    def data(self):
        return self._data

    @property
    def instructions(self):
        return self._instructions

    @instructions.setter
    def instructions(self, values):
        self._instructions = values

    @property
    def is_relocation_section(self):
        return isinstance(self._cs_section, RelocationSection)

    def iter_cs_relocations(self):
        return self._cs_section.iter_relocations()
