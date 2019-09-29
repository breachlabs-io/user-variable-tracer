class Relocation:
    def __init__(self, cs_relocation, cs_symbol, section):
        self._name = cs_symbol.name
        self._address = cs_relocation["r_offset"]
        self._section = section

    def __str__(self):
        return self._name

    @property
    def name(self):
        return self._name

    @property
    def address(self):
        return self._address

    @property
    def section(self):
        return self._section

    @property
    def is_libc_start_main(self):
        return self._name == "__libc_start_main"
