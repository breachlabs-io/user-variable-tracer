from .base import BaseAnalyzer


class RelocationAnalyzer(BaseAnalyzer):
    def analyze(self):
        self._analyze_section(self.application.get_section_for_name(".plt"))
        self._analyze_section(self.application.get_section_for_name(".text"))

    def _analyze_section(self, section):
        if not section:
            return
        for instruction in section.instructions:
            if instruction.has_instruction_offset:
                relocation = self.application.get_relocation_for_address(
                    instruction.get_instruction_offset()
                )
                if relocation:
                    instruction.relocation = relocation
                else:
                    offset_instruction = self.application.get_instruction_for_address(
                        instruction.get_instruction_offset()
                    )
                    if (
                        offset_instruction
                        and offset_instruction.section.name == ".plt"
                    ):
                        instruction.relocation = offset_instruction.relocation
