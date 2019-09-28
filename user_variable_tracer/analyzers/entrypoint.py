from .base import BaseAnalyzer


class EntrypointAnalyzer(BaseAnalyzer):

    def analyze(self):
        text_section = self.application.get_section_for_name('.text')
        if not text_section:
            return

        for i, instruction in enumerate(text_section.instructions):
            if (instruction.has_relocation and
                    instruction.relocation.is_libc_start_main):
                if i == 0:
                    # Something went wrong. We should have an instruction
                    # before this one that passes the offset to main().
                    break

                prev_instruction = text_section.instructions[i-1]
                if prev_instruction.has_instruction_offset:
                    self.application.entrypoint = prev_instruction\
                        .get_instruction_offset()
                break
