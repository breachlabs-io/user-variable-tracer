from .entrypoint import EntrypointAnalyzer
from .relocation import RelocationAnalyzer


def run_analyzers(application):
    RelocationAnalyzer(application).analyze()
    EntrypointAnalyzer(application).analyze()
