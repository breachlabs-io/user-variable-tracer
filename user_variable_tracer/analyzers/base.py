from abc import ABC, abstractmethod


class BaseAnalyzer(ABC):

    def __init__(self, application):
        self.application = application

    @abstractmethod
    def analyze(self):
        pass
