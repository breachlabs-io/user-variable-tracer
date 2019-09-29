class AddressRange:
    def __init__(self, start, end):
        self._start = start
        self._end = end

    def in_range(self, address):
        return address >= self._start and address <= self._end
