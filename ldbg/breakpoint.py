from ldbg import internals

class Breakpoint:
    """A class representing a breakpoint for a given process
    """
    def __init__(self, addr: int, pid: int, enabled: bool=True):
        self._addr = addr
        self._pid = pid

        self._enabled = enabled

        if enabled:
            self._enable()

    def disable(self):
        """Disables the breakpoint, no-op if breakpoint is already disabled
        """
        if self.enabled:
            internals.poke_text(self._pid, self.addr, self._old_data)
            self._enabled = False

    def enable(self):
        """Enables the breakpoint, no-op if breakpoint is already enabled
        """
        if self.enabled:
            return

        self._enable()

    def _enable(self):
        self._old_data = internals.peek_text(self._pid, self.addr) & 0xffffffffffffffff
        
        data = self._old_data
        data &= 0xffffffffffffff00
        data |= 0xcc

        internals.poke_text(self._pid, self.addr, data)
        self._enabled = True

    @property
    def addr(self) -> int:
        """The address of the breakpoint

        :type: int
        """
        return self._addr

    @property
    def enabled(self) -> bool:
        """Weither or not the breakpoint is enabled
        
        :type: bool
        """
        return self._enabled