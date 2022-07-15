stopped_reasons = {
    1: 'SIGHUP',
    2: 'SIGINT',
    3: 'SIQQUIT',
    4: 'SIGILL',
    5: 'SIGTRAP',
    6: 'SIGABRT',
    7: 'SIGBUS',
    8: 'SIGFPE',
    9: 'SIGKILL',
    10: 'SIGUSR1',
    11: 'SIGSEGV',
    12: 'SIGUSR2',
    13: 'SIGPIPE',
    14: 'SIGALRM',
    15: 'SIGTERM',
    16: 'SIGSTKFLT',
    17: 'SIGCHLD',
    18: 'SIGCONT',
    19: 'SIGSTOP',
    20: 'SIGTSTP',
    21: 'SIGTTIN',
    22: 'SIGTTOU',
    23: 'SIGURG',
    24: 'SIGXCPU',
    25: 'SIGXFSZ',
    26: 'SIGVTALRM',
    27: 'SIGPROF',
    28: 'SIGWINCH',
    29: 'SIGIO',
    30: 'SIGPWR',
    31: 'SIGSYS'
}


class ProcessSignaledException(Exception):
    """Exception raised when process stopped for a certain reason
    """
    def __init__(self, n: str):
        self._n = int(n) # signal number
        self.message = f'Process stopped with reason : {stopped_reasons[self.n]} ({self.n})'

        super().__init__(self.message)

    @property
    def n(self) -> int:
        """Returns the signal number

        :type: int
        """
        return self._n

class ProcessExitedException(Exception):
    """Exception raised when process exited (exit or _exit)
    """
    def __init__(self, n: str):
        self._n = int(n)
        self.message = f'Process exited with status code: {n}'

        super().__init__(self.message)

    @property
    def n(self) -> int:
        """Returns the exit code

        :type: int
        """
        return self._n