import os

class Stream:
    """A class reprensenting a stream (stdin or stdout)
    """
    def __init__(self, fd: int, writeable: bool =  False):
        self._fd = fd
        self._writeable = writeable
        
        mode = 'wb' if writeable else 'rb'

        try:
            self._file = open(f'/proc/self/fd/{fd}', mode)
            os.set_blocking(self._file.fileno(), False)
        except FileNotFoundError:
            self._file = None

    def read(self, n: int) -> bytes:
        """Reads `n` bytes from stream

        :param n: The number of bytes to read.
        :type n: int
        :returns: bytes -- the read bytes.
        :raises: ValueError - if `n` is negative 
        """
        if n < 0:
            raise ValueError('Size must be a positive integer')

        return self._file.read(n)

    def write(self, data: bytes) -> None:
        """Write `data` to stream

        :param data: The bytes to write
        :type data: bytes
        :returns: None
        :raises: IOError - if stream is not writeable
        """
        if not self._writeable:
            raise IOError('Stream is not writeable (stdout|stderr)')

        print(self._file.write(data))