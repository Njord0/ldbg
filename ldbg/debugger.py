from ldbg import internals
from ldbg.breakpoint import Breakpoint
from ldbg.stream import Stream
from ldbg.exceptions import ProcessExitedException, ProcessSignaledException

from ldbg.internals import StoppedException, ExitedException

from abc import ABC, abstractmethod
from typing import List, Dict, Union
from functools import wraps

import lief
import os

def handle_bp(method):
    @wraps(method)
    def wrapper(self):
        ip = self.get_instruction_pointer() # eip or rip

        bp = self._get_breakpoint_at(ip) 
        if bp:
            bp.disable()
        
        ret = method(self)

        if bp:
            bp.enable()

        ip = self.get_instruction_pointer()
        bp = self._get_breakpoint_at(ip - 1)

        if bp:
            self._set_instruction_pointer(ip - 1) # because interruption instruction is one byte long

        return ret
    
    return wrapper

def handle_exception(method):
    @wraps(method)
    def wrapper(self, *args):
        if self._exception:
            raise self._exception

        try:
            ret = method(self, *args)
            return ret
        except StoppedException as e:
            self._exception = ProcessSignaledException(str(e))
            raise self._exception
        except ExitedException as e:
            self._exception = ProcessExitedException(str(e))
            raise self._exception

    return wrapper

class Debugger(ABC):
    """The base debugger class, never instantiated.
    Do not use :class:`Debugger` constructor, use :func:`Debugger.debug` instead. 
    """
    def __init__(self, path: str, parameters: List[str], x64=True):
        self._path = str(os.path.realpath(path))
        #self._path = path.replace('./', '')
        self._parameters = parameters
        self._x64 = x64 # weither it is a 64 bits process or not
        self._exception = None
        self._binary = lief.parse(path)

        self._pid, self._stdin_fd, self._stdout_fd, self._stderr_fd = internals.create_process(path, parameters)
        binary = lief.parse(self._path)

        self._breakpoints = []

        self._base_addr = int(self._parse_base_address(), 16)

        entry = binary.header.entrypoint
        if binary.is_pie:
            entry += self._base_addr

        self.breakpoint(entry)
        self.pcontinue()

        self._stdout = Stream(self._stdout_fd)
        self._stderr = Stream(self._stderr_fd)
        self._stdin = Stream(self._stdin_fd, writeable=True)

    @staticmethod
    def debug(path: str, parameters: List[str]=[]):
        """Starts debugging a file

        :param path: The absolute or relative path to the executable.
        :type path: str
        :param parameters: Commands line arguments to be passed to the program.
        :type parameters: List[str]
        :returns: :class:`Debugger32` or :class:`Debugger64`
        :raises: ValueError - if the file is not an ELF file or if it's not a supported architecture.

        """
        elf = lief.parse(path)

        if elf is None:
            raise ValueError('Invalid elf file {path}')

        if str(elf.header.machine_type) == 'ARCH.x86_64':
            return Debugger64(path, parameters)
        elif str(elf.header.machine_type) == 'ARCH.i386':
            return Debugger32(path, parameters)

        raise ValueError(f'Unsupported architecture: {elf.header.machine_type}')

    def breakpoint(self, addr: int, enabled: bool=True):
        """Add a breakpoint
        
        :param addr: The address of the breakpoint.
        :type addr: int
        :param enabled: Weither or not the breakpoint is enabled.
        :type enabled: bool
        :returns: None

        """
        bp = Breakpoint(addr, self._pid, enabled)
        self._breakpoints.append(bp)

        return bp

    @handle_bp
    @handle_exception
    def pcontinue(self):
        """Continues process execution until it stops

        :returns: None

        """
        internals.pcontinue(self.pid)

    @handle_bp
    @handle_exception
    def step(self):
        """Executes a single instruction

        :returns: None

        """
        internals.step(self.pid)

    @handle_exception
    def read_memory(self, addr: int, size: int) -> bytes:
        """Reads bytes at address of current process

        :param addr: The address from where bytes will be read.
        :type addr: int
        :param size: The number of bytes to read.
        :type size: int
        :returns: bytes -- The bytes read

        :raises: MemoryException - if the address is invalid

        """
        out = b""

        while len(out) < size:
            a = internals.peek_text(self.pid, addr) & 0xffffffff
            addr += 4
            out += a.to_bytes(4, byteorder='little')
        return out[:size]

    @handle_exception
    def read_string(self, addr: int) -> bytes:
        """Reads bytes at address until a null bytes is found

        :param addr: The address from where bytes will be read.
        :type addr: int
        :returns: bytes -- the bytes read
        :raises: MemoryException - if the address is invalid

        """
        out = b""
        n = self.read_memory(addr, 1)
        while n != b'\x00':
            out += n
            addr += 1
            n = self.read_memory(addr, 1)
        return out



    @abstractmethod
    def get_regs(self) -> Dict:
        """Gets all registers

        :returns: Dict -- A dict associating the register name with its value.

        """
        raise NotImplementedError()

    @abstractmethod
    def get_reg(self, regname: str) -> int:
        """Gets a register value by name

        :param regname: The name of the register to read.
        :type regname: str
        :returns: int -- The value of register.
        :raises: KeyError - if the register doesn't exist.

        """
        raise NotImplementedError()

    @abstractmethod
    def get_instruction_pointer(self) -> int:
        """Gets the instruction pointer

        :returns: iny -- The instruction pointer register value.
        """
        raise NotImplementedError()

    @abstractmethod
    def _set_regs(self, regs: Dict) -> None:
        raise NotImplementedError()
    
    @abstractmethod
    def set_reg(self, regname: str, value: int) -> None:
        """Sets a register value

        :param regname: The name of the register.
        :type regname: str
        :param value: The value to write to the register.
        :type value: int
        :returns: None
        :raises: KeyError - if the register doesn't exist.

        """
        raise NotImplementedError()

    @abstractmethod
    def _set_instruction_pointer(self, value: int) -> None:
        raise NotImplementedError()

    @property
    def pid(self) -> int:
        """Returns the PID of the currently attached process

        :type: int
        
        """
        return self._pid

    @property
    def breakpoints(self) -> List[Breakpoint]:
        """Returns a list of all breakpoints
        
        :type: List[:class:`breakpoint.Breakpoint`]
        
        """
        return self._breakpoints

    @property
    def stdin(self) -> Stream:
        """Returns the :class:`stream.Stream` associated with stdin for the attached process
        
        :type: Stream

        """
        return self._stdin
    
    @property
    def stdout(self) -> Stream:
        """Returns the :class:`stream.Stream` associated with stdout for the attached process
        
        :type: Stream
        
        """
        return self._stdout

    @property
    def stderr(self) -> Stream:
        """Returns the :class:`stream.Stream` associated with stderr for the attached process
        
        :type: Stream

        """
        return self._stderr

    @property
    def binary(self) -> lief.ELF.Binary:
        """Returns the binary

        .. _LIEF: https://lief-project.github.io/doc/latest/api/python/elf.html#binary

        :type: `lief.ELF.Binary <https://lief-project.github.io/doc/latest/api/python/elf.html#binary>`_

        """
        return self._binary

    def _get_breakpoint_at(self, addr: int) -> Breakpoint:
        for bp in self.breakpoints:
            if bp.addr == addr:
                return bp
        return None

    def _parse_base_address(self):
        while True:
            with open(f'/proc/{self.pid}/maps', 'r') as f:
                lines = f.readlines()
                for line in lines:
                    if self._path in line:
                        return line.split('-')[0]
            internals.singleblock(self.pid)


class Debugger32(Debugger):
    """The debugger class for 32 bits process, do not instantiate manualy, use :func:`Debugger.debug`.
    """
    def __init__(self, path: str, parameters: List[str], x64=False):
        super().__init__(path, parameters, x64=x64)

    @handle_exception
    def get_regs(self) -> Dict:
        """Gets all registers for a 32 bits process, see :func:`Debugger.get_regs`.
        """
        return internals.get_regsx86(self._pid)

    @handle_exception
    def get_reg(self, regname: str) -> int:
        """Gets a register value by name for a 32 bits process, see :func:`Debugger.get_reg`.
        """
        regs = self.get_regs()

        if regname not in regs.keys():
            raise KeyError(f'No such register for 32 bits process: {regname}')
        return regs[regname]

    @handle_exception
    def get_instruction_pointer(self) -> int:
        """Gets the instruction pointer for a 32 bits process, eip, see :func:`Debugger.get_instruction_pointer`.
        """
        return self.get_reg('eip')

    def _set_regs(self, regs: Dict) -> None:
        internals.set_regsx86(self._pid, regs)

    @handle_exception
    def set_reg(self, regname: str, value: int) -> None:
        """Sets a register value for a 32 bits process, see :func:`Debugger.set_reg`.
        """
        if value < 0:
            raise ValueError('value must be an unsigned int')

        regs = self.get_regs()
        if regname not in regs.keys():
            raise KeyError(f'No such register for 32 bits process: {regname}')

        regs[regname] = value
        self._set_regs(regs)

    def _set_instruction_pointer(self, value: int) -> None:
        self.set_reg('eip', value)


class Debugger64(Debugger):
    """The debugger class for 64 bits process, do not instantiate manualy, use :func:`Debugger.debug`.
    """
    def __init__(self, path: str, parameters: List[str], x64=True):
        super().__init__(path, parameters, x64=x64)

    @handle_exception
    def get_regs(self) -> Dict:
        """Gets all registers for a 64 bits process, see :func:`Debugger.get_regs`.
        """
        return internals.get_regsx64(self._pid) ## to-do implement register cache if execution 

    @handle_exception
    def get_reg(self, regname: str) -> int:
        """Gets a register value by name for a 64 bits process, see :func:`Debugger.get_reg`.
        """
        regs = self.get_regs()

        if regname not in regs.keys():
            raise KeyError(f'No such register for 64 bits process: {regname}')
        return regs[regname]

    @handle_exception
    def get_instruction_pointer(self) -> int:
        """Gets the instruction pointer for a 64 bits process, rip, see :func:`Debugger.get_instruction_pointer`.
        """
        return self.get_reg('rip')

    def _set_regs(self, regs: Dict) -> None:
        internals.set_regsx64(self._pid, regs)

    @handle_exception
    def set_reg(self, regname: str, value: int) -> None:
        """Sets a register value for a 64 bits process, see :func:`Debugger.set_reg`.
        """
        if value < 0:
            raise ValueError('value must be an unsigned int')

        regs = self.get_regs()
        if regname not in regs.keys():
            raise KeyError(f'No such register for 64 bits process: {regname}')

        regs[regname] = value
        self._set_regs(regs)

    def _set_instruction_pointer(self, value: int) -> None:
        self.set_reg('rip', value)