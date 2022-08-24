from ldbg import internals
from ldbg.breakpoint import Breakpoint
from ldbg.stream import Stream
from ldbg.exceptions import ProcessExitedException, ProcessSignaledException
from ldbg.function import Function, _parse_functions
from ldbg.snapshot import Snapshot
from ldbg.internals import StoppedException, ExitedException

from abc import ABC, abstractmethod
from typing import List, Dict, Union
from functools import wraps
from lief.ELF import ARCH

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
    def __init__(self, path: str, parameters: List[str], aslr: bool = False):
        self._path = str(os.path.realpath(path))
        #self._path = path.replace('./', '')
        self._parameters = parameters
        self._exception = None
        self._binary = lief.parse(path)
        self._breakpoints = []

        binary = lief.parse(self._path)

        self._pid, self._stdin_fd, self._stdout_fd, self._stderr_fd = internals.create_process(path, aslr, parameters)

        self._base_addr = int(self._parse_base_address(), 16)

        entry = binary.header.entrypoint
        if binary.is_pie:
            entry += self._base_addr

        self.breakpoint(entry)

        if self.get_instruction_pointer() != entry: # fix for statics binaries
            self.pcontinue()

        self._stdout = Stream(self._stdout_fd)
        self._stderr = Stream(self._stderr_fd)
        self._stdin = Stream(self._stdin_fd, writeable=True)

        self._functions = _parse_functions(self._binary, self._base_addr)

    @staticmethod
    def debug(path: str, parameters: List[str]=[], aslr: bool = False):
        """Starts debugging a file

        :param path: The absolute or relative path to the executable.
        :type path: str
        :param parameters: Commands line arguments to be passed to the program.
        :type parameters: List[str]
        :param aslr: Weither or not the ASLR will be enabled for the child process, True = enable, False = disabled
        :type aslr: bool
        :returns: :class:`Debugger32` or :class:`Debugger64`
        :raises: ValueError - if the file is not an ELF file or if it's not a supported architecture.

        """
        elf = lief.parse(path)
        if elf is None:
            raise ValueError('Invalid elf file {path}')

        if elf.header.machine_type == ARCH.x86_64:
            return Debugger64(path, parameters, aslr=aslr)
        elif elf.header.machine_type == ARCH.i386:
            return Debugger32(path, parameters, aslr=aslr)

        raise ValueError(f'Unsupported architecture: {elf.header.machine_type}')

    def breakpoint(self, addr: int, enabled: bool=True, relative: bool=False):
        """Adds a breakpoint
        
        :param addr: The address of the breakpoint.
        :type addr: int
        :param enabled: Weither or not the breakpoint is enabled.
        :type enabled: bool
        :returns: None
        """
        if relative:
            addr += self._base_addr

        bp = Breakpoint(addr, self._pid, enabled)
        self._breakpoints.append(bp)

        return bp

    def get_breakpoint_at(self, addr: int) -> Breakpoint:
        """Returns the breakpoint at address

        :param addr: The address of the breakpoint.
        :type addr: int
        :returns: :class:`breakpoint.Breakpoint` -- The breakpoint if found, else None.
        """
        for breakpoint in self.breakpoints:
            if breakpoint.addr == addr:
                return breakpoint
        return None

    def delete_breakpoint(self, bp: Breakpoint):
        """Deletes a breakpoint

        :param bp: The breakpoint to delete.
        :type bp: :class:`breakpoint.Breakpoint`
        """
        if not bp in self._breakpoints:
            return

        bp.disable() # first disable the breakpoint
        self._breakpoints.remove(bp)

    def make_snapshot(self) -> Snapshot:
        """Returns a memory snapshot of the process
        
        :returns: :class:`snapshot.Snapshot` -- the memory snapshot
        """
        return Snapshot(self)

    def restore_snapshot(self, snapshot: Snapshot) -> None:
        """Restores a memory snapshot

        :return: None
        """
        snapshot._restore()

    @handle_bp
    @handle_exception
    def pcontinue(self):
        """Continues process execution until it stops

        :returns: None

        """
        ip = self.get_instruction_pointer()
        bp = self.get_breakpoint_at(ip)

        if bp:
            self.step()

        internals.pcontinue(self.pid)

    @handle_bp
    @handle_exception
    def step(self):
        """Executes a single instruction

        :returns: None

        """
        internals.step(self.pid)

    @handle_bp
    @handle_exception
    def syscall(self):
        """Continues process execution until a syscall occur, call it a second time to watch syscall return value

        :returns: None
        """
        internals.syscall(self.pid)

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
        # disable breakpoints (temporarily)
        saved_state = [bp.enabled for bp in self.breakpoints]
        for bp in self.breakpoints:
            bp.disable()

        out = b""

        while len(out) < size:
            a = internals.peek_text(self.pid, addr) & 0xffffffff
            addr += 4
            out += a.to_bytes(4, byteorder='little')

        # restore breakpoints
        for i, bp in enumerate(self.breakpoints):
            if saved_state[i]:
                bp.enable()

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

    def get_function_by_name(self, name: str) -> Function:
        """Returns the function with name `name`

        :param name: The function name.
        :type name: str
        :returns: :class:`function.Function` -- the function

        """
        for f in self.functions:
            if f.name == name:
                return f
        
        for f in self.functions:
            if f.name.startswith(name):
                return f
        return None
        

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

        :returns: int -- The instruction pointer register value.
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

    @property
    def base_address(self) -> int:
        """Returns the binary base address

        :type: int
        """
        return self._base_addr

    @property
    def functions(self) -> List[Function]:
        """Returns the list of defined functions

        :type: List[:class:`function.Function`]
        """
        return self._functions

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
    def __init__(self, path: str, parameters: List[str], aslr: bool = False):
        super().__init__(path, parameters, aslr=aslr)

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
    def __init__(self, path: str, parameters: List[str], aslr: bool = False):
        super().__init__(path, parameters, aslr=aslr)

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