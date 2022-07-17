from capstone import CsInsn, Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from lief.ELF import ARCH
import lief


from typing import List

class Function:
    """A class representing an exported function, instantiated by Debugger, see :func:`debugger.Debugger.functions`
    """
    def __init__(self, name: str, addr: int):
        self._name = name
        self._addr = addr

        self._xrefs = []

    def _add_xref(self, addr: int):
        self._xrefs.append(addr)

    @property
    def name(self) -> str:
        """Returns the function name

        :type: str
        """
        return self._name

    @property
    def address(self) -> int:
        """Returns the function address

        :type: int
        """
        return self._addr

    @property
    def call_xrefs(self) -> List[int]:
        """Returns the list of instructions addresses that calls this function
        
        :type: List[int]
        """
        return self._xrefs


def _get_calls(binary: lief.ELF.Binary) -> List[CsInsn]:
    arch  = str(binary.header.machine_type)

    if arch == 'ARCH.x86_64':
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    elif arch == 'ARCH.i386':
        md = Cs(CS_ARCH_X86, CS_MODE_32)

    text_section = binary.get_section('.text')
    if not text_section:
        return []

    insns = md.disasm(bytes(text_section.content), text_section.offset, text_section.size)
    out = []

    for insn in insns:
        if insn.mnemonic == 'call':
            out.append(insn)

    return out

def _is_compiled_with_gcc(binary: lief.ELF.Binary) -> bool:
    comment = binary.get_section('.comment')
    if not comment:
        return False
    
    content = bytes(comment.content)
    return b'GCC' in content and not b'clang' in content

# todo
def _relocated_functions(binary: lief.ELF.Binary, base: int) -> List[Function]:
    if not _is_compiled_with_gcc(binary): # only parse relocated functions for gcc compiled binaries
        return []

    plt = binary.get_section('.plt.sec')
    if not plt:
        plt = binary.get_section('.plt')
    if not plt:
        return []

    out = []

    i = 1
    for relocation in binary.pltgot_relocations:
        if relocation.has_symbol and relocation.symbol.is_function:
            addr = plt.offset + (relocation.info-1) * 16
        
            if binary.is_pie and binary.header.machine_type == ARCH.i386:
                addr -= 0x10 * i
            elif binary.is_pie:
                addr -= 0x20
            elif binary.header.machine_type == ARCH.x86_64:
                addr -= 0x10

            out.append(
                Function(relocation.symbol.name, addr + base)
            )
        i += 1
    return out


def _parse_functions(binary: lief.ELF.Binary, base: int) -> List[Function]:
    fncts = binary.exported_functions


    functions = []
    for f in fncts:
        functions.append(
            Function(f.name, f.address + base) if binary.is_pie else Function(f.name, f.address)
        )

    calls = _get_calls(binary)

    for call in calls:
        try:
            addr = int(call.op_str, 16) + base
        except ValueError:
            continue

        for func in functions:
            if func.address == addr:
                func._add_xref(call.address + base)
                break

    return functions




