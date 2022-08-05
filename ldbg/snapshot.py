from typing import List, Tuple, Dict

import re

class Snapshot:
    """A class representing a memory snapshot of the process
    """
    def __init__(self, dbg):
        self._dbg = dbg
        self._general_regs = dbg.get_regs()
        # todo handle floating points registers

        self._memory_bounds = self._parse_memory_bounds(dbg)
        self._memory: bytes = self._copy_process_memory(dbg)

    @property
    def regs(self) -> Dict:
        """Returns the snapshot copied registers

        :returns: Dict
        """
        return self._general_regs

    @property
    def memory(self) -> bytes:
        """Returns the snapshot copied memory
        
        :returns: bytes
        """
        return self._memory

    def _restore(self):
        dbg = self._dbg
        dbg._set_regs(self._general_regs)

        mem = open(f'/proc/{dbg.pid}/mem', 'wb')
        
        i = 0
        for (lower, upper) in self._memory_bounds:
            size = upper - lower
            mem.seek(lower)
            try:
                mem.write(
                    self._memory[i:i+size]
                )
            except OSError:
                pass

            i += size

    def _copy_process_memory(self, dbg) -> bytes:
        
        mem = open(f'/proc/{dbg.pid}/mem', 'rb')
        data = b''

        for (lower, upper) in self._memory_bounds:
            size = upper - lower

            mem.seek(lower)
            try:
                data += mem.read(size)
            except OSError as e:
                pass

        mem.close()
        return data


    def _parse_memory_bounds(self, dbg) -> List[Tuple[int, int]]:
        bounds = []
        maps = open(f'/proc/{dbg.pid}/maps')

        for line in maps.readlines():
            m = re.match(r'([0-9A-Fa-f]+)-([0-9A-Fa-f]+) ([r])', line)

            if m:
                bounds.append(
                    (int(m[1], 16), int(m[2], 16))
                ) # lower and upper bounds of memory
            
        maps.close()

        return bounds