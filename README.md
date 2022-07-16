### ldbg

ldbg is a simple debugging python API for x86 and x86-64 ELF executables.

## About

ldbg is basically a wrapper around linux ptrace utility, made for automatizing your reverse-engineering tasks or building your own tiny debugger from scratch!


The exposed python API is meant to be simple to use and to understand, the documentation is available (here)[https://njord0.github.io/ldbg].

## Installation

ldbg can be installed by cloning this repository and running the (setup.py)[https://github.com/njord0/ldbg/main/setup.py] script :

```shell
$ git clone https://github.com/njord0/ldbg
$ cd ldbg
$ python3 -m pip install requirements.txt
$ python3 setup.py install
```

## Example

```py
from ldbg import Debugger
import ldbg

p  = Debugger.debug('./executable')

print(f'Process started with PID: {p.pid}')
print(f'The process is stopped at the entry point by default, {hex(p.get_instruction_pointer())}')

try:
    p.pcontinue()
except ldbg.ProcessExitedException as e:
    print('The process exited with code: ', e.n)
    
print(
    p.stdout.read() 
) ## printing the output of the program
```

Where `executable` can either be a x86 or a x86-64 ELF file.
