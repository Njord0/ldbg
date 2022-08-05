.. ldbg documentation master file, created by
   sphinx-quickstart on Thu Jul 14 17:02:34 2022.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to ldbg's documentation!
================================

Welcome to ldbg's documentation

Installation
------------

`ldbg` can be installed from the github `repository <https://github.com/njord0/ldbg>`_.

.. code-block:: shell

   $ git clone https://github.com/njord0/ldbg
   $ cd ldbg
   $ python3 -m pip install requirements.txt
   $ python3 setup.py install


Examples
--------

Simple program
^^^^^^^^^^^^^^
.. code-block:: python

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


Where `executable` can either be a x86 or a x86-64 ELF file.

Interception of function calls and modifying parameters
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Here is a simple example of usage of the functions property to intercept functions calls and modify parameters:

source.c :

.. code-block:: c

   // gcc -o executable source.c
   #include <stdio.h>
   #include <stdlib.h>

   void power2(int a)
   {
      printf("a^2 = %d\n", a*a);
   }

   int main(int argc, char **argv)
   {

      int a;
      printf("Give me a number: ");
      scanf("%d", &a);

      power2(a);

      return 0;
   }


And the script:

.. code-block:: python

   from ldbg import Debugger
   import ldbg

   p  = Debugger.debug('./executable')

   power2 = p.get_function_by_name('power2')

   for xref in power2.call_xrefs:
      p.breakpoint(xref)

   p.stdin.write(b'10\n') # feeding scanf
   p.pcontinue()

   rdi = p.get_reg('rdi')
   print(f'Intercepted value: {rdi}')
   p.set_reg('rdi', 42)

   try:
      p.pcontinue()
   except ldbg.ProcessExitedException as e:
      print(p.stdout.read(100))
      print('process exited with status code: ', e.n)


And the output of program will be:

.. code-block:: none

   Intercepted value: 10
   b'Give me a number: 42^2 = 1764\n'
   process exited with status code:  0


A simple strace like tool
^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   from ldbg import Debugger
   import ldbg

   p  = Debugger.debug('./executable')

   format_str = '{0:4} {1:20} {2:20} {3:20}' 

   print(format_str.format('no', 'rdi', 'rsi', 'rdx'))

   while True:
      p.syscall() # stops before syscall execution

      regs = p.get_regs()

      rax, rdi, rsi, rdx = regs['orig_rax'], regs['rdi'], regs['rsi'], regs['rdx']

      print(format_str.format(hex(rax)[2:], hex(rdi)[2:], hex(rsi)[2:], hex(rdx)[2:]), end="")

      try:
         p.syscall() # stops after syscall
      except ldbg.ProcessExitedException as e:
         exit(0)

      rax = p.get_reg('rax')
      
      print('= ' + hex(rax)[2:])


Links
-------

.. toctree::
   :maxdepth: 1

   index
   debugger
   stream
   breakpoint
   exception
   function
   snapshot