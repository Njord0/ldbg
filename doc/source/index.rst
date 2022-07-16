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


Links
-------

.. toctree::
   :maxdepth: 1

   index
   debugger
   stream
   breakpoint
   exception