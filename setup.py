from distutils.core import setup, Extension

setup( 
    name='ldbg', 
    version='0.0',
    packages=['ldbg'],
    ext_modules=[Extension('ldbg.internals', ['c/process.c', 'c/main.c', 'c/exception.c'],
                        swig_opts=['-Wall', '-lrt'])]
)
