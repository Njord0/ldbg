#define PY_SSIZE_T_CLEAN
#include <Python.h>

PyObject* ProcessException;
PyObject* MemoryException;

PyObject* StoppedException;
PyObject* ExitedException;

void
init_exception()
{
    ProcessException = PyErr_NewException(
        "internals.ProcessException",
        NULL,
        NULL
    );

    if (!ProcessException)
        ProcessException = PyExc_Exception;

    MemoryException = PyErr_NewException(
        "internals.MemoryException",
        ProcessException,
        NULL
    );


    StoppedException = PyErr_NewException(
        "internals.StoppedException",
        ProcessException,
        NULL
    );
    
    ExitedException = PyErr_NewException(
        "internals.ExitedException",
        ProcessException,
        NULL
    );

    if (!MemoryException)
        MemoryException = PyExc_Exception;

    if (!StoppedException)
        StoppedException = PyExc_Exception;

    if (!ExitedException)
        ExitedException = PyExc_Exception;
}