#ifndef LDBG_EXCEPTION_H
#define LDBG_EXCEPTION_H

#define PY_SSIZE_T_CLEAN
#include <Python.h>

extern PyObject* ProcessException;
extern PyObject* MemoryException;
extern PyObject* StoppedException;
extern PyObject* ExitedException;

void init_exception();

#endif // LDBG_EXCEPTION_H