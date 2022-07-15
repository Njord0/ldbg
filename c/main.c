#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "exception.h"
#include "process.h"

static struct PyMethodDef methods[] = {
    {"create_process", create_process, METH_VARARGS, "create_process"},
    {"get_regsx64", get_regsx64, METH_VARARGS, "get_regsx64"},
    {"get_regsx86", get_regsx86, METH_VARARGS, "get_regsx86"},
    {"set_regsx64", set_regsx64, METH_VARARGS, "set_regsx64"},
    {"set_regsx86", set_regsx86, METH_VARARGS, "set_regsx86"},


    {"singleblock", singleblock, METH_VARARGS, "singleblock process"},
    {"pcontinue", pcontinue, METH_VARARGS, "continue process"},
    {"step", step, METH_VARARGS, "step"},

    {"peek_text", peek_text, METH_VARARGS, "peek_text"},
    {"poke_text", poke_text, METH_VARARGS, "poke_text"},
    {NULL, NULL, 0, NULL}
};

static PyModuleDef InternalsDef = {
    PyModuleDef_HEAD_INIT, "internals", "", -1, methods,
    NULL, NULL, NULL, NULL
};

PyMODINIT_FUNC PyInit_internals(void) {
    init_exception();

    PyObject* m = PyModule_Create(&InternalsDef);

    if (!m)
        return NULL;

    PyModule_AddObject(m, "ProcessException", ProcessException);
    PyModule_AddObject(m, "MemoryException", MemoryException);
    PyModule_AddObject(m, "StoppedException", StoppedException);
    PyModule_AddObject(m, "ExitedException", ExitedException);

    return m;
}

