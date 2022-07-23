#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h> /* for errno global variable */
#include <sys/mman.h>
#include <sys/stat.h>

#include "exception.h"
#include "process.h"


PyObject*
create_process(PyObject* self, PyObject* args)
{
    char* tok;
    int cols;

    PyObject* listObj;
    const char* path;

    if (!PyArg_ParseTuple(args, "sO!", &path, &PyList_Type, &listObj, &cols, &tok))
        return NULL;

    if (!check_file_exists(path))
    {
        PyErr_Format(
            PyExc_FileNotFoundError,
            "File \"%s\" not found", path
        );
        return NULL;
    }

    const char** execve_arguments = string_list_to_c_array(listObj);
    if (!execve_arguments)
        return NULL; // error already set by string_list_to_c_array

    
    int pin[2], pout[2], perr[2];
    pipe(pin);
    pipe(pout);
    pipe(perr);

    int pid = fork();
    if (pid == 0)
    {
        close(pout[0]);
        close(perr[0]);
        close(pin[1]);

        dup2(pout[1], 1);
        dup2(pin[0], 0);
        dup2(perr[1], 2);

        ptrace(PTRACE_TRACEME, 0, NULL, NULL);     
        execve(path, execve_arguments, NULL);
    }

    close(pin[0]);
    close(pout[1]);
    close(perr[1]);

    free(execve_arguments);
    wait(NULL);

    return Py_BuildValue("(iiii)", pid, pin[1], pout[0], perr[0]);
}

PyObject*
get_regsx64(PyObject* self, PyObject* args)
{
    Py_ssize_t pid;

    if (!PyArg_ParseTuple(args, "n", &pid))
        return NULL;

    if (pid < 0)
    {
        PyErr_Format(
            PyExc_ValueError, "Invalid PID: %lld", pid
        );
        return NULL;
    }

    struct user_regs_structx regs;

    if (!get_regs(pid, &regs))
        return NULL;

    PyObject* dict = regs_to_dictx64(&regs);
    if (!dict)
        return PyErr_NoMemory();

    return dict;
}

PyObject*
regs_to_dictx64(struct user_regs_structx* regs)
{
    PyObject* dict = PyDict_New();
    if (! dict)
        return NULL;
    #if defined(__x86_64__)
    PyDict_SetItemString(dict, "r15", Py_BuildValue("K", regs->r15));
    PyDict_SetItemString(dict, "r14", Py_BuildValue("K", regs->r14));
    PyDict_SetItemString(dict, "r13", Py_BuildValue("K", regs->r13));
    PyDict_SetItemString(dict, "r12", Py_BuildValue("K", regs->r12));
    PyDict_SetItemString(dict, "rbp", Py_BuildValue("K", regs->rbp));
    PyDict_SetItemString(dict, "rbx", Py_BuildValue("K", regs->rbx));
    PyDict_SetItemString(dict, "r11", Py_BuildValue("K", regs->r11));
    PyDict_SetItemString(dict, "r10", Py_BuildValue("K", regs->r10));
    PyDict_SetItemString(dict, "r9", Py_BuildValue("K", regs->r9));
    PyDict_SetItemString(dict, "r8", Py_BuildValue("K", regs->r8));
    PyDict_SetItemString(dict, "rax", Py_BuildValue("K", regs->rax));
    PyDict_SetItemString(dict, "rcx", Py_BuildValue("K", regs->rcx));
    PyDict_SetItemString(dict, "rdx", Py_BuildValue("K", regs->rdx));
    PyDict_SetItemString(dict, "rsi", Py_BuildValue("K", regs->rsi));
    PyDict_SetItemString(dict, "rdi", Py_BuildValue("K", regs->rdi));
    PyDict_SetItemString(dict, "orig_rax", Py_BuildValue("K", regs->orig_rax));
    PyDict_SetItemString(dict, "rip", Py_BuildValue("K", regs->rip));
    PyDict_SetItemString(dict, "cs", Py_BuildValue("K", regs->cs));
    PyDict_SetItemString(dict, "eflags", Py_BuildValue("K", regs->eflags));
    PyDict_SetItemString(dict, "rsp", Py_BuildValue("K", regs->rsp));
    PyDict_SetItemString(dict, "ss", Py_BuildValue("K", regs->ss));
    PyDict_SetItemString(dict, "fs_base", Py_BuildValue("K", regs->fs_base));
    PyDict_SetItemString(dict, "gs_base", Py_BuildValue("K", regs->gs_base));
    PyDict_SetItemString(dict, "ds", Py_BuildValue("K", regs->ds));
    PyDict_SetItemString(dict, "es", Py_BuildValue("K", regs->es));
    PyDict_SetItemString(dict, "fs", Py_BuildValue("K", regs->fs));
    PyDict_SetItemString(dict, "gs", Py_BuildValue("K", regs->gs));
    #else
    // do nothing
    #endif
    Py_IncRef(dict);
    return dict;
}

PyObject*
get_regsx86(PyObject* self, PyObject* args)
{
    Py_ssize_t pid;

    if (!PyArg_ParseTuple(args, "n", &pid))
        return NULL;

    if (pid < 0)
    {
        PyErr_Format(
            PyExc_ValueError, "Invalid PID: %lld", pid
        );
        return NULL;
    }

    struct user_regs_structx regs;

    if (!get_regs(pid, &regs))
        return NULL;

    PyObject* dict = regs_to_dictx86(&regs);
    if (!dict)
        return PyErr_NoMemory();

    return dict;
}

PyObject*
regs_to_dictx86(struct user_regs_structx* regs)
{
    PyObject* dict = PyDict_New();
    if (! dict)
        return NULL;

    #if defined(__x86_64__)
    PyDict_SetItemString(dict, "ebx", Py_BuildValue("k", regs->rbx));
    PyDict_SetItemString(dict, "ecx", Py_BuildValue("k", regs->rcx));
    PyDict_SetItemString(dict, "edx", Py_BuildValue("k", regs->rdx));
    PyDict_SetItemString(dict, "esi", Py_BuildValue("k", regs->rsi));
    PyDict_SetItemString(dict, "edi", Py_BuildValue("k", regs->rdi));
    PyDict_SetItemString(dict, "ebp", Py_BuildValue("k", regs->rbp));
    PyDict_SetItemString(dict, "eax", Py_BuildValue("k", regs->rax));
    PyDict_SetItemString(dict, "xds", Py_BuildValue("k", regs->ds));
    PyDict_SetItemString(dict, "xes", Py_BuildValue("k", regs->es));
    PyDict_SetItemString(dict, "xfs", Py_BuildValue("k", regs->fs));
    PyDict_SetItemString(dict, "orig_eax", Py_BuildValue("k", regs->orig_rax));
    PyDict_SetItemString(dict, "eip", Py_BuildValue("k", regs->rip));
    PyDict_SetItemString(dict, "xcs", Py_BuildValue("k", regs->cs));
    PyDict_SetItemString(dict, "eflags", Py_BuildValue("k", regs->eflags));
    PyDict_SetItemString(dict, "esp", Py_BuildValue("k", regs->rsp));
    PyDict_SetItemString(dict, "xss", Py_BuildValue("k", regs->ss));
    #else
    PyDict_SetItemString(dict, "ebx", Py_BuildValue("k", regs->ebx));
    PyDict_SetItemString(dict, "ecx", Py_BuildValue("k", regs->ecx));
    PyDict_SetItemString(dict, "edx", Py_BuildValue("k", regs->edx));
    PyDict_SetItemString(dict, "esi", Py_BuildValue("k", regs->esi));
    PyDict_SetItemString(dict, "edi", Py_BuildValue("k", regs->edi));
    PyDict_SetItemString(dict, "ebp", Py_BuildValue("k", regs->ebp));
    PyDict_SetItemString(dict, "eax", Py_BuildValue("k", regs->eax));
    PyDict_SetItemString(dict, "xds", Py_BuildValue("k", regs->xds));
    PyDict_SetItemString(dict, "xes", Py_BuildValue("k", regs->xes));
    PyDict_SetItemString(dict, "xfs", Py_BuildValue("k", regs->xfs));
    PyDict_SetItemString(dict, "orig_eax", Py_BuildValue("k", regs->orig_eax));
    PyDict_SetItemString(dict, "eip", Py_BuildValue("k", regs->eip));
    PyDict_SetItemString(dict, "xcs", Py_BuildValue("k", regs->xcs));
    PyDict_SetItemString(dict, "eflags", Py_BuildValue("k", regs->eflags));
    PyDict_SetItemString(dict, "esp", Py_BuildValue("k", regs->esp));
    PyDict_SetItemString(dict, "xss", Py_BuildValue("k", regs->xss));
    #endif


    Py_IncRef(dict);
    return dict;
}

struct user_regs_structx*
get_regs(Py_ssize_t pid, struct user_regs_structx* regs)
{
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs) == -1)
    {
        if (errno == EPERM || errno == EIO)
        {
            PyErr_Format(
                ProcessException, "Error getting regs for PID: %lld", pid
            );
        }
        else
        {
            PyErr_Format(
                PyExc_ValueError, "Invalid or not attached PID: %lld", pid
            );
        }
        return NULL;
    }
    return regs;
}


PyObject*
set_regsx64(PyObject* self, PyObject* args)
{
    Py_ssize_t pid;
    PyObject* dict;

    if (!PyArg_ParseTuple(args, "nO!", &pid, &PyDict_Type, &dict))
        return NULL;

    if (pid < 0)
    {
        PyErr_Format(
            PyExc_ValueError, "Invalid PID: %lld", pid
        );
        return NULL;
    }

    struct user_regs_structx regs;
    if (!get_regs(pid, &regs))
        return NULL;

    dict_to_regsx64(dict, &regs);

    if (!set_regs(pid, &regs))
        return NULL;

    Py_RETURN_NONE;
}

void
dict_to_regsx64(PyObject* dict, struct user_regs_structx* regs)
{
    #if defined(__x86_64__)
    PyObject* obj = PyDict_GetItemString(dict, "r15");
    if (obj)
        regs->r15 = PyLong_AsUnsignedLongLong(obj);

    obj = PyDict_GetItemString(dict, "r14");
    if (obj)
        regs->r14 = PyLong_AsUnsignedLongLong(obj);

    obj = PyDict_GetItemString(dict, "r13");
    if (obj)
        regs->r13 = PyLong_AsUnsignedLongLong(obj);

    obj = PyDict_GetItemString(dict, "r12");
    if (obj)
        regs->r12 = PyLong_AsUnsignedLongLong(obj);

    obj = PyDict_GetItemString(dict, "r12");
    if (obj)
        regs->r12 = PyLong_AsUnsignedLongLong(obj);

    obj = PyDict_GetItemString(dict, "rbp");
    if (obj)
        regs->rbp = PyLong_AsUnsignedLongLong(obj);

    obj = PyDict_GetItemString(dict, "rbx");
    if (obj)
        regs->rbx = PyLong_AsUnsignedLongLong(obj);

    obj = PyDict_GetItemString(dict, "r11");
    if (obj)
        regs->r11 = PyLong_AsUnsignedLongLong(obj);

    obj = PyDict_GetItemString(dict, "r10");
    if (obj)
        regs->r10 = PyLong_AsUnsignedLongLong(obj);

    obj = PyDict_GetItemString(dict, "r9");
    if (obj)
        regs->r9 = PyLong_AsUnsignedLongLong(obj);

    obj = PyDict_GetItemString(dict, "r8");
    if (obj)
        regs->r8 = PyLong_AsUnsignedLongLong(obj);

    obj = PyDict_GetItemString(dict, "rax");
    if (obj)
        regs->rax = PyLong_AsUnsignedLongLong(obj);

    obj = PyDict_GetItemString(dict, "rcx");
    if (obj)
        regs->rdx = PyLong_AsUnsignedLongLong(obj);

    obj = PyDict_GetItemString(dict, "rdx");
    if (obj)
        regs->rdx = PyLong_AsUnsignedLongLong(obj);

    obj = PyDict_GetItemString(dict, "rsi");
    if (obj)
        regs->rsi = PyLong_AsUnsignedLongLong(obj);

    obj = PyDict_GetItemString(dict, "rdi");
    if (obj)
        regs->rdi = PyLong_AsUnsignedLongLong(obj);

    obj = PyDict_GetItemString(dict, "orig_rax");
    if (obj)
        regs->orig_rax = PyLong_AsUnsignedLongLong(obj);

    obj = PyDict_GetItemString(dict, "rip");
    if (obj)
        regs->rip = PyLong_AsUnsignedLongLong(obj);

    obj = PyDict_GetItemString(dict, "cs");
    if (obj)
        regs->cs = PyLong_AsUnsignedLongLong(obj);

    obj = PyDict_GetItemString(dict, "eflags");
    if (obj)
        regs->eflags = PyLong_AsUnsignedLongLong(obj);

    obj = PyDict_GetItemString(dict, "rsp");
    if (obj)
        regs->rsp = PyLong_AsUnsignedLongLong(obj);

    obj = PyDict_GetItemString(dict, "ss");
    if (obj)
        regs->ss = PyLong_AsUnsignedLongLong(obj);

    obj = PyDict_GetItemString(dict, "fs_base");
    if (obj)
        regs->fs_base = PyLong_AsUnsignedLongLong(obj);

    obj = PyDict_GetItemString(dict, "gs_base");
    if (obj)
        regs->gs_base = PyLong_AsUnsignedLongLong(obj);

    obj = PyDict_GetItemString(dict, "ds");
    if (obj)
        regs->ds = PyLong_AsUnsignedLongLong(obj);

    obj = PyDict_GetItemString(dict, "es");
    if (obj)
        regs->es = PyLong_AsUnsignedLongLong(obj);

    obj = PyDict_GetItemString(dict, "fs");
    if (obj)
        regs->fs = PyLong_AsUnsignedLongLong(obj);

    obj = PyDict_GetItemString(dict, "gs");
    if (obj)
        regs->gs = PyLong_AsUnsignedLongLong(obj);
    #else
    // do nothing
    #endif
}

PyObject*
set_regsx86(PyObject* self, PyObject* args)
{
    Py_ssize_t pid;
    PyObject* dict;

    if (!PyArg_ParseTuple(args, "nO!", &pid, &PyDict_Type, &dict))
        return NULL;

    if (pid < 0)
    {
        PyErr_Format(
            PyExc_ValueError, "Invalid PID: %lld", pid
        );
        return NULL;
    }

    struct user_regs_structx regs;
    if (!get_regs(pid, &regs))
        return NULL;

    dict_to_regsx86(dict, &regs); // update regs

    if (!set_regs(pid, &regs))
        return NULL;

    Py_RETURN_NONE;
}

void
dict_to_regsx86(PyObject* dict, struct user_regs_structx* regs)
{
    #if defined(__x86_64__)
    PyObject* obj = PyDict_GetItemString(dict, "ebx");
    if (obj)
        regs->rbx = PyLong_AsUnsignedLongLong(obj);

    obj = PyDict_GetItemString(dict, "ecx");
    if (obj)
        regs->rcx = PyLong_AsUnsignedLongLong(obj);

    obj = PyDict_GetItemString(dict, "edx");
    if (obj)
        regs->rdx = PyLong_AsUnsignedLongLong(obj);

    obj = PyDict_GetItemString(dict, "esi");
    if (obj)
        regs->rsi = PyLong_AsUnsignedLongLong(obj);

    obj = PyDict_GetItemString(dict, "edi");
    if (obj)
        regs->rdi = PyLong_AsUnsignedLongLong(obj);

    obj = PyDict_GetItemString(dict, "ebp");
    if (obj)
        regs->rbp = PyLong_AsUnsignedLongLong(obj);

    obj = PyDict_GetItemString(dict, "eax");
    if (obj)
        regs->rax = PyLong_AsUnsignedLongLong(obj);

    obj = PyDict_GetItemString(dict, "xds");
    if (obj)
        regs->ds = PyLong_AsUnsignedLongLong(obj);

    obj = PyDict_GetItemString(dict, "xes");
    if (obj)
        regs->es = PyLong_AsUnsignedLongLong(obj);

    obj = PyDict_GetItemString(dict, "xfs");
    if (obj)
        regs->fs = PyLong_AsUnsignedLongLong(obj);

    obj = PyDict_GetItemString(dict, "orig_eax");
    if (obj)
        regs->orig_rax = PyLong_AsUnsignedLongLong(obj);

    obj = PyDict_GetItemString(dict, "eip");
    if (obj)
        regs->rip = PyLong_AsUnsignedLongLong(obj);

    obj = PyDict_GetItemString(dict, "xcs");
    if (obj)
        regs->cs = PyLong_AsUnsignedLongLong(obj);

    obj = PyDict_GetItemString(dict, "eflags");
    if (obj)
        regs->eflags = PyLong_AsUnsignedLongLong(obj);

    obj = PyDict_GetItemString(dict, "esp");
    if (obj)
        regs->rsp = PyLong_AsUnsignedLongLong(obj);

    obj = PyDict_GetItemString(dict, "xss");
    if (obj)
        regs->ss = PyLong_AsUnsignedLongLong(obj);

    regs->r15 = 0;
    regs->r14 = 0;
    regs->r13 = 0;
    regs->r12 = 0;
    regs->r11 = 0;
    regs->r10 = 0;
    regs->r9 = 0;
    regs->r8 = 0;
    #endif

    #if defined(__i386__)
    PyObject* obj = PyDict_GetItemString(dict, "ebx");
    if (obj)
        regs->ebx = PyLong_AsUnsignedLong(obj);

    obj = PyDict_GetItemString(dict, "ecx");
    if (obj)
        regs->ecx = PyLong_AsUnsignedLong(obj);

    obj = PyDict_GetItemString(dict, "edx");
    if (obj)
        regs->edx = PyLong_AsUnsignedLong(obj);

    obj = PyDict_GetItemString(dict, "esi");
    if (obj)
        regs->esi = PyLong_AsUnsignedLong(obj);

    obj = PyDict_GetItemString(dict, "edi");
    if (obj)
        regs->edi = PyLong_AsUnsignedLong(obj);

    obj = PyDict_GetItemString(dict, "ebp");
    if (obj)
        regs->ebp = PyLong_AsUnsignedLong(obj);

    obj = PyDict_GetItemString(dict, "eax");
    if (obj)
        regs->eax = PyLong_AsUnsignedLong(obj);

    obj = PyDict_GetItemString(dict, "xds");
    if (obj)
        regs->xds = PyLong_AsUnsignedLong(obj);

    obj = PyDict_GetItemString(dict, "xes");
    if (obj)
        regs->xes = PyLong_AsUnsignedLong(obj);

    obj = PyDict_GetItemString(dict, "xfs");
    if (obj)
        regs->xfs = PyLong_AsUnsignedLong(obj);

    obj = PyDict_GetItemString(dict, "orig_eax");
    if (obj)
        regs->orig_eax = PyLong_AsUnsignedLong(obj);

    obj = PyDict_GetItemString(dict, "eip");
    if (obj)
        regs->eip = PyLong_AsUnsignedLong(obj);

    obj = PyDict_GetItemString(dict, "xcs");
    if (obj)
        regs->xcs = PyLong_AsUnsignedLong(obj);

    obj = PyDict_GetItemString(dict, "eflags");
    if (obj)
        regs->eflags = PyLong_AsUnsignedLong(obj);

    obj = PyDict_GetItemString(dict, "esp");
    if (obj)
        regs->esp = PyLong_AsUnsignedLong(obj);

    obj = PyDict_GetItemString(dict, "xss");
    if (obj)
        regs->xss = PyLong_AsUnsignedLong(obj);
    #endif
}

struct user_regs_structx*
set_regs(Py_ssize_t pid, struct user_regs_structx* regs)
{
    if (ptrace(PTRACE_SETREGS, pid, NULL, regs) == -1)
    {
        if (errno == EPERM || errno == EIO)
        {
            PyErr_Format(
                ProcessException, "Can't set regs for PID: %lld", pid
            );
        }
        else
        {
            PyErr_Format(
                PyExc_ValueError, "Invalid or not attached PID: %lld", pid
            );
        }

        return NULL;
    }
    return regs;
}

PyObject*
singleblock(PyObject* self, PyObject* args)
{
    Py_ssize_t pid;

    if (!PyArg_ParseTuple(args, "n", &pid))
        return NULL;

    if (pid < 0)
    {
        PyErr_Format(
            PyExc_ValueError, "Invalid PID: %lld", pid
        );
        return NULL;
    }

    if (ptrace(PTRACE_SINGLEBLOCK, pid, NULL, NULL) == -1)
    {
        if (errno == EPERM || errno == EIO)
        {
            PyErr_Format(
                ProcessException, "Can't singleblock process with PID: %lld", pid
            );
        }
        else
        {
            PyErr_Format(
                PyExc_ValueError, "Invalid or not attached PID: %lld", pid
            );
        }
        return NULL;
    }

    int status;
    waitpid(pid, &status, WSTOPPED);

    if (!check_status(status))
        return NULL;

    Py_RETURN_NONE;
}

PyObject*
pcontinue(PyObject* self, PyObject* args)
{
    Py_ssize_t pid;

    if (!PyArg_ParseTuple(args, "n", &pid))
        return NULL;

    if (pid < 0)
    {
        PyErr_Format(
            PyExc_ValueError, "Invalid PID: %lld", pid
        );
        return NULL;
    }

    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1)
    {
        if (errno == EPERM || errno == EIO)
        {
            PyErr_Format(
                ProcessException, "Can't continue process with PID: %lld", pid
            );
        }
        else
        {
            PyErr_Format(
                PyExc_ValueError, "Invalid or not attached PID: %lld", pid
            );
        }
        return NULL;
    }

    int status;
    waitpid(pid, &status, WSTOPPED);

    if (!check_status(status))
        return NULL;

    Py_RETURN_NONE;
}

PyObject* psyscall(PyObject* self, PyObject* args)
{
    Py_ssize_t pid;

    if (!PyArg_ParseTuple(args, "n", &pid))
        return NULL;

    if (pid < 0)
    {
        PyErr_Format(
            PyExc_ValueError, "Invalid PID: %lld", pid
        );
        return NULL;
    }

    if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1)
    {
        if (errno == EPERM || errno == EIO)
        {
            PyErr_Format(
                ProcessException, "Can't continue process with PID: %lld", pid
            );
        }
        else
        {
            PyErr_Format(
                PyExc_ValueError, "Invalid or not attached PID: %lld", pid
            );
        }
        return NULL;
    }

    int status;
    waitpid(pid, &status, WSTOPPED);

    if (!check_status(status))
        return NULL;

    Py_RETURN_NONE;
}

PyObject*
step(PyObject* self, PyObject* args)
{
    Py_ssize_t pid;

    if (!PyArg_ParseTuple(args, "n", &pid))
        return NULL;

    if (pid < 0)
    {
        PyErr_Format(
            PyExc_ValueError, "Invalid PID: %lld", pid
        );
        return NULL;
    }

    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1)
    {
        if (errno == EPERM || errno == EIO)
        {
            PyErr_Format(
                ProcessException, "Can't singlestep on process with PID: %lld", pid
            );
        }
        else
        {
            PyErr_Format(
                PyExc_ValueError, "Invalid or not attached PID: %lld", pid
            );
        }
        return NULL;
    }

    int status;
    waitpid(pid, &status, WSTOPPED);

    if (!check_status(status))
        return NULL;

    Py_RETURN_NONE;
}

bool
check_status(int status)
{
    if (WIFSTOPPED(status))
    {
        int code = WSTOPSIG(status);

        if (code == SIGTRAP)
            return true;

        PyErr_SetObject(StoppedException, Py_BuildValue("i", code));
        return false;
    }
    else if (WIFEXITED(status))
    {
        int code = WEXITSTATUS(status);

        PyErr_SetObject(ExitedException, Py_BuildValue("i", code));
        return false;
    }

    return true;
}


PyObject*
peek_text(PyObject* self, PyObject* args)
{
    Py_ssize_t pid;
    unsigned long long addr;

    if (!PyArg_ParseTuple(args, "nK", &pid, &addr))
        return NULL;

    if (pid < 0)
    {
        PyErr_Format(
            PyExc_ValueError, "Invalid PID: %lld", pid
        );
        return NULL;
    }

    long data = ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);
    if (data == -1)
    {
        if (errno == EFAULT || errno == EIO)
        {
            PyErr_Format(
                MemoryException, "Invalid address: 0x%llx", addr
            );
        }
        else if (errno == EPERM)
        {
            PyErr_Format(
                PyExc_ValueError, "Invalid or not attached PID: %lld", pid
            );
        }

        return NULL;
    }

    data &= 0xffffffffffffffff;

    return Py_BuildValue("l", data);
}

PyObject*
poke_text(PyObject* self, PyObject* args)
{
    Py_ssize_t pid;
    unsigned long long addr;
    unsigned long long data;

    if (!PyArg_ParseTuple(args, "nKK", &pid, &addr, &data))
        return NULL;

    if (pid < 0)
    {
        PyErr_Format(
            PyExc_ValueError, "Invalid PID: %lld", pid
        );
        return NULL;
    }

    long to_send = data & 0xffffffffffffffff;

    if (ptrace(PTRACE_POKETEXT, pid, addr, to_send) == -1)
    {
        if (errno == EFAULT || errno == EIO)
        {
            PyErr_Format(
                MemoryException, "Invalid address: 0x%llx", addr
            );
        }
        else if (errno == EPERM)
        {
            PyErr_Format(
                PyExc_ValueError, "Invalid or not attached PID: %lld", pid
            );
        }
        return NULL;
    }

    Py_RETURN_NONE;
}

bool
check_file_exists(const char* path)
{
    int fd = open(path, O_RDONLY);

    if (fd != -1)
        close(fd);

    return fd != -1;
}

const char**
string_list_to_c_array(PyObject* string_list)
{
    Py_ssize_t size = PyList_Size(string_list);

    if (size < 0)
        return NULL;

    const char** array = malloc((size+1) * sizeof(char*));
    Py_ssize_t i = 0;
    for (; i < size; i++)
    {
        PyObject* string = PyList_GetItem(string_list, i);
        if (PyUnicode_Check(string))
        {
            Py_ssize_t ssize;
            const char *ptr = PyUnicode_AsUTF8AndSize(string, &ssize);
            array[i] = ptr;
        }
        else
        {
            free(array);
            PyErr_SetString(PyExc_ValueError, "an array of strings was expected");
            return NULL;
        }
    }

    array[i] = NULL;

    return array;
}
