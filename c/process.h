#ifndef LDBG_PROCESS_H
#define LDBG_PROCESS_H

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <stdbool.h>

struct user_regs_structx;

/**
 * Given a path to an executable and a list of arguments, fork the process and call execve(path, args) in the child process
 * Return the pid as a PyLong object 
 */
PyObject* create_process(PyObject* self, PyObject* args);

/**
 * Get registers for a 64 bits process 
 */
PyObject* get_regsx64(PyObject* self, PyObject* args);

/**
 * Get registers for a 32 bits process
 */
PyObject* get_regsx86(PyObject* self, PyObject* args);

/**
 * Ptrace getregs, return regs or return NULL on error and set exception
 */
struct user_regs_structx* get_regs(Py_ssize_t pid, struct user_regs_structx* regs);

/**
 *  Convert a user_regs_structx to a python dict
 */
PyObject* regs_to_dictx64(struct user_regs_structx* regs);

/**
 * Convert a user_regs_structx to a python dict
 */
PyObject* regs_to_dictx86(struct user_regs_structx* regs);


/**
 * Set regs for a 64 bits process
 */
PyObject* set_regsx64(PyObject* self, PyObject* args);

/**
 * Set regs for a 32 bits process
 */
PyObject* set_regsx86(PyObject* self, PyObject* args);

/**
 * Ptrace setregs, return regs or return NULL on error and set exception
 */
struct user_regs_structx* set_regs(Py_ssize_t pid, struct user_regs_structx* regs);

/**
 * Copy a python dict to a user_regs_structx (x64)
 */
void dict_to_regsx64(PyObject* dict, struct user_regs_structx* regs);

/**
 * Copy a python dict to a user_regs_structx (x86) 
 */
void dict_to_regsx86(PyObject* self, struct user_regs_structx* regs);

/**
 * Ptrace singleblock on a process with a given PID 
 */
PyObject* singleblock(PyObject* self, PyObject* args);

/**
 * Ptrace continue on a process with a given PID
 */
PyObject* pcontinue(PyObject* self, PyObject* args);

/**
 *  Ptrace syscall on a process with a gived PID
 */
PyObject* psyscall(PyObject* self, PyObject* args);

/**
 * Ptrace step on a process with a given PID
 */
PyObject* step(PyObject* self, PyObject* args);

/**
 * Check process status, if error set exception and return false
 */
bool check_status(int status);

/**
 * Ptrace peektext on a proccess with a given PID and a given addr
 * Return the data (4 bytes on 32 bits, 8 bytes on 64 bits)
 */
PyObject* peek_text(PyObject* self, PyObject* args);

/**
 * Ptrace poketext on a process with a given PID, addr and data 
 */
PyObject* poke_text(PyObject* self, PyObject* args);


/**
 * Returns true if the file exists, false otherwise
 */
bool check_file_exists(const char* path);

/**
 * Parses a PyList of strings to an array of const char*
 */
const char** string_list_to_c_array(PyObject* string_list);

#if defined(__x86_64__)
// user_regs_struct for x86-64
struct user_regs_structx
{
  __extension__ unsigned long long int r15;
  __extension__ unsigned long long int r14;
  __extension__ unsigned long long int r13;
  __extension__ unsigned long long int r12;
  __extension__ unsigned long long int rbp;
  __extension__ unsigned long long int rbx;
  __extension__ unsigned long long int r11;
  __extension__ unsigned long long int r10;
  __extension__ unsigned long long int r9;
  __extension__ unsigned long long int r8;
  __extension__ unsigned long long int rax;
  __extension__ unsigned long long int rcx;
  __extension__ unsigned long long int rdx;
  __extension__ unsigned long long int rsi;
  __extension__ unsigned long long int rdi;
  __extension__ unsigned long long int orig_rax;
  __extension__ unsigned long long int rip;
  __extension__ unsigned long long int cs;
  __extension__ unsigned long long int eflags;
  __extension__ unsigned long long int rsp;
  __extension__ unsigned long long int ss;
  __extension__ unsigned long long int fs_base;
  __extension__ unsigned long long int gs_base;
  __extension__ unsigned long long int ds;
  __extension__ unsigned long long int es;
  __extension__ unsigned long long int fs;
  __extension__ unsigned long long int gs;
};
#endif

#if defined(__i386__)
// user regs_struct for x86
struct user_regs_structx
{
  long int ebx;
  long int ecx;
  long int edx;
  long int esi;
  long int edi;
  long int ebp;
  long int eax;
  long int xds;
  long int xes;
  long int xfs;
  long int xgs;
  long int orig_eax;
  long int eip;
  long int xcs;
  long int eflags;
  long int esp;
  long int xss;
};
#endif

#endif // LDBG_PROCESS_H