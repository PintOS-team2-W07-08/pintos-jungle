#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#define COMMANDLINE_LENGTH 128
#define ARGUMENT_LENGTH COMMANDLINE_LENGTH/2

#include "threads/thread.h"
#include "threads/synch.h"

struct semaphore_elem {
	struct list_elem elem;              /* List element. */
	struct semaphore semaphore;         /* This semaphore. */
};

// struct semaphore_tid_elem {
// 	tid_t tid;
// 	struct list_elem elem;              /* List element. */
// 	struct semaphore semaphore;         /* This semaphore. */
// };

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);

uintptr_t argument_stack(uintptr_t *if_rsp, char **argv, int argc);

#endif /* userprog/process.h */
