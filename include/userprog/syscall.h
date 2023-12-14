#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
void exit_with_status(int status);
struct lock *filesys_lock;

#endif /* userprog/syscall.h */
