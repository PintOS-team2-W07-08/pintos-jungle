#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

#include "threads/init.h"
#include <lib/user/syscall.h>  /* include lib/usr/syscall.h for pid_t */

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

static void _halt (struct intr_frame *);
static void _exit_ (struct intr_frame *);
static void _fork (struct intr_frame *);
static void _exec (struct intr_frame *);
static void _wait (struct intr_frame *);
static void _create (struct intr_frame *);
static void _remove (struct intr_frame *);
static void _open (struct intr_frame *);
static void _filesize (struct intr_frame *);
static void _read (struct intr_frame *);
static void _write (struct intr_frame *);
static void _seek (struct intr_frame *);
static void _tell (struct intr_frame *);
static void _close (struct intr_frame *);
static void _dup2 (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {
	// printf ("system call! #:%d\n", (int)f->R.rax);
	// printf("thread name: %s\n",thread_current()->name);

	switch((int)f->R.rax){
		case SYS_HALT :  	_halt (f); 		break;
		case SYS_EXIT :  	_exit_ (f); 	break;  
		case SYS_FORK :  	_fork (f); 		break;  
		case SYS_EXEC : 	_exec (f); 		break;  
		case SYS_WAIT :  	_wait (f); 		break;  
		case SYS_CREATE : 	_create (f); 	break;  
		case SYS_REMOVE :  	_remove (f);  	break;  
		case SYS_OPEN :  	_open (f);  	break;  
		case SYS_FILESIZE : _filesize (f); 	break;  
		case SYS_READ : 	_read (f);  	break;  
		case SYS_WRITE :	_write (f);		break;  
		case SYS_SEEK :  	_seek (f); 		break;  
		case SYS_TELL : 	_tell (f); 		break;  
		case SYS_CLOSE : 	_close (f); 	break;
		case SYS_DUP2 : 	_dup2 (f); 		break;  
		default :
			printf("없는 시스템 콜입니다.\n");
			thread_exit (); //변경
			break;
	} 
	return; //변경
}

static void 
_halt (struct intr_frame *f UNUSED) {
	power_off();
}

static void
_exit_ (struct intr_frame *f) {
	int status = f->R.rdi;
	thread_current() -> exit_status = status;
	thread_exit ();
}

static void
_fork (struct intr_frame *f){
	const char *thread_name = (char *)f->R.rdi;

	pid_t pid;
	f->R.rax = pid;
}

static void
_exec (struct intr_frame *f) {
	const char *file = (char *)f->R.rdi;

	int exit_status;
	f->R.rax = exit_status;
}

static void
_wait (struct intr_frame *f) {
	pid_t pid = f->R.rdi;

	int exit_status;
	f->R.rax = exit_status;
}

static void
_create (struct intr_frame *f) {
	const char *file = (char *)f->R.rdi;
	unsigned initial_size = f->R.rsi;


	bool success;
	f->R.rax = success;
}

static void
_remove (struct intr_frame *f) {
	const char *file = (char *)f->R.rdi;
	

	bool success;
	f->R.rax = success;
}

static void
_open (struct intr_frame *f) {
	const char *file = (char *)f->R.rdi;
	
	int fd ;
	f->R.rax = fd;
}

static void
_filesize (struct intr_frame *f) {
	int fd = f->R.rdi;
	
	int fsize;
	f->R.rax = fsize;
}

static void
_read (struct intr_frame *f) {
	int fd = f->R.rdi;
	void *buffer = (void *)f->R.rsi;
	unsigned size = f->R.rdx;
	
	
	int r_bytes;
	f->R.rax = r_bytes;
}

static void
_write (struct intr_frame *f) {
	int fd = f->R.rdi;
	const void *buffer = (void *)f->R.rsi; //&아닌 이유?
	unsigned size = f->R.rdx;

	printf("%s",(char *)buffer);

	int w_bytes;
	f->R.rax = w_bytes;
}

static void
_seek (struct intr_frame *f) {
	int fd = f->R.rdi;
	unsigned position = f->R.rsi;
	
}

static void
_tell (struct intr_frame *f) {
	int fd = f->R.rdi;


	unsigned next_bytes;
	f->R.rax = next_bytes;
}

static void
_close (struct intr_frame *f) {
	int fd = f->R.rdi;
	
}

static void
_dup2 (struct intr_frame *f){
	int oldfd = f->R.rdi;
	int newfd = f->R.rsi;

	f->R.rax = newfd;
}