#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>  /* include lib/usr/syscall.h for pid_t */

#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"

#include "userprog/process.h"

#include "threads/flags.h"
#include "intrinsic.h"

#include "threads/init.h"

#include "filesys/filesys.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

static void thread_terminate(void);
static void validate_pointer(void * ptr);
static void validate_pointer2(void * ptr);
struct file *validate_fd(int fd);

static int64_t get_user (const uint8_t *uaddr);

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

static void thread_terminate(void){
	thread_current()->exit_status = -1;
	thread_exit();
}
/* 
	첫번째 방법 - 유효성 확인 후 포인터 해제
		thread/mmu.c , vaddr.h 함수 참고
*/
static void validate_pointer(void *ptr){
	struct thread *curr = thread_current();
	uintptr_t ptr_addr = &ptr;

	if(!is_user_vaddr(ptr) 
		|| pml4_get_page(curr->pml4, ptr)==NULL){
		thread_terminate();
	}
}

/*
	두번째 방법 - KERN_BASE 아래 가리키는지만 확인 후 역참조.
*/
static void validate_pointer2(void * ptr){
	struct thread *curr = thread_current();
	uintptr_t ptr_addr = &ptr;

	bool success = false;
	if(!is_user_vaddr(ptr)
		|| get_user(ptr)==-1 //여기서 검사하지 않고 역참조시 검사하는게 맞는 걸수도
	){
		thread_terminate();
	}
}

struct file *validate_fd(int fd){

	if(!check_fd_validate(fd)){
		// printf("not valid fd %d\n",fd);
		thread_terminate();
	}
	
	struct thread *curr = thread_current();
	struct file *file = curr->files[fd];
	// printf("valid fd %d\n",fd);
	// validate_pointer(file); //file은 이미 NULL체크를 했기 때문에 검사할 필요 없다.
	return file;
}

static int64_t
get_user (const uint8_t *uaddr) {
    int64_t result;
    __asm __volatile (
    "movabsq $done_get, %0\n"
    "movzbq %1, %0\n"
    "done_get:\n"
    : "=&a" (result) : "m" (*uaddr));
    return result;
}

static void 
_halt (struct intr_frame *f UNUSED) {
	power_off();
}

static void
_exit_ (struct intr_frame *f) {
	int status = f->R.rdi;

	// const char *thread_name = thread_current()->name;
	// const char *file_name =
	//실행중인 게 하나인지
	// file_allow_write(filename);

	thread_current() -> exit_status = status; //이거 맞나?
	thread_exit ();
}

static void
_fork (struct intr_frame *f){
	const char *thread_name = (char *)f->R.rdi;

	pid_t pid = process_fork(thread_name, f);
	f->R.rax = pid;
}

static void
_exec (struct intr_frame *f) {
	const char *cmd_line = (char *)f->R.rdi;

	
	//file_deny_write(filename);

	int exit_status;
	f->R.rax = exit_status;
}

static void
_wait (struct intr_frame *f) {
	pid_t pid = f->R.rdi;

	int exit_status = process_wait(pid);
	f->R.rax = exit_status;
}

static void
_create (struct intr_frame *f) {
	const char *file = (char *)f->R.rdi;
	unsigned initial_size = f->R.rsi;
	// printf("create file: %s\n", file);
	bool success = false;

	validate_pointer(file);

	if(file!=NULL){
		success = filesys_create(file, initial_size);
	}
	f->R.rax = success;
}

static void
_remove (struct intr_frame *f) {
	const char *filename = (char *)f->R.rdi;
	bool success = filesys_remove(filename);
	f->R.rax = success;
}

static void
_open (struct intr_frame *f) {
	const char *filename = (char *)f->R.rdi;
	const struct file *file;
	const struct thread *curr = thread_current();

	validate_pointer(filename);

	int fd = -1;
	if((file = filesys_open(filename)) != NULL){//reopen 구현
		fd = next_fd(curr);
		fd = apply_fd(curr,fd,file);
	}
	
	f->R.rax = fd;
}

static void
_filesize (struct intr_frame *f) {
	int fd = f->R.rdi;

	struct file* file = validate_fd(fd);

	int fsize = (int)file_length(file);
	f->R.rax = fsize;
}

static void
_read (struct intr_frame *f) {  //0에서 읽기
	int fd = f->R.rdi;
	void *buffer = (void *)f->R.rsi;
	unsigned size = f->R.rdx;

	validate_pointer(buffer);

	struct file* file = validate_fd(fd);

	int r_bytes = (int)file_read(file, buffer, size);
	f->R.rax = r_bytes;
}

static void
_write (struct intr_frame *f) { //1,2에 출력하기
	int fd = f->R.rdi;
	const void *buffer = (void *)f->R.rsi; //&아닌 이유?
	unsigned size = f->R.rdx;

	validate_pointer(buffer);

	struct file* file;
	int w_bytes = -1;
	if(fd==1){
		printf("%s",(char *)buffer);
		w_bytes = size;
	}else{
		if((file =  validate_fd(fd))!=NULL){  //TODO: deny_write 체크
			w_bytes = (int)file_write(file, buffer, size);
		}
	}
	// 
	f->R.rax = w_bytes;
}

static void
_seek (struct intr_frame *f) {
	int fd = f->R.rdi;
	unsigned position = f->R.rsi;

	struct file* file = validate_fd(fd);

	file_seek(file,position);
}

static void
_tell (struct intr_frame *f) {
	int fd = f->R.rdi;

	struct file* file = validate_fd(fd);
	
	unsigned next_bytes = file_tell(file);
	f->R.rax = next_bytes;
}

static void
_close (struct intr_frame *f) { //암시적으로 닫기 (실제로 호출 필요 없어보임)
	int fd = f->R.rdi;
	
	const struct thread *curr = thread_current();

	if(!delete_fd(curr,fd)){
		thread_terminate();
	}
}

static void
_dup2 (struct intr_frame *f){
	int oldfd = f->R.rdi;
	int newfd = f->R.rsi;

	f->R.rax = newfd;
}