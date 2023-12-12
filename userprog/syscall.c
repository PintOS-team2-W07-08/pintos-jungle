#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

bool check_address(const char *file);

void _halt (void);
void _exit (struct intr_frame *f);
int _write (struct intr_frame *f );
// pid_t _fork (struct intr_frame *f );
// int _exec (struct intr_frame *f );
// int _wait (pid_t pid);
bool _create (struct intr_frame *f );
// bool _remove (struct intr_frame *f);
int _open (struct intr_frame *f);
// int _filesize (struct intr_frame *f);
// void _seek (struct intr_frame *f);
// unsigned _tell (struct intr_frame *f);
void _close (struct intr_frame *f);

// int _dup2(int oldfd, int newfd);

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
syscall_handler (struct intr_frame *f UNUSED) {
	// printf("시스템 호출 번호: %d\n", f->R.rax);
	// printf("rdi에 저장된 값: %d\n", f->R.rdi);
	// printf("rsi에 저장된 값: %s\n", f->R.rsi);
	// printf("rdx에 저장된 값: %d\n", f->R.rdx);
	// printf("r10에 저장된 값: %d\n", f->R.r10);
	// printf("r8에 저장된 값: %d\n", f->R.r8);
	// printf("r9에 저장된 값: %d\n", f->R.r9);
	// TODO: Your implementation goes here.
	// Implement system call
	switch(f->R.rax)
	{
		case SYS_HALT:	_halt();	break;
		case SYS_EXIT:	_exit(f);	break;
		// case SYS_FORK:	_fork(f);	break;
		// case SYS_EXEC:	_exec(f);	break;
		// case SYS_WAIT:	_wait(pid);	break;
		// case SYS_CREATE:	_create(f);	break;
		// case SYS_REMOVE:	_remove(f);	break;
		case SYS_OPEN:	_open(f);	break;
		// case SYS_FILESIZE:	_filesize(f);	break;
		// case SYS_READ:	_read(f);	break;
		case SYS_WRITE:	_write(f);	break;
		// case SYS_SEEK:	_seek(f);	break;
		// case SYS_TELL:	_tell(f);	break;
		case SYS_CLOSE:	_close(f);	break;
		// case SYS_DUP2:	_dup2();	break;
		default:
			break;
	}
	// printf ("system call!\n");
	// thread_exit ();
}

// Implement system call
void 
_halt (void) {
	power_off();                                           
}

void
_exit (struct intr_frame *f) {
	// 현재 사용자 프로그램 종료 + status 커널로 반환
	thread_current()->tf.exit_status = f->R.rdi;
	thread_exit();
	// TODO: 프로세스 부모가 wait인 경우, 부모는 이 status를 반환
}

bool
_create (struct intr_frame *f) {
	const char *file = f->R.rdi;
	int initial_size = f->R.rsi;
	// ASSERT 잘못된 주소의 접근 막기 (NULL값이거나 PHYS_BASE 위의 주소이다)
	bool success = false;
	if(!check_address(file)) {
		return false;
	}
	// initial_size 바이트 크기의 file 이라는 새 파일 만듦
	return filesys_create(file, initial_size);
	// 주의: 새 파일 만든다해서 파일 열리지는 않음. 열려면, open() 필요
}

bool
check_address(const char *file) {
	struct thread *curr = thread_current();
	uint64_t *_pml4 = curr -> pml4;
	// NULL 포인터인지는 알아서 걸러줌.
	// PHYS_BASE 아래의 주소인지 && 페이지 할당이 되었는지(함수로 구현되어 있음.)
	if(is_user_vaddr(file) && pml4_get_page(_pml4, file) != NULL) {
		return true;
	}
	return false;
}



int _write(struct intr_frame *f) {
	printf("%s", f->R.rsi);
	return 0;
}

// pid_t _fork (const char *thread_name) {
// 	const char *thread_name = f->R.rdi;
// 	pid_t child_process;

// 	return child_process;
// }

// int _exec (struct intr_frame *f) {
// 	char *cmd_line= f->R.rdi;
	
// 	return(0); // 정상일때
// }

// int _wait (pid_t) {

// }
// bool _remove (struct intr_frame *f);

int _open (struct intr_frame *f) {
	struct char *file = f->R.rdi;
	struct thread *curr = thread_current();
	struct file *arr_fdt[64] = curr -> fdt;
	int i;

	// inode가 NULL인 비어있는 FD찾기
	for (i = 3; i< 64 ;i++){
		if(arr_fdt[i].inode == NULL){
			arr_fdt[i].inode = file->inode;
			return i;
		}
	}
}

// int _filesize (struct intr_frame *f);

// int _read (struct intr_frame *f);

// void _seek (struct intr_frame *f);

// unsigned _tell (struct intr_frame *f);

// void _close (struct intr_frame *f);
