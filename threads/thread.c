#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>

#include "threads/malloc.h"
#include "threads/fixed_point.h"

#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* Random value for basic thread
   Do not modify this value. */
#define THREAD_BASIC 0xd42df210

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;
static struct list sleep_list;

static int64_t global_wakeup_tick;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;
static struct lock mlfq_lock;

/* Thread destruction requests */
static struct list destruction_req;

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;
static struct list multiple_ready_list[PRI_MAX - PRI_MIN + 1];
static struct list temp_ready_list[PRI_MAX - PRI_MIN + 1];

static fixed_point load_avg;
static int ready_threads = 0;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *next_thread_to_run (void);
static struct thread *next_mlfqs_thread_to_run(void);
static void init_thread (struct thread *, const char *name, int priority);
static void do_schedule(int status);
static void schedule (void);
static tid_t allocate_tid (void);

/* Returns true if T appears to point to a valid thread. */
#define is_thread(t) ((t) != NULL && (t)->magic == THREAD_MAGIC)

/* Returns the running thread.
 * Read the CPU's stack pointer `rsp', and then round that
 * down to the start of a page.  Since `struct thread' is
 * always at the beginning of a page and the stack pointer is
 * somewhere in the middle, this locates the curent thread. */
#define running_thread() ((struct thread *) (pg_round_down (rrsp ())))


// Global descriptor table for the thread_start.
// Because the gdt will be setup after the thread_init, we should
// setup temporal gdt first.
static uint64_t gdt[3] = { 0, 0x00af9a000000ffff, 0x00cf92000000ffff };

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) {
	ASSERT (intr_get_level () == INTR_OFF);

	/* Reload the temporal gdt for the kernel
	 * This gdt does not include the user context.
	 * The kernel will rebuild the gdt with user context, in gdt_init (). */
	struct desc_ptr gdt_ds = {
		.size = sizeof (gdt) - 1,
		.address = (uint64_t) gdt
	};
	lgdt (&gdt_ds);

	/* Init the globla thread context */
	lock_init (&tid_lock);
	lock_init (&mlfq_lock);

	if(!thread_mlfqs){
		list_init (&ready_list);
	}else{
		// printf("multiple_ready_list\n");
		for (int i = PRI_MIN; i<=PRI_MAX; i++){
			// printf("multipe_ready_list %d is null: %d\n", i, &multiple_ready_list[i]==NULL);
			list_init(&multiple_ready_list[i]);
			list_init(&temp_ready_list[i]);
		}
	}

	list_init (&destruction_req);
	list_init (&sleep_list);

	/* Set up a thread structure for the running thread. */
	initial_thread = running_thread ();
	init_thread (initial_thread, "main", PRI_DEFAULT);
	initial_thread->status = THREAD_RUNNING;
	initial_thread->tid = allocate_tid ();
	initial_thread->wakeup_tick = -1;
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) {
	/* Create the idle thread. */
	struct semaphore idle_started;
	sema_init (&idle_started, 0);
	thread_create ("idle", PRI_MIN, idle, &idle_started);

	/* Start preemptive thread scheduling. */
	intr_enable ();

	/* Wait for the idle thread to initialize idle_thread. */
	sema_down (&idle_started);
}

/*
	wakeup_tick의 오름차순으로 sleep_list에 넣고, block한다.
*/
void thread_sleep(int64_t ticks){
	enum intr_level old_level;
	struct thread *curr = thread_current ();
	
	old_level = intr_disable ();
	ASSERT (!intr_context ());
	
	if (curr != idle_thread ){
		curr->wakeup_tick = ticks;
		list_insert_ordered(&sleep_list, &curr->elem, less_wakeup_tick, NULL);
		if(ticks < global_wakeup_tick){
			set_global_wakeup_tick(ticks);
		}
		thread_block();
	}
	//global tick 업데이트 (thread_tick)
	intr_set_level (old_level);
};

void set_global_wakeup_tick(int64_t ticks){
	global_wakeup_tick=ticks;
}

int64_t get_global_wakeup_tick(void){
	return global_wakeup_tick; 
}

struct list_elem *get_sleep_list_begin(void){
	// list_sort(&sleep_list, less_wakeup_tick, NULL);
	return list_begin (&sleep_list);
}

struct list_elem *get_sleep_list_tail(void){
	return list_tail(&sleep_list);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) {
	struct thread *t = thread_current ();

	/* Update statistics. */
	if (t == idle_thread)
		idle_ticks++;
#ifdef USERPROG
	else if (t->pml4 != NULL)
		user_ticks++;
#endif
	else
		kernel_ticks++;

	/* Enforce preemption. */
	if (++thread_ticks >= TIME_SLICE)
		intr_yield_on_return ();
}

/* Prints thread statistics. */
void
thread_print_stats (void) {
	printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
			idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
		thread_func *function, void *aux) {
	struct thread *t;
	tid_t tid;

	ASSERT (function != NULL);

	/* Allocate thread. */
	t = palloc_get_page (PAL_ZERO);
	if (t == NULL)
		return TID_ERROR;

	/* Initialize thread. */
	init_thread (t, name, priority);

	tid = t->tid = allocate_tid ();

	/* Call the kernel_thread if it scheduled.
	 * Note) rdi is 1st argument, and rsi is 2nd argument. */
	t->tf.rip = (uintptr_t) kernel_thread;
	t->tf.R.rdi = (uint64_t) function;
	t->tf.R.rsi = (uint64_t) aux;
	t->tf.ds = SEL_KDSEG;
	t->tf.es = SEL_KDSEG;
	t->tf.ss = SEL_KDSEG;
	t->tf.cs = SEL_KCSEG;
	t->tf.eflags = FLAG_IF;

	/* Add to run queue. */
	thread_unblock (t);
	// if(t!=thread_current() && (name,"idle")==0 && t->base_priority > thread_current()->base_priority){
	// 	thread_launch(t);
	// }
	thread_preemtion();

	return tid;
}

/* 
   BLOCK 상태로 바꾸고, 스케줄링(ready_list에서 다음 실행 쓰레드를 선택해 실행)
   sleep_list나 ready_list에 넣은 뒤에 호출해야 다음 실행으로 잡힌다.
   그렇지 않으면 메모리만 먹고, 죽지도 않음.

   Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) {
	ASSERT (!intr_context ());
	ASSERT (intr_get_level () == INTR_OFF);
	thread_current ()->status = THREAD_BLOCKED;
	schedule ();
}

/* 
   상태를 READY로 바꾸고 ready_list에 집어넣는다. 
   Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) {
	enum intr_level old_level;

	ASSERT (is_thread (t));

	old_level = intr_disable ();
	ASSERT (t->status == THREAD_BLOCKED);
	if(!thread_mlfqs) {
		list_push_back(&ready_list, &t->elem); // 변동 있을 수 있으므로 ordered필요 없다.
	}
	else {
		// ASSERT(strcmp(t->name,"idle")!=0);
		// if(strcmp(t->name,"idle")!=0){
			
		// }
		list_push_back(&multiple_ready_list[t->base_priority], &(t->elem));
		ready_threads += 1;
		// if(t==idle_thread){
			
		// }
		// TIL: idle은 if(ready_list=empty) 일때 실행되기 때문에 count 안해도됌
	}
	t->status = THREAD_READY;
	intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void) {
	return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) {
	struct thread *t = running_thread ();

	/* Make sure T is really a thread.
	   If either of these assertions fire, then your thread may
	   have overflowed its stack.  Each thread has less than 4 kB
	   of stack, so a few big automatic arrays or moderate
	   recursion can cause stack overflow. */
	ASSERT (is_thread (t));
	ASSERT (t->status == THREAD_RUNNING);

	return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) {
	return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) {
	ASSERT (!intr_context ());

#ifdef USERPROG
	process_exit ();
#endif

	/* Just set our status to dying and schedule another process.
	   We will be destroyed during the call to schedule_tail(). */
	intr_disable ();
	do_schedule (THREAD_DYING);
	NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) {
	struct thread *curr = thread_current ();
	enum intr_level old_level;

	ASSERT (!intr_context ());

	old_level = intr_disable ();
	if (curr != idle_thread){
		if(!thread_mlfqs){
			list_push_back(&ready_list, &curr->elem);
		}
	}
	if(thread_mlfqs){
		// printf("multiple[%d]에 push\n",curr->base_priority);
		list_push_back(&multiple_ready_list[curr->base_priority], &curr->elem);
		ready_threads += 1;
	}
	
	do_schedule (THREAD_READY);
	intr_set_level (old_level);
}

void
thread_preemtion(void){
	if(!thread_mlfqs){
		if(!list_empty(&ready_list)){
			struct thread *curr = thread_current();
			list_sort(&ready_list, bigger_priority, NULL);
			struct list_elem *front_elem = list_front(&ready_list);
			struct thread *first_thread = list_entry(front_elem, struct thread, elem);
			if(first_thread->priority > curr->priority){
				thread_yield();
			}
		}
	}else{
		if(ready_threads!=0){
			struct thread *curr = thread_current();
			int ready_priority = highest_priority();
			if(ready_priority > curr->base_priority){
				printf("mlfq priority: %d\n", ready_priority);
				thread_yield();
			}
		}
	}
}

int highest_priority(void){
	struct list *mlfq;
	for(int i = PRI_MAX; i >= PRI_MIN; i--) {
		mlfq = &multiple_ready_list[i];
		if(!list_empty(mlfq)) return i;
	}
	ASSERT(false);
	return -1;
}

struct list_elem *mlfq_begin(void){
	struct list *mlfq;
	for(int i = PRI_MAX; i >= PRI_MIN; i--) {
		mlfq = &multiple_ready_list[i];
		// list_thread_dump(mlfq);
		if(list_empty(mlfq)) continue;
		// printf("list안의 갯수 %d", list_size(mlfq));
		// list_sort(mlfq, bigger_base_priority, NULL);
		return list_front(mlfq);
	}
	ASSERT(false);
	return NULL;
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) {
	// printf("우선권 설정\n");
	if(thread_mlfqs) return;

	struct thread *thrd = thread_current();
	thrd->base_priority = new_priority;
	thrd->priority = new_priority;
	
	if(!list_empty(&(thrd->donor_list))){
		list_sort(&(thrd->donor_list),bigger_priority_donor,NULL);
		thrd->priority = list_entry(list_front(&(thrd->donor_list)), struct thread, donor_elem) -> priority;
		// thrd->priority = list_min(&(thrd->donor_list), bigger_priority_donor, NULL);
	}
	thread_preemtion();
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) {
	// printf("우선권 가져오기\n");
	struct thread* thisThrd = thread_current();
	if(!thread_mlfqs){
		return thread_get_superficial_priority(thisThrd);
	}
	else {
		return thread_get_base_priority(thisThrd);
	}
}

int
thread_get_superficial_priority(struct thread* Thread){
	return Thread->priority;
}

int 
thread_get_base_priority(struct thread* Thread){
	// printf("기본 우선권 가져오기\n");
	return Thread->base_priority;
}

void 
thread_donate_priority(struct thread* toThread, struct thread* donor){
	if(thread_mlfqs) return; //TIL
	// printf("우선권 기부하기 -> %d\n", prioirty);
	ASSERT(&(toThread->donor_list)!=NULL);
	struct thread* nowThrd = toThread;
	toThread->priority = donor->priority;	
	list_push_back(&(toThread->donor_list), &donor->donor_elem);
	
	while(nowThrd->waitonlock){
		struct lock *lock = nowThrd->waitonlock;
		struct thread *holder = lock->holder;
		// list_push_back(&(holder->donor_list), &nowThrd->donor_elem);
		holder->priority = nowThrd->priority; //무조건 높은애만 들어옴
		nowThrd = holder;
	}
	thread_yield();
}

void 
thread_recall_priority(struct lock *lock){
	if(thread_mlfqs) return; //TIL

	struct thread* thrd = thread_current();
	// printf("우선권 반납준비\n");
	ASSERT(&(thrd->donor_list)!=NULL);
	struct list *list= &(thrd->donor_list);
	struct thread *threadA;
	struct list_elem *e;
	for (e = list_begin (list); e != list_end (list); e = list_next (e)){
		threadA = list_entry(e, struct thread, donor_elem);
		if(threadA->waitonlock == lock){
			list_remove(e);
		}
	}
	if(!list_empty(list)){
		list_sort(list, bigger_priority_donor, NULL);
		thrd->priority = list_entry(list_front(list), struct thread, donor_elem)->priority;
	}else{
		thrd->priority = thrd->base_priority;
	}
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice) {
	enum intr_level old_level;
	old_level = intr_disable ();
	struct thread* thrd = thread_current();
	thrd -> niceness = nice;
	// bool flag = thrd->status == THREAD_READY;
	// ASSERT(thrd->status == THREAD_RUNNING);
	// thread_calculate_priority(thrd, (bool *)flag);
	thread_calculate_priority_all();
	thread_preemtion();
	intr_set_level (old_level);
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) {  //TIL
	enum intr_level old_level;
	old_level = intr_disable ();
	struct thread* thrd = thread_current();
	int result = thrd -> niceness;
	intr_set_level (old_level);
	return result;
}

/* Set the system load average. */
void
thread_set_load_avg (void) {
	int ready_threads_with_run = ready_threads;
	if(thread_current()!=idle_thread){
		ready_threads_with_run+=1;
	} 
	fixed_point f60 = int_to_fp(60);
	fixed_point f59 = int_to_fp(59);
	fixed_point f1 = int_to_fp(1);
	fixed_point f59_60 = fp_div_fp(f59,f60);
	fixed_point f1_60 = fp_div_fp(f1,f60);
	//fp_add_fp;
	fixed_point pre = fp_mult_fp(f59_60,load_avg);
	fixed_point post = fp_mult_int(f1_60, ready_threads_with_run);
	load_avg = fp_add_fp(pre,post);
	return ;		
}
 
/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) {
	enum intr_level old_level;
	old_level = intr_disable ();
	int result = fp_to_int_round_near(fp_mult_int(load_avg, 100));
	intr_set_level (old_level);
	return result;
}


/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) {
	enum intr_level old_level;
	old_level = intr_disable ();
	struct thread* thrd = thread_current();
	int result = fp_to_int_round_near(fp_mult_int(thrd -> recent_cpu, 100));
	intr_set_level (old_level);
	return result;
}

void
thread_calculate_recent_cpu (struct thread* thrd, void *aux UNUSED){
	ASSERT(thrd!=idle_thread);
	if(thrd==idle_thread) return;
	
	int nice = thrd->niceness;
	fixed_point recent_cpu = thrd->recent_cpu;
	fixed_point decay_child = fp_mult_int(load_avg,2);
	fixed_point decay_parent = fp_add_int(decay_child,1);
	fixed_point decay = fp_div_fp(decay_child,decay_parent); 
	recent_cpu = fp_add_int(fp_mult_fp(decay, recent_cpu) ,nice);
	thrd->recent_cpu = recent_cpu;
	return;
} 

void thread_calculate_priority(struct thread *thrd, void *aux) {
	ASSERT(thrd!=idle_thread);
	if(thrd==idle_thread) return;

	fixed_point recent_cpu = thrd->recent_cpu;
	int nice = thrd->niceness;

	fixed_point cpu_4 = fp_div_int(recent_cpu,4);
	fixed_point fixed_PRI_MAX = int_to_fp(PRI_MAX);
	// int checkPRI_MAX = fp_to_int_round_near(fixed_PRI_MAX);

	fixed_point priority = fp_sub_int(fp_sub_fp(fixed_PRI_MAX,cpu_4), (nice * 2));
	int trun_priority = fp_to_int_round_near(priority);
	
	int before_priority = thrd -> base_priority;
	thrd -> base_priority = trun_priority;
	
	struct list_elem *e = &(thrd->elem);

	bool in_ready_list = (bool *)aux == (bool *)1;
	if(in_ready_list && before_priority!=trun_priority){ //ready 여부
		ASSERT(in_ready_list==true);
		ASSERT(thrd!=idle_thread);
		list_remove(e);
		list_push_back(&temp_ready_list[trun_priority], e);
	}
	return;
}

void thread_calculate_priority_all(void){
	//current_thread
	thread_calculate_priority(thread_current(),(bool *)false);
	
	//multiple_ready_list
	struct list *list;
	ASSERT(ready_threads>=0);
	if(ready_threads>0){
		// lock_acquire(&mlfq_lock);
		
		for (int i = PRI_MAX; i >= PRI_MIN; i--){
			list = &multiple_ready_list[i];
			execute_func_in_list(list, thread_calculate_priority, (bool *)true);
		}

		//swap
		struct list *temp;

		for (int i = PRI_MIN; i <= PRI_MAX; i++) {
			temp = &multiple_ready_list[i - PRI_MIN];
			multiple_ready_list[i - PRI_MIN] = temp_ready_list[i - PRI_MIN];
			temp_ready_list[i - PRI_MIN] = *temp;
		}
		
		// lock_release(&mlfq_lock);
	}
	
	//sleep list
	if(!list_empty(&sleep_list)){	
		// lock_acquire(&mlfq_lock);
		execute_func_in_list(&sleep_list, thread_calculate_priority, (bool *)false);
		// lock_release(&mlfq_lock);
	}
	// thread_preemtion();
	
}

//TIL
void execute_func_in_list(struct list *list, list_exec_func func, void *aux){
	if(list_empty(list)) return;
	struct list_elem * e;
	struct thread* thrd;
	struct list_elem *nexte;
	for (e = list_front (list); e != list_tail (list); e = nexte){
		nexte = list_next(e);
		thrd = list_entry(e, struct thread, elem);
		func(thrd, (void *)aux);
	}
}

void thread_calculate_recent_cpu_all(void){
	thread_calculate_recent_cpu(thread_current(), NULL);
	//multiple_ready_list
	struct list *list;
	for (int i = PRI_MAX; i >= PRI_MIN; i--){
		list = &multiple_ready_list[i];
		execute_func_in_list(list, thread_calculate_recent_cpu, NULL);
	}
	//sleep list
	execute_func_in_list(&sleep_list, thread_calculate_recent_cpu, NULL);
}


/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) {
	struct semaphore *idle_started = idle_started_;

	idle_thread = thread_current ();
	sema_up (idle_started);

	for (;;) {
		/* Let someone else run. */
		intr_disable ();
		thread_block ();

		/* Re-enable interrupts and wait for the next one.

		   The `sti' instruction disables interrupts until the
		   completion of the next instruction, so these two
		   instructions are executed atomically.  This atomicity is
		   important; otherwise, an interrupt could be handled
		   between re-enabling interrupts and waiting for the next
		   one to occur, wasting as much as one clock tick worth of
		   time.

		   See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
		   7.11.1 "HLT Instruction". */
		asm volatile ("sti; hlt" : : : "memory");
	}
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) {
	ASSERT (function != NULL);

	intr_enable ();       /* The scheduler runs with interrupts off. */
	function (aux);       /* Execute the thread function. */
	thread_exit ();       /* If function() returns, kill the thread. */
}


/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority) {
	ASSERT (t != NULL);
	ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
	ASSERT (name != NULL);

	memset (t, 0, sizeof *t);
	t->status = THREAD_BLOCKED;
	strlcpy (t->name, name, sizeof t->name);
	t->tf.rsp = (uint64_t) t + PGSIZE - sizeof (void *);

	if(!thread_mlfqs) {
		t->base_priority = priority;
		t->priority = priority;
		list_init(&(t->donor_list));
	}
	else {
		struct thread *parent_thread = running_thread();
		if(is_thread(parent_thread)){
			t->niceness = parent_thread->niceness;
			t->recent_cpu = parent_thread->recent_cpu;
		}else{
			t->niceness = 0;
			t->recent_cpu = 0;
		}
		thread_calculate_priority(t, (bool *)false);
		t->priority = PRI_MAX + 1;
	} 

	t->magic = THREAD_MAGIC;
	return;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) {
	if (list_empty (&ready_list)) return idle_thread; //thread_current();
	else {
		list_sort(&ready_list, bigger_priority, NULL);
		return list_entry(list_pop_front(&ready_list), struct thread, elem);
	}
}

static struct thread * 
next_mlfqs_thread_to_run(void) {

	struct thread* run_thrd = running_thread();
	ASSERT(ready_threads>=0);
	// printf("ready_threads: %d\n", ready_threads);
	if (ready_threads == 0){
		ASSERT(run_thrd->status!=THREAD_RUNNING);
		if(run_thrd->status==THREAD_RUNNING){
			return run_thrd;
		}
	}else{

		// ASSERT(run_thrd->status==THREAD_BLOCKED);
		// ASSERT(run_thrd!=idle_thread);
		// if(run_thrd->status==THREAD_BLOCKED && run_thrd!=idle_thread){
		// 	thread_unblock(run_thrd);
		// }

		struct list *mlfq;
		struct thread* thrd;
		// lock_acquire(&mlfq_lock);
		for(int i = PRI_MAX; i >= run_thrd->base_priority; i--) {
			mlfq = &multiple_ready_list[i];
			// list_thread_dump(mlfq);
			if(list_empty(mlfq)) continue;
			// printf("list안의 갯수 %d", list_size(mlfq));
			list_sort(mlfq, bigger_base_priority, NULL);
			thrd = list_entry(list_pop_front(mlfq), struct thread, elem);
			ready_threads -= 1;
			// if(thrd!=idle_thread){
				
			// }
			// printf("쓰레드 명: %s\n",thrd->name);
			ASSERT(is_thread(thrd));
			return thrd;
		}
		ASSERT(is_thread(thrd));
		// lock_release(&mlfq_lock);
		return run_thrd;
	}
}

bool less_wakeup_tick(const struct list_elem *a, 
				   const struct list_elem *b, 
				   void *aux UNUSED){
	struct thread *threadA = list_entry(a, struct thread, elem);
	struct thread *threadB = list_entry(b, struct thread, elem);
	if(threadA->wakeup_tick < threadB->wakeup_tick){
		return true;
	}else{
		return false;
	}
}

bool bigger_priority(const struct list_elem *a, 
				   const struct list_elem *b, 
				   void *aux UNUSED){
	struct thread *threadA = list_entry(a, struct thread, elem);
	struct thread *threadB = list_entry(b, struct thread, elem);
	if(threadA->priority > threadB->priority){
		return true;
	}else{
		return false;
	}
}

bool lesser_priority(const struct list_elem *a, 
				   const struct list_elem *b, 
				   void *aux UNUSED){
	struct thread *threadA = list_entry(a, struct thread, elem);
	struct thread *threadB = list_entry(b, struct thread, elem);
	if(threadA->priority < threadB->priority){
		return true;
	}else{
		return false;
	}
}

bool bigger_base_priority(const struct list_elem *a, 
				   const struct list_elem *b, 
				   void *aux UNUSED){
	struct thread *threadA = list_entry(a, struct thread, elem);
	struct thread *threadB = list_entry(b, struct thread, elem);
	if(threadA->base_priority > threadB->base_priority){
		return true;
	}else{
		return false;
	}
}

bool bigger_priority_donor(const struct list_elem *a, 
				   const struct list_elem *b, 
				   void *aux UNUSED){
	struct thread *threadA = list_entry(a, struct thread, donor_elem);
	struct thread *threadB = list_entry(b, struct thread, donor_elem);
	if(threadA->priority > threadB->priority){
		return true;
	}else{
		return false;
	}
}

/* Use iretq to launch the thread */
void
do_iret (struct intr_frame *tf) {
	__asm __volatile(
			"movq %0, %%rsp\n"
			"movq 0(%%rsp),%%r15\n"
			"movq 8(%%rsp),%%r14\n"
			"movq 16(%%rsp),%%r13\n"
			"movq 24(%%rsp),%%r12\n"
			"movq 32(%%rsp),%%r11\n"
			"movq 40(%%rsp),%%r10\n"
			"movq 48(%%rsp),%%r9\n"
			"movq 56(%%rsp),%%r8\n"
			"movq 64(%%rsp),%%rsi\n"
			"movq 72(%%rsp),%%rdi\n"
			"movq 80(%%rsp),%%rbp\n"
			"movq 88(%%rsp),%%rdx\n"
			"movq 96(%%rsp),%%rcx\n"
			"movq 104(%%rsp),%%rbx\n"
			"movq 112(%%rsp),%%rax\n"
			"addq $120,%%rsp\n"
			"movw 8(%%rsp),%%ds\n"
			"movw (%%rsp),%%es\n"
			"addq $32, %%rsp\n"
			"iretq"
			: : "g" ((uint64_t) tf) : "memory");
}

/* Switching the thread by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function. */
static void
thread_launch (struct thread *th) {
	uint64_t tf_cur = (uint64_t) &running_thread ()->tf;
	uint64_t tf = (uint64_t) &th->tf;
	ASSERT (intr_get_level () == INTR_OFF);

	/* The main switching logic.
	 * We first restore the whole execution context into the intr_frame
	 * and then switching to the next thread by calling do_iret.
	 * Note that, we SHOULD NOT use any stack from here
	 * until switching is done. */
	__asm __volatile (
			/* Store registers that will be used. */
			"push %%rax\n"
			"push %%rbx\n"
			"push %%rcx\n"
			/* Fetch input once */
			"movq %0, %%rax\n"
			"movq %1, %%rcx\n"
			"movq %%r15, 0(%%rax)\n"
			"movq %%r14, 8(%%rax)\n"
			"movq %%r13, 16(%%rax)\n"
			"movq %%r12, 24(%%rax)\n"
			"movq %%r11, 32(%%rax)\n"
			"movq %%r10, 40(%%rax)\n"
			"movq %%r9, 48(%%rax)\n"
			"movq %%r8, 56(%%rax)\n"
			"movq %%rsi, 64(%%rax)\n"
			"movq %%rdi, 72(%%rax)\n"
			"movq %%rbp, 80(%%rax)\n"
			"movq %%rdx, 88(%%rax)\n"
			"pop %%rbx\n"              // Saved rcx
			"movq %%rbx, 96(%%rax)\n"
			"pop %%rbx\n"              // Saved rbx
			"movq %%rbx, 104(%%rax)\n"
			"pop %%rbx\n"              // Saved rax
			"movq %%rbx, 112(%%rax)\n"
			"addq $120, %%rax\n"
			"movw %%es, (%%rax)\n"
			"movw %%ds, 8(%%rax)\n"
			"addq $32, %%rax\n"
			"call __next\n"         // read the current rip.
			"__next:\n"
			"pop %%rbx\n"
			"addq $(out_iret -  __next), %%rbx\n"
			"movq %%rbx, 0(%%rax)\n" // rip
			"movw %%cs, 8(%%rax)\n"  // cs
			"pushfq\n"
			"popq %%rbx\n"
			"mov %%rbx, 16(%%rax)\n" // eflags
			"mov %%rsp, 24(%%rax)\n" // rsp
			"movw %%ss, 32(%%rax)\n"
			"mov %%rcx, %%rdi\n"
			"call do_iret\n"
			"out_iret:\n"
			: : "g"(tf_cur), "g" (tf) : "memory"
			);
}

/* 
   실행중(running)인 쓰레드를 satus로 상태를 바꾸고, 
   destruction큐의 쓰레드 메모리 해제하고, 
   스케줄링한다.
   Schedules a new process. At entry, interrupts must be off.
 * This function modify current thread's status to status and then
 * finds another thread to run and switches to it.
 * It's not safe to call printf() in the schedule(). */
static void
do_schedule(int status) {
	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (thread_current()->status == THREAD_RUNNING);
	while (!list_empty (&destruction_req)) {
		struct thread *victim =
			list_entry(list_pop_front (&destruction_req), struct thread, elem);
		// free(victim->donor_list);
		palloc_free_page(victim);
	}
	thread_current ()->status = status;
	schedule ();
}

/*
	다음 실행 쓰레드(next)를 결정한다.
	현재 쓰레드가 DYING이라면 destruction 큐에 넣는다.
	next를 launch한다. (컨텍스트 스위치)
*/
static void
schedule (void) {
	struct thread *curr = running_thread ();
	struct thread *next;
	// printf("thread_mlfqs : %d\n", thread_mlfqs);
	if (!thread_mlfqs){
		// printf("거짓\n");
		next = next_thread_to_run();
	}else{
		// printf("참\n");
		next = next_mlfqs_thread_to_run();
	}

	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (curr->status != THREAD_RUNNING);
	ASSERT (is_thread (next));
	/* Mark us as running. */
	next->status = THREAD_RUNNING;

	/* Start new time slice. */
	thread_ticks = 0;

#ifdef USERPROG
	/* Activate the new address space. */
	process_activate (next);
#endif

	if (curr != next) {
		/* If the thread we switched from is dying, destroy its struct
		   thread. This must happen late so that thread_exit() doesn't
		   pull out the rug under itself.
		   We just queuing the page free reqeust here because the page is
		   currently used by the stack.
		   The real destruction logic will be called at the beginning of the
		   schedule(). */
		if (curr && curr->status == THREAD_DYING && curr != initial_thread) {
			ASSERT (curr != next);
			list_push_back (&destruction_req, &curr->elem);
		}

		/* Before switching the thread, we first save the information
		 * of current running. */
		thread_launch (next);
	}
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) {
	static tid_t next_tid = 1;
	tid_t tid;

	lock_acquire (&tid_lock);
	tid = next_tid++;
	lock_release (&tid_lock);

	return tid;
}

void list_thread_dump(struct list *list){
	enum intr_level old_level;
	old_level = intr_disable ();
	struct list_elem *e;
	ASSERT (list != NULL);
	struct thread *threadA;
	printf("------list dump------\n");
	for (e = list_begin (list); e != list_end (list); e = list_next (e)){
		threadA = list_entry(e, struct thread, elem);
		printf("priority: %d, tid: %d\n",threadA->base_priority,threadA->tid);
	}
	printf("-----------------------\n");
	intr_set_level (old_level);
	return;
}