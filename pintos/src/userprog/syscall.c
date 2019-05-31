#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <devices/shutdown.h>
#include <threads/vaddr.h>
#include <filesys/filesys.h>
#include <string.h>
#include <filesys/file.h>
#include <devices/input.h>
#include <threads/palloc.h>
#include <threads/malloc.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "process.h"
#include "pagedir.h"
#include "syscall.h"
#include "vm/page.h"


// syscall array
syscall_function syscalls[16];


static uint32_t *esp;
static void sys_mmap (struct intr_frame * f);
static void sys_munmap (struct intr_frame * f);
static bool is_valid_uvaddr (const void *);



static void syscall_handler (struct intr_frame *);


void exit(int exit_status){
  thread_current()->exit_status = exit_status;
  thread_exit ();
}



void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  // initialize the syscalls
  for(int i = 0; i < 16; i++) syscalls[i] = NULL;
  // bind the syscalls to specific index of the array
  syscalls[SYS_EXIT] = sys_exit;
  syscalls[SYS_HALT] = sys_halt;
  syscalls[SYS_EXEC] = sys_exec;
  syscalls[SYS_WAIT] = sys_wait;
  syscalls[SYS_CREATE] = sys_create;
  syscalls[SYS_REMOVE] = sys_remove;
  syscalls[SYS_OPEN] = sys_open;
  syscalls[SYS_FILESIZE] = sys_filesize;
  syscalls[SYS_READ] = sys_read;
  syscalls[SYS_WRITE] = sys_write;
  syscalls[SYS_SEEK] = sys_seek;
  syscalls[SYS_TELL] = sys_tell;
  syscalls[SYS_CLOSE] = sys_close;
  syscalls[SYS_MMAP] = sys_mmap;
  syscalls[SYS_MUNMAP] = sys_munmap;
}

// check whether page p and p+3 has been in kernel virtual memory
void check_page(void *p) {
  void *pagedir = pagedir_get_page(thread_current()->pagedir, p);
  if(pagedir == NULL) exit(-1);
  pagedir = pagedir_get_page(thread_current()->pagedir, p + 3);
  if(pagedir == NULL) exit(-1);
}

// check whether page p and p+3 is a user virtual address
void check_addr(void *p) {
  if(!is_user_vaddr(p)) exit(-1);
  if(!is_user_vaddr(p + 3)) exit(-1);
}

// make check for page p
void check(void *p) {
  if(p == NULL) exit(-1);
  check_addr(p);
  check_page(p);
}

// make check for every function arguments
void check_func_args(void *p, int argc) {
  for(int i = 0; i < argc; i++) {
    check(p);
    p++;
  }
}

// search the file list of the thread_current()
// to get the file has corresponding fd
struct file_node * find_file(struct list *files, int fd){
  struct list_elem *e;
  struct file_node * fn =NULL;
  for (e = list_begin (files); e != list_end (files); e = list_next (e)){
    fn = list_entry (e, struct file_node, file_elem);
    if (fd == fn->fd)
      return fn;
  }
  return NULL;
}

static void
syscall_handler (struct intr_frame *f)
{
  check((void *)f->esp);
  check((void *)(f->esp + 4));
  int num=*((int *)(f->esp));
  // check whether the function is implemented
  if(num < 0 || num >= SYSCALL_NUMBER) exit(-1);
  if(syscalls[num] == NULL) exit(-1);
  syscalls[num](f);
}

void sys_exit(struct intr_frame * f) {
  int *p = f->esp;
  // save exit status
  exit(*(p + 1));
}

void sys_halt(struct intr_frame * f UNUSED) {
  shutdown_power_off();
}

void sys_exec(struct intr_frame * f) {
  int * p =f->esp;
  check((void *)(p + 1));
  check((void *)(*(p + 1)));
  f->eax = process_execute((char*)*(p + 1));
}

void sys_wait(struct intr_frame * f) {
  int * p =f->esp;
  check(p + 1);
  f->eax = process_wait(*(p + 1));
}

void sys_create(struct intr_frame * f) {
  int * p =f->esp;
  check_func_args((void *)(p + 1), 2);
  check((void *)*(p + 1));

  acquire_file_lock();
  // thread_exit ();
  f->eax = filesys_create((const char *)*(p + 1),*(p + 2));
  release_file_lock();
}

void sys_remove(struct intr_frame * f) {
  int * p =f->esp;
  
  check_func_args((void *)(p + 1), 1);
  check((void*)*(p + 1));

  acquire_file_lock();
  f->eax = filesys_remove((const char *)*(p + 1));
  release_file_lock();
}

void sys_open(struct intr_frame * f) {
  int * p =f->esp;
  check_func_args((void *)(p + 1), 1);
  check((void*)*(p + 1));

  struct thread * t = thread_current();
  acquire_file_lock();
  struct file * open_f = filesys_open((const char *)*(p + 1));
  release_file_lock();
  // check whether the open file is valid
  if(open_f){
    struct file_node *fn = malloc(sizeof(struct file_node));
    fn->fd = t->max_fd++;
    fn->file = open_f;
    // put in file list of the corresponding thread
    list_push_back(&t->files, &fn->file_elem);
    f->eax = fn->fd;
  } else
    f->eax = -1;
}

void sys_filesize(struct intr_frame * f) {
  int * p =f->esp;
  check_func_args((void *)(p + 1), 1);
  struct file_node * open_f = find_file(&thread_current()->files, *(p + 1));
  // check whether the write file is valid
  if (open_f){
    acquire_file_lock();
    f->eax = file_length(open_f->file);
    release_file_lock();
  } else
    f->eax = -1;
}

void sys_read(struct intr_frame * f) {
    int * p =f->esp;
    check_func_args((void *)(p + 1), 3);
    check((void *)*(p + 2));
    int fd = *(p + 1);
    uint8_t * buffer = (uint8_t*)*(p + 2);
    off_t size = *(p + 3);
    off_t buffer_size = size;
    uint8_t * buffer_tmp = buffer;
    struct thread *t = thread_current ();


    while (buffer_tmp != NULL)
    {
        if (!is_valid_uvaddr (buffer_tmp))
            exit (-1);

        if (pagedir_get_page (t->pagedir, buffer_tmp) == NULL)
        {
            struct suppl_pte *spte;
            spte = get_suppl_pte (&t->suppl_page_table,
                                  pg_round_down (buffer_tmp));
            if (spte != NULL && !spte->is_loaded)
                load_page (spte);
            else if (spte == NULL && buffer_tmp >= (esp - 32))
                grow_stack (buffer_tmp);
            else
                exit (-1);
        }

        /* Advance */
        if (buffer_size == 0)
        {
            /* terminate the checking loop */
            buffer_tmp = NULL;
        }
        else if (buffer_size > PGSIZE)
        {
            buffer_tmp += PGSIZE;
            buffer_size -= PGSIZE;
        }
        else
        {
            /* last loop */
            buffer_tmp = buffer + size - 1;
            buffer_size = 0;
        }
    }


    // read from standard input
    if (fd == STDIN_FILENO) {
        for (int i=0; i<size; i++)
            buffer[i] = input_getc();
        f->eax = size;
    }else if (fd == STDOUT_FILENO)
    {
        f->eax = -1;
    }
    else{
        struct file_node * open_f = find_file(&thread_current()->files, *(p + 1));
        // check whether the read file is valid
        if (open_f){
            acquire_file_lock();
            f->eax = file_read(open_f->file, buffer, size);
            release_file_lock();
        } else
            f->eax = -1;
    }
}


void sys_write(struct intr_frame * f) {
    int * p =f->esp;
    check_func_args((void *)(p + 1), 3);
    check((void *)*(p + 2));
    int fd2 = *(p + 1);
    const char * buffer2 = (const char *)*(p + 2);
    off_t size2 = *(p + 3);
    char * buffer_tmp = buffer2;
    off_t buffer_size = size2;
    struct thread *t = thread_current ();


    while (buffer_tmp != NULL)
    {
        if (!is_valid_uvaddr (buffer_tmp))
            exit (-1);

        if (pagedir_get_page (t->pagedir, buffer_tmp) == NULL)
        {
            struct suppl_pte *spte;
            spte = get_suppl_pte (&t->suppl_page_table,
                                  pg_round_down (buffer_tmp));
            if (spte != NULL && !spte->is_loaded)
                load_page (spte);
            else if (spte == NULL && buffer_tmp >= (esp - 32))
                grow_stack (buffer_tmp);
            else
                exit (-1);
        }

        /* Advance */
        if (buffer_size == 0)
        {
            /* terminate the checking loop */
            buffer_tmp = NULL;
        }
        else if (buffer_size > PGSIZE)
        {
            buffer_tmp += PGSIZE;
            buffer_size -= PGSIZE;
        }
        else
        {
            /* last loop */
            buffer_tmp = buffer2 + size2 - 1;
            buffer_size = 0;
        }
    }




    // write to standard output
    if (fd2==STDOUT_FILENO) {
        putbuf(buffer2,size2);
        f->eax = size2;
    } else if(fd2==STDIN_FILENO){
        f->eax = -1;
    }
    else{
        struct file_node * openf = find_file(&thread_current()->files, *(p + 1));
        // check whether the write file is valid
        if (openf){
            acquire_file_lock();
            f->eax = file_write(openf->file, buffer2, size2);
            release_file_lock();
        } else
            f->eax = 0;
    }
}

void sys_seek(struct intr_frame * f) {
  int * p =f->esp;
  check_func_args((void *)(p + 1), 2);
  struct file_node * openf = find_file(&thread_current()->files, *(p + 1));
  if (openf){
    acquire_file_lock();
    file_seek(openf->file, *(p + 2));
    release_file_lock();
  }
}

void sys_tell(struct intr_frame * f) {
  int * p =f->esp;
  check_func_args((void *)(p + 1), 1);
  struct file_node * open_f = find_file(&thread_current()->files, *(p + 1));
  // check whether the tell file is valid
  if (open_f){
    acquire_file_lock();
    f->eax = file_tell(open_f->file);
    release_file_lock();
  }else
    f->eax = -1;
}

void sys_close(struct intr_frame * f) {
  int *p = f->esp;
  check_func_args((void *)(p + 1), 1);
  struct file_node * openf = find_file(&thread_current()->files, *(p + 1));
  if (openf){
    acquire_file_lock();
    file_close(openf->file);
    release_file_lock();

    // remove file form file list
    list_remove(&openf->file_elem);
    free(openf);
  }
}

void
sys_mmap (struct intr_frame * f) {
    int *p = f->esp;
    int offset;
    struct thread *t = thread_current();
    int32_t len;
    void *addr = (void *) *(esp + 2);
    check_func_args((void *) (p + 1), 1);
    struct file_node *open_f = find_file(&thread_current()->files, *(p + 1));
    if (open_f) {
        len = file_length(open_f->file);
        if (len <= 0)
            f->eax = -1;
        offset = 0;
        while (offset < len) {
            if (get_suppl_pte(&t->suppl_page_table, addr + offset))
                f->eax = -1;

            if (pagedir_get_page(t->pagedir, addr + offset))
                f->eax = -1;

            offset += PGSIZE;
        }
        acquire_file_lock();
        struct file *newfile = file_reopen(open_f->file);
        release_file_lock();
         f->eax = (newfile == NULL) ? -1 : mmfiles_insert(addr, newfile, len);

    }
}

void
sys_munmap (struct intr_frame * f)
{
    int * p =f->esp;
    mmfiles_remove((mapid_t)(*(p+1)));
}
static bool
is_valid_uvaddr (const void *uvaddr)
{
    return (uvaddr != NULL && is_user_vaddr (uvaddr));
}

bool
is_valid_ptr (const void *usr_ptr)
{
    struct thread *cur = thread_current ();
    if (is_valid_uvaddr (usr_ptr))
    {
        return (pagedir_get_page (cur->pagedir, usr_ptr)) != NULL;
    }
    return false;
}
