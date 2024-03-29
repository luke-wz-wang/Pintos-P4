#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "threads/malloc.h"
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "userprog/syscall.h"
static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, const char *realcmd, void (**eip) (void), void **esp);



/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;
  //printf("execute start\n");
  if(thread_current()->work_dir == NULL){
  if(thread_current()->parent->work_dir != NULL){
    thread_current()->work_dir = thread_current()->parent->work_dir;
  }
  else{
    thread_current()->work_dir = dir_open_root();
  }
}
  //printf("work till wd \n");
  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  //
  char *f_name, *s_ptr;
  f_name = malloc(strlen(file_name)+1);
  strlcpy(f_name,file_name, strlen(file_name)+1);
  f_name = strtok_r(file_name, " ", &s_ptr);
  //printf("exe : %s id %d\n", fn_copy, thread_current()->tid);

  /* Create a new thread to execute FILE_NAME. */
  //
  tid = thread_create (f_name, PRI_DEFAULT, start_process, fn_copy);
  //printf("execute : %d is created\n", tid);
  if (tid == TID_ERROR)
    palloc_free_page (fn_copy); 
  sema_down(&thread_current()->cr_sm);
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

  char *fn_copy =palloc_get_page (0);
  strlcpy (fn_copy, file_name, PGSIZE);
 // printf("this %s\n", fn_copy);

  char *fd_copy =palloc_get_page (0);
  strlcpy (fd_copy, file_name, PGSIZE);
  char *part = NULL;
  char *s_ptr = NULL;
  part = strtok_r(fd_copy, " ", &s_ptr);
  //printf("start process: %s %s\n", file_name, fn_copy);
  

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  //success = load (part, &if_.eip, &if_.esp);
  success = load (file_name,fn_copy, &if_.eip, &if_.esp);
  struct thread *t = thread_current();
  /* If load failed, quit. */
  palloc_free_page (file_name);
  if (!success) {
    //thread_current()->tid = -1;
    //printf("??, *&%d, %d**\n", thread_current()->tid, thread_current()->parent->tid);
    thread_current()->ret = -1;
    sema_up(&thread_current()->parent->cr_sm);
    thread_exit();
  }
  //printf("!!, *&%d, %d**\n",thread_current()->tid, thread_current()->parent->tid);
  thread_current()->parent->count++;
  sema_up(&thread_current()->parent->cr_sm);

  //t->myFile = filesys_open(fd_copy);
  //file_deny_write(t->myFile);

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{
  //printf("wait start here! %d %d\n", thread_current()->tid, thread_current()->count);
  //while (1);
  /*
  struct list_elem *e;
  struct thread *t;

  for(e= list_begin(&all_list); e!=list_end(&all_list);e= list_next(e)){
    t = list_entry(e, struct thread, allelem);
      if(t->tid == child_tid){
       break;
      }
    }
    */
    //printf("Pocess wait start: cur %d, child %d\n", thread_current()->tid, child_tid);
   /* struct thread *t = find_child_thread(child_tid);
  if(t == NULL){
    //printf("%d did find child with id %d\n",thread_current()->tid, child_tid);
    return -1;

  }*/
  struct list_elem *e2;
  struct child_ret *rt ;
  int temp = -1;
  int find = -1;
  for(e2= list_begin(&thread_current()->children); e2!=list_end(&thread_current()->children);e2= list_next(e2)){
    rt = list_entry(e2, struct child_ret, elem);
    if(rt->tid == child_tid){
      temp = rt->ret;
      find = 0;
      //rt->ret = -1;
      //printf("temp %d find!! child id %d\n", temp, t->tid);
      break;
    }
  }
  if(find == -1){
    //printf("search list %d did find child with id %d\n",thread_current()->tid, child_tid);
    return -1;
  }
  else{

  //if(t->status == THREAD_DYING)
    //return temp;
  /*if(t->exited==true){
    printf("exited == true \n");
    return temp;
  }*/
  //t->waited = true;
 //printf("^^%d starts waiting\n", thread_current()->tid);
/*
 filelock_acquire();

 if(thread_current()->myFile != NULL){
  file_deny_write(thread_current()->myFile);
  printf("%d deny write at wait\n", thread_current()->tid);
}
 filelock_release();
*/
  if(thread_current()->count!=0)
  sema_down(&thread_current()->ch_sm);
  //printf("^^%d ends waiting, parent tid %d\n", thread_current()->tid, thread_current()->parent->tid);

filelock_acquire();
  //printf("acquire the file lock \n");
  if(thread_current()->myFile != NULL) {

    file_allow_write(thread_current()->myFile);
    //printf("%d Allow write successfully at wait\n", thread_current()->tid);
    file_close(thread_current()->myFile);
    thread_current()->myFile = NULL; 
  }
  while(!list_empty(&thread_current()->curWriteFiles)){
        
        struct p_files *fpt = list_entry(list_pop_front(&thread_current()->curWriteFiles), struct p_files, elem);
        //printf("wait : work till here %d\n", thread_current()->fcount);
        if(fpt->fptr!=NULL){
         // printf("Allow write cur files %d\n", fpt->fid);
          //file_allow_write(fpt->fptr);
          //file_allow_write(fpt->fptr);
          //file_allow_write(fpt->fptr);
          //file_close(fpt->fptr);
          //printf("WAit after allowed\n");
        }
        
        free(fpt);
      }
  filelock_release();
  int status_code = -1;
  //printf("search child ret child id%d\n", child_tid);

  for(e2= list_begin(&thread_current()->children); e2!=list_end(&thread_current()->children);e2= list_next(e2)){
    rt = list_entry(e2, struct child_ret, elem);
    //printf("where is it ???tid %d ret%d \n",rt->tid, rt->ret);
    if(rt->tid == child_tid){
      status_code = rt->ret;
      //printf("status code : %d\n", status_code);

      rt->ret = -1;
      break;
    }
  }
  //list_remove(e);
  return status_code;
}
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;
  //sema_up(&thread_current()->parent->ch_sm);
  //printf("process exit : %d %d count\n", cur->tid, cur->parent->count);
  free(thread_current()->fd_array);
  //printf("%s: exit(%d)\n", cur->name, cur->ret);
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;


  //lock_acquire(&filesys_lock);
  filelock_acquire();
  //printf("acquire the file lock \n");
  if(thread_current()->myFile != NULL) {

    file_allow_write(thread_current()->myFile);
    //printf("%d Allow write successfully at exit\n", thread_current()->tid);
    file_close(thread_current()->myFile);
    thread_current()->myFile = NULL;
  }
    
  //struct list_elem *e;
  //struct p_files *fpt;
  /*
  printf("exit till here\n");
  while(!list_empty(&thread_current()->allFiles)){
        
        struct p_files *fpt = list_entry(list_pop_front(&thread_current()->allFiles), struct p_files, elem);
        printf("Exit : work till here %d\n", thread_current()->fcount);
        if(fpt->fptr!=NULL){
          printf("Exit : work till here before ALLOW WRITE\n");
          //file_allow_write(fpt->fptr);
          printf("Exit : work till here ALLOW WRITE\n");
          file_close(fpt->fptr);
          printf("Exit : work till here CLOSE\n");
        }
          
        free(fpt);
      }
      */
  filelock_release();
  //printf("Exit: file lock released\n");  //lock_release(&filesys_lock);

/*
  if(cur->myFile!=NULL){
    //printf(" i have not crueshed \n");
        //file_allow_write(cur->myFile);
        //file_close(cur->myFile);
        if(cur->parent->count == 1 && cur->parent->myFile !=NULL){
          //printf("close parent cur %d\n", cur->tid);
          //file_allow_write(cur->parent->myFile);
        //file_close(cur->parent->myFile);
        cur->parent->myFile = NULL;
        }
      }*/

  //lock_release(&filesys_lock);
  //printf("%d not curshed\n", cur->tid);
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      /*
      if(cur->myFile!=NULL){
        file_allow_write(cur->myFile);
        file_close(cur->myFile);
      }*/
      struct child_ret *rt = (struct child_ret*)malloc(sizeof(struct child_ret));
      rt->tid = cur->tid;
      rt->ret = cur->ret; 
      //printf("cur ret %d, cur id %d in the exit \n", cur->ret, cur->tid);
      //list_push_back(&cur->parent->children, &rt->elem);
    cur->parent->count--;
    struct list_elem *e2;
    struct child_ret *rt1;
    int find = -1;
    for(e2= list_begin(&thread_current()->parent->children); e2!=list_end(&thread_current()->parent->children);e2= list_next(e2)){
    rt1 = list_entry(e2, struct child_ret, elem);
    if(rt1->tid == cur->tid){
      find = 0;
      rt1->ret = cur->ret;
    }
    //printf("Store is it stored ???tid %d ret%d \n",rt1->tid, rt1->ret);
    }
    if(find == -1){
      list_push_back(&cur->parent->children, &rt->elem);
      //printf("pushed\n");
    }
  
      //cur->exited = true;
      //printf("Exit current id %d parent %d\n", cur->tid, cur->parent->tid);
      //sema_up(&thread_current()->parent->cr_sm);
      if(cur->parent!=NULL && cur->parent->count == 0){
        while(!list_empty(&cur->parent->ch_sm.waiters))
          sema_up(&cur->parent->ch_sm);
      }
      while(!list_empty(&cur->children)){
        struct child_ret *rt1 = list_entry(list_pop_front(&cur->children), struct child_ret, elem);
        free(rt1);
      }
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (char* cmd_line, void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, const char *cmdline, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  //printf(" load here\n");
  //lock_acquire(&fsys_lock);
  filelock_acquire();

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */

  
/*
  char *ftest;
  
  char fnn[12] = "child-simple";
  ftest = malloc(strlen(fnn)+1);
  ftest = fnn;
  printf("%s %s\n", fnn, ftest);
  //char *kfilename = copy_in_string(ftest);
  file = filesys_open (fnn);
  if(file == NULL)
    printf("%s cannot  be opened at %d\n", fnn,thread_current()->tid);
  printf("cannot continue\n");
  file_close(file);
  printf("file closed ><\n");
*/

  char *f_name, *s_ptr;
  f_name = malloc(strlen(file_name)+1);
  strlcpy(f_name, file_name, strlen(file_name)+1);
  f_name = strtok_r(f_name, " ", &s_ptr);
  
  //lock_acquire(&filesys_lock);
  file = file_open(filesys_open (f_name));
  //lock_release(&filesys_lock);
  
  //printf("filesys_open: *%s*\n",f_name);
  //int f_id = open(f_name);
  //file = thread_current()->fd_array[f_id];
  free(f_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      //printf("load faied %d\n", thread_current()->tid);
      //exit(-1);
      if(thread_current()->parent != NULL)
        thread_current()->parent->loadSuc = false;
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (cmdline, esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;


  file_deny_write(file);
  //printf("%d deny write \n", thread_current()->tid);
  thread_current()->myFile = file;

  //printf("%d is loaded!\n", thread_current()->tid);

 done:
  /* We arrive here whether the load is successful or not. */
  //lock_acquire(&filesys_lock);
 //lock_release(&filesys_lock);
 filelock_release();

 //if(success != true)
  //file_close (file);

  //printf("FIle close: cur id %d\n", thread_current()->tid);
  //lock_release(&filesys_lock);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}





/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (char* cmd_line, void **esp) 
{
  uint8_t *kpage;
  bool success = false;
  //printf("***%s***\n", cmd_line);

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }

    char *part = NULL;
    char *s_ptr = NULL;
    part = strtok_r(cmd_line, " ", &s_ptr);
    int *arg[256];
    int i = 0;
  int n = 0;
  for(;part !=NULL; part = strtok_r(NULL, " ", &s_ptr))
  {
    *esp -= strlen(part) + 1;
    memcpy(*esp, part, strlen(part)+1);
    arg[n] = *esp;
    //printf("**%s**%d\n", arg[n], n);
    n++;
  }
  //printf("**%d **%d\n", sizeof(char), sizeof(int));
  //align
  while((int)*esp%4!=0){
    (*esp)--;
    //char ch = 0;
    //memcpy(*esp,&ch,1);
  }

  int value = 0;
  *esp-=4;
  int *p = *esp;
  *p = 0;

  for(i=n-1;i>=0;i--)
  {
    *esp-=4;
    memcpy(*esp,&arg[i],4);
  }

  //address of arg[]
  int ad_arg = *esp;
  *esp-=4;
  memcpy(*esp,&ad_arg,4);
  
  *esp-=4;
  p = *esp;
  (*p) = n;

  //return address
  *esp-=4;
  p = *esp;
  (*p) = 0;
  
  return success;

}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
