#include <stdio.h>
#include <syscall-nr.h>
#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "threads/loader.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/loader.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
//#include "filesys/inode.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include <string.h>
static void syscall_handler (struct intr_frame *);


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
}

static void
syscall_handler (struct intr_frame *f) 
{
  //printf("Enter sys call \n");
  unsigned call_nr;
  int args[3];
  copy_in (&call_nr, f->esp, sizeof call_nr);
  memset (args, 0, sizeof args);
  switch(call_nr) {
  	case SYS_HALT:
  	  halt();
  	  break;
  	case SYS_EXIT:
  	  copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * 1);
  	  exit(args[0]);
  	  break;
    case SYS_EXEC:
      copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * 1);
      f->eax = exec(args[0]);
      break;
    case SYS_WAIT:
      copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * 1);
      f->eax = wait(args[0]);
      break;
    case SYS_CREATE:
      copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * 2);
      f->eax = create(args[0], args[1]);
      break;
    case SYS_REMOVE: 
      copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * 1);
      f->eax = remove(args[0]);
      break;
    case SYS_OPEN:
      copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * 1);
      f->eax = open(args[0]);
      break;
    case SYS_FILESIZE:
      copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * 1);
      f->eax = filesize(args[0]);
      break;
    case SYS_READ:
      copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * 3);
      f->eax = read(args[0], args[1], args[2]);
      break;
    case SYS_WRITE:
      copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * 3);
      f->eax = write(args[0], args[1], args[2]);
      break;
    case SYS_SEEK:
      copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * 2);
      seek(args[0], args[1]);
      break;
    case SYS_TELL:
      copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * 1);
      f->eax = tell(args[0]);
      break;
    case SYS_CLOSE:
      copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * 1);
      close(args[0]);
      //closes(args[0], f->esp);
      break;
    case SYS_MKDIR:
      copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * 1);
      f->eax = mkdir(args[0]);
      break;
    case SYS_CHDIR:
      copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * 1);
      f->eax = chdir(args[0]);
      break;
    case SYS_READDIR:
      copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * 2);
      f->eax = readdir(args[0], args[1]);
      break;
    case SYS_ISDIR:
      copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * 1);
      f->eax = isdir(args[0]);
      break;
    case SYS_INUMBER:
      copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * 1);
      f->eax = inumber(args[0]);
      break;
  	default:
  	  exit(-1);
  	  break;
  }
}

/* System call halt */
static void halt(void)
{
  shutdown_power_off();
}


/* System call exit. */
void exit(int status)
{
  struct thread *current = thread_current();
  /* close all the file descriptor held by current process. */
  if (current->fd_array != NULL){
    int fid = 2;
    for (; fid < MAX_FID; fid++) 
      close(fid);
  }
  printf("%s: exit(%d)\n", current->name, status);
  current->ret = status;
  thread_exit();
}

static int exec (const char *ufile) 
{

  char *kfile = copy_in_string (ufile);
  lock_acquire(&filesys_lock);
  int tid = process_execute(kfile);
  //printf("**Syscall exex tid%d****\n", tid);
  lock_release(&filesys_lock);
  if (tid == TID_ERROR)
    return -1;
  if(thread_current()->loadSuc == false){
    return -1;
  }
  return tid;

}


static int wait (int pid) 
{
  //printf("**cur %d syscall wait pid %d*****&&\n", thread_current()->tid, pid);
  return process_wait(pid);
}
/* Syscall create file. */
static bool create (const char *ufilename, unsigned initial_size) 
{

  char *kfilename = copy_in_string (ufilename);
  //If filename is an empty string.
  if (kfilename == NULL) exit(-1);
  lock_acquire(&filesys_lock);
  enum inode_type type = FILE_INODE;
  bool ok = filesys_create(kfilename, initial_size, type);
  lock_release(&filesys_lock);
  palloc_free_page(kfilename);
  return ok;
}
/* syscall remove. */
static bool remove (const char *ufilename) 
{
  char *kfilename = copy_in_string (ufilename);
  lock_acquire(&filesys_lock);
  bool ok = filesys_remove(kfilename);
  lock_release(&filesys_lock);
  palloc_free_page(kfilename);
  return ok;
}

bool mkdir(const char *ufilename){
  //printf("enter mkdir\n");
  char *kfilename = copy_in_string(ufilename);
  bool success = filesys_create(kfilename,0,DIR_INODE);
  palloc_free_page(kfilename);
  return success;
}

bool chdir(const char *ufilename){
  char *kfilename = copy_in_string(ufilename);
  bool success = filesys_chdir(kfilename);
  palloc_free_page(kfilename);
  return success;
}

bool readdir(int handle, const char *ufilename){
  struct p_files *pf = lookup_pfile(handle,DIR_INODE);
  char part[NAME_MAX + 1];
  bool success = dir_readdir(pf->dir, part);
  if(success){
    copy_out(ufilename, part,strlen(part) + 1);
  }
  return success;
}

bool isdir(int handle){
  struct p_files *pf = lookup_simple_pfile(handle);
  if(pf->dir != NULL)
    return true;
  else
    return false;
}

int inumber(int handle){
  struct p_files *pf;
  struct inode *inode;
  if(isdir(handle)){
    pf = lookup_pfile(handle, DIR_INODE);
    inode = dir_get_inode(pf->dir);
    //return inode_get_inumber(inode);
  }
  else{
    pf = lookup_pfile(handle, FILE_INODE);
    inode = file_get_inode(pf->fptr);
  }
  return inode_get_inumber(inode);
}
/* */
 int open(const char *ufilename) 
{
  char *kfilename = copy_in_string(ufilename);
  //printf("opening \n");
  struct p_files *pfile;
  if (kfilename == NULL) return -1;
  lock_acquire(&filesys_lock);
 // struct file * file_ = filesys_open(kfilename);
  struct inode* inode = filesys_open(kfilename);
  lock_release(&filesys_lock);
  if (inode == NULL) 
  {
    palloc_free_page(kfilename);
    return -1;
  } //
  else{
    pfile = (struct p_files*)malloc(sizeof(struct p_files));
    if(inode_get_itype(inode) == DIR_INODE){
      pfile->dir = dir_open(inode);
      pfile->fptr = NULL;
    }
    else{
      pfile->fptr = file_open(inode);
      pfile->dir = NULL;
    }
    
    pfile->fid = thread_current()->fcount + 1;
    
  }
  if(pfile->dir == NULL && pfile->fptr == NULL){
    inode_close(inode);
    free(pfile);
    palloc_free_page(kfilename);
    return -1;
  }

  pfile->handle = thread_current()->fcount + 1;
  //printf(" before push \n");
  list_push_back(&thread_current()->allFiles, &pfile->elem);
  thread_current()->fcount++;

  if(pfile->fptr == NULL){
    palloc_free_page(kfilename);
    return pfile->handle;
  }
  //printf("after push\n");

  struct thread * current = thread_current();
  if (current->fd_array == NULL) {
    thread_current()->fd_array = malloc(MAX_FID * sizeof(struct file*));
    int i = 0;
    for (; i < MAX_FID; i++) thread_current()->fd_array[i] = NULL;
  }
  int i = 2;
  for (; i < MAX_FID; i++) {
      if ((struct file*)current->fd_array[i] == NULL) {
        current->fd_array[i] = pfile->fptr;
        break;
      }
  }
  palloc_free_page(kfilename);
  return i;
}


/* Return the size of a file corresponding to a file. */
static int filesize(int fid)
{
  struct file * file_ = lookup_fd(fid);
  return file_length(file_);
}
/* read from stdin or a file. */
static int read (int fid, void *buffer_, unsigned size) 
{
  //printf("aaa\n");
  if (size == 0) return 0;
  if (buffer_ == NULL) exit(-1);
  int read_amount = size;
  uint8_t *buffer = buffer_; 
  if (fid == STDIN_FILENO) {
      lock_acquire(&filesys_lock);
      for (; size > 0; size--, buffer++)
        if (buffer >= (uint8_t *) PHYS_BASE || !put_user (buffer, input_getc()))
          exit(-1);
      lock_release(&filesys_lock);
      read_amount -= size;
  }
  else {    
    struct file * file_ = lookup_fd(fid);
    if (file_ == NULL) exit(-1);
    char *kbuffer = palloc_get_page (0);
    lock_acquire(&filesys_lock);
    read_amount = file_read(file_, kbuffer, size);
    int temp = read_amount;
    lock_release(&filesys_lock);
    int i = 0;
    for (; i < temp; i++, buffer++)
        if (buffer >= (uint8_t *) PHYS_BASE || !put_user (buffer, kbuffer[i])) { 
          palloc_free_page(kbuffer);         
          exit(-1);          
        }
    palloc_free_page(kbuffer);
  }
  return read_amount;
}
/* Write to a console or a file.*/
static int write (int handle, void *usrc_, unsigned size) 
{  
  if (size == 0) return 0;
  char *usrc = copy_in_string(usrc_);
  int sizeToWrite = size;
  int retval;
  /* write to stdout. */
  if (handle == STDOUT_FILENO)
  {
    lock_acquire(&filesys_lock);
    putbuf (usrc, size);
    lock_release(&filesys_lock);
    retval = size;
  }
  else{
    struct file * file_ = lookup_fd(handle);
    if (file_ == NULL) {
      palloc_free_page(usrc);
      exit(-1);
    }
    //printf("%d try to write the file %d\n", thread_current()->tid, handle);

    struct thread* par = thread_current()->parent;
    struct list_elem *e;
    for(e = list_begin(&par->curWriteFiles); ; e= list_next(e)){
      struct p_files* fpf = list_entry(e, struct p_files, elem);
      //printf("actually searched %d file %d\n", par->tid, fpf->fid);
      if(fpf->fptr == file_ || fpf->fid == handle){
        //printf("find it \n");
        return 0;
      }
      if (e ==list_end(&par->curWriteFiles)) break;
    }

    lock_acquire(&filesys_lock);
    
    //printf("syscall: acquire lock\n");
    while(sizeToWrite > 0) {
      retval = file_write (file_, usrc_, sizeToWrite);
      //
      if(retval <= 0){
        //printf("%d write is not successful\n", thread_current()->tid);
        //lock_release(&filesys_lock);
        //exit(-1);
        size = 0;
        break;
      }
      usrc_ += retval;
      sizeToWrite -= retval;
    }

    if(size> 0 && file_ != thread_current()->myFile && thread_current()->myFile!= NULL){
      //file_deny_write(file_);
      //printf("deny %d at write %d\n", handle, thread_current()->tid);
      struct p_files *pfile = (struct p_files*)malloc(sizeof(struct p_files));
      pfile->fptr = file_;
      pfile->fid = handle;
      list_push_back(&thread_current()->curWriteFiles, &pfile->elem);
      //thread_current()->fcount++;
    }
    //printf("syscall : able to relsease\n");
    lock_release(&filesys_lock);
    usrc_ -= size;
  }
  palloc_free_page(usrc);
  //printf("able to reach here %d\n", thread_current()->tid);
  return size;
}

static void seek (int fid, unsigned position) 
{
  struct file * file_ = lookup_fd(fid);
  lock_acquire(&filesys_lock);
  if (file_ != NULL) file_seek(file_, position); 
  lock_release(&filesys_lock);
}

static unsigned tell (int fid) 
{
  struct file * file_ = lookup_fd(fid);
  if (file_ == NULL) return 0;
  return file_tell(file_);  
}
/* Closes file descriptor fd. 
Exiting or terminating a process implicitly closes all its open file descriptors, 
as if by calling this function for each one. */
static void close (int fid) 
{
  //printf("work till close %d\n", thread_current()->tid);
  /*if (fid < 2 || fid > MAX_FID) exit(-1);
  if(thread_current()->parent->tid!=1){
        if(thread_current()->parent->fd_array[fid] !=NULL){
            exit(0);
            return;
        }
    }
    */
  //if(thread_current()->parent->fd_array[fid] !=NULL)
    //exit(0);
  struct file * file_ = lookup_fd(fid);
  struct p_files *pf= lookup_simple_pfile(fid);
  //printf("work after look up\n");
  /* If the fid is valid, close the file and set the file descriptor to NULL */
  if (file_ != NULL) {
    lock_acquire(&filesys_lock);
    //printf("work till the middle of close\n");
    file_close(file_);
    lock_release(&filesys_lock);
    //printf("work till the mid 2 sof close\n");
    thread_current()->fd_array[fid] = NULL;
  }
  if(pf!=NULL){
    dir_close(pf->dir);
    list_remove(&pf->elem);
    free(pf);
  }
  else{
    //exit(0);
  }
  //printf("work till the end of close\n");
}

static void closes(int fid, const void *addr){
  printf("cur tid %d\n", thread_current()->tid); 
    if(!is_user_vaddr(addr)){
      exit(-1);
      return;
    }
    void *pt = pagedir_get_page(thread_current()->pagedir, addr);
    if(!pt){
      exit(-1);
      return;
    }
    /*if(thread_current()->parent->tid!=1){
        if(thread_current()->parent->fd_array[fid] !=NULL){
            exit(0);
            return;
        }
    }*/
    
  struct file * file_ = lookup_fd(fid);
  //printf("work after look up\n");
  /* If the fid is valid, close the file and set the file descriptor to NULL */
  if (file_ != NULL) {
    lock_acquire(&filesys_lock);
    //printf("work till the middle of close\n");
    file_close(file_);
    lock_release(&filesys_lock);
    //printf("work till the mid 2 sof close\n");
    thread_current()->fd_array[fid] = NULL;
  }
  
  //printf("work till the end of close\n");
}
/* Copies a byte from user address USRC to kernel address DST.  USRC must
   be below PHYS_BASE.  Returns true if successful, false if a segfault
   occurred. Unlike the one posted on the p2 website, this one takes two
   arguments: dst, and usrc */

static inline bool
get_user (uint8_t *dst, const uint8_t *usrc)
{
  int eax;
  asm ("movl $1f, %%eax; movb %2, %%al; movb %%al, %0; 1:"
       : "=m" (*dst), "=&a" (eax) : "m" (*usrc));
  return eax != 0;
}


/* Writes BYTE to user address UDST.  UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static inline bool
put_user (uint8_t *udst, uint8_t byte)
{
  int eax;
  asm ("movl $1f, %%eax; movb %b2, %0; 1:"
       : "=m" (*udst), "=&a" (eax) : "q" (byte));
  return eax != 0;
}


/* Copies SIZE bytes from user address USRC to kernel address DST.  Call
   thread_exit() if any of the user accesses are invalid. */ 
static void 
copy_in (void *dst_, const void *usrc_, size_t size) 
{ 
  uint8_t *dst = dst_; 
  //const uint8_t *usrc = usrc_;  
  for (; size > 0; size--, dst++, usrc_++)
    if (usrc_ >= (uint8_t *) PHYS_BASE || !get_user (dst, usrc_))
      exit (-1);
}

static void 
copy_out (void *dst_, const void *usrc_, size_t size) 
{ 
  uint8_t *dst = dst_; 
  //const uint8_t *usrc = usrc_;  
  for (; size > 0; size--, dst++, usrc_++)
    if (usrc_ >= (uint8_t *) PHYS_BASE || !get_user (dst, usrc_))
      exit (-1);
}



/* Creates a copy of user string US in kernel memory and returns it as a
   page that must be **freed with palloc_free_page()**.  Truncates the string
   at PGSIZE bytes in size.  Call thread_exit() if any of the user accesses
   are invalid. */
char *
copy_in_string (const char *us)
{
  if (us ==  NULL) exit(-1);
  const char *ks;
  ks = palloc_get_page (0);
  if (ks == NULL)
    thread_exit ();
  int i = 0;
  for (;; i++) 
    {     
      /* bad pointer */
      if (us + i >= (char *) PHYS_BASE || !get_user (ks + i, us + i))
        exit(-1);
      if (us[i] == '\0') break;
    }
  // If file name is an empty string, return null string as the file name.
  if (i == 0) {    
    palloc_free_page(ks);
    ks = NULL;
  }
  return ks;
}


struct p_files*
lookup_pfile(int handle, enum inode_type type){
  struct p_files *pf;
  struct list_elem *e;
  struct thread* cur = thread_current();
  for(e = list_begin(&cur->allFiles); e != list_end(&cur->allFiles); e = list_next(e)){
    pf = list_entry(e, struct p_files, elem);
    if(pf->handle == handle){
      break;
    }
  }
  if(type == DIR_INODE){
    if(pf->dir == NULL){
      //printf(" such dir is not found\n");
      exit(0);
    }
    return pf;
  }
  if(type == FILE_INODE){
    if(pf->fptr == NULL){
      //printf(" such file not exist\n");
      exit(0);
    }
    return pf;
  }

}

struct p_files*
lookup_simple_pfile(int handle){
  struct p_files *pf;
  struct list_elem *e;
  struct thread* cur = thread_current();
  for(e = list_begin(&cur->allFiles); e != list_end(&cur->allFiles); e = list_next(e)){
    pf = list_entry(e, struct p_files, elem);
    if(pf->handle == handle){
      return pf;
    }
  }
  return NULL;
}

/* find file ptr corresponding to a fid */
static struct file *
lookup_fd(int fid) {
  /* if try to look for stdin, stdout and other invalid fid, exit. */
  
  if (fid < 2 || fid > MAX_FID) exit(-1);
  struct thread * current = thread_current();
  if(current->fd_array == NULL) return NULL;
  //printf("work till here look up %d\n", fid);
  return current->fd_array[fid];
}



