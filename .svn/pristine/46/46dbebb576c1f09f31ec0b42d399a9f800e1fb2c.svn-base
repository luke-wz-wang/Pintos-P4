#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "filesys/inode.h"

#define MAX_FID 135;

enum inode_type;

static struct lock filesys_lock;
void syscall_init (void);

static void halt(void);

void exit(int status);

static int exec (const char *cmd_line);

static int wait (int pid);

static bool create (const char *file, unsigned initial_size);

static bool remove (const char *ufile);

bool mkdir(const char *ufilename);

bool chdir(const char *ufilename);

bool readdir(int handle, const char *ufilename);

bool isdir(int handle);

int inumber(int handle);

int open(const char *ufile);

static int filesize(int fd);

static int read (int fd, void *buffer, unsigned size);

static int write (int handle, void *usrc_, unsigned size);

static void seek (int fd, unsigned position);

static unsigned tell (int fd);

static void close (int fd); 

static void closes(int fd, const void *addr);

static inline bool get_user (uint8_t *dst, const uint8_t *usrc);

static inline bool put_user (uint8_t *udst, uint8_t byte);

static void copy_in (void *dst_, const void *usrc_, size_t size);

static void copy_out (void *dst_, const void *usrc_, size_t size);

 char * copy_in_string (const char *us);

static struct file * lookup_fd(int fid);

struct p_files *lookup_pfile(int handle, enum inode_type type);

struct p_files * lookup_simple_pfile(int handle);


#endif /* userprog/syscall.h */
