#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/cache.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "filesys/free-map.h"
#include "filesys/directory.h"
#include "filesys/cache.h"
#include "threads/malloc.h"
#include "threads/thread.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  cache_init();
  free_map_init ();

  if (format) 
    do_format ();

  free_map_open ();
  //printf("free map opened\n");
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{

  free_map_close ();
  cache_flush();

}

/* Extracts a file name part from *SRCP into PART,
   and updates *SRCP so that the next call will return the next
   file name part.
   Returns 1 if successful, 0 at end of string, -1 for a too-long
   file name part. */
static int
get_next_part (char part[NAME_MAX], const char **srcp)
{
  const char *src = *srcp;
  char *dst = part;

  /* Skip leading slashes.
     If it's all slashes, we're done. */
  while (*src == '/')
    src++;
  if (*src == '\0')
    return 0;

  /* Copy up to NAME_MAX character from SRC to DST.
     Add null terminator. */
  while (*src != '/' && *src != '\0')
    {
      if (dst < part + NAME_MAX)
        *dst++ = *src;
      else
        return -1;
      src++;
    }
  *dst = '\0';

  /* Advance source pointer. */
  *srcp = src;
  return 1;
}

/* Resolves relative or absolute file NAME.
   Returns true if successful, false on failure.
   Stores the directory corresponding to the name into *DIRP,
   and the file name part into BASE_NAME. */
static bool
resolve_name_to_entry (const char *name,
                       struct dir **dirp, char base_name[NAME_MAX + 1])
{
  // ...
  struct dir *dir;
  struct inode *inode;
  //absolute
  //printf(" enter entry with name %s\n",name);
  if(name == NULL){
    return false;
  }
  if(name[0] == '/'){
    //printf(" is  /\n");
    dir = dir_open_root();
  }
  // relative
  else{
    //printf("here \n");
    if(!thread_current()->work_dir){
      //printf(" cur tid %d wd is null\n", thread_current()->tid);
      dir = dir_open_root();
      //printf(" cur tid %d wd is null\n", thread_current()->tid);
    }
    else{
      //printf("reopensssss\n");
      dir = dir_reopen(thread_current()->work_dir);
      //printf("re open \n");
    }

  }

  if(!dir){
    //p
    *dirp = NULL;
    base_name[0] = '\0';
    return false;
  }
  else{
    int l = strlen(name);
    char *copy = (char*)malloc(sizeof(char)*(l+1));
    memcpy(copy, name, sizeof(char)*(l+1));
    char part[NAME_MAX + 1];
    char token[NAME_MAX + 1];
    char *c_name = name;
    int flag;
    bool success;
    free(copy);

    int count = 0;
    /*
    int i = 0;
    bool text = true;
    while(i < l){
      if(name[i] != '/' && text == true){
        count++;
        text = false;
      }
      if(name[i] == '/' && text == false){
        text = true;
      }
      i++;
    }
    int m = count;
    printf("count = %d\n",count);

*/
    char previous[NAME_MAX + 1];
    do{
      strlcpy(previous, token, NAME_MAX+1);
      flag = get_next_part(token,&c_name);
      //printf(" flag %d, token %s, previous %s\n",flag, token, previous);
      if(flag < 0){
        dir_close(dir);
        base_name[0] = '\0';
        *dirp =NULL;
        return false;
      } else if (flag == 0){
        if(0 == count){
          flag = -1;
        }
        break;
      }
      strlcpy(part, token, NAME_MAX+1);
      if(count >0){
      success = dir_lookup(dir, previous, &inode);
      //printf(" inumber %d\n", inode_get_inumber(dir->inode));
      if(!success){
        //printf("dir look up %s failed\n",previous);
        dir_close(dir);
        *dirp = NULL;
        base_name[0] = '\0';
        return false;
      }
      dir_close(dir);
      dir = dir_open(inode);
      if(!dir){
        *dirp = NULL;
        base_name[0] = '\0';
        return false;
      }
    }
    count++;
    }while(flag > 0);

    if(flag == 0){
      *dirp = dir;
      strlcpy(base_name, part, NAME_MAX+1);
      return true;
    }

    *dirp = NULL;
    base_name[0] = '\0';
    return false;
  }
}

/* Resolves relative or absolute file NAME to an inode.
   Returns an inode if successful, or a null pointer on failure.
   The caller is responsible for closing the returned inode. */
static struct inode *
resolve_name_to_inode (const char *name)
{
  // ...
  // name such as "////"
  int i = 0;
  while(name[i] == '/'){
    i++;
  }
  if(name[i] == '\0'){
    return inode_open(ROOT_DIR_SECTOR);
  }
  else{
    struct dir *dir;
    char b_name[NAME_MAX + 1];
    struct inode* inode;
    bool success = resolve_name_to_entry(name, &dir,b_name);
    if(success){
      dir_lookup(dir, b_name, &inode);
      dir_close(dir);
      return inode;
    }
    return NULL;
  }
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool //filesys_create(){ return true;}
filesys_create (const char *name, off_t initial_size, enum inode_type type) 
{
  block_sector_t inode_sector = 0;
  struct dir *dir;
  char base[NAME_MAX+1];
  //printf(" before resolve %s\n", name);
  if(name ==NULL){
    //printf(" xxx\n");
    return false;
  }
  char *copy;
  if(type == FILE_INODE){
    int l = strlen(name);
    copy = (char*)malloc(sizeof(char)*(l+1));
    memcpy(copy, name, sizeof(char)*(l+1));


  }


  bool success = (resolve_name_to_entry(name, &dir, base)
                  && free_map_allocate (1, &inode_sector));
  //printf("after resolve\n");
  if(!success){
    if(inode_sector != 0)
      free_map_release(inode_sector,1);
    dir_close(dir);
    return false;
  }
  else{
    struct inode *inode;
    if(type == DIR_INODE){
      struct inode *pinode = dir_get_inode(dir);
      block_sector_t inode_par = inode_get_inumber(pinode);
      inode  = dir_create(inode_sector, inode_par);
    }
    else{
      //printf("creating file in filesys\n");
      inode = file_create(inode_sector,initial_size);
    }
    if(!inode){
      //printf("creating failed\n");
      dir_close(dir);
      return false;
    }
    else{
      //printf("(creating success)\n");
      //printf("base name %s\n", base);
      if(dir_add(dir, base, inode_sector)){
        inode_close(inode);
        dir_close(dir);
        return true;
      }
      else{
        inode_remove(inode);
        dir_close(dir);
        return false;
      }
    }
  }
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct inode*
filesys_open (const char *name)
{
  //printf("file sys open %s\n", name);
  return resolve_name_to_inode(name);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  struct dir *dir;
  char base[NAME_MAX+1];
  bool success = resolve_name_to_entry(name, &dir, base);
  if(!success){
    dir_close(dir);
    return false;
  }
  else{
    if(dir_remove(dir, base)){
      dir_close(dir);
      return true;
    }
    else{
      dir_close(dir);
      return false;
    }
  }
}

/* Change current directory to NAME.
   Return true if successful, false on failure. */
bool
filesys_chdir (const char *name)
{
  // ...
  struct inode* inode = filesys_open(name);
  struct dir* dir = dir_open(inode);
  if(!dir){
    return false;
  }
  dir_close(thread_current()->work_dir);
  thread_current()->work_dir = dir;
  return true;
}



/* Formats the file system. */
static void
do_format (void)
{
  struct inode *inode;
  printf ("Formatting file system...");

  /* Set up free map. */
  free_map_create ();

  //printf(" free map create\n");

  /* Set up root directory. */
  inode = dir_create (ROOT_DIR_SECTOR, ROOT_DIR_SECTOR);

  if (inode == NULL)
    PANIC ("root directory creation failed");
  inode_close (inode);

  free_map_close ();

  printf ("done.\n");
}
