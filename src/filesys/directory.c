#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"

/* A directory. */
struct dir 
  {
    struct inode *inode;                /* Backing store. */
    off_t pos;                          /* Current position. */
  };

/* A single directory entry. */
struct dir_entry 
  {
    block_sector_t inode_sector;        /* Sector number of header. */
    char name[NAME_MAX + 1];            /* Null terminated file name. */
    bool in_use;                        /* In use or free? */
  };

/* Creates a directory in the given SECTOR.
   The directory's parent is in PARENT_SECTOR.
   Returns inode of created directory if successful,
   null pointer on faiilure.
   On failure, SECTOR is released in the free map. */
struct inode *
dir_create (block_sector_t sector, block_sector_t parent_sector)
{
  // ..
  struct inode *inode = inode_create_dir(sector, DIR_INODE);
  
  if(!inode){
    //printf(" inode create dir failed\n");
    return NULL;
  }
  struct dir *dir = dir_open(inode);
  if(!dir){
    //printf(" dir open failed.\n");
    return NULL;
  }
  struct dir_entry e[2];
  memset(e, 0, sizeof e);
  e[0].inode_sector = sector;
  e[0].in_use = true;
  //memcpy(e[0].name, ".\0", 2);
  strlcpy(e[0].name, ".", sizeof e[0].name);

  e[1].inode_sector = parent_sector;
  e[1].in_use = true;
  //memcpy(e[1].name, "..\0", 3);
  strlcpy(e[1].name, "..", sizeof e[1].name);
  int byte_written = inode_write_at(dir->inode, e, sizeof e, 0);
  if(byte_written!= sizeof e){
    inode_close(inode);
    //printf("write at failed %d %d \n", byte_written, sizeof e);
    inode = NULL;
  }
  dir_close(dir);
  return inode;
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open (struct inode *inode) 
{
  struct dir *dir = calloc (1, sizeof *dir);
  if (inode != NULL && dir != NULL)
    {
      dir->inode = inode;
      dir->pos = 0;
      return dir;
    }
  else
    {
      inode_close (inode);
      free (dir);
      return NULL; 
    }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir *
dir_open_root (void)
{
  return dir_open (inode_open (ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir *
dir_reopen (struct dir *dir) 
{
  return dir_open (inode_reopen (dir->inode));
}

/* Destroys DIR and frees associated resources. */
void
dir_close (struct dir *dir) 
{
  if (dir != NULL)
    {
      inode_close (dir->inode);
      free (dir);
    }
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct dir *dir) 
{
  return dir->inode;
}

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool
lookup (const struct dir *dir, const char *name,
        struct dir_entry *ep, off_t *ofsp) 
{
  struct dir_entry e;
  size_t ofs;
  
  ASSERT (dir != NULL);
  ASSERT (name != NULL);



  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) {
    //printf(" inside for loop\n");
    //printf("name %s name to be search %s,  sector in dir entry %d\n", e.name, name, e.inode_sector);
    if (e.in_use && !strcmp (name, e.name)) 
      {
        if (ep != NULL)
          *ep = e;
        if (ofsp != NULL)
          *ofsp = ofs;
        return true;
      }
    }
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool
dir_lookup (const struct dir *dir, const char *name,
            struct inode **inode) 
{
  struct dir_entry e;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  if (lookup (dir, name, &e, NULL)){
    *inode = inode_open (e.inode_sector);
    //printf("inode open\n");
    if(inode_get_itype(*inode)==FILE_INODE){
      //printf(" is file inode\n");
    }

  }
  else{
    *inode = NULL;
    //printf("look up failed\n");
  }

  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool
dir_add (struct dir *dir, const char *name, block_sector_t inode_sector)
{
  struct dir_entry e;
  off_t ofs;
  bool success = false;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen (name) > NAME_MAX)
    return false;

  /* Check that NAME is not in use. */
  if (lookup (dir, name, NULL, NULL))
    goto done;

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.
     
     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  //printf("not in use\n");
  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (!e.in_use)
      break;

    //printf("ofs %d\n", ofs);

  /* Write slot. */
  e.in_use = true;
  strlcpy (e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  int byte_written = inode_write_at (dir->inode, &e, sizeof e, ofs);
  //printf("byte written %d\n",byte_written);
  success = (byte_written == sizeof e);
  if(success== false){
    //printf("inode write failed\n");
  }

 done:
  return success;
}



/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct dir *dir, const char *name) 
{
  struct dir_entry e;
  struct inode *inode = NULL;
  bool success = false;
  off_t ofs;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

 if (!strcmp (name, ".") || !strcmp (name, ".."))
    return false;

  /* Find directory entry. */
  //inode_lock (dir->inode);
  if (!lookup (dir, name, &e, &ofs))
    goto done;

  /* Open inode. */
  inode = inode_open (e.inode_sector);
  if (inode == NULL)
    goto done;

  /* Verify that it is not an in-use or non-empty directory. */
  struct dir_entry e2;
  off_t ofs2;
  if(inode_get_itype(inode) == DIR_INODE){
      for(ofs2 = 0; inode_read_at(inode, &e2, sizeof e2,ofs2); ofs2 += sizeof e2){
        if(e2.in_use == true){
          goto done;
        }
      }
  }


  /* Erase directory entry. */
  e.in_use = false;
  if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e) 
    goto done;

  /* Remove inode. */
  inode_remove (inode);
  success = true;

 done:
  inode_close (inode);
  return success;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool
dir_readdir (struct dir *dir, char name[NAME_MAX + 1])
{
  struct dir_entry e;

  while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e) 
    {
      dir->pos += sizeof e;
      if (e.in_use && strcmp(e.name, ".") && strcmp(e.name, ".."))
        {
          strlcpy (name, e.name, NAME_MAX + 1);
          return true;
        } 
    }
  return false;
}
