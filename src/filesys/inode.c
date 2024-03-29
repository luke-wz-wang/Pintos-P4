#include "filesys/inode.h"
#include <bitmap.h>
#include <list.h>
#include <debug.h>
#include <round.h>
#include <stdio.h>
#include <string.h>
#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"

#define INODE_MAGIC 0x494e4f44

#define DIRECT_CNT 123
#define INDIRECT_CNT 1
#define DBL_INDIRECT_CNT 1
#define SECTOR_CNT (DIRECT_CNT + INDIRECT_CNT + DBL_INDIRECT_CNT)

#define PTRS_PER_SECTOR ((off_t) (BLOCK_SECTOR_SIZE / sizeof (block_sector_t)))
#define INODE_SPAN ((DIRECT_CNT                                              \
                     + PTRS_PER_SECTOR * INDIRECT_CNT                        \
                     + PTRS_PER_SECTOR * PTRS_PER_SECTOR * DBL_INDIRECT_CNT) \
                    * BLOCK_SECTOR_SIZE)
/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    //block_sector_t start;               /* First data sector. */
    enum inode_type type; 
    block_sector_t sectors[SECTOR_CNT]; /* Sectors. */
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
  };

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
void inode_get_sector(struct inode_disk * data, size_t n);
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct inode_disk data;             /* Inode content. */
    struct lock lock; 
  };

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  size_t offsets[3];
  size_t offset_cnt;
  int sector = pos / BLOCK_SECTOR_SIZE;
  //printf("%d\n", sector);
  inode_read(inode->sector, &inode->data);
  struct inode_disk * data = &inode->data;
  calculate_indices (sector, offsets, &offset_cnt);
  if (offset_cnt == 1) {
    return data->sectors[offsets[0]];
  }
    // Indirect index.
  static block_sector_t sector_n[128];
  if (offset_cnt == 2) {
    int s1 = offsets[0];
    int s2 = offsets[1];
    inode_read (data->sectors[s1], &sector_n);
    return sector_n[s2];
  }
  if (offset_cnt == 3) {
    int s1 = offsets[0];
    int s2 = offsets[1];
    int s3 = offsets[2];
    inode_read (data->sectors[s1], &sector_n);
    s2 = sector_n[s2];
    inode_read (s2, &sector_n);
    return sector_n[s3];
  }
  
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);
  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      size_t sectors = bytes_to_sectors (length);
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
      disk_inode->type = FILE_INODE;
    if (true) 
        {
          int i;
          //for (i = 0; i < SECTOR_CNT; i++) disk_inode->sectors[i] = 0;
          if (sectors > 0) 
            {
              size_t i;
              inode_get_sector(disk_inode, sectors);
            }  
          inode_write (sector, disk_inode);          
          success = true; 
        } 
      free (disk_inode);
    }
  return success;
}

struct inode* 
inode_create_dir(block_sector_t sector, enum inode_type type){
  /*
  struct cache_block* i_block = cache_lock(sector, DIR_INODE);
  struct inode_disk * i_d = cache_zero(i_block);
 
  i_d->type = DIR_INODE;
  i_d->length = 0;
  i_d->magic = INODE_MAGIC;
  cache_dirty(i_block);
  cache_unlock(i_block);
  struct inode* i_node = inode_open(sector);
  if(!i_node){
    free(i_d);
    return NULL;
  }
  return i_node;
  */
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      //printf("disk inode is not  null \n");
      size_t sectors = bytes_to_sectors (512);
      //printf("b 2 sec\n");
      disk_inode->length = 512;
      disk_inode->magic = INODE_MAGIC;
      disk_inode->type = type;
      if (true) 
        {
          
          if (sectors > 0) 
            {
              size_t i;
              inode_get_sector(disk_inode, sectors);
            }  
          inode_write (sector, disk_inode);          
          success = true; 
        } 
      free (disk_inode);
    }
    if(success){
      //printf("success create inode dir\n");
      return inode_open(sector);
    }else{
      return NULL;
    }
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;
  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          //printf("%d", sector);
          return inode; 
        }
    }
  //printf("sss %d\n", sector);
  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  inode_read (inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

enum inode_type
inode_get_itype(const struct inode *inode){
  struct cache_block *c_b = cache_lock(inode->sector, NON_EXCLUSIVE);
  struct inode_disk *i_d = cache_read(c_b);
  enum inode_type type = i_d->type;
  cache_unlock(c_b);
  return type;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);

      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          free_inode(inode);
        }

      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  if (size + offset > inode_length(inode)) return 0;
  //lock_acquire(&inode->lock);
  uint8_t *buffer = buffer_;
  off_t length = size + offset;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;
  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
          inode_read (sector_idx, buffer + bytes_read);
        }
      else 
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          inode_read (sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
    //lock_release(&inode->lock);
  free (bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

  

  if (size + offset > inode_length (inode)) {
    /*
    struct cache_block *b = cache_lock (inode->sector, NON_EXCLUSIVE);  
    struct inode_disk *data = cache_read (b);
    printf("www %d\n", data->sectors[0]);
    cache_unlock(b);
    */
    inode_read(inode->sector, &inode->data);
    struct inode_disk * data = &inode->data;
    off_t length = size + offset;
    size_t sectors = bytes_to_sectors (length);
    //lock_acquire(&inode->lock);
    inode_get_sector(data, sectors);
    //lock_release(&inode->lock);
    data->length = length;
    inode_write (inode->sector, data);
    
  }
  //lock_acquire(&inode->lock);
  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector directly to disk. */
          inode_write (sector_idx, buffer + bytes_written);
        }
      else 
        {
          /* We need a bounce buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left) 
            inode_read (sector_idx, bounce);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          inode_write (sector_idx, bounce);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);
  //lock_release(&inode->lock);
  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  inode_read(inode->sector, &inode->data);
  struct inode_disk * data = &inode->data;
  return data->length;
}
 
void inode_get_sector(struct inode_disk * data, size_t n) {
  static char zeros[BLOCK_SECTOR_SIZE];
  static block_sector_t sector_n[128];
  size_t offsets[3];
  size_t offset_cnt;
  size_t s1, s2, s3;
  size_t sector;
  int i;

  for (i = 0; i <= n; i++) {
    calculate_indices (i, offsets, &offset_cnt);
    if (offset_cnt == 1) {
      if (data->sectors[i] <= 0 || data->sectors[i] >= 4096) {

        free_map_allocate(1, &data->sectors[i]);
        inode_write (data->sectors[i], zeros);
      }
    }
    // Indirect index.
    if (offset_cnt == 2) {
      s1 = offsets[0];
      s2 = offsets[1];
      if (s2 == 0) {
        if (data->sectors[s1] == 0 || data->sectors[s1] > 4096) {
          free_map_allocate(1, &data->sectors[s1]);
          inode_write (data->sectors[s1], zeros);
        }
        inode_read(data->sectors[s1], &sector_n);
      }
      if (sector_n[s2] == 0) free_map_allocate(1, &sector_n[s2]);
      if (s2 == 127 || i == n) {
        inode_write (data->sectors[s1], sector_n);

      }  
      //printf("%d %d %d\n", data->sectors[s1], sector_n[s2], data->length);   
    }
    static block_sector_t sector_n1[128];

    // Double indirect
    if (offset_cnt == 3) {
      s1 = offsets[0];
      s2 = offsets[1];
      s3 = offsets[2];
      //printf("%d %d %d\n", data->sectors[s1], sector_n[s2], sector_n1[s3]);
      if (s2 == 0 && s3 == 0) {
        if (data->sectors[s1] == 0) {
          // allocate first level of sector
          free_map_allocate(1, &data->sectors[s1]);
          inode_write (data->sectors[s1], zeros);
        }
        inode_read (data->sectors[s1], &sector_n);
      }
      if (s3 == 0) {
        if (sector_n[s2] == 0) {
          free_map_allocate(1, &sector_n[s2]);
          inode_write (sector_n[s2], zeros);
        }
        inode_read (sector_n[s2], &sector_n1);
      }
      if (sector_n1[s3] == 0) {
        free_map_allocate(1, &sector_n1[s3]);
        inode_write (sector_n1[s3], zeros);
      }   
      if (i == n) {
        inode_write (sector_n[s2], sector_n1);
        inode_write(data->sectors[s1], sector_n);
        break;
      }
      if (s3 == 127) inode_write (sector_n[s2], sector_n1);
      if (s2 == 127 && s3 == 127) inode_write(data->sectors[s1], sector_n);
      //printf("%d %d %d\n", data->sectors[s1], sector_n[s2], sector_n1[s3]);
    }
      //printf("%d\n", data->sectors[i]);
  }
}



static void
calculate_indices (off_t sector_idx, size_t offsets[], size_t *offset_cnt)
{
  /* Handle direct blocks. */
  if (sector_idx < DIRECT_CNT) 
    {
      offsets[0] = sector_idx;
      *offset_cnt = 1;
      return;
    }
  sector_idx -= DIRECT_CNT;

  /* Handle indirect blocks. */
  if (sector_idx < PTRS_PER_SECTOR * INDIRECT_CNT)
    {
      offsets[0] = DIRECT_CNT + sector_idx / PTRS_PER_SECTOR;
      offsets[1] = sector_idx % PTRS_PER_SECTOR;
      *offset_cnt = 2;
      return;
    }
  sector_idx -= PTRS_PER_SECTOR * INDIRECT_CNT;

  /* Handle doubly indirect blocks. */
  if (sector_idx < DBL_INDIRECT_CNT * PTRS_PER_SECTOR * PTRS_PER_SECTOR)
    {
      offsets[0] = (DIRECT_CNT + INDIRECT_CNT
                    + sector_idx / (PTRS_PER_SECTOR * PTRS_PER_SECTOR));
      offsets[1] = sector_idx / PTRS_PER_SECTOR;
      offsets[2] = sector_idx % PTRS_PER_SECTOR;
      *offset_cnt = 3;
      return;
    }
  NOT_REACHED ();
}


void inode_write(block_sector_t sector, void * buffer) {
  struct cache_block * b = cache_lock (sector, EXCLUSIVE);
  void * sector_data = cache_read (b);
  memcpy (sector_data, buffer, BLOCK_SECTOR_SIZE);
  cache_dirty (b);
  cache_unlock (b);
}

void inode_read(block_sector_t sector, void * buffer) {
  struct cache_block * b = cache_lock (sector, NON_EXCLUSIVE);
  void * sector_data = cache_read(b);
  memcpy (buffer, sector_data, BLOCK_SECTOR_SIZE);
  cache_unlock(b); 
}

void free_inode(struct inode * inode) {
  struct cache_block *b = cache_lock (inode->sector, EXCLUSIVE);
  struct inode_disk *data = cache_read (b);
  cache_unlock(b);
  int i;
  for (i = 0; i < DIRECT_CNT; i++) {
    free_block_direct(data->sectors[i]);
  }
  for (i = DIRECT_CNT; i < DIRECT_CNT + INDIRECT_CNT; i++) {
    free_block_indirect(data->sectors[i]);
  }
  for (i = DIRECT_CNT + INDIRECT_CNT; i < SECTOR_CNT; i++) {
    free_block_d_indirect(data->sectors[i]);
  }
  free_block_direct(inode->sector);
}

void free_block_direct(block_sector_t sector) {
  if (sector == 0) return;
  cache_free (sector);
  free_map_release (sector, 1);
}

void free_block_indirect(block_sector_t sector) {
  if (sector == 0) return;
  block_sector_t sectors[128];
  inode_read(sector, sectors);
  int i;
  for (i = 0; i < 128; i++) {
    free_block_direct(sectors[i]);
  }
  cache_free(sector);
  free_map_release (sector, 1);
}

void free_block_d_indirect(block_sector_t sector) {
  if (sector == 0) return;
  block_sector_t sectors[128];
  inode_read(sector, sectors);
  int i;
  for (i = 0; i < 128; i++) {
    free_block_indirect(sectors[i]);
  }
  cache_free(sector);
  free_map_release (sector, 1);
}