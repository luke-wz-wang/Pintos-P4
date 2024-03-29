#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "devices/block.h"

struct bitmap;
/* Type of an inode. */
enum inode_type 
  {
    FILE_INODE,         /* Ordinary file. */
    DIR_INODE           /* Directory. */
  };
void inode_init (void);
bool inode_create (block_sector_t, off_t);
struct inode *inode_create_dir(block_sector_t, enum inode_type);
struct inode *inode_open (block_sector_t);
struct inode *inode_reopen (struct inode *);
block_sector_t inode_get_inumber (const struct inode *);
enum inode_type inode_get_itype(const struct inode *);
void inode_close (struct inode *);
void inode_remove (struct inode *);
off_t inode_read_at (struct inode *, void *, off_t size, off_t offset);
off_t inode_write_at (struct inode *, const void *, off_t size, off_t offset);
void inode_deny_write (struct inode *);
void inode_allow_write (struct inode *);
off_t inode_length (const struct inode *);
static void calculate_indices (off_t sector_idx, size_t offsets[], size_t *offset_cnt);
void inode_write(block_sector_t sector, void * buffer);
void inode_read(block_sector_t sector, void * buffer);
void free_inode(struct inode * inode);
void free_block_direct(block_sector_t sector);
void free_block_indirect(block_sector_t sector);
void free_block_d_indirect(block_sector_t sector);
#endif /* filesys/inode.h */
