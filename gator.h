/**
 * Copyright 2010  ARM, Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/******************************************************************************
 * Filesystem
 ******************************************************************************/
int gatorfs_create_file_perm(struct super_block *sb, struct dentry *root,
	char const *name, const struct file_operations *fops, int perm);

struct dentry *gatorfs_mkdir(struct super_block *sb,
	struct dentry *root, char const *name);

int gatorfs_create_ulong(struct super_block *sb, struct dentry *root,
	char const *name, unsigned long *val);

int gatorfs_create_ro_ulong(struct super_block *sb, struct dentry *root,
	char const *name, unsigned long *val);

/******************************************************************************
 * Events
 ******************************************************************************/
struct __gator_interface {
	int  (*create_files)(struct super_block *sb, struct dentry *root);
	int  (*init)(int *key);
	int  (*start)(void);
	void (*stop)(void);
	int  (*read)(int **buffer);
	struct __gator_interface *next;
};

typedef struct __gator_interface gator_interface;

int gator_event_install(int (*event_install)(gator_interface *));
