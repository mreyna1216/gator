/**
 * Copyright 2010  ARM, Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */


struct __gator_interface {
	int  (*create_files)(struct super_block *sb, struct dentry *root);
	int  (*init)(int *key);
	int  (*start)(void);
	void (*stop)(void);
	int  (*read)(int **buffer);
	struct __gator_interface *next;
};

typedef struct __gator_interface gator_interface;
