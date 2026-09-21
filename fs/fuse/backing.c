// SPDX-License-Identifier: GPL-2.0
/*
 * FUSE passthrough to backing file.
 *
 * Copyright (c) 2023 CTERA Networks.
 */

#include "dev.h"
#include "fuse_i.h"

#include <linux/file.h>
#include <linux/rhashtable.h>

static struct fuse_backing *fuse_backing_get(struct fuse_backing *fb)
{
	if (fb && refcount_inc_not_zero(&fb->count))
		return fb;
	return NULL;
}

static void fuse_backing_free(struct fuse_backing *fb)
{
	pr_debug("%s: fb=0x%p\n", __func__, fb);

	if (fb->file)
		fput(fb->file);
	put_cred(fb->cred);
	kfree_rcu(fb, rcu);
}

void fuse_backing_put(struct fuse_backing *fb)
{
	if (fb && refcount_dec_and_test(&fb->count))
		fuse_backing_free(fb);
}

static int fuse_backing_id_alloc(struct fuse_conn *fc, struct fuse_backing *fb)
{
	int id;

	idr_preload(GFP_KERNEL);
	spin_lock(&fc->lock);
	/* FIXME: xarray might be space inefficient */
	id = idr_alloc_cyclic(&fc->backing_files_map, fb, 1, 0, GFP_ATOMIC);
	spin_unlock(&fc->lock);
	idr_preload_end();

	WARN_ON_ONCE(id == 0);
	return id;
}

static const struct rhashtable_params fuse_backing_params = {
	.head_offset = offsetof(struct fuse_backing, hash_node),
	.key_offset = offsetof(struct fuse_backing, backing_id),
	.key_len = sizeof_field(struct fuse_backing, backing_id),
};

int fuse_backing_add_64(struct fuse_conn *fc, struct fuse_backing *fb)
{
	return rhashtable_insert_fast(&fc->backing_64_ht, &fb->hash_node, fuse_backing_params);
}

static struct fuse_backing *fuse_backing_id_remove(struct fuse_conn *fc, u64 id, bool is_64bit)
{
	struct fuse_backing *fb;
	int err;

	guard(spinlock)(&fc->lock);
	if (!is_64bit)
		return idr_remove(&fc->backing_files_map, id);

	fb = rhashtable_lookup_fast(&fc->backing_64_ht, &id, fuse_backing_params);
	if (!fb)
		return NULL;

	err = rhashtable_remove_fast(&fc->backing_64_ht, &fb->hash_node, fuse_backing_params);
	WARN_ON(err);

	return fb;
}

int fuse_backing_open(struct fuse_conn *fc, struct fuse_backing_map *map)
{
	struct file *file;
	struct super_block *backing_sb;
	struct fuse_backing *fb;
	bool is_64bit = map->flags & FUSE_BACKING_ID_64;
	int res;

	pr_debug("%s: fd=%d flags=0x%x\n", __func__, map->fd, map->flags);

	/* TODO: relax CAP_SYS_ADMIN once backing files are visible to lsof */
	res = -EPERM;
	if (!fc->passthrough || !capable(CAP_SYS_ADMIN))
		goto out;

	res = -EINVAL;
	if (map->flags & ~FUSE_BACKING_ID_64)
		goto out;

	if (!is_64bit && map->backing_id != 0)
		goto out;

	file = fget_raw(map->fd);
	res = -EBADF;
	if (!file)
		goto out;

	/* read/write/splice/mmap passthrough only relevant for regular files */
	res = d_is_dir(file->f_path.dentry) ? -EISDIR : -EINVAL;
	if (!d_is_reg(file->f_path.dentry))
		goto out_fput;

	backing_sb = file_inode(file)->i_sb;
	res = -ELOOP;
	if (backing_sb->s_stack_depth >= fc->max_stack_depth)
		goto out_fput;

	fb = kmalloc_obj(struct fuse_backing);
	res = -ENOMEM;
	if (!fb)
		goto out_fput;

	fb->file = file;
	fb->cred = get_current_cred();
	fb->backing_id = map->backing_id;
	refcount_set(&fb->count, 1);

	if (is_64bit)
		res = fuse_backing_add_64(fc, fb);
	else
		res = fuse_backing_id_alloc(fc, fb);
	if (res < 0) {
		fuse_backing_free(fb);
		fb = NULL;
	}

out:
	pr_debug("%s: fb=0x%p, ret=%i\n", __func__, fb, res);

	return res;

out_fput:
	fput(file);
	goto out;
}

int fuse_backing_close(struct fuse_conn *fc, u64 backing_id, bool is_64bit)
{
	struct fuse_backing *fb = NULL;
	int err;

	pr_debug("%s: backing_id=%lld\n", __func__, backing_id);

	err = -EINVAL;
	if (!is_64bit && (backing_id == 0 || backing_id > INT_MAX))
		goto out;

	err = -ENOENT;
	fb = fuse_backing_id_remove(fc, backing_id, is_64bit);
	if (!fb)
		goto out;

	fuse_backing_put(fb);
	err = 0;
out:
	pr_debug("%s: fb=0x%p, err=%i\n", __func__, fb, err);

	return err;
}

struct fuse_backing *fuse_backing_lookup(struct fuse_conn *fc, u64 backing_id, bool is_64bit)
{
	struct fuse_backing *fb;

	guard(rcu)();
	if (!is_64bit)
		fb = idr_find(&fc->backing_files_map, backing_id);
	else
		fb = rhashtable_lookup(&fc->backing_64_ht, &backing_id, fuse_backing_params);

	return fuse_backing_get(fb);
}

static void fuse_backing_check_free(struct fuse_backing *fb)
{
	WARN_ON_ONCE(refcount_read(&fb->count) != 1);
	fuse_backing_free(fb);
}

static int fuse_backing_idr_free(int id, void *p, void *data)
{
	fuse_backing_check_free(p);
	return 0;
}

static void fuse_backing_rht_free(void *p, void *data)
{
	fuse_backing_check_free(p);
}

void fuse_backing_files_free(struct fuse_conn *fc)
{
	idr_for_each(&fc->backing_files_map, fuse_backing_idr_free, NULL);
	idr_destroy(&fc->backing_files_map);

	rhashtable_free_and_destroy(&fc->backing_64_ht, fuse_backing_rht_free, NULL);
}

void fuse_backing_files_init(struct fuse_conn *fc)
{
	int err;

	idr_init(&fc->backing_files_map);
	err = rhashtable_init(&fc->backing_64_ht, &fuse_backing_params);
	WARN_ON(err); /* fails on programming error only */
}
