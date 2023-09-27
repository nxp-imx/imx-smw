// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <errno.h>
#include <sys/file.h>
#include <sys/stat.h>

#include "local.h"

#define PRIxID "0x%08X"

struct obj_db {
	int fp;
	void *mutex;
};

__weak void dbg_entry(struct obj_entry *entry)
{
	(void)entry;
}

__weak void dbg_entry_info(void *buf, size_t len)
{
	(void)buf;
	(void)len;
}

__weak void dbg_get_lock_file(int fp)
{
	(void)fp;
}

static int lock_db(struct obj_db *db)
{
	int ret = 0;
	struct flock lock = { 0 };

	ret = mutex_lock(db->mutex);
	if (ret)
		return ret;

	lock.l_type = F_WRLCK;
	if (fcntl(db->fp, F_SETLKW, &lock)) {
		dbg_get_lock_file(db->fp);
		DBG_PRINTF(DEBUG, "Unable to lock: %s\n", get_strerr());
		(void)mutex_unlock(db->mutex);
		ret = -1;
	}

	// coverity[missing_unlock]
	return ret;
}

static int unlock_db(struct obj_db *db)
{
	struct flock lock = { 0 };

	lock.l_type = F_UNLCK;
	if (fcntl(db->fp, F_SETLKW, &lock)) {
		DBG_PRINTF(DEBUG, "Unable to unlock: %s\n", get_strerr());
		return -1;
	}

	return mutex_unlock(db->mutex);
}

/**
 * find_db_obj_id() - Find an object ID in the database
 * @db: Object database
 * @id: Object id to find
 * @obj: Object entry found
 * @pos: File position to the object header if object id found, else -1
 *
 */
static void find_db_obj_id(struct obj_db *db, unsigned int id,
			   struct obj_entry *obj, long *pos)
{
	off_t off = 0;
	ssize_t nb_bytes = 0;
	size_t inc = 0;

	*pos = -1;

	while ((nb_bytes = pread(db->fp, obj, sizeof(*obj), off)) > 0 &&
	       nb_bytes == sizeof(*obj)) {
		DBG_PRINTF(DEBUG, "%s ID=%u vs %u\n", __func__, obj->id, id);
		if (obj->id != id) {
			/* Go to the next entry */
			if (ADD_OVERFLOW(sizeof(*obj), obj->info_size, &inc) ||
			    ADD_OVERFLOW(off, inc, &off))
				break;
			continue;
		}

		*pos = off;

		dbg_entry(obj);
		break;
	}
}

/**
 * find_db_obj_free() - Find an object ID free in the database
 * @db: Object database
 * @obj: OSAL object
 * @free_id: Free object id in range
 * @pos: File position to the object header if object id found, else -1
 *
 * The @free_id value is the free object id in the database matching
 * the OSAL object range given if the free entry found.
 * If no free object entry found, the @free_id is the next free object id
 * in the given OSAL object range.
 *
 */
static void find_db_obj_free(struct obj_db *db, struct osal_obj *obj,
			     unsigned int *free_id, long *pos)
{
	off_t off = 0;
	off_t inc_off = 0;
	ssize_t nb_bytes = 0;
	struct obj_entry rd_obj = { 0 };
	unsigned int last_id = 0;

	*pos = -1;

	while ((nb_bytes = pread(db->fp, &rd_obj, sizeof(rd_obj), off)) > 0 &&
	       nb_bytes == sizeof(rd_obj)) {
		/*
		 * If the object id read is the requested range
		 * set the last_id value
		 */
		if (rd_obj.id >= obj->range.min && rd_obj.id <= obj->range.max)
			last_id = rd_obj.id;

		if (last_id != rd_obj.id || rd_obj.flags != ENTRY_FREE ||
		    rd_obj.info_size < obj->info_size) {
			/* Go to the next entry */
			if (ADD_OVERFLOW(rd_obj.info_size, sizeof(rd_obj),
					 &inc_off))
				return;
			if (ADD_OVERFLOW(inc_off, off, &off))
				return;

			continue;
		}

		*pos = off;
		*free_id = rd_obj.id;

		return;
	}

	if (!last_id)
		*free_id = obj->range.min;
	else
		*free_id = last_id + 1;
}

/**
 * write_obj_db() - Write an object in the database
 * @db: Object database
 * @obj: Object entry
 * @info: Object information
 * @pos: Position from the beginning to write
 *
 * Return:
 * 0 if success, -1 otherwise
 */
static int write_obj_db(struct obj_db *db, struct obj_entry *obj, void *info,
			long pos)
{
	int err = -1;
	off_t off = pos;
	struct stat f_stat = { 0 };
	ssize_t nb_bytes = 0;

	DBG_PRINTF(DEBUG, "%s (%d) pos = %ld\n", __func__, __LINE__, pos);

	dbg_entry(obj);

	if (off < 0) {
		if (fstat(db->fp, &f_stat)) {
			DBG_PRINTF(ERROR, "%s (%d) DB fstat error\n", __func__,
				   __LINE__);
			goto end;
		}
		off = f_stat.st_size;
	}

	nb_bytes = pwrite(db->fp, obj, sizeof(*obj), off);
	if (nb_bytes < 0 || nb_bytes != (ssize_t)sizeof(*obj)) {
		DBG_PRINTF(ERROR, "%s (%d) DB write error\n", __func__,
			   __LINE__);
		goto end;
	}

	if (info) {
		dbg_entry_info(info, obj->info_size);

		off += sizeof(*obj);
		nb_bytes = pwrite(db->fp, info, obj->info_size, off);
		if (nb_bytes < 0 || (size_t)nb_bytes != obj->info_size) {
			DBG_PRINTF(ERROR, "%s (%d) DB write error\n", __func__,
				   __LINE__);
			goto end;
		}

		if (fsync(db->fp)) {
			DBG_PRINTF(ERROR, "%s (%d) DB write error\n", __func__,
				   __LINE__);
			goto end;
		}
	}

	err = 0;

end:
	return err;
}

static void close_db_file(struct obj_db *db)
{
	if (db->fp) {
		(void)mutex_destroy(&db->mutex);

		(void)close(db->fp);

		db->fp = 0;
	}
}

int obj_db_open(const char *obj_db)
{
	int ret = -1;
	struct osal_ctx *ctx = get_osal_ctx();
	struct obj_db *db = NULL;

	if (!ctx)
		return ret;

	db = ctx->obj_db;

	if (!db) {
		/*
		 * Allocate the object database and mutex
		 */
		db = calloc(1, sizeof(*db));
		if (!db) {
			DBG_PRINTF(ERROR, "Object database allocation error\n");
			goto end;
		}

		ctx->obj_db = db;
	} else if (db->fp) {
		close_db_file(db);
	}

	/*
	 * Open the application object database file.
	 * Try to open it for read/write assuming file exist, if
	 * file doesn't exist create a new file.
	 */
	db->fp = open(obj_db, O_RDWR | O_SYNC | O_CREAT, 777);
	if (db->fp < 0) {
		DBG_PRINTF(ERROR, "%s (%d): %s\n", __func__, __LINE__,
			   get_strerr());
		db->fp = 0;
		goto end;
	}

	ret = mutex_init(&db->mutex);

end:
	if (ret && db) {
		close_db_file(db);
		(void)mutex_destroy(&db->mutex);

		free(db);
		ctx->obj_db = NULL;
	}

	return ret;
}

void obj_db_close(void)
{
	struct osal_ctx *ctx = get_osal_ctx();
	struct obj_db *db = NULL;

	if (!ctx)
		return;

	db = ctx->obj_db;

	if (!db)
		return;

	close_db_file(db);

	free(db);

	ctx->obj_db = NULL;
}

int obj_db_get_info(struct osal_obj *obj)
{
	int ret = -1;
	ssize_t nb_bytes = 0;
	long pos = -1;
	off_t offset = 0;
	struct osal_ctx *ctx = get_osal_ctx();
	struct obj_db *db = NULL;
	struct obj_entry entry = { 0 };

	if (!ctx)
		return ret;

	db = ctx->obj_db;

	if (!db || !db->fp) {
		DBG_PRINTF(ERROR, "Object database not valid");
		return ret;
	}

	if (!obj || !obj->info || !obj->info_size)
		return ret;

	if (lock_db(db))
		return ret;

	find_db_obj_id(db, obj->id, &entry, &pos);

	DBG_PRINTF(INFO, "%s (%d) object id " PRIxID " @%ld\n", __func__,
		   __LINE__, obj->id, pos);

	if (pos < 0) {
		/* Set object id to 0 - invalid */
		obj->id = 0;
		goto end;
	}

	if (entry.flags != ENTRY_USE) {
		DBG_PRINTF(ERROR, "%s (%d) object id " PRIxID " not valid\n",
			   __func__, __LINE__, obj->id);
		/* Set object id to 0 - invalid */
		obj->id = 0;
		goto end;
	}

	if (obj->info_size < entry.info_size) {
		DBG_PRINTF(ERROR, "%s (%d) out too short (%zu) expected %zu\n",
			   __func__, __LINE__, obj->info_size, entry.info_size);
		goto end;
	}

	/* Read the object information and exit */
	if (ADD_OVERFLOW(pos, sizeof(entry), &offset))
		goto end;

	nb_bytes = pread(db->fp, obj->info, entry.info_size, offset);
	if (nb_bytes > 0 || nb_bytes == (ssize_t)entry.info_size) {
		dbg_entry_info(obj->info, entry.info_size);
		ret = 0;
	} else {
		DBG_PRINTF(ERROR, "%s (%d) bad info\n", __func__, __LINE__);
	}

end:
	if (unlock_db(db))
		ret = -1;

	return ret;
}

int obj_db_add(struct osal_obj *obj)
{
	struct osal_ctx *ctx = get_osal_ctx();
	struct obj_db *db = NULL;
	int ret = -1;
	long pos = -1;
	unsigned int free_id = 0;
	struct obj_entry entry = { 0 };

	if (!ctx)
		return ret;

	db = ctx->obj_db;

	if (!db || !db->fp) {
		DBG_PRINTF(ERROR, "Object database not valid");
		return ret;
	}

	if (!obj || !obj->info || !obj->info_size)
		return ret;

	if (lock_db(db))
		return ret;

	entry.id = obj->range.min;

	/* Try to find a free object entry */
	find_db_obj_free(db, obj, &free_id, &pos);

	/*
	 * No free object entry found add the object entry at the end.
	 * Object ID must be in the given object range.
	 * Note the free_id value has been incremented by the
	 * function find_db_obj_free()
	 */
	if (pos == -1 && free_id > obj->range.max)
		goto end;

	entry.id = free_id;
	entry.flags = ENTRY_USE;
	entry.persistence = obj->persistence;
	entry.info_size = obj->info_size;

	ret = write_obj_db(db, &entry, obj->info, pos);

end:
	if (!ret) {
		obj->id = entry.id;
		DBG_PRINTF(INFO, "%s (%d) Added object id " PRIxID "\n",
			   __func__, __LINE__, obj->id);
	}

	if (unlock_db(db))
		ret = -1;

	return ret;
}

int obj_db_update(struct osal_obj *obj)
{
	int ret = -1;
	long pos = -1;
	struct osal_ctx *ctx = get_osal_ctx();
	struct obj_db *db = NULL;
	struct obj_entry entry = { 0 };

	if (!ctx)
		return ret;

	db = ctx->obj_db;

	if (!db || !db->fp) {
		DBG_PRINTF(ERROR, "Object database not valid");
		return ret;
	}

	if (!obj || !obj->info || !obj->info_size)
		return ret;

	if (lock_db(db))
		return ret;

	find_db_obj_id(db, obj->id, &entry, &pos);

	DBG_PRINTF(INFO, "%s (%d) object id " PRIxID " @%ld\n", __func__,
		   __LINE__, obj->id, pos);

	if (pos < 0)
		goto end;

	if (entry.flags != ENTRY_USE) {
		DBG_PRINTF(ERROR, "%s (%d) object id " PRIxID " not valid\n",
			   __func__, __LINE__, obj->id);
		goto end;
	}

	if (obj->info_size > entry.info_size) {
		DBG_PRINTF(ERROR, "%s (%d) input too long (%zu) expected %zu\n",
			   __func__, __LINE__, obj->info_size, entry.info_size);
		goto end;
	}

	entry.info_size = obj->info_size;
	ret = write_obj_db(db, &entry, obj->info, pos);

end:
	if (unlock_db(db))
		ret = -1;

	return ret;
}

int obj_db_delete(struct osal_obj *obj)
{
	int ret = -1;
	long pos = -1;
	struct osal_ctx *ctx = get_osal_ctx();
	struct obj_db *db = NULL;
	struct obj_entry entry = { 0 };

	if (!ctx)
		return ret;

	db = ctx->obj_db;

	if (!db || !db->fp) {
		DBG_PRINTF(ERROR, "Object database not valid");
		return ret;
	}

	if (!obj)
		return ret;

	if (lock_db(db))
		return ret;

	find_db_obj_id(db, obj->id, &entry, &pos);

	DBG_PRINTF(INFO, "%s (%d) object id " PRIxID " @%ld\n", __func__,
		   __LINE__, obj->id, pos);

	if (pos >= 0) {
		entry.flags = ENTRY_FREE;
		ret = write_obj_db(db, &entry, NULL, pos);
	}

	if (unlock_db(db))
		ret = -1;

	return ret;
}
