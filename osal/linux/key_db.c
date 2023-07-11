// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <errno.h>
#include <sys/file.h>
#include <sys/stat.h>

#include "local.h"

#define PRIxID "0x%08X"

struct key_db_obj {
	int fp;
	void *mutex;
};

__weak void dbg_entry(struct key_entry *entry)
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

static int lock_db(struct key_db_obj *db)
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

static int unlock_db(struct key_db_obj *db)
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
 * find_db_key_id() - Find a key ID in the database
 * @db: Key database
 * @id: Key id to find
 * @key: Key entry found
 * @pos: File position to the key header if key id found, else -1
 *
 */
static void find_db_key_id(struct key_db_obj *db, unsigned int id,
			   struct key_entry *key, long *pos)
{
	off_t off = 0;
	ssize_t nb_bytes = 0;
	size_t inc = 0;

	*pos = -1;

	while ((nb_bytes = pread(db->fp, key, sizeof(*key), off)) > 0 &&
	       nb_bytes == sizeof(*key)) {
		DBG_PRINTF(DEBUG, "%s ID=%u vs %u\n", __func__, key->id, id);
		if (key->id != id) {
			/* Go to the next entry */
			if (ADD_OVERFLOW(sizeof(*key), key->info_size, &inc) ||
			    ADD_OVERFLOW(off, inc, &off))
				break;
			continue;
		}

		*pos = off;

		dbg_entry(key);
		break;
	}
}

/**
 * find_db_key_free() - Find a key ID free in the database
 * @db: Key database
 * @key: OSAL key object
 * @free_id: Free key id in range
 * @pos: File position to the key header if key id found, else -1
 *
 * The @free_id value is the key id free in the database matching
 * the OSAL key range given if the free entry found.
 * If no key free entry found, the @free_id is the next key id
 * free in the given OSAL key range.
 *
 */
static void find_db_key_free(struct key_db_obj *db, struct osal_key *key,
			     unsigned int *free_id, long *pos)
{
	off_t off = 0;
	off_t inc_off = 0;
	ssize_t nb_bytes = 0;
	struct key_entry rd_key = { 0 };
	unsigned int last_id = 0;

	*pos = -1;

	while ((nb_bytes = pread(db->fp, &rd_key, sizeof(rd_key), off)) > 0 &&
	       nb_bytes == sizeof(rd_key)) {
		/*
		 * If the key id read is the requested range
		 * set the last_id value
		 */
		if (rd_key.id >= key->range.min && rd_key.id <= key->range.max)
			last_id = rd_key.id;

		if (last_id != rd_key.id || rd_key.flags != ENTRY_FREE ||
		    rd_key.info_size < key->info_size) {
			/* Go to the next entry */
			if (ADD_OVERFLOW(rd_key.info_size, sizeof(rd_key),
					 &inc_off))
				return;
			if (ADD_OVERFLOW(inc_off, off, &off))
				return;

			continue;
		}

		*pos = off;
		*free_id = rd_key.id;

		return;
	}

	if (!last_id)
		*free_id = key->range.min;
	else
		*free_id = last_id + 1;
}

/**
 * write_key_db() - Write a Key in the database
 * @db: Key database
 * @key: Key entry
 * @info: Key information
 * @pos: Position from the beginning to write
 *
 * Return:
 * 0 if success, -1 otherwise
 */
static int write_key_db(struct key_db_obj *db, struct key_entry *key,
			void *info, long pos)
{
	int err = -1;
	off_t off = pos;
	struct stat f_stat = { 0 };
	ssize_t nb_bytes = 0;

	DBG_PRINTF(DEBUG, "%s (%d) pos = %ld\n", __func__, __LINE__, pos);

	dbg_entry(key);

	if (off < 0) {
		if (fstat(db->fp, &f_stat)) {
			DBG_PRINTF(ERROR, "%s (%d) DB fstat error\n", __func__,
				   __LINE__);
			goto end;
		}
		off = f_stat.st_size;
	}

	nb_bytes = pwrite(db->fp, key, sizeof(*key), off);
	if (nb_bytes < 0 || nb_bytes != (ssize_t)sizeof(*key)) {
		DBG_PRINTF(ERROR, "%s (%d) DB write error\n", __func__,
			   __LINE__);
		goto end;
	}

	if (info) {
		dbg_entry_info(info, key->info_size);

		off += sizeof(*key);
		nb_bytes = pwrite(db->fp, info, key->info_size, off);
		if (nb_bytes < 0 || (size_t)nb_bytes != key->info_size) {
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

static void close_db_file(struct key_db_obj *db)
{
	if (db->fp) {
		(void)mutex_destroy(&db->mutex);

		(void)close(db->fp);

		db->fp = 0;
	}
}

int key_db_open(const char *key_db)
{
	int ret = -1;
	struct osal_ctx *ctx = get_osal_ctx();
	struct key_db_obj *db = NULL;

	if (!ctx)
		return ret;

	db = ctx->key_db_obj;

	if (!db) {
		/*
		 * Allocate the Key database object and mutex
		 */
		db = calloc(1, sizeof(*db));
		if (!db) {
			DBG_PRINTF(ERROR, "Key database allocation error\n");
			goto end;
		}

		ctx->key_db_obj = db;
	} else if (db->fp) {
		close_db_file(db);
	}

	/*
	 * Open the application key database file.
	 * Try to open it for read/write assuming file exist, if
	 * file doesn't exist create a new file.
	 */
	db->fp = open(key_db, O_RDWR | O_SYNC | O_CREAT, 777);
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
		ctx->key_db_obj = NULL;
	}

	return ret;
}

void key_db_close(void)
{
	struct osal_ctx *ctx = get_osal_ctx();
	struct key_db_obj *db = NULL;

	if (!ctx)
		return;

	db = ctx->key_db_obj;

	if (!db)
		return;

	close_db_file(db);

	free(db);

	ctx->key_db_obj = NULL;
}

int key_db_get_info(struct osal_key *key)
{
	int ret = -1;
	ssize_t nb_bytes = 0;
	long pos = -1;
	off_t offset = 0;
	struct osal_ctx *ctx = get_osal_ctx();
	struct key_db_obj *db = NULL;
	struct key_entry entry = { 0 };

	if (!ctx)
		return ret;

	db = ctx->key_db_obj;

	if (!db || !db->fp) {
		DBG_PRINTF(ERROR, "Key database not valid");
		return ret;
	}

	if (!key || !key->info || !key->info_size)
		return ret;

	if (lock_db(db))
		return ret;

	find_db_key_id(db, key->id, &entry, &pos);

	DBG_PRINTF(INFO, "%s (%d) key id " PRIxID " @%ld\n", __func__, __LINE__,
		   key->id, pos);

	if (pos < 0) {
		/* Set key to 0 - invalid key id */
		key->id = 0;
		goto end;
	}

	if (entry.flags != ENTRY_USE) {
		DBG_PRINTF(ERROR, "%s (%d) key id " PRIxID " not valid\n",
			   __func__, __LINE__, key->id);
		/* Set key to 0 - invalid key id */
		key->id = 0;
		goto end;
	}

	if (key->info_size < entry.info_size) {
		DBG_PRINTF(ERROR, "%s (%d) out too short (%zu) expected %zu\n",
			   __func__, __LINE__, key->info_size, entry.info_size);
		goto end;
	}

	/* Read the key information and exit */
	if (ADD_OVERFLOW(pos, sizeof(entry), &offset))
		goto end;

	nb_bytes = pread(db->fp, key->info, entry.info_size, offset);
	if (nb_bytes > 0 || nb_bytes == (ssize_t)entry.info_size) {
		dbg_entry_info(key->info, entry.info_size);
		ret = 0;
	} else {
		DBG_PRINTF(ERROR, "%s (%d) bad info\n", __func__, __LINE__);
	}

end:
	if (unlock_db(db))
		ret = -1;

	return ret;
}

int key_db_add(struct osal_key *key)
{
	struct osal_ctx *ctx = get_osal_ctx();
	struct key_db_obj *db = NULL;
	int ret = -1;
	long pos = -1;
	unsigned int free_id = 0;
	struct key_entry entry = { 0 };

	if (!ctx)
		return ret;

	db = ctx->key_db_obj;

	if (!db || !db->fp) {
		DBG_PRINTF(ERROR, "Key database not valid");
		return ret;
	}

	if (!key || !key->info || !key->info_size)
		return ret;

	if (lock_db(db))
		return ret;

	entry.id = key->range.min;

	/* Try to find a key entry free */
	find_db_key_free(db, key, &free_id, &pos);

	/*
	 * No free key entry found add the key entry at the end.
	 * Key ID must be in the given key range.
	 * Note the free_id value has been incremented by the
	 * function find_db_key_free()
	 */
	if (pos == -1 && free_id > key->range.max)
		goto end;

	entry.id = free_id;
	entry.flags = ENTRY_USE;
	entry.persitent = key->persistent;
	entry.info_size = key->info_size;

	ret = write_key_db(db, &entry, key->info, pos);

end:
	if (!ret) {
		key->id = entry.id;
		DBG_PRINTF(INFO, "%s (%d) Added key id " PRIxID "\n", __func__,
			   __LINE__, key->id);
	}

	if (unlock_db(db))
		ret = -1;

	return ret;
}

int key_db_update(struct osal_key *key)
{
	int ret = -1;
	long pos = -1;
	struct osal_ctx *ctx = get_osal_ctx();
	struct key_db_obj *db = NULL;
	struct key_entry entry = { 0 };

	if (!ctx)
		return ret;

	db = ctx->key_db_obj;

	if (!db || !db->fp) {
		DBG_PRINTF(ERROR, "Key database not valid");
		return ret;
	}

	if (!key || !key->info || !key->info_size)
		return ret;

	if (lock_db(db))
		return ret;

	find_db_key_id(db, key->id, &entry, &pos);

	DBG_PRINTF(INFO, "%s (%d) key id " PRIxID " @%ld\n", __func__, __LINE__,
		   key->id, pos);

	if (pos < 0)
		goto end;

	if (entry.flags != ENTRY_USE) {
		DBG_PRINTF(ERROR, "%s (%d) key id " PRIxID " not valid\n",
			   __func__, __LINE__, key->id);
		goto end;
	}

	if (key->info_size > entry.info_size) {
		DBG_PRINTF(ERROR, "%s (%d) input too long (%zu) expected %zu\n",
			   __func__, __LINE__, key->info_size, entry.info_size);
		goto end;
	}

	entry.info_size = key->info_size;
	ret = write_key_db(db, &entry, key->info, pos);

end:
	if (unlock_db(db))
		ret = -1;

	return ret;
}

int key_db_delete(struct osal_key *key)
{
	int ret = -1;
	long pos = -1;
	struct osal_ctx *ctx = get_osal_ctx();
	struct key_db_obj *db = NULL;
	struct key_entry entry = { 0 };

	if (!ctx)
		return ret;

	db = ctx->key_db_obj;

	if (!db || !db->fp) {
		DBG_PRINTF(ERROR, "Key database not valid");
		return ret;
	}

	if (!key)
		return ret;

	if (lock_db(db))
		return ret;

	find_db_key_id(db, key->id, &entry, &pos);

	DBG_PRINTF(INFO, "%s (%d) key id " PRIxID " @%ld\n", __func__, __LINE__,
		   key->id, pos);

	if (pos >= 0) {
		entry.flags = ENTRY_FREE;
		ret = write_key_db(db, &entry, NULL, pos);
	}

	if (unlock_db(db))
		ret = -1;

	return ret;
}
