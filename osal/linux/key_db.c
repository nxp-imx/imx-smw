// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022 NXP
 */

#include <errno.h>
#include <sys/file.h>

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
	struct flock lock = { 0 };

	lock.l_type = F_WRLCK;
	if (fcntl(db->fp, F_SETLKW, &lock)) {
		dbg_get_lock_file(db->fp);
		DBG_PRINTF(DEBUG, "Unable to lock: %s\n", get_strerr());
		return -1;
	}

	return mutex_lock(db->mutex);
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
 *
 * Return:
 * File position to the key header if key id found,
 * Otherwise -1
 */
static long find_db_key_id(struct key_db_obj *db, unsigned int id,
			   struct key_entry *key)
{
	long pos = -1;
	long cur_pos = 0;
	ssize_t off;

	if (lseek(db->fp, 0, SEEK_SET))
		return pos;

	while (read(db->fp, key, sizeof(*key)) == sizeof(*key)) {
		cur_pos += sizeof(*key);
		if (key->id != id) {
			/* Go to the next entry */
			off = lseek(db->fp, key->info_size, SEEK_CUR);
			cur_pos += key->info_size;
			if (off != cur_pos)
				break;

			continue;
		}

		pos = cur_pos - sizeof(*key);

		dbg_entry(key);
		break;
	}

	return pos;
}

/**
 * find_db_key_free() - Find a key ID free in the database
 * @db: Key database
 * @key: OSAL key object
 * @free_id: Free key id in range
 *
 * The @free_id value is the key id free in the database matching
 * the OSAL key range given if the free entry found.
 * If no key free entry found, the @free_id is the next key id
 * free in the given OSAL key range.
 *
 * Return:
 * File position to the key header if key id found,
 * Otherwise -1
 */
static long find_db_key_free(struct key_db_obj *db, struct osal_key *key,
			     unsigned int *free_id)
{
	long cur_pos = 0;
	long pos = -1;
	ssize_t off;
	struct key_entry rd_key;
	unsigned int last_id = 0;

	while (read(db->fp, &rd_key, sizeof(rd_key)) == sizeof(rd_key)) {
		cur_pos += sizeof(rd_key);
		/*
		 * If the key id read is the requested range
		 * set the last_id value
		 */
		if (rd_key.id >= key->range.min && rd_key.id <= key->range.max)
			last_id = rd_key.id;

		if (last_id != rd_key.id || rd_key.flags != ENTRY_FREE ||
		    rd_key.info_size < key->info_size) {
			/* Go to the next entry */
			off = lseek(db->fp, rd_key.info_size, SEEK_CUR);
			cur_pos += rd_key.info_size;
			if (off != cur_pos)
				break;

			continue;
		}

		pos = cur_pos - sizeof(rd_key);
		*free_id = rd_key.id;

		return pos;
	}

	if (!last_id)
		*free_id = key->range.min;
	else
		*free_id = last_id + 1;

	return pos;
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
	DBG_PRINTF(DEBUG, "%s (%d) pos = %ld\n", __func__, __LINE__, pos);
	if (pos < 0 || lseek(db->fp, pos, SEEK_SET) != pos)
		return -1;

	dbg_entry(key);

	if (write(db->fp, key, sizeof(*key)) != sizeof(*key)) {
		DBG_PRINTF(ERROR, "%s (%d) DB write error\n", __func__,
			   __LINE__);
		return -1;
	}

	if (!info)
		return 0;

	dbg_entry_info(info, key->info_size);

	if (write(db->fp, info, key->info_size) != (ssize_t)key->info_size) {
		DBG_PRINTF(ERROR, "%s (%d) DB write error\n", __func__,
			   __LINE__);
		return -1;
	}

	return 0;
}

static void close_db_file(void)
{
	struct key_db_obj *db = osal_priv.key_db_obj;

	if (!db)
		return;

	if (db->fp) {
		(void)mutex_destroy(&db->mutex);

		(void)close(db->fp);

		db->fp = 0;
	}
}

int key_db_open(const char *key_db)
{
	struct key_db_obj *db = osal_priv.key_db_obj;

	if (!db) {
		/*
		 * Allocate the Key database object and mutex
		 */
		db = calloc(1, sizeof(*db));
		if (!db) {
			DBG_PRINTF(ERROR, "Key database allocation error\n");
			return -1;
		}

		osal_priv.key_db_obj = db;
	}

	if (db->fp)
		close_db_file();

	/*
	 * Open the application key database file.
	 * Try to open it for read/write assuming file exist, if
	 * file doesn't exist create a new file.
	 */
	db->fp = open(key_db, O_RDWR | O_SYNC | O_CREAT, 777);
	if (db->fp < 0) {
		DBG_PRINTF(ERROR, "%s (%d): %s\n", __func__, __LINE__,
			   get_strerr());

		free(db);
		osal_priv.key_db_obj = NULL;

		return -1;
	}

	return mutex_init(&db->mutex);
}

void key_db_close(void)
{
	struct key_db_obj *db = osal_priv.key_db_obj;

	if (!db)
		return;

	close_db_file();

	free(db);

	osal_priv.key_db_obj = NULL;
}

int key_db_get_info(struct osal_key *key)
{
	int ret = -1;
	long pos;
	struct key_db_obj *db = osal_priv.key_db_obj;
	struct key_entry entry = { 0 };

	if (!db || !db->fp) {
		DBG_PRINTF(ERROR, "Key database not valid");
		return ret;
	}

	if (!key || !key->info || !key->info_size)
		return ret;

	if (lock_db(db))
		return ret;

	pos = find_db_key_id(db, key->id, &entry);
	if (pos == -1)
		goto end;

	DBG_PRINTF(INFO, "%s (%d) key id " PRIxID " @%ld\n", __func__, __LINE__,
		   key->id, pos);

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
	if (pread(db->fp, key->info, entry.info_size, pos + sizeof(entry)) ==
	    (ssize_t)entry.info_size) {
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
	struct key_db_obj *db = osal_priv.key_db_obj;
	int ret = -1;
	long pos = -1;
	unsigned int free_id = 0;
	struct key_entry entry = { 0 };

	if (!db || !db->fp) {
		DBG_PRINTF(ERROR, "Key database not valid");
		return ret;
	}

	if (!key || !key->info || !key->info_size)
		return ret;

	if (lock_db(db))
		return ret;

	/* Place the file pointer to the beginning of the file */
	if (lseek(db->fp, 0, SEEK_SET))
		goto end;

	entry.id = key->range.min;

	/* Try to find a key entry free */
	pos = find_db_key_free(db, key, &free_id);
	if (pos == -1) {
		/*
		 * No free key entry found add the key entry at the end.
		 * Key ID must be in the given key range.
		 * Note the free_id value has been incremented by the
		 * function find_db_key_free()
		 */
		if (free_id > key->range.max)
			goto end;

		pos = lseek(db->fp, 0, SEEK_END);
	}

	entry.id = free_id;
	entry.flags = ENTRY_USE;
	entry.persitent = key->persistent;
	entry.info_size = key->info_size;
	if (pos >= 0)
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
	long pos;
	struct key_db_obj *db = osal_priv.key_db_obj;
	struct key_entry entry = { 0 };

	if (!db || !db->fp) {
		DBG_PRINTF(ERROR, "Key database not valid");
		return ret;
	}

	if (!key || !key->info || !key->info_size)
		return ret;

	if (lock_db(db))
		return ret;

	pos = find_db_key_id(db, key->id, &entry);
	if (pos == -1)
		goto end;

	DBG_PRINTF(INFO, "%s (%d) key id " PRIxID " @%ld\n", __func__, __LINE__,
		   key->id, pos);

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
	long pos;
	struct key_db_obj *db = osal_priv.key_db_obj;
	struct key_entry entry = { 0 };

	if (!db || !db->fp) {
		DBG_PRINTF(ERROR, "Key database not valid");
		return ret;
	}

	if (!key)
		return ret;

	if (lock_db(db))
		return ret;

	pos = find_db_key_id(db, key->id, &entry);
	if (pos == -1)
		goto end;

	DBG_PRINTF(INFO, "%s (%d) key id " PRIxID " @%ld\n", __func__, __LINE__,
		   key->id, pos);

	entry.flags = ENTRY_FREE;
	ret = write_key_db(db, &entry, NULL, pos);

end:
	if (unlock_db(db))
		ret = -1;

	return ret;
}
