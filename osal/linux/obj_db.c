// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sqlite3.h>
#include <sys/stat.h>

#include "psa/crypto.h"

#include "local.h"

#include "smw_keymgr.h"
#include "smw_storage.h"

enum obj_attribute_tag {
	TAG_NONE,
	TAG_ID,
	TAG_PERSISTENCE_ID,
	TAG_SLOT_ID,
	TAG_SUBSYSTEM_ID,
	TAG_SUBSYSTEM_NAME,
	TAG_SUBSYSTEM_BLOB,
	TAG_TYPE,
	TAG_PRIVACY,
	TAG_SIZE,
	TAG_ATTRIBUTES,
	TAG_STORAGE_ID,
	TAG_GROUP,
	TAG_CLASS,
	TAG_LABEL,
	TAG_PIN_SO,
};

#define OBJECT_DB_TABLE_NAME "OBJECTS"

enum obj_attribute_type {
	OBJ_TYPE_TEXT,
	OBJ_TYPE_INTEGER,
	OBJ_TYPE_REAL,
	OBJ_TYPE_BLOB
};

#define OBJ_FLAG_NONE	     0x00
#define OBJ_FLAG_PRIMARY_KEY 0x01
#define OBJ_FLAG_UNIQUE	     0x02
#define OBJ_FLAG_NOT_NULL    0x04

/*
 * Supported attribute clause
 * separated by a whitespace.
 */
#define OBJ_CLAUSE_PRIMARY_KEY " PRIMARY KEY AUTOINCREMENT"
#define OBJ_CLAUSE_UNIQUE      " UNIQUE"
#define OBJ_CLAUSE_NOT_NULL    " NOT NULL"

/**
 * struct obj_attribute - Object attribute
 * @type: Object attribute type. See &enum obj_attribute_type
 * @flags: Object attribute flags
 * @tag: Object attribute tag
 */
struct obj_attribute {
	enum obj_attribute_type type;
	unsigned int flags;
	enum obj_attribute_tag tag;
};

#define ATTRIBUTE(_type, _flag, _tag)                                          \
	{                                                                      \
		.type = OBJ_TYPE_##_type, .flags = OBJ_FLAG_##_flag,           \
		.tag = TAG_##_tag                                              \
	}

#define PRIxID "0x%08X"
#define OEM_INJECTED_OBJECTS 0x70000000
#define OBJ_DB_BUSY_TIMEOUT  50 /* ms */

struct obj_db {
	sqlite3 *persistent_db;
	sqlite3 *transient_db;
	void *mutex;
	bool threadsafe;
};

static int lock_db(struct obj_db *db)
{
	int ret = 0;

	if (!db->threadsafe) {
		ret = mutex_lock(db->mutex);
		if (ret)
			return ret;
	}

	// coverity[missing_unlock]
	return ret;
}

static int unlock_db(struct obj_db *db)
{
	if (!db->threadsafe)
		return mutex_unlock(db->mutex);

	return 0;
}

static sqlite3 *get_database_handle(smw_attr_attributes_t attributes)
{
	struct osal_ctx *ctx = get_osal_ctx();
	struct obj_db *db = NULL;

	if (!ctx)
		return NULL;

	db = ctx->obj_db;

	if (!db) {
		DBG_PRINTF(ERROR, "Object database not valid");
		return NULL;
	}

	if (SMW_ATTR_GET_PERSISTENCE(attributes) ==
	    SMW_ATTR_PERSISTENCE_TRANSIENT)
		return db->transient_db;
	else
		return db->persistent_db;

	return NULL;
}

static bool sql_print(char *out, size_t *length, const char *format, ...)
{
	int l = 0;
	va_list args;

	if (out && (out + *length < out))
		return true;

	va_start(args, format);

	if (out)
		l = vsprintf(out + *length, format, args);
	else
		l = vsnprintf(NULL, 0, format, args);

	if (l < 0)
		l = 0;

	va_end(args);

	if (ADD_OVERFLOW(*length, l, length)) {
		DBG_PRINTF(ERROR, "SQL print fail");
		return true;
	}

	return false;
}

static int sql_print_create(char *name, uint32_t start_id,
			    struct obj_attribute attributes[],
			    unsigned int nb_attributes, char *sql,
			    size_t *length)
{
	int ret = -1;
	static char *create = "CREATE TABLE IF NOT EXISTS %s(";
	static char *const type[] = { "TEXT", "INTEGER", "REAL", "BLOB" };
	static char *update_sequence =
		"\nBEGIN TRANSACTION;\n"
		" UPDATE sqlite_sequence SET seq = %d WHERE name = '%s';\n"
		" INSERT INTO sqlite_sequence (name, seq)\n"
		" SELECT '%s', %d WHERE NOT EXISTS\n"
		" (SELECT changes() AS change FROM sqlite_sequence WHERE change <> 0);\n"
		" COMMIT;";
	unsigned int i = 0;

	if (!name || !attributes)
		return ret;

	if (sql_print(sql, length, create, name))
		return ret;

	for (; i < nb_attributes; i++) {
		if (sql_print(sql, length, "\"0x%X\" %s", attributes[i].tag,
			      type[attributes[i].type]))
			return ret;

		if (attributes[i].flags & OBJ_FLAG_PRIMARY_KEY) {
			if (sql_print(sql, length, OBJ_CLAUSE_PRIMARY_KEY))
				return ret;
		}

		if (attributes[i].flags & OBJ_FLAG_UNIQUE) {
			if (sql_print(sql, length, OBJ_CLAUSE_UNIQUE))
				return ret;
		}

		if (attributes[i].flags & OBJ_FLAG_NOT_NULL) {
			if (sql_print(sql, length, OBJ_CLAUSE_NOT_NULL))
				return ret;
		}

		if (i < nb_attributes - 1) {
			if (sql_print(sql, length, ", "))
				return ret;
		}
	}

	if (sql_print(sql, length, ");"))
		return ret;

	if (sql_print(sql, length, update_sequence, start_id, name, name,
		      start_id))
		return ret;

	if (ADD_OVERFLOW(*length, 1, length)) /* null terminated char */
		return ret;

	return 0;
}

static int sql_print_insert(struct osal_obj *obj, char *sql, size_t *length)
{
	static const char *insert = "INSERT INTO %s (";

	if (sql_print(sql, length, insert, OBJECT_DB_TABLE_NAME))
		return -1;

	if (sql_print(sql, length, "\"0x%X\", ", TAG_PERSISTENCE_ID))
		return -1;

	if (sql_print(sql, length, "\"0x%X\", ", TAG_ATTRIBUTES))
		return -1;

	if (sql_print(sql, length, "\"0x%X\", ", TAG_SUBSYSTEM_NAME))
		return -1;

	if (sql_print(sql, length, "\"0x%X\", ", TAG_CLASS))
		return -1;

	if (sql_print(sql, length, "\"0x%X\", ", TAG_GROUP))
		return -1;

	if (sql_print(sql, length, "\"0x%X\", ", TAG_LABEL))
		return -1;

	if (sql_print(sql, length, "\"0x%X\", ", TAG_ID))
		return -1;

	if (obj->descriptor->type == SMW_OBJECT_TYPE_NAME_SECRET_KEY ||
	    obj->descriptor->type == SMW_OBJECT_TYPE_NAME_KEY_PAIR)
		if (sql_print(sql, length, "\"0x%X\", ", TAG_TYPE))
			return -1;

	if (sql_print(sql, length, "\"0x%X\"", TAG_SIZE))
		return -1;

	if (sql_print(sql, length, ") VALUES ("))
		return -1;

	if (!obj->id) {
		if (sql_print(sql, length, "null, "))
			return -1;
	} else {
		if (sql_print(sql, length, "%d, ", obj->id))
			return -1;
	}

	if (sql_print(sql, length, "%d, ", obj->descriptor->attributes))
		return -1;

	if (sql_print(sql, length, "%d, ", obj->descriptor->subsystem_name))
		return -1;

	if (sql_print(sql, length, "%d, ", obj->descriptor->type))
		return -1;

	if (sql_print(sql, length, "%d, ", obj->descriptor->group))
		return -1;

	if (sql_print(sql, length, "\"%s\", ", obj->descriptor->label))
		return -1;

	switch (obj->descriptor->type) {
	case SMW_OBJECT_TYPE_NAME_KEY_PAIR:
	case SMW_OBJECT_TYPE_NAME_SECRET_KEY:
		if (sql_print(sql, length, "%d, ", obj->descriptor->key.id))
			return -1;

		if (sql_print(sql, length, "%d, ",
			      obj->descriptor->key.type_name))
			return -1;

		if (sql_print(sql, length, "%d",
			      obj->descriptor->key.security_size))
			return -1;
		break;

	case SMW_OBJECT_TYPE_NAME_DATA:
		if (sql_print(sql, length, "%d, ",
			      obj->descriptor->data.identifier))
			return -1;

		if (sql_print(sql, length, "%d", obj->descriptor->data.length))
			return -1;
		break;

	default:
		if (sql_print(sql, length, "null, null"))
			return -1;
		break;
	}

	if (sql_print(sql, length, ");"))
		return -1;

	if (ADD_OVERFLOW(*length, 1, length)) /* null terminated char */
		return -1;

	return 0;
}

static int sql_print_update(struct osal_obj *obj, char *sql, size_t *length)
{
	static const char *update = "UPDATE %s SET ";

	if (sql_print(sql, length, update, OBJECT_DB_TABLE_NAME))
		return -1;

	if (sql_print(sql, length, "\"0x%X\" = %d, ", TAG_ATTRIBUTES,
		      obj->descriptor->attributes))
		return -1;

	if (sql_print(sql, length, "\"0x%X\" = %d, ", TAG_SUBSYSTEM_NAME,
		      obj->descriptor->subsystem_name))
		return -1;

	if (sql_print(sql, length, "\"0x%X\" = %d, ", TAG_CLASS,
		      obj->descriptor->type))
		return -1;

	if (sql_print(sql, length, "\"0x%X\" = %d, ", TAG_GROUP,
		      obj->descriptor->group))
		return -1;

	if (obj->descriptor->label) {
		if (sql_print(sql, length, "\"0x%X\" = \"%s\", ", TAG_LABEL,
			      obj->descriptor->label))
			return -1;
	}

	switch (obj->descriptor->type) {
	case SMW_OBJECT_TYPE_NAME_KEY_PAIR:
	case SMW_OBJECT_TYPE_NAME_SECRET_KEY:
		if (sql_print(sql, length, "\"0x%X\" = %d, ", TAG_ID,
			      obj->descriptor->key.id))
			return -1;

		if (sql_print(sql, length, "\"0x%X\" = %d, ", TAG_TYPE,
			      obj->descriptor->key.type_name))
			return -1;

		if (sql_print(sql, length, "\"0x%X\" = %d ", TAG_SIZE,
			      obj->descriptor->key.security_size))
			return -1;
		break;

	case SMW_OBJECT_TYPE_NAME_DATA:
		if (sql_print(sql, length, "\"0x%X\" = %d, ", TAG_ID,
			      obj->descriptor->data.identifier))
			return -1;

		if (sql_print(sql, length, "\"0x%X\" = %d ", TAG_SIZE,
			      obj->descriptor->data.length))
			return -1;
		break;

	default:
		if (sql_print(sql, length, "null, null"))
			return -1;
		break;
	}

	if (sql_print(sql, length, " WHERE \"0x%X\" = %d;", TAG_PERSISTENCE_ID,
		      obj->id))
		return -1;

	if (ADD_OVERFLOW(*length, 1, length)) /* null terminated char */
		return -1;

	return 0;
}

static int sql_print_delete(struct osal_obj *obj, char *sql, size_t *length)
{
	static const char *delete = "DELETE FROM %s";

	if (sql_print(sql, length, delete, OBJECT_DB_TABLE_NAME))
		return -1;

	if (sql_print(sql, length, " WHERE \"0x%X\" = %d;", TAG_PERSISTENCE_ID,
		      obj->id))
		return -1;

	if (ADD_OVERFLOW(*length, 1, length)) /* null terminated char */
		return -1;

	return 0;
}

static int sql_print_select(struct osal_obj *obj, char *sql, size_t *length)
{
	static const char *select = "SELECT * FROM %s";

	if (sql_print(sql, length, select, OBJECT_DB_TABLE_NAME))
		return -1;

	if (sql_print(sql, length, " WHERE \"0x%X\" = %d;", TAG_PERSISTENCE_ID,
		      obj->id))
		return -1;

	if (ADD_OVERFLOW(*length, 1, length)) /* null terminated char */
		return -1;

	return 0;
}

static int obj_db_create_table(char *name, smw_attr_attributes_t smw_attributes,
			       uint32_t start_id,
			       struct obj_attribute attributes[],
			       unsigned int nb_attributes)
{
	int result = 0;
	int ret = -1;
	char *sql = NULL;
	char *messageError = NULL;
	size_t length = 0;
	struct osal_ctx *ctx = get_osal_ctx();
	struct obj_db *db = NULL;

	if (!name || !attributes)
		return ret;

	if (!ctx)
		return ret;

	db = ctx->obj_db;

	if (!db) {
		DBG_PRINTF(ERROR, "Object database not valid");
		return ret;
	}

	if (lock_db(db)) {
		DBG_PRINTF(ERROR, "Object database lock fail");
		return ret;
	}

	if (sql_print_create(name, start_id, attributes, nb_attributes, NULL,
			     &length))
		goto end;

	sql = calloc(1, length);
	if (!sql)
		goto end;

	length = 0;
	if (sql_print_create(name, start_id, attributes, nb_attributes, sql,
			     &length))
		goto end;

	result = sqlite3_exec(get_database_handle(smw_attributes), sql, NULL,
			      NULL, &messageError);
	if (result != SQLITE_OK) {
		DBG_PRINTF(ERROR, "SQL Error: %s\n", messageError);
		sqlite3_free(messageError);
	} else {
		ret = 0;
	}

end:
	if (sql)
		free(sql);

	if (unlock_db(db)) {
		DBG_PRINTF(ERROR, "Object database unlock fail");
		ret = -1;
	}

	return ret;
}

/**
 * obj_db_create_object_table() - Create the objects tables if not exist.
 * Create a persistent and transient objects table.
 *
 * Return:
 * 0 if success, -1 otherwise
 */
static int obj_db_create_object_table(void)
{
	int result = 0;

	struct obj_attribute attributes[] = {
		ATTRIBUTE(INTEGER, PRIMARY_KEY, PERSISTENCE_ID),
		ATTRIBUTE(INTEGER, NONE, ID),
		ATTRIBUTE(INTEGER, NONE, SUBSYSTEM_NAME),
		ATTRIBUTE(INTEGER, NONE, TYPE),
		ATTRIBUTE(INTEGER, NONE, PRIVACY),
		ATTRIBUTE(INTEGER, NONE, SIZE),
		ATTRIBUTE(INTEGER, NONE, ATTRIBUTES),
		ATTRIBUTE(INTEGER, NONE, STORAGE_ID),
		ATTRIBUTE(INTEGER, NONE, GROUP),
		ATTRIBUTE(INTEGER, NONE, CLASS),
		ATTRIBUTE(TEXT, NOT_NULL, LABEL),
	};
	unsigned int nb_attributes = ARRAY_SIZE(attributes);

	/* Create Volatile Object table */
	result = obj_db_create_table(OBJECT_DB_TABLE_NAME,
				     SMW_ATTR_PERSISTENCE_TRANSIENT,
				     PSA_KEY_ID_USER_MAX, attributes,
				     nb_attributes);
	if (result)
		return result;

	/* Create Persistent Object table */
	return obj_db_create_table(OBJECT_DB_TABLE_NAME,
				   SMW_ATTR_PERSISTENCE_PERSISTENT, 0,
				   attributes, nb_attributes);
}

static int obj_db_init(void)
{
	return obj_db_create_object_table();
}

/**
 * obj_db_to_osal_obj() - Convert SQLite object to OSAL object
 * @data: Reference to the OSAL object
 *
 * Return:
 * 0 if success, -1 otherwise
 */
static int obj_db_to_osal_obj(void *data, int argc, char **argv,
			      char **azColName)
{
	struct osal_obj *obj = (struct osal_obj *)data;
	char *endPtr = NULL;
	int i = 0;

	enum obj_attribute_tag attribute_tag = 0;
	unsigned int attribute_value = 0;
	unsigned long l = 0;

	if (!obj || !obj->descriptor)
		return -1;

	/* Get common attributes */
	for (; i < argc; i++) {
		if (!argv[i])
			continue;

		l = strtoul(azColName[i], &endPtr, 0);
		if (!l && endPtr == azColName[i])
			continue;

		if (SET_OVERFLOW(l, attribute_tag))
			continue;

		l = strtoul(argv[i], &endPtr, 0);
		if (!l && endPtr == argv[i])
			continue;

		if (SET_OVERFLOW(l, attribute_value))
			continue;

		switch (attribute_tag) {
		case TAG_CLASS:
			obj->descriptor->type =
				(smw_object_type_t)attribute_value;
			break;

		case TAG_PERSISTENCE_ID:
			obj->id = attribute_value;
			obj->descriptor->id = attribute_value;
			break;

		case TAG_GROUP:
			obj->descriptor->group = attribute_value;
			break;

		case TAG_LABEL:
			obj->descriptor->label = strdup(argv[i]);
			break;

		case TAG_ATTRIBUTES:
			obj->descriptor->attributes =
				(smw_attr_attributes_t)attribute_value;
			break;

		case TAG_SUBSYSTEM_NAME:
			obj->descriptor->subsystem_name =
				(smw_subsystem_t)attribute_value;
			break;

		default:
			break;
		}
	}

	for (i = 0; i < argc; i++) {
		if (!argv[i])
			continue;

		l = strtoul(azColName[i], &endPtr, 0);
		if (!l && endPtr == azColName[i])
			continue;

		if (SET_OVERFLOW(l, attribute_tag))
			continue;

		l = strtoul(argv[i], &endPtr, 0);
		if (!l && endPtr == argv[i])
			continue;

		if (SET_OVERFLOW(l, attribute_value))
			continue;

		switch (attribute_tag) {
		case TAG_TYPE:
			if (obj->descriptor->type ==
				    SMW_OBJECT_TYPE_NAME_SECRET_KEY ||
			    obj->descriptor->type ==
				    SMW_OBJECT_TYPE_NAME_KEY_PAIR)
				obj->descriptor->key.type_name =
					(smw_key_type_t)attribute_value;
			break;

		case TAG_ID:
			if (obj->descriptor->type ==
				    SMW_OBJECT_TYPE_NAME_SECRET_KEY ||
			    obj->descriptor->type ==
				    SMW_OBJECT_TYPE_NAME_KEY_PAIR)
				obj->descriptor->key.id = attribute_value;
			break;

		case TAG_PERSISTENCE_ID:
			if (obj->descriptor->type == SMW_OBJECT_TYPE_NAME_DATA)
				obj->descriptor->data.identifier =
					attribute_value;
			break;

		case TAG_SIZE:
			if (obj->descriptor->type ==
				    SMW_OBJECT_TYPE_NAME_SECRET_KEY ||
			    obj->descriptor->type ==
				    SMW_OBJECT_TYPE_NAME_KEY_PAIR)
				obj->descriptor->key.security_size =
					attribute_value;
			else if (obj->descriptor->type ==
				 SMW_OBJECT_TYPE_NAME_DATA)
				obj->descriptor->data.length = attribute_value;
			break;

		default:
			break;
		}
	}

	return 0;
}

/**
 * obj_db_exec() - Run database request
 * @obj: OSAL object
 * @sql: SQL request
 * @data: First argument of the callback
 * @callback: Function called for each request result
 *
 * Return:
 * 0 if success, -1 otherwise
 */
static int obj_db_exec(struct osal_obj *obj, char *sql, void *data,
		       int (*callback)(void *, int, char **, char **))
{
	struct osal_ctx *ctx = get_osal_ctx();
	struct obj_db *db = NULL;
	sqlite3 *sql_db = NULL;
	sqlite3_stmt *stmt = NULL;
	sqlite3_int64 rowid = 0;
	char *messageError = NULL;
	int ret = -1;
	int result = SQLITE_OK;

	if (!ctx)
		return ret;

	db = ctx->obj_db;

	if (!db) {
		DBG_PRINTF(ERROR, "Object database not valid");
		return ret;
	}

	if (!obj || !sql)
		return ret;

	if (obj->id != 0) {
		if (obj->id < PSA_KEY_ID_VENDOR_MIN ||
		    obj->id >= OEM_INJECTED_OBJECTS)
			sql_db = db->persistent_db;
		else
			sql_db = db->transient_db;
	} else {
		sql_db = get_database_handle(obj->attributes);
	}

	if (!sql_db) {
		DBG_PRINTF(ERROR, "Object database not open");
		return ret;
	}

	if (lock_db(db)) {
		DBG_PRINTF(ERROR, "Object database lock fail");
		return ret;
	}

	if (callback) {
		result = sqlite3_prepare_v2(sql_db, sql, -1, &stmt, NULL);
		if (result != SQLITE_OK) {
			DBG_PRINTF(ERROR, "SQL Error: %s\n",
				   sqlite3_errmsg(sql_db));
			goto end;
		}

		result = sqlite3_step(stmt);
		sqlite3_finalize(stmt);
		if (result != SQLITE_ROW) {
			obj->id = 0;
			goto end;
		}
	}

	result = sqlite3_exec(sql_db, sql, callback, data, &messageError);
	if (result != SQLITE_OK) {
		DBG_PRINTF(ERROR, "SQL Error: %s\n", messageError);
		sqlite3_free(messageError);
		goto end;
	}

	rowid = sqlite3_last_insert_rowid(sql_db);
	if (SET_OVERFLOW(rowid, obj->id))
		goto end;

	ret = 0;

end:
	if (unlock_db(db)) {
		DBG_PRINTF(ERROR, "Object database unlock fail");
		ret = -1;
	}

	return ret;
}

static void close_db_file(struct obj_db *db)
{
	if (!db->threadsafe)
		(void)mutex_destroy(&db->mutex);

	if (db->persistent_db)
		sqlite3_close(db->persistent_db);

	if (db->transient_db)
		sqlite3_close(db->transient_db);

	db->persistent_db = NULL;
	db->transient_db = NULL;
}

static int create_directory(const char *filename)
{
	int ret = -1;
	char *end = NULL;
	char *directory = NULL;
	size_t length = 0;

	end = strrchr(filename, '/');
	if (!end)
		goto end;

	if (SUB_OVERFLOW((uintptr_t)end, (uintptr_t)filename, &length))
		goto end;

	if (!length) {
		ret = 0;
		goto end;
	}

	if (INC_OVERFLOW(length, 1))
		goto end;

	directory = malloc(length);
	if (!directory)
		goto end;

	memcpy(directory, filename, length);
	directory[length - 1] = '\0';

	if (mkdir(directory, 0777)) {
		if (__errno_location() && errno != EEXIST) {
			DBG_PRINTF(ERROR, "%s (%d): %s\n", __func__, __LINE__,
				   get_strerr());
			goto end;
		}
	}

	ret = 0;

end:
	if (directory)
		free(directory);

	return ret;
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

		db->threadsafe = sqlite3_threadsafe();
	} else {
		close_db_file(db);
	}

	/*
	 * Open the application object database file.
	 */
	if (create_directory(obj_db))
		goto end;

	ret = sqlite3_open(obj_db, &db->persistent_db);
	if (ret) {
		DBG_PRINTF(ERROR, "Error opening/creating sqlite db %s\n",
			   sqlite3_errmsg(db->persistent_db));
		ret = -1;
		goto end;
	}

	ret = sqlite3_busy_timeout(db->persistent_db, OBJ_DB_BUSY_TIMEOUT);
	if (ret) {
		DBG_PRINTF(ERROR, "Error sqlite db %s\n",
			   sqlite3_errmsg(db->persistent_db));
		ret = -1;
		goto end;
	}

	ret = sqlite3_open_v2(obj_db, &db->transient_db,
			      SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
				      SQLITE_OPEN_MEMORY,
			      NULL);
	if (ret) {
		DBG_PRINTF(ERROR, "Error opening/creating sqlite db %s\n",
			   sqlite3_errmsg(db->transient_db));
		ret = -1;
		goto end;
	}

	ret = sqlite3_busy_timeout(db->transient_db, OBJ_DB_BUSY_TIMEOUT);
	if (ret) {
		DBG_PRINTF(ERROR, "Error sqlite db %s\n",
			   sqlite3_errmsg(db->persistent_db));
		ret = -1;
		goto end;
	}

	if (!db->threadsafe) {
		ret = mutex_init(&db->mutex);
		if (ret) {
			DBG_PRINTF(ERROR, "Mutex initialization failed\n");
			goto end;
		}
	}

	ret = obj_db_init();

end:
	if (ret && db) {
		close_db_file(db);

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

int obj_db_add(struct osal_obj *obj)
{
	int ret = -1;
	char *sql = NULL;
	size_t length = 0;

	if (sql_print_insert(obj, NULL, &length))
		return ret;

	sql = calloc(1, length);
	if (!sql)
		return ret;

	length = 0;
	if (sql_print_insert(obj, sql, &length))
		goto end;

	ret = obj_db_exec(obj, sql, NULL, NULL);

end:
	free(sql);
	return ret;
}

int obj_db_update(struct osal_obj *obj)
{
	int ret = -1;
	char *sql = NULL;
	size_t length = 0;

	if (sql_print_update(obj, NULL, &length))
		return ret;

	sql = calloc(1, length);
	if (!sql)
		return ret;

	length = 0;
	if (sql_print_update(obj, sql, &length))
		goto end;

	ret = obj_db_exec(obj, sql, NULL, NULL);

end:
	free(sql);
	return ret;
}

int obj_db_delete(struct osal_obj *obj)
{
	int ret = -1;
	char *sql = NULL;
	size_t length = 0;

	if (sql_print_delete(obj, NULL, &length))
		return ret;

	sql = calloc(1, length);
	if (!sql)
		return ret;

	length = 0;
	if (sql_print_delete(obj, sql, &length))
		goto end;

	ret = obj_db_exec(obj, sql, NULL, NULL);

end:
	free(sql);
	return ret;
}

int obj_db_get_info(struct osal_obj *obj)
{
	int ret = -1;
	char *sql = NULL;
	size_t length = 0;

	if (sql_print_select(obj, NULL, &length))
		return ret;

	sql = calloc(1, length);
	if (!sql)
		return ret;

	length = 0;
	if (sql_print_select(obj, sql, &length))
		goto end;

	ret = obj_db_exec(obj, sql, obj, obj_db_to_osal_obj);

end:
	free(sql);
	return ret;
}
