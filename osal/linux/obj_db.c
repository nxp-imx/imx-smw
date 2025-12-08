// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2025 NXP
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

/**
 * enum obj_attribute_tag - OSAL object attribute tag
 *
 * @TAG_NONE: Invalid attribute tag.
 * @TAG_DATABASE_ID: Unique object id in DB table
 * @TAG_SUBSYSTEM_ID: ID return by the subsystem
 * @TAG_USER_ID: User define ID
 * @TAG_SUBSYSTEM_NAME: SMW subsystem name
 * @TAG_OBJECT_TYPE: SMW object type
 * @TAG_SIZE: SMW object size
 * @TAG_ATTRIBUTES: SMW object attributes
 * @TAG_KEY_TYPE: SMW key type name
 * @TAG_RESERVED: Reserved for future use
 * @TAG_STORAGE_ID: SMW storage id
 * @TAG_KEY_GROUP: SMW key group
 * @TAG_LABEL: PKCS11 storage object label
 * @TAG_KEY_PERMITTED_ALGO: SMW key permitted algo
 * @TAG_KEY_USAGE: SMW key usage flag
 */
/* Attribute tag */
enum obj_attribute_tag {
	TAG_NONE = 0,
	TAG_DATABASE_ID,
	TAG_SUBSYSTEM_ID,
	TAG_USER_ID,
	TAG_SUBSYSTEM_NAME,
	TAG_OBJECT_TYPE, /* 5 */
	TAG_SIZE,
	TAG_ATTRIBUTES,
	TAG_KEY_TYPE,
	TAG_RESERVED,
	TAG_STORAGE_ID, /* 10 */
	TAG_KEY_GROUP,
	TAG_LABEL,
	TAG_KEY_PERMITTED_ALGO,
	TAG_KEY_USAGE,
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

#define PRIxID		     "0x%08X"
#define OEM_INJECTED_OBJECTS 0x70000000
#define OBJ_DB_BUSY_TIMEOUT  80 /* ms */

struct range_ids {
	uint32_t start;
	uint32_t end;
};

struct obj_db {
	sqlite3 *handle;
	void *mutex;
	unsigned int nb_ranges;
	struct range_ids *range;
};

static int lock_db(struct obj_db *db)
{
	int ret = -1;

	if (db && db->mutex)
		ret = mutex_lock(db->mutex);

	DBG_PRINTF_COND(ERROR, ret, "Object database lock fail\n");

	return ret;
}

static int unlock_db(struct obj_db *db)
{
	int ret = -1;

	if (db && db->mutex)
		ret = mutex_unlock(db->mutex);

	DBG_PRINTF_COND(ERROR, ret, "Object database unlock fail\n");

	return ret;
}

static bool is_id_in_range(unsigned int obj_id, struct obj_db *db)
{
	unsigned int i = 0;

	for (; i < db->nb_ranges; i++) {
		if (obj_id >= db->range[i].start && obj_id <= db->range[i].end)
			return true;
	}

	return false;
}

static struct obj_db *get_database_obj(smw_attr_attributes_t persistency,
				       unsigned int obj_id,
				       bool log __maybe_unused)
{
	struct osal_ctx *ctx = get_osal_ctx();
	struct obj_db *db = NULL;

	if (!ctx)
		goto end;

	if (obj_id != 0) {
		db = ctx->obj_db_transient;
		if (db && is_id_in_range(obj_id, db))
			goto end;

		db = ctx->obj_db_persistent;
		if (db && is_id_in_range(obj_id, db))
			goto end;

		db = NULL;
	} else {
		persistency = SMW_ATTR_GET_PERSISTENCE(persistency);
		if (persistency == SMW_ATTR_PERSISTENCE_TRANSIENT)
			db = ctx->obj_db_transient;
		else
			db = ctx->obj_db_persistent;
	}

	DBG_PRINTF_COND(ERROR, !db && log, "Object database not valid\n");

end:
	return db;
}

static bool sql_print(char *out, size_t *length, const char *format, ...)
{
	bool ret = false;
	int l = 0;
	va_list args = { 0 };

	if (out && (out + *length < out))
		return true;

	va_start(args, format);

	if (out)
		l = vsprintf(out + *length, format, args);
	else
		l = vsnprintf(NULL, 0, format, args);

	if (l < 0)
		ret = true;

	va_end(args);

	if (!ret && ADD_OVERFLOW(*length, l, length)) {
		DBG_PRINTF(ERROR, "SQL print fail");
		ret = true;
	}

	return ret;
}

static int sql_print_create(char *name, uint32_t start_id,
			    struct obj_attribute attributes[],
			    unsigned int nb_attributes, char *sql,
			    size_t *length)
{
	int ret = -1;
	static char *user_version = "PRAGMA user_version = %d;";
	static char *create = "CREATE TABLE %s(";
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
		goto end;

	if (sql_print(sql, length, user_version, CONFIG_SMW_DATABASE_VERSION))
		goto end;

	if (sql_print(sql, length, create, name))
		goto end;

	for (; i < nb_attributes; i++) {
		if (sql_print(sql, length, "\"0x%X\" %s", attributes[i].tag,
			      type[attributes[i].type]))
			goto end;

		if (attributes[i].flags & OBJ_FLAG_PRIMARY_KEY) {
			if (sql_print(sql, length, OBJ_CLAUSE_PRIMARY_KEY))
				goto end;
		}

		if (attributes[i].flags & OBJ_FLAG_UNIQUE) {
			if (sql_print(sql, length, OBJ_CLAUSE_UNIQUE))
				goto end;
		}

		if (attributes[i].flags & OBJ_FLAG_NOT_NULL) {
			if (sql_print(sql, length, OBJ_CLAUSE_NOT_NULL))
				goto end;
		}

		if (i < nb_attributes - 1) {
			if (sql_print(sql, length, ", "))
				goto end;
		}
	}

	if (sql_print(sql, length, ");"))
		goto end;

	if (sql_print(sql, length, update_sequence, start_id, name, name,
		      start_id))
		goto end;

	/* Null terminated char */
	if (!ADD_OVERFLOW(*length, 1, length))
		ret = 0;

end:
	return ret;
}

static int sql_print_insert(struct smw_osal_object *obj, char *sql,
			    size_t *length)
{
	int ret = -1;
	struct smw_object_descriptor *descriptor = obj->obj_desc;
	smw_attr_attributes_t obj_attributes = 0;
	static const char *insert = "INSERT INTO %s (";

	/*
	 * Define the row fields to insert
	 */
	if (sql_print(sql, length, insert, OBJECT_DB_TABLE_NAME))
		goto end;

	if (sql_print(sql, length, "\"0x%X\", ", TAG_DATABASE_ID))
		goto end;

	if (sql_print(sql, length, "\"0x%X\", ", TAG_ATTRIBUTES))
		goto end;

	if (sql_print(sql, length, "\"0x%X\", ", TAG_SUBSYSTEM_NAME))
		goto end;

	if (sql_print(sql, length, "\"0x%X\", ", TAG_OBJECT_TYPE))
		goto end;

	if (sql_print(sql, length, "\"0x%X\", ", TAG_KEY_GROUP))
		goto end;

	if (sql_print(sql, length, "\"0x%X\", ", TAG_LABEL))
		goto end;

	if (descriptor->user_id)
		if (sql_print(sql, length, "\"0x%X\", ", TAG_USER_ID))
			goto end;

	if (sql_print(sql, length, "\"0x%X\", ", TAG_SUBSYSTEM_ID))
		goto end;

	switch (descriptor->type) {
	case SMW_OBJECT_TYPE_NAME_SECRET_KEY:
	case SMW_OBJECT_TYPE_NAME_PUBLIC_KEY:
	case SMW_OBJECT_TYPE_NAME_KEY_PAIR:
		if (sql_print(sql, length, "\"0x%X\", ", TAG_KEY_TYPE))
			goto end;

		if (sql_print(sql, length, "\"0x%X\", ",
			      TAG_KEY_PERMITTED_ALGO))
			goto end;

		if (sql_print(sql, length, "\"0x%X\", ", TAG_KEY_USAGE))
			goto end;

		obj_attributes = descriptor->key.attributes.attributes;
		break;

	case SMW_OBJECT_TYPE_NAME_DATA:
		obj_attributes = descriptor->data.attributes.attributes;
		break;
	default:
		break;
	}

	if (sql_print(sql, length, "\"0x%X\", ", TAG_STORAGE_ID))
		goto end;

	if (sql_print(sql, length, "\"0x%X\"", TAG_SIZE))
		goto end;

	if (sql_print(sql, length, ") VALUES ("))
		goto end;

	/*
	 * Set the value of the row fields.
	 */
	/* field: TAG_DATABASE_ID */
	if (!descriptor->id) {
		/* Database will create a new object identifier (User API) */
		if (sql_print(sql, length, "null, "))
			goto end;
	} else {
		if (sql_print(sql, length, "%d, ", descriptor->id))
			goto end;
	}

	/* field: TAG_ATTRIBUTES */
	if (sql_print(sql, length, "%d, ", obj_attributes))
		goto end;

	/* field: TAG_SUBSYSTEM_NAME */
	if (sql_print(sql, length, "%d, ", descriptor->subsystem_name))
		goto end;

	/* field: TAG_OBJECT_TYPE */
	if (sql_print(sql, length, "%d, ", descriptor->type))
		goto end;

	/* field: TAG_KEY_GROUP */
	if (sql_print(sql, length, "%d, ", descriptor->group))
		goto end;

	/* field: TAG_LABEL */
	if (sql_print(sql, length, "'%s', ", descriptor->label))
		goto end;

	/* field: TAG_USER_ID */
	if (descriptor->user_id)
		if (sql_print(sql, length, "'%s', ", descriptor->user_id))
			goto end;

	/* field: TAG_SUBSYSTEM_ID */
	if (sql_print(sql, length, "%d, ", obj->obj_id_subsystem))
		goto end;

	switch (descriptor->type) {
	case SMW_OBJECT_TYPE_NAME_KEY_PAIR:
	case SMW_OBJECT_TYPE_NAME_PUBLIC_KEY:
	case SMW_OBJECT_TYPE_NAME_SECRET_KEY:
		/* field: TAG_KEY_TYPE */
		if (sql_print(sql, length, "%d, ", descriptor->key.type_name))
			goto end;

		/* field: TAG_KEY_PERMITTED_ALGO */
		if (sql_print(sql, length, "%llu, ",
			      descriptor->key.attributes.permitted_algo))
			goto end;

		/* field: TAG_KEY_USAGE */
		if (sql_print(sql, length, "%d, ",
			      descriptor->key.attributes.usage_flags))
			goto end;

		/* field: TAG_STORAGE_ID */
		if (sql_print(sql, length, "%d, ",
			      descriptor->key.attributes.storage_id))
			goto end;

		/* field: TAG_SIZE */
		if (sql_print(sql, length, "%d", descriptor->key.security_size))
			goto end;

		break;

	case SMW_OBJECT_TYPE_NAME_DATA:
		/* field: TAG_STORAGE_ID */
		if (sql_print(sql, length, "%d, ",
			      descriptor->data.attributes.storage_id))
			goto end;

		/* field: TAG_SIZE */
		if (sql_print(sql, length, "%d", descriptor->data.length))
			goto end;

		break;

	default:
		/* field: TAG_STORAGE_ID + TAG_SIZE */
		if (sql_print(sql, length, "null, null"))
			goto end;

		break;
	}

	if (sql_print(sql, length, ");"))
		goto end;

	/* Null terminated char */
	if (!ADD_OVERFLOW(*length, 1, length))
		ret = 0;

end:
	return ret;
}

static int sql_print_update(struct smw_osal_object *obj, char *sql,
			    size_t *length)
{
	int ret = -1;
	struct smw_object_descriptor *descriptor = obj->obj_desc;
	smw_attr_attributes_t obj_attributes = 0;
	static const char *update = "UPDATE %s SET ";

	switch (descriptor->type) {
	case SMW_OBJECT_TYPE_NAME_KEY_PAIR:
	case SMW_OBJECT_TYPE_NAME_PUBLIC_KEY:
	case SMW_OBJECT_TYPE_NAME_SECRET_KEY:
		obj_attributes = descriptor->key.attributes.attributes;
		break;

	case SMW_OBJECT_TYPE_NAME_DATA:
		obj_attributes = descriptor->data.attributes.attributes;
		break;

	default:
		break;
	}

	if (sql_print(sql, length, update, OBJECT_DB_TABLE_NAME))
		goto end;

	/*
	 * Update fields with value (filed=value)
	 */

	/* field: TAG_ATTRIBUTES */
	if (sql_print(sql, length, "\"0x%X\" = %d, ", TAG_ATTRIBUTES,
		      obj_attributes))
		goto end;

	/* field: TAG_SUSYSTEM_NAME */
	if (sql_print(sql, length, "\"0x%X\" = %d, ", TAG_SUBSYSTEM_NAME,
		      descriptor->subsystem_name))
		goto end;

	/* field: TAG_OBJECT_TYPE */
	if (sql_print(sql, length, "\"0x%X\" = %d, ", TAG_OBJECT_TYPE,
		      descriptor->type))
		goto end;

	/* field: TAG_KEY_GROUP */
	if (sql_print(sql, length, "\"0x%X\" = %d, ", TAG_KEY_GROUP,
		      descriptor->group))
		goto end;

	/* field: TAG_LABEL */
	if (descriptor->label) {
		if (sql_print(sql, length, "\"0x%X\" = '%s', ", TAG_LABEL,
			      descriptor->label))
			goto end;
	}

	/* field: TAG_USER_ID */
	if (descriptor->user_id) {
		if (sql_print(sql, length, "\"0x%X\" = '%s', ", TAG_USER_ID,
			      descriptor->user_id))
			goto end;
	}

	/* field: TAG_SUBSYSTEM_ID */
	if (obj->obj_id_subsystem) {
		if (sql_print(sql, length, "\"0x%X\" = %d, ", TAG_SUBSYSTEM_ID,
			      obj->obj_id_subsystem))
			goto end;
	}

	switch (descriptor->type) {
	case SMW_OBJECT_TYPE_NAME_KEY_PAIR:
	case SMW_OBJECT_TYPE_NAME_PUBLIC_KEY:
	case SMW_OBJECT_TYPE_NAME_SECRET_KEY:
		/* field: TAG_KEY_TYPE */
		if (sql_print(sql, length, "\"0x%X\" = %d, ", TAG_KEY_TYPE,
			      descriptor->key.type_name))
			goto end;

		/* field: TAG_KEY_PERMITTED_ALGO */
		if (sql_print(sql, length, "\"0x%X\" = %llu, ",
			      TAG_KEY_PERMITTED_ALGO,
			      descriptor->key.attributes.permitted_algo))
			goto end;

		/* field: TAG_KEY_USAGE */
		if (sql_print(sql, length, "\"0x%X\" = %d, ", TAG_KEY_USAGE,
			      descriptor->key.attributes.usage_flags))
			goto end;

		/* field: TAG_STORAGE_ID */
		if (sql_print(sql, length, "\"0x%X\" = %d, ", TAG_STORAGE_ID,
			      descriptor->key.attributes.storage_id))
			goto end;

		/* field: TAG_SIZE */
		if (sql_print(sql, length, "\"0x%X\" = %d ", TAG_SIZE,
			      descriptor->key.security_size))
			goto end;

		break;

	case SMW_OBJECT_TYPE_NAME_DATA:
		/* field: TAG_STORAGE_ID */
		if (sql_print(sql, length, "\"0x%X\" = %d, ", TAG_STORAGE_ID,
			      descriptor->data.attributes.storage_id))
			goto end;

		/* field: TAG_SIZE */
		if (sql_print(sql, length, "\"0x%X\" = %d ", TAG_SIZE,
			      descriptor->data.length))
			goto end;

		break;

	default:
		break;
	}

	if (sql_print(sql, length, " WHERE \"0x%X\" = %d;", TAG_DATABASE_ID,
		      descriptor->id))
		goto end;

	/* Null terminated char */
	if (!ADD_OVERFLOW(*length, 1, length))
		ret = 0;

end:
	return ret;
}

static int sql_print_delete(struct smw_osal_object *obj, char *sql,
			    size_t *length)
{
	int ret = -1;
	static const char *delete = "DELETE FROM %s";

	if (sql_print(sql, length, delete, OBJECT_DB_TABLE_NAME))
		goto end;

	if (sql_print(sql, length, " WHERE \"0x%X\" = %d;", TAG_DATABASE_ID,
		      obj->obj_desc->id))
		goto end;

	/* Null terminated char */
	if (!ADD_OVERFLOW(*length, 1, length))
		ret = 0;

end:
	return ret;
}

static int sql_print_select(unsigned int u_id, char *sql, size_t *length)
{
	int ret = -1;
	static const char *select = "SELECT * FROM %s";

	if (sql_print(sql, length, select, OBJECT_DB_TABLE_NAME))
		goto end;

	if (sql_print(sql, length, " WHERE \"0x%X\" = %d;", TAG_DATABASE_ID,
		      u_id))
		goto end;

	/* Null terminated char */
	if (!ADD_OVERFLOW(*length, 1, length))
		ret = 0;

end:
	return ret;
}

#define SQL_PRINT_FIND_FIELD(cond, count, sql, length, fmt, ...)               \
	({                                                                     \
		bool _ret = false;                                             \
		__typeof__(count) _count = count;                              \
		__typeof__(sql) _sql = sql;                                    \
		__typeof__(length) _length = length;                           \
		if (cond) {                                                    \
			if (!*_count) {                                        \
				_ret = sql_print(_sql, _length, " WHERE ");    \
			} else {                                               \
				_ret = sql_print(_sql, _length, " AND ");      \
			}                                                      \
			if (!_ret) {                                           \
				_ret = sql_print(_sql, _length, fmt,           \
						 __VA_ARGS__);                 \
				if (!_ret && INC_OVERFLOW(*_count, 1))         \
					_ret = true;                           \
			}                                                      \
		}                                                              \
		_ret;                                                          \
	})

static int sql_print_find(struct smw_osal_object *obj, char *sql,
			  size_t *length)
{
	int ret = -1;
	size_t count = 0;
	static const char *select = "SELECT * FROM %s";
	struct smw_key_descriptor *key = NULL;
	struct smw_data_descriptor *data = NULL;

	struct smw_object_descriptor *descriptor = obj->obj_desc;

	if (sql_print(sql, length, select, OBJECT_DB_TABLE_NAME))
		goto end;

	if (SQL_PRINT_FIND_FIELD(descriptor->id, &count, sql, length,
				 "\"0x%X\" = %d", TAG_DATABASE_ID,
				 descriptor->id))
		goto end;

	if (SQL_PRINT_FIND_FIELD(descriptor->type, &count, sql, length,
				 "\"0x%X\" = %d", TAG_OBJECT_TYPE,
				 descriptor->type))
		goto end;

	switch (descriptor->type) {
	case SMW_OBJECT_TYPE_NAME_KEY_PAIR:
	case SMW_OBJECT_TYPE_NAME_PUBLIC_KEY:
	case SMW_OBJECT_TYPE_NAME_SECRET_KEY:
		key = &descriptor->key;

		if (SQL_PRINT_FIND_FIELD(key->type_name !=
						 SMW_KEY_TYPE_NAME_NONE,
					 &count, sql, length, "\"0x%X\" = %d",
					 TAG_KEY_TYPE, key->type_name))
			goto end;

		if (SQL_PRINT_FIND_FIELD(key->attributes.permitted_algo, &count,
					 sql, length,
					 " (\"0x%X\" & %llu) = %llu",
					 TAG_KEY_PERMITTED_ALGO,
					 key->attributes.permitted_algo,
					 key->attributes.permitted_algo))
			goto end;

		if (SQL_PRINT_FIND_FIELD(key->attributes.usage_flags, &count,
					 sql, length, " (\"0x%X\" & %d) = %d",
					 TAG_KEY_USAGE,
					 key->attributes.usage_flags,
					 key->attributes.usage_flags))
			goto end;

		if (SQL_PRINT_FIND_FIELD(key->attributes.storage_id, &count,
					 sql, length, " \"0x%X\" = %d",
					 TAG_STORAGE_ID,
					 key->attributes.storage_id))
			goto end;

		if (SQL_PRINT_FIND_FIELD(key->security_size, &count, sql,
					 length, " \"0x%X\" = %d", TAG_SIZE,
					 key->security_size))
			goto end;

		break;

	case SMW_OBJECT_TYPE_NAME_DATA:
		data = &descriptor->data;

		if (SQL_PRINT_FIND_FIELD(data->attributes.storage_id, &count,
					 sql, length, " \"0x%X\" = %d",
					 TAG_STORAGE_ID,
					 data->attributes.storage_id))
			goto end;

		if (SQL_PRINT_FIND_FIELD(data->length, &count, sql, length,
					 " \"0x%X\" = %d", TAG_SIZE,
					 data->length))
			goto end;
		break;

	default:
		break;
	}

	if (SQL_PRINT_FIND_FIELD(descriptor->label, &count, sql, length,
				 " \"0x%X\" = '%s'", TAG_LABEL,
				 descriptor->label))
		goto end;

	if (SQL_PRINT_FIND_FIELD(descriptor->user_id, &count, sql, length,
				 " \"0x%X\" = '%s'", TAG_USER_ID,
				 descriptor->user_id))
		goto end;

	if (sql_print(sql, length, ";"))
		goto end;

	/* Null terminated string */
	if (!ADD_OVERFLOW(*length, 1, length))
		ret = 0;

end:
	return ret;
}

static int obj_db_create_table(struct obj_db *db, char *name,
			       struct obj_attribute attributes[],
			       unsigned int nb_attributes)
{
	int ret = -1;
	int result = 0;
	char *sql = NULL;
	char *messageError = NULL;
	size_t length = 0;
	struct osal_ctx *ctx = get_osal_ctx();
	uint32_t db_start_id = 0;

	if (!name || !attributes)
		return ret;

	if (!ctx)
		return ret;

	if (!db->nb_ranges || !db->range)
		return ret;

	if (SUB_OVERFLOW(db->range[0].start, 1, &db_start_id))
		return ret;

	if (sql_print_create(name, db_start_id, attributes, nb_attributes, NULL,
			     &length))
		goto end;

	sql = calloc(1, length);
	if (!sql)
		goto end;

	length = 0;
	if (sql_print_create(name, db_start_id, attributes, nb_attributes, sql,
			     &length))
		goto end;

	ret = lock_db(db);
	if (ret)
		goto end;

	result = sqlite3_exec(db->handle, sql, NULL, NULL, &messageError);

	ret = unlock_db(db);

	if (result != SQLITE_OK) {
		DBG_PRINTF(ERROR, "SQL Error: %s\n", messageError);
		sqlite3_free(messageError);
		ret = -1;
	}

end:
	if (sql)
		free(sql);

	return ret;
}

/**
 * obj_db_object_table_exist() - Return true if the objects tables exist.
 * @db: Object database
 *
 * Return:
 * true if table exist, false otherwise
 */
static bool obj_db_object_table_exist(struct obj_db *db)
{
	int ret = 0;
	sqlite3_stmt *stmt = NULL;
	const char *sql =
		"SELECT name FROM sqlite_master WHERE type='table' AND name=?;";

	if (!db)
		goto end;

	ret = sqlite3_prepare_v2(db->handle, sql, -1, &stmt, 0);
	if (ret != SQLITE_OK)
		goto end;

	sqlite3_bind_text(stmt, 1, OBJECT_DB_TABLE_NAME, -1, SQLITE_STATIC);

	ret = sqlite3_step(stmt);
	sqlite3_finalize(stmt);

	if (ret == SQLITE_ROW)
		return true;

end:
	return false;
}

/**
 * obj_db_create_object_table() - Create the objects tables.
 * @db: Object database
 *
 * Return:
 * 0 if success, -1 otherwise
 */
static int obj_db_create_object_table(struct obj_db *db)
{
	struct obj_attribute attributes[] = {
		ATTRIBUTE(INTEGER, PRIMARY_KEY, DATABASE_ID),
		ATTRIBUTE(INTEGER, NONE, SUBSYSTEM_ID),
		ATTRIBUTE(TEXT, NONE, USER_ID),
		ATTRIBUTE(INTEGER, NONE, SUBSYSTEM_NAME),
		ATTRIBUTE(INTEGER, NONE, OBJECT_TYPE),
		ATTRIBUTE(INTEGER, NONE, SIZE),
		ATTRIBUTE(INTEGER, NONE, ATTRIBUTES),
		ATTRIBUTE(INTEGER, NONE, KEY_TYPE),
		ATTRIBUTE(INTEGER, NONE, RESERVED),
		ATTRIBUTE(INTEGER, NONE, STORAGE_ID),
		ATTRIBUTE(INTEGER, NONE, KEY_GROUP),
		ATTRIBUTE(TEXT, NOT_NULL, LABEL),
		ATTRIBUTE(INTEGER, NONE, KEY_PERMITTED_ALGO),
		ATTRIBUTE(INTEGER, NONE, KEY_USAGE),
	};
	unsigned int nb_attributes = ARRAY_SIZE(attributes);

	/* Create Volatile Object table */
	return obj_db_create_table(db, OBJECT_DB_TABLE_NAME, attributes,
				   nb_attributes);
}

/**
 * osal_obj_set_common_attribute() - Set object common attribute
 * @obj: Reference to the object
 * @attribute_tag_str: Tag id in string format
 * @value_str: Value in string format
 *
 * Return:
 * 0 if success, -1 otherwise
 */
static int osal_obj_set_common_attribute(struct smw_osal_object *obj,
					 const char *attribute_tag_str,
					 const unsigned char *value_str)
{
	int ret = -1;
	struct smw_object_descriptor *descriptor = NULL;
	enum obj_attribute_tag attribute_tag = 0;
	unsigned int attribute_value = 0;
	const char *attribute_value_str = (const char *)value_str;
	unsigned long l = 0;
	char *endPtr = NULL;

	if (!obj || !attribute_tag_str || !value_str)
		goto end;

	descriptor = obj->obj_desc;

	l = strtoul(attribute_tag_str, &endPtr, 0);
	if (!l && endPtr == attribute_tag_str)
		goto end;

	if (SET_OVERFLOW(l, attribute_tag))
		goto end;

	l = strtoul(attribute_value_str, &endPtr, 0);
	if (l || endPtr != attribute_value_str) {
		if (SET_OVERFLOW(l, attribute_value))
			goto end;
	}

	switch (attribute_tag) {
	case TAG_OBJECT_TYPE:
		descriptor->type = (smw_object_type_t)attribute_value;
		break;

	case TAG_DATABASE_ID:
		descriptor->id = attribute_value;
		break;

	case TAG_KEY_GROUP:
		descriptor->group = attribute_value;
		break;

	case TAG_LABEL:
		descriptor->label = strdup(attribute_value_str);
		break;

	case TAG_USER_ID:
		descriptor->user_id = strdup(attribute_value_str);
		break;

	case TAG_SUBSYSTEM_NAME:
		descriptor->subsystem_name = (smw_subsystem_t)attribute_value;
		break;

	default:
		break;
	}

	ret = 0;

end:
	return ret;
}

/**
 * osal_obj_set_specific_attribute() - Set object specific attribute
 * @obj: Reference to the object
 * @attribute_tag_str: Tag id in string format
 * @value_str: Value in string format
 *
 * Return:
 * 0 if success, -1 otherwise
 */
static int osal_obj_set_specific_attribute(struct smw_osal_object *obj,
					   const char *attribute_tag_str,
					   const unsigned char *value_str)
{
	int ret = -1;
	struct smw_object_descriptor *descriptor = NULL;
	enum obj_attribute_tag attribute_tag = 0;
	unsigned int attribute_value = 0;
	const char *attribute_value_str = (const char *)value_str;
	unsigned long l = 0;
	char *endPtr = NULL;

	if (!obj || !attribute_tag_str || !value_str)
		goto end;

	descriptor = obj->obj_desc;

	l = strtoul(attribute_tag_str, &endPtr, 0);
	if (!l && endPtr == attribute_tag_str)
		goto end;

	if (SET_OVERFLOW(l, attribute_tag))
		goto end;

	l = strtoul(attribute_value_str, &endPtr, 0);
	if (l || endPtr != attribute_value_str) {
		if (SET_OVERFLOW(l, attribute_value))
			goto end;
	}

	switch (attribute_tag) {
	case TAG_KEY_TYPE:
		if (descriptor->type == SMW_OBJECT_TYPE_NAME_SECRET_KEY ||
		    descriptor->type == SMW_OBJECT_TYPE_NAME_PUBLIC_KEY ||
		    descriptor->type == SMW_OBJECT_TYPE_NAME_KEY_PAIR)
			descriptor->key.type_name =
				(smw_key_type_t)attribute_value;
		break;

	case TAG_KEY_PERMITTED_ALGO:
		if (descriptor->type == SMW_OBJECT_TYPE_NAME_SECRET_KEY ||
		    descriptor->type == SMW_OBJECT_TYPE_NAME_PUBLIC_KEY ||
		    descriptor->type == SMW_OBJECT_TYPE_NAME_KEY_PAIR)
			descriptor->key.attributes.permitted_algo =
				(smw_attr_algo_t)attribute_value;
		break;

	case TAG_KEY_USAGE:
		if (descriptor->type == SMW_OBJECT_TYPE_NAME_SECRET_KEY ||
		    descriptor->type == SMW_OBJECT_TYPE_NAME_PUBLIC_KEY ||
		    descriptor->type == SMW_OBJECT_TYPE_NAME_KEY_PAIR)
			descriptor->key.attributes.usage_flags =
				(smw_attr_usage_t)attribute_value;
		break;

	case TAG_SUBSYSTEM_ID:
		obj->obj_id_subsystem = attribute_value;
		break;

	case TAG_DATABASE_ID:
		if (descriptor->type == SMW_OBJECT_TYPE_NAME_SECRET_KEY ||
		    descriptor->type == SMW_OBJECT_TYPE_NAME_PUBLIC_KEY ||
		    descriptor->type == SMW_OBJECT_TYPE_NAME_KEY_PAIR)
			descriptor->key.id = attribute_value;
		else if (descriptor->type == SMW_OBJECT_TYPE_NAME_DATA)
			descriptor->data.identifier = attribute_value;

		break;

	case TAG_STORAGE_ID:
		if (descriptor->type == SMW_OBJECT_TYPE_NAME_SECRET_KEY ||
		    descriptor->type == SMW_OBJECT_TYPE_NAME_PUBLIC_KEY ||
		    descriptor->type == SMW_OBJECT_TYPE_NAME_KEY_PAIR)
			descriptor->key.attributes.storage_id = attribute_value;
		else if (descriptor->type == SMW_OBJECT_TYPE_NAME_DATA)
			descriptor->data.attributes.storage_id =
				attribute_value;
		break;

	case TAG_ATTRIBUTES:
		if (descriptor->type == SMW_OBJECT_TYPE_NAME_SECRET_KEY ||
		    descriptor->type == SMW_OBJECT_TYPE_NAME_PUBLIC_KEY ||
		    descriptor->type == SMW_OBJECT_TYPE_NAME_KEY_PAIR)
			descriptor->key.attributes.attributes = attribute_value;
		else if (descriptor->type == SMW_OBJECT_TYPE_NAME_DATA)
			descriptor->data.attributes.attributes =
				attribute_value;
		break;

	case TAG_SIZE:
		if (descriptor->type == SMW_OBJECT_TYPE_NAME_SECRET_KEY ||
		    descriptor->type == SMW_OBJECT_TYPE_NAME_PUBLIC_KEY ||
		    descriptor->type == SMW_OBJECT_TYPE_NAME_KEY_PAIR)
			descriptor->key.security_size = attribute_value;
		else if (descriptor->type == SMW_OBJECT_TYPE_NAME_DATA)
			descriptor->data.length = attribute_value;
		break;

	default:
		break;
	}

	ret = 0;

end:
	return ret;
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
	int ret = -1;
	int i = 0;

	if (!data)
		goto end;

	/* Get common attributes */
	for (; i < argc; i++) {
		if (!argv[i])
			continue;

		if (osal_obj_set_common_attribute(data, azColName[i],
						  (unsigned char *)argv[i]))
			goto end;
	}

	for (i = 0; i < argc; i++) {
		if (!argv[i])
			continue;

		if (osal_obj_set_specific_attribute(data, azColName[i],
						    (unsigned char *)argv[i]))
			goto end;
	}

	ret = 0;

end:
	return ret;
}

/**
 * obj_db_exec() - Run database request
 * @obj: Object
 * @sql: SQL request
 * @data: First argument of the callback
 * @callback: Function called for each request result
 *
 * Return:
 * 0 if success, -1 otherwise
 */
static int obj_db_exec(struct smw_osal_object *obj, char *sql, void *data,
		       int (*callback)(void *, int, char **, char **))
{
	int ret = -1;
	struct osal_ctx *ctx = get_osal_ctx();
	struct obj_db *db = NULL;
	sqlite3_stmt *stmt = NULL;
	sqlite3_int64 rowid = 0;
	char *messageError = NULL;
	int result = SQLITE_OK;

	if (!ctx)
		goto exit;

	if (!obj || !sql)
		goto exit;

	db = get_database_obj(obj->obj_desc->persistency, obj->obj_desc->id,
			      true);
	if (!db)
		goto exit;

	if (!db->handle) {
		DBG_PRINTF(ERROR, "Object database not open");
		goto exit;
	}

	if (lock_db(db))
		goto exit;

	if (callback) {
		result = sqlite3_prepare_v2(db->handle, sql, -1, &stmt, NULL);
		if (result != SQLITE_OK) {
			DBG_PRINTF(ERROR, "SQL Error: %s\n",
				   sqlite3_errmsg(db->handle));
			goto end;
		}

		result = sqlite3_step(stmt);
		sqlite3_finalize(stmt);
		if (result != SQLITE_ROW) {
			obj->obj_desc->id = 0;
			goto end;
		}
	}

	result = sqlite3_exec(db->handle, sql, callback, data, &messageError);
	if (result != SQLITE_OK) {
		DBG_PRINTF(ERROR, "SQL Error: %s\n", messageError);
		DBG_PRINTF(ERROR, "SQL Request: %s\n", sql);
		sqlite3_free(messageError);
		goto end;
	}

	rowid = sqlite3_last_insert_rowid(db->handle);
	if (!SET_OVERFLOW(rowid, obj->obj_desc->id))
		ret = 0;

end:
	if (unlock_db(db))
		ret = ret ? ret : -1;

exit:
	return ret;
}

static void close_db_file(struct obj_db *db)
{
	if (!db)
		return;

	if (db->mutex)
		(void)mutex_destroy(&db->mutex);

	if (db->handle)
		sqlite3_close(db->handle);

	if (db->range)
		free(db->range);

	free(db);
}

static int create_directory(const char *filename)
{
	int ret = -1;
	char *end = NULL;
	char *directory = NULL;
	size_t length = 0;
	int *err = NULL;

	end = strrchr(filename, '/');
	if (!end) {
		ret = 0;
		goto end;
	}

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
		err = __errno_location();
		if (err && *err != EEXIST) {
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

static struct obj_db *create_db(struct obj_db *in_db)
{
	int ret = 0;
	struct obj_db *db = NULL;

	if (in_db)
		close_db_file(in_db);

	/*
	 * Allocate the object database and mutex
	 */
	db = calloc(1, sizeof(*db));
	if (!db) {
		DBG_PRINTF(ERROR, "Object database allocation error\n");
		goto end;
	}

	ret = mutex_init(&db->mutex);
	if (ret) {
		DBG_PRINTF(ERROR, "Mutex initialization failed\n");
		goto end;
	}

end:
	if (ret && db) {
		close_db_file(db);
		db = NULL;
	}

	return db;
}

static int open_db(struct obj_db *db, const char *filename)
{
	int ret = -1;
	const char *sql = "PRAGMA user_version;";
	sqlite3_stmt *stmt = NULL;
	int version = 0;

	if (filename) {
		DBG_PRINTF(INFO, "Create physical database %s\n", filename);
		if (!create_directory(filename))
			ret = sqlite3_open_v2(filename, &db->handle,
					      SQLITE_OPEN_READWRITE |
						      SQLITE_OPEN_CREATE,
					      NULL);
	} else {
		DBG_PRINTF(INFO, "Create memory database\n");
		ret = sqlite3_open_v2(NULL, &db->handle,
				      SQLITE_OPEN_READWRITE |
					      SQLITE_OPEN_CREATE |
					      SQLITE_OPEN_MEMORY,
				      NULL);
	}

	if (ret) {
		DBG_PRINTF(ERROR, "Error opening/creating sqlite db %s\n",
			   sqlite3_errmsg(db->handle));
		ret = -1;
		goto end;
	}

	ret = sqlite3_busy_timeout(db->handle, OBJ_DB_BUSY_TIMEOUT);
	if (ret) {
		DBG_PRINTF(ERROR, "Error sqlite db %s\n",
			   sqlite3_errmsg(db->handle));
		ret = -1;
		goto end;
	}

	if (obj_db_object_table_exist(db)) {
		ret = sqlite3_prepare_v2(db->handle, sql, -1, &stmt, 0);
		if (ret != SQLITE_OK)
			goto end;

		ret = sqlite3_step(stmt);
		if (ret != SQLITE_ROW)
			goto end;

		version = sqlite3_column_int(stmt, 0);
		sqlite3_finalize(stmt);

		if (version != CONFIG_SMW_DATABASE_VERSION) {
			DBG_PRINTF(ERROR,
				   "Invalid data base version %d, expected %d\n",
				   version, CONFIG_SMW_DATABASE_VERSION);
			ret = SQLITE_ERROR;
			goto end;
		}

		ret = SQLITE_OK;
	} else {
		ret = obj_db_create_object_table(db);
	}

end:
	return ret;
}

int obj_db_open(const char *filename)
{
	int ret = -1;
	struct osal_ctx *ctx = get_osal_ctx();
	struct obj_db *db = NULL;

	if (!ctx)
		return ret;

	/*
	 * Step 1. Create/Open persistent database
	 */
	db = get_database_obj(SMW_ATTR_PERSISTENCE_PERSISTENT, 0, false);
	db = create_db(db);
	if (!db)
		goto end;

	ctx->obj_db_persistent = db;

	/* Create the db identifier ranges */
	db->nb_ranges = 2;
	db->range = calloc(1, db->nb_ranges * sizeof(*db->range));
	if (!db->range)
		goto end;

	/* User define persistent key identifers */
	db->range[0].start = PSA_KEY_ID_USER_MIN;
	db->range[0].end = PSA_KEY_ID_USER_MAX;

	db->range[1].start = OEM_INJECTED_OBJECTS;
	db->range[1].end = UINT32_MAX;

	/* Open persistent database */
	ret = open_db(db, filename);
	if (ret)
		goto end;

	/*
	 * Step 1. Create/Open transient database
	 */
	db = get_database_obj(SMW_ATTR_PERSISTENCE_TRANSIENT, 0, false);
	db = create_db(db);
	if (!db)
		goto end;

	ctx->obj_db_transient = db;

	/* Create the db identifier ranges */
	db->nb_ranges = 1;
	db->range = calloc(1, db->nb_ranges * sizeof(*db->range));
	if (!db->range)
		goto end;

	/* Transient key identifers */
	db->range[0].start = PSA_KEY_ID_VENDOR_MIN;
	db->range[0].end = PSA_KEY_ID_VENDOR_MAX;

	/* Open transient database */
	ret = open_db(db, NULL);

end:
	if (ret)
		obj_db_close();

	return ret;
}

void obj_db_close(void)
{
	struct osal_ctx *ctx = get_osal_ctx();
	struct obj_db *db = NULL;

	if (!ctx)
		return;
	/*
	 * Step 1. Close persistent database if exist
	 */
	db = get_database_obj(SMW_ATTR_PERSISTENCE_PERSISTENT, 0, false);
	if (db) {
		close_db_file(db);
		ctx->obj_db_persistent = NULL;
	}

	/*
	 * Step 2. Create/Open transient database
	 */
	db = get_database_obj(SMW_ATTR_PERSISTENCE_TRANSIENT, 0, false);
	if (db) {
		close_db_file(db);
		ctx->obj_db_transient = NULL;
	}
}

int obj_db_add(struct smw_osal_object *obj)
{
	int ret = -1;
	char *sql = NULL;
	size_t length = 0;

	if (sql_print_insert(obj, NULL, &length))
		goto end;

	sql = calloc(1, length);
	if (!sql)
		goto end;

	length = 0;
	if (sql_print_insert(obj, sql, &length))
		goto end;

	ret = obj_db_exec(obj, sql, NULL, NULL);

end:
	if (sql)
		free(sql);

	return ret;
}

int obj_db_update(struct smw_osal_object *obj)
{
	int ret = -1;
	char *sql = NULL;
	size_t length = 0;

	if (sql_print_update(obj, NULL, &length))
		goto end;

	sql = calloc(1, length);
	if (!sql)
		goto end;

	length = 0;
	if (sql_print_update(obj, sql, &length))
		goto end;

	ret = obj_db_exec(obj, sql, NULL, NULL);

end:
	if (sql)
		free(sql);

	return ret;
}

int obj_db_delete(struct smw_osal_object *obj)
{
	int ret = -1;
	char *sql = NULL;
	size_t length = 0;

	if (sql_print_delete(obj, NULL, &length))
		goto end;

	sql = calloc(1, length);
	if (!sql)
		goto end;

	length = 0;
	if (sql_print_delete(obj, sql, &length))
		goto end;

	ret = obj_db_exec(obj, sql, NULL, NULL);

end:
	if (sql)
		free(sql);

	return ret;
}

int obj_db_get_info(struct smw_osal_object *obj)
{
	int ret = -1;
	char *sql = NULL;
	size_t length = 0;

	/*
	 * Select the object by its database identifier that is the same as
	 * the user identifier.
	 */
	if (sql_print_select(obj->obj_desc->id, NULL, &length))
		goto end;

	sql = calloc(1, length);
	if (!sql)
		goto end;

	length = 0;
	if (sql_print_select(obj->obj_desc->id, sql, &length))
		goto end;

	ret = obj_db_exec(obj, sql, obj, obj_db_to_osal_obj);

end:
	if (sql)
		free(sql);

	return ret;
}

struct op_find_context {
	struct obj_db *db;
	sqlite3_stmt *stmt;
};

int obj_db_find_init(void **find_ctx, struct smw_osal_object *obj)
{
	int ret = -1;
	int result = SQLITE_OK;
	struct osal_ctx *ctx = get_osal_ctx();
	struct obj_db *db = NULL;
	char *sql = NULL;
	sqlite3_stmt *stmt;
	size_t length = 0;
	struct op_find_context *op_ctx = NULL;

	if (!find_ctx)
		return ret;

	*find_ctx = NULL;

	if (!ctx || !obj)
		return ret;

	db = get_database_obj(obj->obj_desc->persistency, obj->obj_desc->id,
			      true);
	if (!db)
		return ret;

	if (!db->handle) {
		DBG_PRINTF(ERROR, "Object database not open");
		return ret;
	}

	if (lock_db(db))
		return ret;

	if (sql_print_find(obj, NULL, &length))
		goto end;

	sql = calloc(1, length);
	if (!sql)
		goto end;

	length = 0;
	if (sql_print_find(obj, sql, &length))
		goto end;

	result = sqlite3_prepare_v2(db->handle, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		DBG_PRINTF(ERROR, "SQL Error: %s\n",
			   sqlite3_errmsg(db->handle));
		goto end;
	}

	/* Check that the statement is ready to return a row */
	result = sqlite3_step(stmt);
	if (result != SQLITE_ROW) {
		sqlite3_finalize(stmt);
		ret = 1; /* No row found */
		goto end;
	} else {
		sqlite3_reset(stmt);
	}

	op_ctx = calloc(1, sizeof(*op_ctx));
	if (!op_ctx)
		goto end;

	op_ctx->db = db;
	op_ctx->stmt = stmt;

	*find_ctx = op_ctx;

	ret = 0;

end:
	if (sql)
		free(sql);

	(void)unlock_db(db);

	return ret;
}

int obj_db_find_next(void *find_ctx, struct smw_osal_object *obj)
{
	int ret = -1;
	int i = 0;
	int num_cols = 0;
	struct op_find_context *op_ctx = find_ctx;
	sqlite3_stmt *stmt = NULL;
	const char *column_name = NULL;
	const unsigned char *column_value = NULL;

	if (!op_ctx || !op_ctx->stmt || !obj)
		return ret;

	stmt = op_ctx->stmt;

	if (lock_db(op_ctx->db))
		return ret;

	if (sqlite3_step(stmt) != SQLITE_ROW)
		goto end;

	num_cols = sqlite3_column_count(stmt);

	for (; i < num_cols; i++) {
		column_name = sqlite3_column_name(stmt, i);
		column_value = sqlite3_column_text(stmt, i);
		if (!column_value)
			continue;

		if (osal_obj_set_common_attribute(obj, column_name,
						  column_value))
			goto end;
	}

	for (i = 0; i < num_cols; i++) {
		column_name = sqlite3_column_name(stmt, i);
		column_value = sqlite3_column_text(stmt, i);
		if (!column_value)
			continue;

		if (osal_obj_set_specific_attribute(obj, column_name,
						    column_value))
			goto end;
	}

	ret = 0;

end:
	(void)unlock_db(op_ctx->db);

	return ret;
}

int obj_db_find_finalize(void *find_ctx)
{
	int ret = -1;
	struct op_find_context *op_ctx = find_ctx;

	if (!op_ctx) {
		/* Nothing to do, return success */
		ret = 0;
		goto end;
	}

	if (!op_ctx->db || !op_ctx->stmt)
		goto end;

	if (lock_db(op_ctx->db))
		goto end;

	sqlite3_finalize(op_ctx->stmt);

	ret = 0;

	if (unlock_db(op_ctx->db))
		ret = -1;

end:
	if (op_ctx)
		free(op_ctx);

	return ret;
}
