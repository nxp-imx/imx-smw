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
 * @TAG_TYPE: SMW key type name
 * @TAG_PRIVACY: SMW key privacy name
 * @TAG_STORAGE_ID: SMW key storage id
 * @TAG_GROUP: SMW key group
 * @TAG_LABEL: PKCS11 storage object label
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
	TAG_TYPE,
	TAG_PRIVACY,
	TAG_STORAGE_ID, /* 10 */
	TAG_GROUP,
	TAG_LABEL,
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

static struct obj_db *get_database_obj(smw_attr_attributes_t attributes,
				       unsigned int obj_id)
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
		if (SMW_ATTR_GET_PERSISTENCE(attributes) ==
		    SMW_ATTR_PERSISTENCE_TRANSIENT)
			db = ctx->obj_db_transient;
		else
			db = ctx->obj_db_persistent;
	}

	DBG_PRINTF_COND(ERROR, !db, "Object database not valid\n");

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

static int sql_print_insert(struct osal_obj *obj, char *sql, size_t *length)
{
	int ret = -1;
	static const char *insert = "INSERT INTO %s (";

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

	if (sql_print(sql, length, "\"0x%X\", ", TAG_GROUP))
		goto end;

	if (sql_print(sql, length, "\"0x%X\", ", TAG_LABEL))
		goto end;

	if (obj->descriptor->user_id)
		if (sql_print(sql, length, "\"0x%X\", ", TAG_USER_ID))
			goto end;

	if (sql_print(sql, length, "\"0x%X\", ", TAG_SUBSYSTEM_ID))
		goto end;

	switch (obj->descriptor->type) {
	case SMW_OBJECT_TYPE_NAME_SECRET_KEY:
	case SMW_OBJECT_TYPE_NAME_PUBLIC_KEY:
	case SMW_OBJECT_TYPE_NAME_KEY_PAIR:
		if (sql_print(sql, length, "\"0x%X\", ", TAG_TYPE))
			goto end;
		break;
	case SMW_OBJECT_TYPE_NAME_DATA:
		if (obj->descriptor->data.data_attributes)
			if (sql_print(sql, length, "\"0x%X\", ",
				      TAG_STORAGE_ID))
				goto end;
		break;
	default:
		break;
	}

	if (sql_print(sql, length, "\"0x%X\"", TAG_SIZE))
		goto end;

	if (sql_print(sql, length, ") VALUES ("))
		goto end;

	if (!obj->id) {
		if (sql_print(sql, length, "null, "))
			goto end;
	} else {
		if (sql_print(sql, length, "%d, ", obj->id))
			goto end;
	}

	if (sql_print(sql, length, "%d, ", obj->descriptor->attributes))
		goto end;

	if (sql_print(sql, length, "%d, ", obj->descriptor->subsystem_name))
		goto end;

	if (sql_print(sql, length, "%d, ", obj->descriptor->type))
		goto end;

	if (sql_print(sql, length, "%d, ", obj->descriptor->group))
		goto end;

	if (sql_print(sql, length, "'%s', ", obj->descriptor->label))
		goto end;

	if (obj->descriptor->user_id)
		if (sql_print(sql, length, "'%s', ", obj->descriptor->user_id))
			goto end;

	switch (obj->descriptor->type) {
	case SMW_OBJECT_TYPE_NAME_KEY_PAIR:
	case SMW_OBJECT_TYPE_NAME_PUBLIC_KEY:
	case SMW_OBJECT_TYPE_NAME_SECRET_KEY:
		if (sql_print(sql, length, "%d, ", obj->descriptor->key.id))
			goto end;

		if (sql_print(sql, length, "%d, ",
			      obj->descriptor->key.type_name))
			goto end;

		if (sql_print(sql, length, "%d",
			      obj->descriptor->key.security_size))
			goto end;

		break;

	case SMW_OBJECT_TYPE_NAME_DATA:
		if (sql_print(sql, length, "%d, ",
			      obj->descriptor->data.identifier))
			goto end;

		if (obj->descriptor->data.data_attributes)
			if (sql_print(sql, length, "%d, ",
				      obj->descriptor->data.data_attributes
					      ->storage_id))
				goto end;

		if (sql_print(sql, length, "%d", obj->descriptor->data.length))
			goto end;

		break;

	default:
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

static int sql_print_update(struct osal_obj *obj, char *sql, size_t *length)
{
	int ret = -1;
	static const char *update = "UPDATE %s SET ";

	if (sql_print(sql, length, update, OBJECT_DB_TABLE_NAME))
		goto end;

	if (sql_print(sql, length, "\"0x%X\" = %d, ", TAG_ATTRIBUTES,
		      obj->descriptor->attributes))
		goto end;

	if (sql_print(sql, length, "\"0x%X\" = %d, ", TAG_SUBSYSTEM_NAME,
		      obj->descriptor->subsystem_name))
		goto end;

	if (sql_print(sql, length, "\"0x%X\" = %d, ", TAG_OBJECT_TYPE,
		      obj->descriptor->type))
		goto end;

	if (sql_print(sql, length, "\"0x%X\" = %d, ", TAG_GROUP,
		      obj->descriptor->group))
		goto end;

	if (obj->descriptor->label) {
		if (sql_print(sql, length, "\"0x%X\" = '%s', ", TAG_LABEL,
			      obj->descriptor->label))
			goto end;
	}

	if (obj->descriptor->user_id) {
		if (sql_print(sql, length, "\"0x%X\" = '%s', ", TAG_USER_ID,
			      obj->descriptor->user_id))
			goto end;
	}

	switch (obj->descriptor->type) {
	case SMW_OBJECT_TYPE_NAME_KEY_PAIR:
	case SMW_OBJECT_TYPE_NAME_PUBLIC_KEY:
	case SMW_OBJECT_TYPE_NAME_SECRET_KEY:
		if (sql_print(sql, length, "\"0x%X\" = %d, ", TAG_SUBSYSTEM_ID,
			      obj->descriptor->key.id))
			goto end;

		if (sql_print(sql, length, "\"0x%X\" = %d, ", TAG_TYPE,
			      obj->descriptor->key.type_name))
			goto end;

		if (sql_print(sql, length, "\"0x%X\" = %d ", TAG_SIZE,
			      obj->descriptor->key.security_size))
			goto end;

		break;

	case SMW_OBJECT_TYPE_NAME_DATA:
		if (obj->descriptor->data.data_attributes)
			if (sql_print(sql, length, "\"0x%X\" = %d, ",
				      TAG_STORAGE_ID,
				      obj->descriptor->data.data_attributes
					      ->storage_id))
				goto end;

		if (sql_print(sql, length, "\"0x%X\" = %d, ", TAG_SUBSYSTEM_ID,
			      obj->descriptor->data.identifier))
			goto end;

		if (sql_print(sql, length, "\"0x%X\" = %d ", TAG_SIZE,
			      obj->descriptor->data.length))
			goto end;

		break;

	default:
		if (sql_print(sql, length, "null, null"))
			goto end;

		break;
	}

	if (sql_print(sql, length, " WHERE \"0x%X\" = %d;", TAG_DATABASE_ID,
		      obj->id))
		goto end;

	/* Null terminated char */
	if (!ADD_OVERFLOW(*length, 1, length))
		ret = 0;

end:
	return ret;
}

static int sql_print_delete(struct osal_obj *obj, char *sql, size_t *length)
{
	int ret = -1;
	static const char *delete = "DELETE FROM %s";

	if (sql_print(sql, length, delete, OBJECT_DB_TABLE_NAME))
		goto end;

	if (sql_print(sql, length, " WHERE \"0x%X\" = %d;", TAG_DATABASE_ID,
		      obj->id))
		goto end;

	/* Null terminated char */
	if (!ADD_OVERFLOW(*length, 1, length))
		ret = 0;

end:
	return ret;
}

static int sql_print_select(struct osal_obj *obj, char *sql, size_t *length)
{
	int ret = -1;
	static const char *select = "SELECT * FROM %s";

	if (sql_print(sql, length, select, OBJECT_DB_TABLE_NAME))
		goto end;

	if (sql_print(sql, length, " WHERE \"0x%X\" = %d;", TAG_DATABASE_ID,
		      obj->id))
		goto end;

	/* Null terminated char */
	if (!ADD_OVERFLOW(*length, 1, length))
		ret = 0;

end:
	return ret;
}

static int sql_print_find(struct osal_obj *obj, char *sql, size_t *length)
{
	int ret = -1;
	struct smw_object_descriptor *descriptor = NULL;
	bool and_operator = false;
	static const char *select = "SELECT * FROM %s";

	if (!obj || !obj->descriptor)
		goto end;

	descriptor = obj->descriptor;

	if (sql_print(sql, length, select, OBJECT_DB_TABLE_NAME))
		goto end;

	if (descriptor->id || descriptor->type || descriptor->label ||
	    descriptor->user_id)
		if (sql_print(sql, length, " WHERE "))
			goto end;

	if (descriptor->id) {
		if (sql_print(sql, length, "\"0x%X\" = %d", TAG_DATABASE_ID,
			      descriptor->id))
			goto end;

		and_operator = true;
	}

	if (descriptor->type) {
		if (and_operator) {
			if (sql_print(sql, length, " AND "))
				goto end;
		} else {
			and_operator = true;
		}

		if (sql_print(sql, length, "\"0x%X\" = %d", TAG_OBJECT_TYPE,
			      descriptor->type))
			goto end;

		switch (obj->descriptor->type) {
		case SMW_OBJECT_TYPE_NAME_KEY_PAIR:
		case SMW_OBJECT_TYPE_NAME_PUBLIC_KEY:
		case SMW_OBJECT_TYPE_NAME_SECRET_KEY:
			if (descriptor->key.type_name != SMW_KEY_TYPE_NAME_NONE)
				if (sql_print(sql, length, " AND \"0x%X\" = %d",
					      TAG_TYPE,
					      descriptor->key.type_name))
					goto end;

			if (descriptor->key.security_size)
				if (sql_print(sql, length, " AND \"0x%X\" = %d",
					      TAG_SIZE,
					      descriptor->key.security_size))
					goto end;

			if (descriptor->key.id)
				if (sql_print(sql, length, " AND \"0x%X\" = %d",
					      TAG_SUBSYSTEM_ID,
					      descriptor->key.id))
					goto end;
			break;

		case SMW_OBJECT_TYPE_NAME_DATA:
			if (descriptor->data.length)
				if (sql_print(sql, length, " AND \"0x%X\" = %d",
					      TAG_SIZE,
					      descriptor->data.length))
					goto end;

			if (descriptor->data.identifier)
				if (sql_print(sql, length, " AND \"0x%X\" = %d",
					      TAG_SUBSYSTEM_ID,
					      descriptor->data.identifier))
					goto end;

			if (descriptor->data.data_attributes)
				if (descriptor->data.data_attributes->storage_id)
					if (sql_print(sql, length,
						      " AND \"0x%X\" = %d",
						      TAG_STORAGE_ID,
						      descriptor->data
							      .data_attributes
							      ->storage_id))
						goto end;
			break;
		default:
			break;
		}
	}

	if (descriptor->label) {
		if (and_operator) {
			if (sql_print(sql, length, " AND "))
				goto end;
		} else {
			and_operator = true;
		}

		if (sql_print(sql, length, "\"0x%X\" = '%s'", TAG_LABEL,
			      descriptor->label))
			goto end;
	}

	if (descriptor->user_id) {
		if (and_operator) {
			if (sql_print(sql, length, " AND "))
				goto end;
		}

		if (sql_print(sql, length, "\"0x%X\" = '%s'", TAG_USER_ID,
			      descriptor->user_id))
			goto end;
	}

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
 * obj_db_create_object_table() - Create the objects tables if not exist.
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
		ATTRIBUTE(INTEGER, NONE, TYPE),
		ATTRIBUTE(INTEGER, NONE, PRIVACY),
		ATTRIBUTE(INTEGER, NONE, STORAGE_ID),
		ATTRIBUTE(INTEGER, NONE, GROUP),
		ATTRIBUTE(TEXT, NOT_NULL, LABEL),
	};
	unsigned int nb_attributes = ARRAY_SIZE(attributes);

	/* Create Volatile Object table */
	return obj_db_create_table(db, OBJECT_DB_TABLE_NAME, attributes,
				   nb_attributes);
}

/**
 * osal_obj_set_common_attribute() - Set OSAL object common attribute
 * @obj: Reference to the OSAL object
 * @attribute_tag_str: Tag id in string format
 * @value_str: Value in string format
 *
 * Return:
 * 0 if success, -1 otherwise
 */
static int osal_obj_set_common_attribute(struct osal_obj *obj,
					 const char *attribute_tag_str,
					 const unsigned char *value_str)
{
	int ret = -1;
	enum obj_attribute_tag attribute_tag = 0;
	unsigned int attribute_value = 0;
	const char *attribute_value_str = (const char *)value_str;
	unsigned long l = 0;
	char *endPtr = NULL;

	if (!obj || !attribute_tag_str || !value_str)
		goto end;

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
		obj->descriptor->type = (smw_object_type_t)attribute_value;
		break;

	case TAG_DATABASE_ID:
		obj->id = attribute_value;
		obj->descriptor->id = attribute_value;
		break;

	case TAG_GROUP:
		obj->descriptor->group = attribute_value;
		break;

	case TAG_LABEL:
		obj->descriptor->label = strdup(attribute_value_str);
		break;

	case TAG_USER_ID:
		obj->descriptor->user_id = strdup(attribute_value_str);
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

	ret = 0;

end:
	return ret;
}

/**
 * osal_obj_set_specific_attribute() - Set OSAL object specific attribute
 * @obj: Reference to the OSAL object
 * @attribute_tag_str: Tag id in string format
 * @value_str: Value in string format
 *
 * Return:
 * 0 if success, -1 otherwise
 */
static int osal_obj_set_specific_attribute(struct osal_obj *obj,
					   const char *attribute_tag_str,
					   const unsigned char *value_str)
{
	int ret = -1;
	enum obj_attribute_tag attribute_tag = 0;
	unsigned int attribute_value = 0;
	const char *attribute_value_str = (const char *)value_str;
	unsigned long l = 0;
	char *endPtr = NULL;

	if (!obj || !attribute_tag_str || !value_str)
		goto end;

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
	case TAG_TYPE:
		if (obj->descriptor->type == SMW_OBJECT_TYPE_NAME_SECRET_KEY ||
		    obj->descriptor->type == SMW_OBJECT_TYPE_NAME_PUBLIC_KEY ||
		    obj->descriptor->type == SMW_OBJECT_TYPE_NAME_KEY_PAIR)
			obj->descriptor->key.type_name =
				(smw_key_type_t)attribute_value;
		break;

	case TAG_SUBSYSTEM_ID:
		if (obj->descriptor->type == SMW_OBJECT_TYPE_NAME_SECRET_KEY ||
		    obj->descriptor->type == SMW_OBJECT_TYPE_NAME_PUBLIC_KEY ||
		    obj->descriptor->type == SMW_OBJECT_TYPE_NAME_KEY_PAIR)
			obj->descriptor->key.id = attribute_value;
		break;

	case TAG_DATABASE_ID:
		if (obj->descriptor->type == SMW_OBJECT_TYPE_NAME_DATA)
			obj->descriptor->data.identifier = attribute_value;
		break;

	case TAG_STORAGE_ID:
		if (obj->descriptor->type == SMW_OBJECT_TYPE_NAME_DATA &&
		    obj->descriptor->data.data_attributes)
			obj->descriptor->data.data_attributes->storage_id =
				attribute_value;
		break;

	case TAG_SIZE:
		if (obj->descriptor->type == SMW_OBJECT_TYPE_NAME_SECRET_KEY ||
		    obj->descriptor->type == SMW_OBJECT_TYPE_NAME_PUBLIC_KEY ||
		    obj->descriptor->type == SMW_OBJECT_TYPE_NAME_KEY_PAIR)
			obj->descriptor->key.security_size = attribute_value;
		else if (obj->descriptor->type == SMW_OBJECT_TYPE_NAME_DATA)
			obj->descriptor->data.length = attribute_value;
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
	struct osal_obj *obj = (struct osal_obj *)data;
	int i = 0;

	if (!obj || !obj->descriptor)
		goto end;

	/* Get common attributes */
	for (; i < argc; i++) {
		if (!argv[i])
			continue;

		if (osal_obj_set_common_attribute(obj, azColName[i],
						  (unsigned char *)argv[i]))
			goto end;
	}

	for (i = 0; i < argc; i++) {
		if (!argv[i])
			continue;

		if (osal_obj_set_specific_attribute(obj, azColName[i],
						    (unsigned char *)argv[i]))
			goto end;
	}

	ret = 0;

end:
	return ret;
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

	db = get_database_obj(obj->attributes, obj->id);
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
			obj->id = 0;
			goto end;
		}
	}

	result = sqlite3_exec(db->handle, sql, callback, data, &messageError);
	if (result != SQLITE_OK) {
		DBG_PRINTF(ERROR, "SQL Error: %s\n", messageError);
		sqlite3_free(messageError);
		goto end;
	}

	rowid = sqlite3_last_insert_rowid(db->handle);
	if (!SET_OVERFLOW(rowid, obj->id))
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

	if (filename) {
		DBG_PRINTF(INFO, "Create physical database %s\n", filename);
		if (!create_directory(filename))
			ret = sqlite3_open(filename, &db->handle);
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

	ret = obj_db_create_object_table(db);

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
	db = get_database_obj(SMW_ATTR_PERSISTENCE_PERSISTENT, 0);
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
	db = get_database_obj(SMW_ATTR_PERSISTENCE_TRANSIENT, 0);
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
	db = get_database_obj(SMW_ATTR_PERSISTENCE_PERSISTENT, 0);
	if (db) {
		close_db_file(db);
		ctx->obj_db_persistent = NULL;
	}

	/*
	 * Step 2. Create/Open transient database
	 */
	db = get_database_obj(SMW_ATTR_PERSISTENCE_TRANSIENT, 0);
	if (db) {
		close_db_file(db);
		ctx->obj_db_transient = NULL;
	}
}

int obj_db_add(struct osal_obj *obj)
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

int obj_db_update(struct osal_obj *obj)
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

int obj_db_delete(struct osal_obj *obj)
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

int obj_db_get_info(struct osal_obj *obj)
{
	int ret = -1;
	char *sql = NULL;
	size_t length = 0;

	if (sql_print_select(obj, NULL, &length))
		goto end;

	sql = calloc(1, length);
	if (!sql)
		goto end;

	length = 0;
	if (sql_print_select(obj, sql, &length))
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

int obj_db_find_init(void **find_ctx, struct osal_obj *obj)
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

	if (!ctx)
		return ret;

	if (!obj)
		return ret;

	db = get_database_obj(obj->attributes, obj->id);
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

int obj_db_find_next(void *find_ctx, struct osal_obj *obj)
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
	struct osal_ctx *ctx = get_osal_ctx();
	struct op_find_context *op_ctx = find_ctx;

	if (!ctx || !op_ctx)
		goto end;

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
