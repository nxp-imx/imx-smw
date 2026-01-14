/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2019-2026 NXP
 */

#ifndef __OSAL_H__
#define __OSAL_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdarg.h>

#include "smw_osal.h"
#include "smw_status.h"
#include "smw/attr.h"
#include "smw/names.h"
#include "smw/object.h"

/**
 * union subsystem_info - Union of all subsystem information
 * @tee: TEE Subsystem information.
 * @se: Secure Enclave information.
 */
union subsystem_info {
	struct tee_info tee;
	struct se_info se;
};

/**
 * struct smw_osal_object - OSAL object descriptor
 * @obj_desc: Object descriptor (user information), see &struct smw_object_descriptor.
 * @obj_id_subsystem: Object identifier in Secure Subsystem.
 *
 * The user API identifier is transported by the @obj_desc->id. This identifier
 * value is set when creating the object in the database. This value could
 * be different from the object identifier assigned by the Secure Subsystem.
 *
 * The @obj_id_subsystem is the object identifier assigned by the Secure
 * Subsystem and used internally.
 */
struct smw_osal_object {
	struct smw_object_descriptor *obj_desc;
	unsigned int obj_id_subsystem;
};

/**
 * typedef smw_osal_critical_section_start_t - Start a critical section.
 *
 * This function starts a critical section barrier to prevent operation
 * executing after this call to be interrupted.
 *
 * The critical section is stopped with smw_osal_critical_section_stop_t().
 *
 * Return:
 *  None
 */
typedef void (*smw_osal_critical_section_start_t)(void);

/**
 * typedef smw_osal_critical_section_stop_t - Stop a critical section.
 *
 * This function stops the critical section barrier after this call execution
 * can be interrupted.
 *
 * The critical section is started with smw_osal_critical_section_start_t().
 *
 * Return:
 *  None
 */
typedef void (*smw_osal_critical_section_stop_t)(void);

/**
 * typedef smw_osal_mutex_init_t - Initialize a mutex.
 * @mutex: [out] Pointer to mutex object created.
 *
 * The function allocates and initialize a mutex object. The mutex must be
 * released with smw_osal_mutex_destroy_t().
 *
 * Return:
 *  - 0 on success.
 *  - negative value on failure.
 */
typedef int (*smw_osal_mutex_init_t)(void **mutex);

/**
 * typedef smw_osal_mutex_destroy_t - Destroy a mutex.
 * @mutex: [in/out] Pointer to mutex object to destroy.
 *
 * The function stops and releases a mutex object previously created with
 * smw_osal_mutex_init_t().
 *
 * The @mutexx pointer is set to NULL after destruction.
 *
 * Return:
 *  - 0 on success.
 *  - negative value on failure.
 */
typedef int (*smw_osal_mutex_destroy_t)(void **mutex);

/**
 * typedef smw_osal_mutex_lock_t - Lock a mutex.
 * @mutex: [in] Pointer to mutex object to lock.
 *
 * The functions locks a mutex object previously created with
 * smw_osal_mutex_init_t().
 *
 * Return:
 *  - 0 on success.
 *  - negative value on failure.
 */
typedef int (*smw_osal_mutex_lock_t)(void *mutex);

/**
 * typedef smw_osal_mutex_unlock_t - Unlock a mutex.
 * @mutex: [in] Pointer to mutex object to unlock.
 *
 * The functions unlocks a mutex object previously locked with
 * smw_osal_mutex_lock_t().
 *
 * Return:
 *  - 0 on success.
 *  - negative value on failure.
 */
typedef int (*smw_osal_mutex_unlock_t)(void *mutex);

/**
 * typedef smw_osal_thread_create_t - Create a thread.
 * @thread: [out] Pointer to thread object created.
 * @start_routine: [in] Pointer to the thread start function.
 * @args: [in] Pointer to arguments passed to the thread start function.
 *
 * The function creates a new thread that executes the function pointed to by
 * @start_routine() with the argument @arg. The new thread is identified by the
 * pointer @thread which must be released with smw_osal_thread_cancel_t().
 *
 * Return:
 *  - 0 on success.
 *  - negative value on failure.
 */
typedef int (*smw_osal_thread_create_t)(unsigned long *thread,
					void *(*start_routine)(void *),
					void *args);

/**
 * typedef smw_osal_thread_cancel_t - Cancel a thread.
 * @thread: [in] Thread object to cancel.
 *
 * The function cancels a thread object previously created with
 * smw_osal_thread_create_t(). On success, the thread is terminated and the
 * thread data is released.
 *
 * Return:
 *  - 0 on success.
 *  - negative value on failure.
 */
typedef int (*smw_osal_thread_cancel_t)(unsigned long thread);

/**
 * typedef smw_osal_vprint_t - Print a message with variable arguments.
 * @level: [in] Log level for the message.
 * @fmt: [in] Pointer to the format string.
 * @args: [in] Variable argument list.
 *
 * This function allows to print on the console or into a log file the library
 * debug traces function of the input level value and the VERBOSE built option.
 * It's implementation define.
 *
 * The debug trace is enabled if the project is built with VERBOSE set to the
 * maximum trace level desired. If the project is built in Debug mode the
 * maximum trace level is up to level 5, else it's limited to level 2.
 *
 * The level value definition:
 *   - 0. No trace.
 *   - 1. Failures of which the user must be aware.
 *   - 2. Traces which could interest the user.
 *   - 3. First level of debugging information.
 *   - 4. Second level of debugging information.
 *   - 5. Maximum level of debugging information.
 */
typedef void (*smw_osal_vprint_t)(unsigned int level, const char *fmt,
				  va_list args);

/**
 * typedef smw_osal_hex_dump_t - Print the hexadecimal content of a buffer.
 * @level: [in] Log level for the message.
 * @addr: [in] Pointer to the buffer to dump.
 * @size: [in] Size in bytes of the buffer to dump.
 * @align: [in] Alignment in bytes for line wrapping of the dump.
 *
 * This function allows to print on the console or into a log file some buffer
 * content in hexadecimal.
 * It's implementation define.
 *
 * Like the smw_osal_vprint_t() function, the hexadecimal dump is function of
 * the level of trace. The buffer dump is enabled if the project is built in
 * Debug mode with VERBOSE option set to level 3 or 4.
 */
typedef void (*smw_osal_hex_dump_t)(unsigned int level,
				    const unsigned char *addr,
				    unsigned int size, unsigned int align);

/**
 * typedef smw_osal_register_active_subsystem_t - Register an active subsystem.
 * @subsystem: [in] Subsystem identifier to register as active.
 *
 * This function is called to register the latest subsystem used. The purpose
 * of this feature is purely for debug purposes.
 *
 * Usage of this functionality is implementation define.
 *
 * This information is used by the appplication to know which subsystem was
 * executing the last operation by using a specific OSAL API function like
 * for example the smw_osal_latest_subsystem_name().
 *
 */
typedef void (*smw_osal_register_active_subsystem_t)(smw_subsystem_t subsystem);

/**
 * typedef smw_osal_get_subsystem_info_t - Get subsystem information.
 * @subsystem: [in] Subsystem identifier.
 * @info: [out] Pointer to subsystem information structure.
 *
 * This function returns the @subsystem information required to load and
 * configure the Secure Subsystem. The subsystem information is set when the
 * library is loaded.
 *
 * The way the subsystem information are defined is implementation define.
 *
 * The OSAL API smw_osal_set_subsystem_info() allows to setup the
 * subsystem information.
 *
 * In proposed Linux OSAL implementation, the subsystem information is
 * defined by the system configuration file `smw.conf` and parsed during
 * library initialization, the smw_osal_set_subsystem_info() overwrites the
 * system configuration file settings.
 *
 * The @info parameter points to a subsystem information structure that must
 * be &struct se_info for NXP i.MX Secure Enclave subsystem (ELE, SECO) or
 * &struct tee_info for TEE subsystem.
 *
 * Return:
 * - 0 on success.
 * - -1 on failure.
 */
typedef int (*smw_osal_get_subsystem_info_t)(smw_subsystem_t subsystem,
					     void *info);

/**
 * typedef smw_osal_is_lib_initialized_t - Check if library is initialized.
 *
 * This function returns if the libry is initialized or not.
 *
 * Return:
 *  - True if library is initialized.
 *  - False otherwise.
 */
typedef bool (*smw_osal_is_lib_initialized_t)(void);

/**
 * typedef smw_osal_db_get_obj_t - Get object information from database.
 * @descriptor: [in/out] Pointer to OSAL object descriptor structure.
 *
 * This function retrieves object information from the database based on
 * the @descriptor->obj_desc->id identifier. This identifier is the identifier
 * returned to the user API during the object creation.
 *
 * The function populates the @descriptor structure with the object information
 * stored in the database.
 *
 * Return:
 *  - 0 on success.
 *  - negative value on failure.
 */
typedef int (*smw_osal_db_get_obj_t)(struct smw_osal_object *descriptor);

/**
 * typedef smw_osal_db_add_obj_t - Add object information to database.
 * @descriptor: [in/out] Pointer to OSAL object descriptor structure.
 *
 * This function adds object information to the database based on the
 * input @descriptor content.
 *
 * How the object information is stored in the database is implementation
 * define.
 *
 * The function must return the @descriptor->obj_desc->id identifier which is
 * used for object identifier at user application level. This identifier can
 * be given by the user during the object creation if object is persistent.
 *
 * Return:
 *  - 0 on success.
 *  - negative value on failure.
 */
typedef int (*smw_osal_db_add_obj_t)(struct smw_osal_object *descriptor);

/**
 * typedef smw_osal_db_update_obj_t - Update object information in database.
 * @descriptor: [in] Pointer to OSAL object descriptor structure.
 *
 * This function updates object information in the database with the content
 * of the @descriptor structure.
 *
 * The object is identified by the @descriptor->obj_desc->id identifier returned
 * by the smw_osal_db_add_obj_t() function during object creation.
 *
 * Return:
 *  - 0 on success.
 *  - negative value on failure.
 */
typedef int (*smw_osal_db_update_obj_t)(struct smw_osal_object *descriptor);

/**
 * typedef smw_osal_db_delete_obj_t - Delete object information from database.
 * @descriptor: [in] Pointer to OSAL object descriptor structure.
 *
 * This function deletes the object information from the database based on the
 * content of the @descriptor structure.
 *
 * The object is identified by the @descriptor->obj_desc->id identifier returned
 * by the smw_osal_db_add_obj_t() function during object creation.
 *
 * Return:
 *  - 0 on success.
 *  - negative value on failure.
 */
typedef int (*smw_osal_db_delete_obj_t)(struct smw_osal_object *descriptor);

/**
 * typedef smw_osal_db_find_init_t - Initialize object search in database.
 * @context: [out] Pointer to search context.
 * @descriptor: [in] Pointer to OSAL object descriptor structure used as
 *              search criteria.
 *
 * This function initializes a search context for finding objects in the
 * database that match the criteria specified in the @descriptor structure.
 *
 * The function allocates the @context that must be used each
 * smw_osal_db_find_next_t() call.
 *
 * The @context must be freed by calling smw_osal_db_find_final_t().
 *
 * Return:
 *  - 0 on success.
 *  - negative value on failure.
 */
typedef int (*smw_osal_db_find_init_t)(void **context,
				       struct smw_osal_object *descriptor);

/**
 * typedef smw_osal_db_find_next_t - Get next object from database search.
 * @context: [in/out] Pointer to search context.
 * @descriptor: [out] Pointer to OSAL object descriptor structure.
 *
 * The function retrieves the next object from the database search results
 * corresponding to the search context initialized by smw_osal_db_find_init_t().
 *
 * The function may or not update the @context depending on the implementation.
 *
 * The @descriptor structure is populated with the next object information
 * found.
 *
 * The @descriptor->obj_desc->id field must be set to 0 when no more objects
 * are found in the database search results.
 *
 * Return:
 *  - 0 on success.
 *  - negative value on failure.
 */
typedef int (*smw_osal_db_find_next_t)(void *context,
				       struct smw_osal_object *descriptor);

/**
 * typedef smw_osal_db_find_final_t - Finalize object search in database.
 * @context: [in] Pointer to search context.
 *
 * This function finalizes a search context previously initialized by the
 * smw_osal_db_find_init_t() function and updated by the
 * smw_osal_db_find_next_t() function.
 *
 * The function release the resources allocated by smw_osal_db_find_init_t().
 *
 * Return:
 *  - 0 on success.
 *  - negative value on failure.
 */
typedef int (*smw_osal_db_find_final_t)(void *context);

/**
 * struct smw_ops - SMW OSAL operations interface
 * @critical_section_start: (**optional**) Start critical section, see
 *                          smw_osal_critical_section_start_t().
 * @critical_section_stop: (**optional**) Stop critical section, see
 *                         smw_osal_critical_section_stop_t().
 * @mutex_init: (**mandatory**) Initialize a mutex, see smw_osal_mutex_init_t().
 * @mutex_destroy: (**mandatory**) Destroy a mutex, see smw_osal_mutex_destroy_t().
 * @mutex_lock: (**mandatory**) Lock a mutex, see smw_osal_mutex_lock_t().
 * @mutex_unlock: (**mandatory**) Unlock a mutex, see smw_osal_mutex_unlock_t().
 * @thread_create: (**mandatory**) Create a thread, see smw_osal_thread_create_t().
 * @thread_cancel: (**mandatory**) Cancel a thread, see	smw_osal_thread_cancel_t().
 * @vprint: (**optional**) Print debug trace, see smw_osal_vprint_t().
 * @hex_dump: (**optional**) Print buffer content in hexadecimal format, see
 *            smw_osal_hex_dump_t().
 * @register_active_subsystem: (**optional**) Register the active Secure
 *                             Subsystem, see smw_osal_register_active_subsystem_t().
 * @get_subsystem_info: (**mandatory**) Get Subsystem configuration information,
 *                      see smw_osal_get_subsystem_info_t().
 * @is_lib_initialized: (**mandatory**) Check if the library was successfully
 *                      initialized by OSAL, see smw_osal_is_lib_initialized_t().
 * @get_obj_info: (**mandatory**) Get an object information from database, see
 *                smw_osal_db_get_obj_t().
 * @add_obj_info: (**mandatory**) Add an object information into database, see
 *                smw_osal_db_add_obj_t().
 * @update_obj_info: (**mandatory**) Update an object information into database,
 *                   see smw_osal_db_update_obj_t().
 * @delete_obj_info: (**mandatory**) Delete an object information from database,
 *                   see smw_osal_db_delete_obj_t().
 * @find_obj_init: (**mandatory**) Initialize the find object query, see
 *                 smw_osal_db_find_init_t().
 * @find_obj_next: (**mandatory**) Find the next object matching criteria, see
 *                 smw_osal_db_find_next_t().
 * @find_obj_final: (**mandatory**) Close the find object query, see
 *                  smw_osal_db_find_final_t().
 *
 * This structure defines the SMW OSAL operations interface using function
 * pointers that are implemented in the OSAL module.
 *
 * Function pointers:\
 *  - mutex_* functions pointers are optional together.
 *  - critical_* functions pointers are optional together.
 */
struct smw_ops {
	smw_osal_critical_section_start_t critical_section_start;
	smw_osal_critical_section_stop_t critical_section_stop;

	smw_osal_mutex_init_t mutex_init;
	smw_osal_mutex_destroy_t mutex_destroy;
	smw_osal_mutex_lock_t mutex_lock;
	smw_osal_mutex_unlock_t mutex_unlock;

	smw_osal_thread_create_t thread_create;
	smw_osal_thread_cancel_t thread_cancel;

	smw_osal_vprint_t vprint;
	smw_osal_hex_dump_t hex_dump;

	smw_osal_register_active_subsystem_t register_active_subsystem;

	smw_osal_get_subsystem_info_t get_subsystem_info;

	smw_osal_is_lib_initialized_t is_lib_initialized;

	smw_osal_db_get_obj_t get_obj_info;
	smw_osal_db_add_obj_t add_obj_info;
	smw_osal_db_update_obj_t update_obj_info;
	smw_osal_db_delete_obj_t delete_obj_info;
	smw_osal_db_find_init_t find_obj_init;
	smw_osal_db_find_next_t find_obj_next;
	smw_osal_db_find_final_t find_obj_final;
};

/**
 * smw_init() - Initialize the SMW library.
 * @ops: pointer to the structure SMw OSAL operations interface.
 *
 * This function initializes the Security Middleware core library and must be
 * called before using the library. The function registers the OSAL operations
 * interface.
 *
 * It verifies that all mandatory operations are implemented and all optional
 * operations group are either all NULL or valid.
 *
 * Return:
 *  - SMW_STATUS_OK
 *      Initialization is successful
 *  - SMW_STATUS_OPS_INVALID
 *      @ops is invalid
 *  - SMW_STATUS_MUTEX_INIT_FAILURE
 *      Mutex initialization has failed
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_init(const struct smw_ops *ops);

/**
 * smw_deinit() - Deinitialize the SMW library.
 *
 * This function deinitializes the Security Middleware core library.
 * It frees all memory dynamically allocated by SMW.
 *
 * Return:
 *  - SMW_STATUS_OK
 *      Deinitialization is successful
 *  - SMW_STATUS_INVALID_LIBRARY_CONTEXT
 *      Library context is not valid
 *  - SMW_STATUS_MUTEX_DESTROY_FAILURE
 *      Mutex destruction has failed
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_deinit(void);

#endif /* __OSAL_H__ */
