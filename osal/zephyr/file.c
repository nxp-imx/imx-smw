// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 *
 */

#ifndef CONFIG_FAT_FILESYSTEM_ELM
#error "FATFS not enabled"
#endif

#include <errno.h>
#include <ff.h>
#include <zephyr/fs/fs.h>

#include "internal.h"

#if defined(CONFIG_DISK_DRIVER_SDMMC)
#define DISK_DRIVE_NAME "SD"
#elif defined(CONFIG_DISK_DRIVER_MMC)
#define DISK_DRIVE_NAME "SD2"
#elif defined(CONFIG_DISK_DRIVER_FLASH)
#define DISK_DRIVE_NAME "NAND"
#elif defined(CONFIG_NVME)
#define DISK_DRIVE_NAME "nvme0n0"
#elif defined(CONFIG_DISK_DRIVER_RAM)
/* Since ramdisk is enabled by default on e.g. qemu boards, it needs to be checked last to not
 * override other backends.
 */
#define DISK_DRIVE_NAME "RAM"
#else
#error "No disk device defined, is your board supported?"
#endif

#define DISK_MOUNT_PT "/" DISK_DRIVE_NAME ":"
#define NVM_FILE_PATH DISK_MOUNT_PT "/nvm"

/*
 * The full path will be: /<disk>:/storage_dname/<blob_ext>/<blob_id_msb>/<blob_id_lsb>
 * As per the fatfs documentation, the maximum filename length is 8 characters without
 * extension. The blob_id_msb, blob_id_lsb and blob_ext are represented as hex values.
 * Which means a 32-bit value will take maximum 8 characters (including \0).
 * Maximum file path length calculation:
 * - Mount point: "/<disk>:" = 10 chars
 * - NVM directory: "/<directory>" = 9 chars
 * - blob_ext directory: "/<8-char-hex>" = 9 chars
 * - blob_id_msb directory: "/<8-char-hex>" = 9 chars
 * - blob_id_lsb filename: "<8-char-hex>" = 8 chars
 * - zero terminator: 1 char
 * 46 bytes total, rounded up to 64 bytes for safety margin.
 */
#define MAX_PATH_LEN 64

static FATFS fat_fs;
/* mounting info */
static struct fs_mount_t mp = {
	.type = FS_FATFS,
	.fs_data = &fat_fs,
	.storage_dev = (void *)DISK_DRIVE_NAME,
};

static const char *disk_mount_pt = DISK_MOUNT_PT;

LOG_MODULE_DECLARE(smw_osal);

static int create_dir(char *dir_path)
{
	int error = 0;

	error = fs_mkdir(_T(dir_path));
	/* The directory may already exist, that is not an error */
	if (error && error != -EEXIST)
		return -1;

	return 0;
}

/* Create the filepath of chunk associated with blob_id_msb, blob_id_lsb and blob_ext */
static int get_chunk_file_path(char *path, uint8_t path_buf_sz,
			       char *nvm_storage_dname, uint32_t blob_id_msb,
			       uint32_t blob_id_lsb, uint32_t blob_ext,
			       bool create_path)
{
	uint8_t path_len = 0;
	int err = -1;
	char *path_current = path;
	char *path_end = NULL;

	/*
	 * 1 extra byte in path_len is for accommodating null termination char
	 * \0 in path string. Since fatfs is not enabled with Long file system
	 * names (LFS) due to space limitation, we are only using blob_ext as filename
	 * and rest of the unique values like blob_id_msb and lsb are used in the file path.
	 * Chunk file path will be named <blob_ext> and the path will be
	 * <nvm_storage_dname>/blob_ext/blob_id_msb/blob_id_lsb
	 */
	path_len = strlen(nvm_storage_dname) +
		   1 + /* 1 additional byte for / after every name */
		   sizeof(blob_id_msb) * 2 + 1 + sizeof(blob_id_lsb) * 2 + 1 +
		   sizeof(blob_ext) * 2 + 1;

	if (path_buf_sz < path_len) {
		LOG_ERR("Insufficient size of path buffer");
		return -1;
	}

	path_end =
		path +
		path_len; /* For keeping track of free space when appending to the path string */

	/* If path needs to be created, we need to check and add the required directories */
	if (create_path) {
		path_current += snprintf(path, path_len, "%s/%x",
					 nvm_storage_dname, blob_ext);
		err = create_dir(path);
		if (err)
			return -1;

		path_current += snprintf(path_current, path_end - path_current,
					 "/%x", blob_id_msb);
		err = create_dir(path);
		if (err)
			return -1;

		path_current += snprintf(path_current, path_end - path_current,
					 "/%x", blob_id_lsb);
	} else {
		snprintf(path, path_len - 1, "%s/%x/%x/%x", nvm_storage_dname,
			 blob_ext, blob_id_msb, blob_id_lsb);
	}

	return 0;
}

/* Create and write to a file identified by passed blob_id */
int osal_zephyr_file_write(uint32_t blob_id_msb, uint32_t blob_id_lsb,
			   uint32_t blob_ext, uint32_t *chunk, size_t chunk_sz)
{
	int error = 0;
	struct fs_file_t g_fileObject = { 0 }; /* File object */
	char path[MAX_PATH_LEN] = { 0 };
	size_t bytesWritten = 0;

	/* Get the filepath of chunk associated with blob ID and blob_ext. */
	if (get_chunk_file_path((char *)path, sizeof(path), NVM_FILE_PATH,
				blob_id_msb, blob_id_lsb, blob_ext, true))
		return -1;

	error = fs_open(&g_fileObject, path, (FS_O_RDWR | FS_O_CREATE));
	if (error && error != -EEXIST) {
		LOG_ERR("Open file failed");
		return -1;
	}

	bytesWritten = fs_write(&g_fileObject, chunk, chunk_sz);
	fs_sync(&g_fileObject);
	fs_close(&g_fileObject);

	if (bytesWritten != chunk_sz) {
		LOG_ERR("Write file failed.");
		return -1;
	}

	return 0;
}

int osal_zephyr_file_read(uint32_t blob_id_msb, uint32_t blob_id_lsb,
			  uint32_t blob_id_ext, uint32_t *chunk, size_t *sz)
{
	int error = 0;
	struct fs_file_t g_fileObject = { 0 }; /* File object */
	struct fs_dirent entry = { 0 };
	char path[MAX_PATH_LEN] = { 0 };
	uint32_t file_sz = 0;
	size_t bytesRead = 0;

	if (get_chunk_file_path((char *)path, sizeof(path), NVM_FILE_PATH,
				blob_id_msb, blob_id_lsb, blob_id_ext, false))
		return -1;

	error = fs_stat(path, &entry);
	if (error && error != -ENOENT)
		return -1;

	if (error == -ENOENT) {
		/* File doesn't exist, return success with chunk_sz 0 */
		*sz = 0;
		return 0;
	}

	file_sz = entry.size;
	if (!chunk || *sz < file_sz) {
		*sz = file_sz;
		return 0;
	}

	error = fs_open(&g_fileObject, path, (FS_O_READ));
	if (error && error != -EEXIST) {
		LOG_ERR("Open file failed");
		return -1;
	}

	memset(chunk, 0U, file_sz);
	/* Read the chunk data */
	bytesRead = fs_read(&g_fileObject, chunk, file_sz);
	if (bytesRead == file_sz)
		error = 0;
	else
		error = -1;

	DCACHE_CLEAN(chunk, file_sz);

	fs_close(&g_fileObject);
	return error;
}

/* Initialize the FAT FS for SD */
int osal_zephyr_file_initialize(void)
{
	int error = 0;

	mp.mnt_point = disk_mount_pt;
	mp.mountp_len = strlen(disk_mount_pt);

	error = fs_mount(&mp);
	if (error) {
		LOG_ERR("Mount volume failed.");
		return -1;
	}

	LOG_INF("Create directory......");
	error = fs_mkdir(NVM_FILE_PATH);
	if (error && error != -EEXIST) {
		LOG_ERR("Make directory failed.");
		return -1;
	}

	return 0;
}
