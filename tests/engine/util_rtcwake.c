// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022 NXP
 */

#include <linux/rtc.h>
#include <fcntl.h>
#include <time.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include "util.h"
#include "util_file.h"
#include "util_rtcwake.h"

#define RTC_DEVICE "/dev/rtc0"

static int open_rtc_drv(const char *devname, int *fd)
{
	int res = ERR_CODE(INTERNAL);

	*fd = open(devname, O_RDONLY | O_CLOEXEC);
	if (*fd < 0)
		DBG_PRINT("open(%s) %s", devname, util_get_strerr());
	else
		res = ERR_CODE(PASSED);

	return res;
}

static int program_wakeup(int fd, int sec)
{
	int res = ERR_CODE(INTERNAL);

	time_t tm_sec;
	struct tm time = { 0 };
	struct rtc_time rtc_time = { 0 };
	struct rtc_wkalrm rtc_wake = { 0 };

	if (ioctl(fd, RTC_RD_TIME, &rtc_time)) {
		DBG_PRINT("RTC get time %s", util_get_strerr());
		goto exit;
	}

	/*
	 * Convert the RTC time in seconds to add the wakeup seconds
	 * and program the RTC wakeup
	 */
	time.tm_sec = rtc_time.tm_sec;
	time.tm_min = rtc_time.tm_min;
	time.tm_hour = rtc_time.tm_hour;
	time.tm_mday = rtc_time.tm_mday;
	time.tm_mon = rtc_time.tm_mon;
	time.tm_year = rtc_time.tm_year;
	/* RTC doesn't define those value */
	time.tm_wday = -1;
	time.tm_yday = -1;
	time.tm_isdst = -1;

	tm_sec = mktime(&time);
	if (tm_sec < -1) {
		DBG_PRINT("Error in time to seconds conversion");
		goto exit;
	}

	tm_sec += sec;

	if (!localtime_r(&tm_sec, &time)) {
		DBG_PRINT("Error in seconds to time conversion");
		goto exit;
	}

	rtc_wake.time.tm_sec = time.tm_sec;
	rtc_wake.time.tm_min = time.tm_min;
	rtc_wake.time.tm_hour = time.tm_hour;
	rtc_wake.time.tm_mday = time.tm_mday;
	rtc_wake.time.tm_mon = time.tm_mon;
	rtc_wake.time.tm_year = time.tm_year;
	/* RTC doesn't define those value */
	rtc_wake.time.tm_wday = -1;
	rtc_wake.time.tm_yday = -1;
	rtc_wake.time.tm_isdst = -1;

	/* Enable the alarm */
	rtc_wake.enabled = 1;

	if (ioctl(fd, RTC_WKALM_SET, &rtc_wake))
		DBG_PRINT("RTC set wakeup %s", util_get_strerr());
	else
		res = ERR_CODE(PASSED);

exit:
	return res;
}

static int disable_rtc_wakeup(int fd)
{
	int res = ERR_CODE(PASSED);

	if (ioctl(fd, RTC_AIE_OFF, NULL)) {
		DBG_PRINT("RTC disable alarm %s", util_get_strerr());
		res = ERR_CODE(INTERNAL);
	}

	return res;
}

static int suspend_to_mem(void)
{
	int res = ERR_CODE(INTERNAL);
	FILE *f = NULL;

	res = util_file_open(NULL, "/sys/power/state", "w", &f);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Ensure all stdout are done and all buffered data written */
	(void)fflush(stdout);
	sleep(1);

	sync();

	if (fprintf(f, "mem\n") < 0) {
		DBG_PRINT("Error setting suspend mode %s", util_get_strerr());
		goto exit;
	}

	(void)fflush(f);
	res = ERR_CODE(PASSED);

exit:
	if (f && fclose(f))
		DBG_PRINT("fclose() %s", util_get_strerr());

	return res;
}

int util_rtcwake_suspend_to_mem(int sec)
{
	int res;
	int fd = -1;

	if (!sec) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	res = open_rtc_drv(RTC_DEVICE, &fd);
	if (res == ERR_CODE(PASSED)) {
		res = program_wakeup(fd, sec);

		if (res == ERR_CODE(PASSED))
			res = suspend_to_mem();

		if (res == ERR_CODE(PASSED))
			res = disable_rtc_wakeup(fd);
	}

	if (fd >= 0)
		(void)close(fd);

	return res;
}
