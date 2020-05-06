// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */
#include <stdarg.h>

#include "trace.h"
#include "util.h"

bool util_check_ptrs_null(int nb, ...)
{
	void *ptr;
	va_list args;
	int idx;
	int nb_null = 0;

	va_start(args, nb);

	for (idx = 0; idx < nb; idx++) {
		ptr = va_arg(args, void *);
		if (!ptr)
			nb_null++;

		DBG_TRACE("Parameter %d=%p", idx, ptr);
	}
	va_end(args);

	return (nb_null == nb);
}

bool util_check_ptrs_set(int nb, ...)
{
	void *ptr;
	va_list args;
	int idx;
	int nb_set = 0;

	va_start(args, nb);

	for (idx = 0; idx < nb; idx++) {
		ptr = va_arg(args, void *);
		if (ptr)
			nb_set++;

		DBG_TRACE("Parameter %d=%p", idx, ptr);
	}

	va_end(args);

	return (nb_set == nb);
}
