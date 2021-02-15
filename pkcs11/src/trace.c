// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021 NXP
 */
#include <stdarg.h>
#include <stdio.h>

#include "trace.h"

void trace_print(const char *function, int line, const char *format, ...)
{
	char buf[256];
	int nbchar = 0;
	va_list args;

	va_start(args, format);

	if (function) {
		nbchar = snprintf(buf, sizeof(buf), "[%s:%d] ", function, line);
		if (nbchar < 0)
			goto exit;
	}

	nbchar += vsnprintf(&buf[nbchar], sizeof(buf) - nbchar, format, args);
	if (sizeof(buf) - nbchar > 2) {
		if (sprintf(&buf[nbchar], "\n\r") < 0)
			buf[nbchar] = '\0';
	}

	(void)fprintf(stdout, "%s", buf);

exit:
	va_end(args);
}
