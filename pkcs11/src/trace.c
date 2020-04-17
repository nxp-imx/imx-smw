// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

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
	if (sizeof(buf) - nbchar > 2)
		sprintf(&buf[nbchar], "\n\r");

	fprintf(stdout, "%s", buf);

exit:
	va_end(args);
}
