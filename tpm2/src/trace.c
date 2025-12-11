// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */
#include <stdarg.h>
#include <stdio.h>

#include "trace.h"

void trace_print(const char *function, int line, const char *format, ...)
{
	char buf[256] = { 0 };
	unsigned int nb_char = 0;
	int tmp_char = 0;
	va_list args;

	va_start(args, format);

	tmp_char = snprintf(buf, sizeof(buf), "[TPM2] ");
	if (tmp_char < 0)
		goto exit;

	nb_char += tmp_char;

	if (nb_char >= sizeof(buf))
		goto end;

	if (function) {
		tmp_char = snprintf(&buf[nb_char], sizeof(buf) - nb_char,
				    "[%s:%d] ", function, line);
		if (tmp_char < 0)
			goto end;

		nb_char += tmp_char;

		if (nb_char >= sizeof(buf))
			goto end;
	}

	tmp_char =
		vsnprintf(&buf[nb_char], sizeof(buf) - nb_char, format, args);
	if (tmp_char < 0)
		goto end;

	nb_char += tmp_char;

end:
	if (sizeof(buf) - nb_char > 2) {
		if (sprintf(&buf[nb_char], "\n\r") < 0)
			buf[nb_char] = '\0';
	}

	buf[sizeof(buf) - 1] = '\0';

	(void)fprintf(stdout, "%s", buf);

exit:
	va_end(args);
}
