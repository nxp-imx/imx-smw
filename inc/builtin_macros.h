/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023, 2026 NXP
 */

#ifndef __BUILTIN_MACROS_H__
#define __BUILTIN_MACROS_H__

#include <stdint.h>

#ifndef BIT
#define BIT(n) (1UL << (n))
#endif
#ifndef BIT_MASK
#define BIT_MASK(length) ((1UL << (length)) - 1)
#endif
#define SET_BITS(val, mask)   ((val) |= (mask))
#define CLEAR_BITS(val, mask) ((val) &= ~(mask))

#define BYTES_TO_BITS(size) ((size) << 3)

/* Extract the byte @n of the value @val */
#define GET_BYTE(val, n)                                                       \
	({                                                                     \
		__typeof__(val) _val = (val);                                  \
		uint8_t _b = 0;                                                \
		_val >>= (n) * (8);                                            \
		_b = _val & UINT8_MAX;                                         \
		_b;                                                            \
	})

#define STR(x) #x

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#endif

#ifndef MIN
#define MIN(a, b)                                                              \
	({                                                                     \
		__typeof__(a) _a = (a);                                        \
		__typeof__(b) _b = (b);                                        \
		_a < _b ? _a : _b;                                             \
	})
#endif /* MIN */

#ifndef MAX
#define MAX(a, b)                                                              \
	({                                                                     \
		__typeof__(a) _a = (a);                                        \
		__typeof__(b) _b = (b);                                        \
		_a < _b ? _b : _a;                                             \
	})
#endif /* MAX */

#define ADD_OVERFLOW(a, b, res) __builtin_add_overflow(a, b, res)
#define SUB_OVERFLOW(a, b, res) __builtin_sub_overflow(a, b, res)
#define MUL_OVERFLOW(a, b, res) __builtin_mul_overflow(a, b, res)
#define INC_OVERFLOW(a, b)	__builtin_add_overflow(a, b, &(a))
#define DEC_OVERFLOW(a, b)	__builtin_sub_overflow(a, b, &(a))

#define SET_OVERFLOW_UNSIGNED(ua, res)                                         \
	({                                                                     \
		__typeof__(res) _max = 0;                                      \
		__typeof__(ua) _ua = (ua);                                     \
		int _overflow = 1;                                             \
		if (sizeof(ua) > sizeof(res))                                  \
			_ua = _ua & ~_max;                                     \
		if (_ua == _ua) {                                              \
			res = _ua;                                             \
			_overflow = 0;                                         \
		}                                                              \
		_overflow;                                                     \
	})

#define TO_UNSIGNED(v, res)                                                    \
	({                                                                     \
		__typeof__(v) _max_v = 0;                                      \
		__typeof__(v) _v = (v);                                        \
		__typeof__(res) _res = 0;                                      \
		int _overflow = 1;                                             \
		_max_v = ~_max_v;                                              \
		if ((_v & _max_v) == _v) {                                     \
			_res = _v;                                             \
			_overflow = 0;                                         \
		} else if (!ADD_OVERFLOW(~_v, 1, &_res)) {                     \
			_overflow = 0;                                         \
		}                                                              \
		res = _res;                                                    \
		_overflow;                                                     \
	})

#define SET_OVERFLOW(a, res)                                                   \
	({                                                                     \
		__typeof__(a) _a = (a);                                        \
		__typeof__(res) _res = 0;                                      \
		int _overflow = 1;                                             \
		if (sizeof(_a) == sizeof(uint64_t)) {                          \
			uint64_t __ua = 0;                                     \
			if (!TO_UNSIGNED(_a, __ua))                            \
				_overflow = SET_OVERFLOW_UNSIGNED(__ua, _res); \
		} else if (sizeof(_a) == sizeof(uint32_t)) {                   \
			uint32_t __ua = 0;                                     \
			if (!TO_UNSIGNED(_a, __ua))                            \
				_overflow = SET_OVERFLOW_UNSIGNED(__ua, _res); \
		} else if (sizeof(_a) == sizeof(uint8_t)) {                    \
			uint8_t __ua = 0;                                      \
			if (!TO_UNSIGNED(_a, __ua))                            \
				_overflow = SET_OVERFLOW_UNSIGNED(__ua, _res); \
		}                                                              \
		res = _res;                                                    \
		_overflow;                                                     \
	})

#define BITS_TO_BYTES_SIZE(size)                                               \
	({                                                                     \
		__typeof__(size) _bits = 0;                                    \
		ADD_OVERFLOW((size), 7, &_bits) ? 0 : _bits / 8;               \
	})

#define SET_CLEAR_MASK(val, set, clear) (((val) & ~(clear)) | (set))

#ifndef IS_ENABLED
/**
 * @brief Check for macro definition in compiler-visible expressions
 *
 * This trick was pioneered in Linux as the config_enabled() macro.
 * The madness has the effect of taking a macro value that may be
 * defined to "1" (e.g. CONFIG_MYFEATURE), or may not be defined at
 * all and turning it into a literal expression that can be used at
 * "runtime".  That is, it works similarly to
 * "defined(CONFIG_MYFEATURE)" does except that it is an expansion
 * that can exist in a standard expression and be seen by the compiler
 * and optimizer.  Thus much ifdef usage can be replaced with cleaner
 * expressions like:
 *
 *     if (IS_ENABLED(CONFIG_MYFEATURE))
 *             myfeature_enable();
 *
 * INTERNAL
 * First pass just to expand any existing macros, we need the macro
 * value to be e.g. a literal "1" at expansion time in the next macro,
 * not "(1)", etc...  Standard recursive expansion does not work.
 */
#define IS_ENABLED(CONFIG_macro) Z_IS_ENABLED1(CONFIG_macro)

/* Now stick on a "_XXXX" prefix, it will now be "_XXXX1" if CONFIG_macro
 * is "1", or just "_XXXX" if it's undefined.
 *   ENABLED:   Z_IS_ENABLED2(_XXXX1)
 *   DISABLED   Z_IS_ENABLED2(_XXXX)
 */
#define Z_IS_ENABLED1(CONFIG_macro) Z_IS_ENABLED2(_XXXX##CONFIG_macro)

/* Here's the core trick, we map "_XXXX1" to "_YYYY," (i.e. a string
 * with a trailing comma), so it has the effect of making this a
 * two-argument tuple to the preprocessor only in the case where the
 * value is defined to "1"
 *   ENABLED:    _YYYY,    <--- note comma!
 *   DISABLED:   _XXXX
 */
#define _XXXX1 _YYYY,

/* Then we append an extra argument to fool the gcc preprocessor into
 * accepting it as a varargs macro.
 *                         arg1   arg2  arg3
 *   ENABLED:   Z_IS_ENABLED3(_YYYY,    1,    0)
 *   DISABLED   Z_IS_ENABLED3(_XXXX 1,  0)
 */
#define Z_IS_ENABLED2(one_or_two_args)                                         \
	Z_IS_ENABLED3(one_or_two_args true, false)

/* And our second argument is thus now cooked to be 1 in the case
 * where the value is defined to 1, and 0 if not:
 */
#define Z_IS_ENABLED3(type, val, ...) val

#endif /* IS_ENABLE */

#endif /* __BUILTIN_MACROS_H__ */
