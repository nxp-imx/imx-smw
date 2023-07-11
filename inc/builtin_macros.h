/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */

#ifndef __BUILTIN_MACROS_H__
#define __BUILTIN_MACROS_H__

#define BIT(n)		 (1 << (n))
#define BIT_MASK(length) ((1ULL << (length)) - 1)
#define SHIFT_BIT(n)	 (1ULL << (n))

#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

#ifndef MIN
#define MIN(a, b)                                                              \
	({                                                                     \
		__typeof__(a) _a = (a);                                        \
		__typeof__(b) _b = (b);                                        \
		_a < _b ? _a : _b;                                             \
	})
#endif /* MIN */

#define ADD_OVERFLOW(a, b, res) __builtin_add_overflow(a, b, res)
#define SUB_OVERFLOW(a, b, res) __builtin_sub_overflow(a, b, res)
#define MUL_OVERFLOW(a, b, res) __builtin_mul_overflow(a, b, res)
#define INC_OVERFLOW(a, b)	__builtin_add_overflow(a, b, &(a))

#define SET_OVERFLOW_UNSIGNED(ua, res)                                         \
	({                                                                     \
		__typeof__(res) _max = 0;                                      \
		__typeof__(ua) _ua = (ua);                                     \
		int _overflow = 1;                                             \
		_max = ~_max;                                                  \
		if ((_ua & _max) == _ua) {                                     \
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
		} else if (ADD_OVERFLOW(~_v, 1, &_res)) {                      \
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

#endif /* __BUILTIN_MACROS_H__ */
