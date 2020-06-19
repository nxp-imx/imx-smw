/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */

#ifndef __LIST_H__
#define __LIST_H__

/*
 * Definition of the head of the list @name
 */
#define LIST_HEAD(name)                                                        \
	struct name {                                                          \
		void *first;                                                   \
		void *last;                                                    \
	}

#define LIST_INIT(head)                                                        \
	do {                                                                   \
		__typeof__(head) _head = (head);                               \
		_head->first = NULL;                                           \
		_head->last = NULL;                                            \
	} while (0)

#define LIST_EMPTY(head) (!(head)->first)
#define LIST_FIRST(head) ((head)->first)
#define LIST_NEXT(elem)	 ((elem)->next)

/*
 * Insert a new element @elem in the list pointed by the @head
 */
#define LIST_INSERT_TAIL(head, elem)                                           \
	do {                                                                   \
		__typeof__(head) _head = (head);                               \
		__typeof__(elem) _elem = (elem);                               \
		__typeof__(elem) _prev = _head->last;                          \
		_elem->next = NULL;                                            \
		if (LIST_EMPTY(_head))                                         \
			_head->first = _elem;                                  \
		else                                                           \
			_prev->next = _elem;                                   \
		_head->last = _elem;                                           \
		_elem->prev = _prev;                                           \
	} while (0)

/*
 * Remove the element @elem from the list pointed by the @head
 */
#define LIST_REMOVE(head, elem)                                                \
	do {                                                                   \
		__typeof__(head) _head = (head);                               \
		__typeof__(elem) _elem = (elem);                               \
		__typeof__(elem) _prev = _elem->prev;                          \
		__typeof__(elem) _next = _elem->next;                          \
		if (_head->first == _elem)                                     \
			_head->first = _next;                                  \
		if (_head->last == _elem)                                      \
			_head->last = _prev;                                   \
		if (_prev)                                                     \
			_prev->next = _next;                                   \
		if (_next)                                                     \
			_next->prev = _prev;                                   \
	} while (0)

#define LIST_FIND(res, head, find)                                             \
	do {                                                                   \
		__typeof__(find) _elem = LIST_FIRST(head);                     \
		for (; _elem && _elem != (find); _elem = LIST_NEXT(_elem))     \
			;                                                      \
		res = _elem;                                                   \
	} while (0)

#endif /* __LIST_H__ */
