/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021, 2023 NXP
 */

#ifndef __LIST_H__
#define __LIST_H__

/*
 * Definition of the head of the list @name
 */
#define LIST_HEAD(name, type)                                                  \
	struct name {                                                          \
		struct type *first;                                            \
		struct type *last;                                             \
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

/*
 * Find the element @find in the list pointed by the @head
 * The element found (otherwise NULL) is returned in @res
 */
#define LIST_FIND(res, head, find)                                             \
	do {                                                                   \
		__typeof__(find) _elem = LIST_FIRST(head);                     \
		for (; _elem && _elem != (find); _elem = LIST_NEXT(_elem))     \
			;                                                      \
		res = _elem;                                                   \
	} while (0)

/*
 * Definition of the head of the list @name
 * This list includes a lock (mutex) object
 */
#define LLIST_HEAD(name, type)                                                 \
	struct name {                                                          \
		void *lock;                                                    \
		struct type *first;                                            \
		struct type *last;                                             \
	}

/*
 * Lock/Unlock list access
 */
#define LLIST_LOCK(head)   libmutex_lock((head)->lock)
#define LLIST_UNLOCK(head) libmutex_unlock((head)->lock)

/* Initialize the list, creates list mutex */
#define LLIST_INIT(head)                                                       \
	({                                                                     \
		CK_RV _ret;                                                    \
		do {                                                           \
			__typeof__(head) _head = (head);                       \
			_head->first = NULL;                                   \
			_head->last = NULL;                                    \
			_ret = libmutex_create(&_head->lock);                  \
		} while (0);                                                   \
		_ret;                                                          \
	})

/* Close the list, destroyes list mutex */
#define LLIST_CLOSE(head)                                                      \
	({                                                                     \
		do {                                                           \
			__typeof__(head) _head = (head);                       \
			_head->first = NULL;                                   \
			_head->last = NULL;                                    \
		} while (0);                                                   \
		LLIST_UNLOCK(head);                                            \
		libmutex_destroy(&head->lock);                                 \
	})

#define LLIST_EMPTY(head) LIST_EMPTY(head)
#define LLIST_FIRST(head) LIST_FIRST(head)
#define LLIST_NEXT(elem)  LIST_NEXT(elem)

/*
 * Insert a new element @elem in the list pointed by the @head
 */
#define LLIST_INSERT_TAIL(head, elem)                                          \
	({                                                                     \
		CK_RV _ret;                                                    \
		do {                                                           \
			__typeof__(head) _head = (head);                       \
			__typeof__(elem) _elem = (elem);                       \
			__typeof__(elem) _prev = _head->last;                  \
			_ret = LLIST_LOCK(_head);                              \
			if (_ret == CKR_OK) {                                  \
				_elem->next = NULL;                            \
				if (LIST_EMPTY(_head))                         \
					_head->first = _elem;                  \
				else                                           \
					_prev->next = _elem;                   \
				_head->last = _elem;                           \
				_elem->prev = _prev;                           \
				LLIST_UNLOCK(_head);                           \
			}                                                      \
		} while (0);                                                   \
		_ret;                                                          \
	})

/*
 * Remove the element @elem from the list pointed by the @head
 */
#define LLIST_REMOVE(head, elem) LIST_REMOVE(head, elem)

#endif /* __LIST_H__ */
