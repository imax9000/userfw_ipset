/*-
 * Copyright (c) 2010 Isilon Systems, Inc.
 * Copyright (c) 2010 iX Systems, Inc.
 * Copyright (c) 2010 Panasas, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef	_LINUX_BITOPS_H_
#define	_LINUX_BITOPS_H_

#define	NBLONG	(NBBY * sizeof(long))

#define	set_bit(i, a)							\
    atomic_set_long(&((volatile long *)(a))[(i)/NBLONG], 1 << (i) % NBLONG)

#define	clear_bit(i, a)							\
    atomic_clear_long(&((volatile long *)(a))[(i)/NBLONG], 1 << (i) % NBLONG)

#define	test_bit(i, a)							\
    !!(atomic_load_acq_long(&((volatile long *)(a))[(i)/NBLONG]) & 1 << ((i) % NBLONG))

static inline long
test_and_clear_bit(long bit, long *var)
{
	long val;

	var += bit / (sizeof(long) * NBBY);
	bit %= sizeof(long) * NBBY;
	bit = 1 << bit;
	do {
		val = *(volatile long *)var;
	} while (atomic_cmpset_long(var, val, val & ~bit) == 0);

	return !!(val & bit);
}

static inline long
test_and_set_bit(long bit, long *var)
{
	long val;

	var += bit / (sizeof(long) * NBBY);
	bit %= sizeof(long) * NBBY;
	bit = 1 << bit;
	do {
		val = *(volatile long *)var;
	} while (atomic_cmpset_long(var, val, val | bit) == 0);

	return !!(val & bit);
}

#endif	/* _LINUX_BITOPS_H_ */
