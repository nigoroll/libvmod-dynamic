/*-
 * Copyright (c) 2010 Varnish Software AS
 * All rights reserved.
 *
 * Author: Poul-Henning Kamp <phk@phk.freebsd.dk>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Memory barriers
 *
 */

#ifndef VMB_H_INCLUDED
#define VMB_H_INCLUDED

#if defined(HAVE_STDATOMIC_H) && !defined(__FLEXELINT__)

#  include <stdatomic.h>
#  define VWMB()	atomic_thread_fence(memory_order_release)
#  define VRMB()	atomic_thread_fence(memory_order_acquire)

#elif defined(__amd64__) && defined(__GNUC__)

#  define VWMB()	__asm __volatile("sfence;" : : : "memory")
#  define VRMB()	__asm __volatile("lfence;" : : : "memory")

#elif defined(__i386__) && defined(__GNUC__)

#  define VWMB()	__asm __volatile("lock; addl $0,(%%esp)" : : : "memory")
#  define VRMB()	__asm __volatile("lock; addl $0,(%%esp)" : : : "memory")

#elif defined(__sparc64__) && defined(__GNUC__)

#  define VWMB()	__asm__ __volatile__ ("membar #MemIssue": : :"memory")
#  define VRMB()	__asm__ __volatile__ ("membar #MemIssue": : :"memory")

#else

#  define VMB_NEEDS_PTHREAD_WORKAROUND_THIS_IS_BAD_FOR_PERFORMANCE 1
   void vmb_pthread(void);
#  define VWMB()	vmb_pthread()
#  define VRMB()	vmb_pthread()

#endif

#endif /* VMB_H_INCLUDED */
