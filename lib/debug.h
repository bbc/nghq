/*
 * nghq
 *
 * Copyright (c) 2018 British Broadcasting Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef LIB_DEBUG_H_
#define LIB_DEBUG_H_

#include "config.h"

/*
 * Stops GCC complaining about variadic macros
 */
#pragma GCC system_header

#ifdef DEBUGOUT
#include <stdio.h>
#define DEBUG(fmt, ...) fprintf(stdout, "%s:%d (DBG:%s): " fmt, __FILE__, __LINE__, __func__, ## __VA_ARGS__)
#define ERROR(fmt, ...) fprintf(stderr, "%s:%d (ERR:%s): " fmt, __FILE__, __LINE__, __func__, ## __VA_ARGS__)
#else
#define DEBUG(...) do {} while (0)
#define ERROR(...) do {} while (0)
#endif /* DEBUGOUT */

#endif /* LIB_DEBUG_H_ */
