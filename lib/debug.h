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
#include "nghq_internal.h"

/*
 * Stops GCC complaining about variadic macros
 */
#pragma GCC system_header

#define NGHQ_LOG_LEVEL_ALERT_STR "ALERT"
#define NGHQ_LOG_LEVEL_ERROR_STR "ERROR"
#define NGHQ_LOG_LEVEL_WARN_STR "WARN"
#define NGHQ_LOG_LEVEL_INFO_STR "INFO"
#define NGHQ_LOG_LEVEL_DEBUG_STR "DEBUG"
#define NGHQ_LOG_LEVEL_TRACE_STR "TRACE"

extern const char* log_level_as_str (nghq_log_level level);

extern void nghq_log (nghq_session* session, nghq_log_level level,
                      const char *function, const char *filename,
                      unsigned int linenumber, const char *format, ...);

#define NGHQ_LOG(session, level, format, ...) \
  nghq_log (session, level, __func__, __FILE__, __LINE__, format, ## __VA_ARGS__)

#define NGHQ_LOG_ALERT(session, fmt, ...) \
  NGHQ_LOG (session, NGHQ_LOG_LEVEL_ALERT, fmt, ## __VA_ARGS__)
#define NGHQ_LOG_ERROR(session, fmt, ...) \
  NGHQ_LOG (session, NGHQ_LOG_LEVEL_ERROR, fmt, ## __VA_ARGS__)
#define NGHQ_LOG_WARN(session, fmt, ...) \
  NGHQ_LOG (session, NGHQ_LOG_LEVEL_WARN, fmt, ## __VA_ARGS__)
#define NGHQ_LOG_INFO(session, fmt, ...) \
  NGHQ_LOG (session, NGHQ_LOG_LEVEL_INFO, fmt, ## __VA_ARGS__)
#define NGHQ_LOG_DEBUG(session, fmt, ...) \
  NGHQ_LOG (session, NGHQ_LOG_LEVEL_DEBUG, fmt, ## __VA_ARGS__)
#define NGHQ_LOG_TRACE(session, fmt, ...) \
  NGHQ_LOG (session, NGHQ_LOG_LEVEL_TRACE, fmt, ## __VA_ARGS__)

#endif /* LIB_DEBUG_H_ */
