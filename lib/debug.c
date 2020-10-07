/*
 * nghq
 *
 * Copyright (c) 2020 British Broadcasting Corporation
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

#include "nghq/nghq.h"
#include "nghq_internal.h"
#include "debug.h"
#include <stdarg.h>
#include <stdio.h>

#define DEFAULT_DEBUG_LINE_BUF 1024

const char* log_level_as_str(nghq_log_level level) {
  const char* rv;
  switch(level) {
    case NGHQ_LOG_LEVEL_ALERT:
      rv = "ALERT";
      break;
    case NGHQ_LOG_LEVEL_ERROR:
      rv = "ERROR";
      break;
    case NGHQ_LOG_LEVEL_WARN:
      rv = "WARN";
      break;
    case NGHQ_LOG_LEVEL_INFO:
      rv = "INFO";
      break;
    case NGHQ_LOG_LEVEL_DEBUG:
      rv = "DEBUG";
      break;
    case NGHQ_LOG_LEVEL_TRACE:
      rv = "TRACE";
      break;
    default:
      rv = "";
  }
  return rv;
}

void nghq_log (nghq_session* session, nghq_log_level level,
               const char *function, const char *filename,
               unsigned int linenumber, const char *format, ...) {
  va_list args;
  va_start(args, format);

  if (session->log_level >= level) {
    char outbuf[DEFAULT_DEBUG_LINE_BUF];
    char buf[DEFAULT_DEBUG_LINE_BUF];

    va_list ap;
    va_copy(ap, args);
    int buf_size = vsnprintf(0, 0, format, ap);
    va_end(ap);

    vsnprintf(buf, buf_size + 1, format, args);

    int printsz = snprintf(outbuf, DEFAULT_DEBUG_LINE_BUF, "%s (%s:%d): %s",
                           function, filename, linenumber, buf);

    if (session->log_cb != NULL) {
      session->log_cb(session, level, outbuf, printsz);
    } else {
      fprintf(stderr, "[%s] %s", log_level_as_str(level), outbuf);
    }
  }

  va_end(args);
}
