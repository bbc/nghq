#ifndef __NGHQ__LIB_LANG_H_
#define __NGHQ__LIB_LANG_H_

#include "config.h"

#ifdef HAVE_FUNC_ATTRIBUTE_PACKED
#define PACKED_STRUCT(name)
#define PACKED_STRUCT_FIELD(defn) defn __attribute__ ((packed))
#define END_PACKED_STRUCT(name)
#else
#ifdef HAVE_PRAGMA_PACK
#define PACKED_STRUCT(name) #pragma push \
#pragma pack(1)
#define PACKED_STRUCT_FIELD(defn) defn
#define END_PACKED_STRUCT(name) #pragma pop
#else
#ifdef HAVE_PACKED_ATTRIBUTE
#define PACKED_STRUCT(name)
#define PACKED_STRUCT_FIELD(defn) defn __packed
#define END_PACKED_STRUCT(name)
#else
#error "Compiler does not support packed structures!"
#endif
#endif
#endif

#endif
