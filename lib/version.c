#include "config.h"
#include "nghq/version.h"
#include "git-version.h"

#define STR(s) #s

const char *nghq_version_string()
{
  static const char version_string[] = PACKAGE_NAME "/" PACKAGE_VERSION
#ifdef PACKAGE_REVISION
    "-git" PACKAGE_REVISION
#endif
  ;
  return version_string;
}

unsigned int nghq_version_major()
{
  return NGHQ_VERSION_MAJOR;
}

unsigned int nghq_version_minor()
{
  return NGHQ_VERSION_MINOR;
}

unsigned int nghq_version_micro()
{
  return NGHQ_VERSION_MICRO;
}

unsigned int nghq_version()
{
  return NGHQ_VERSION;
}
