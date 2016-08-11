/* Copyright 2016 Connor Taffe */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "path.h"

int path(char *name, char **out) {
  size_t i, last;
  char *path;

  assert(name);

  if ((path = getenv("PATH")) == 0)
    return -1;

  last = 0;
  for (i = 0; path[i]; i++) {
    if (path[i] == ':') {
      char *buf, fmt[10]; /* three digit string size */
      size_t sz;
      struct stat info;

      if (i - last > 999)
        continue;

      /* create format string */
      snprintf(fmt, sizeof(fmt), "%%.%lds/%%s", i - last);

      /* create file path */
      sz = (i - last) + strlen(name) + 2;
      buf = calloc(sizeof(char), sz);

/* disable errors for format nonliteral */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
      /* format path */
      snprintf(buf, sz, fmt, &path[last], name);
#pragma GCC diagnostic pop

      last = i + 1; /* ignore ':' */

      /* stat file */
      if (stat(buf, &info) == -1)
        continue;

      /* not a directory, at least one executable bit set */
      if (!S_ISDIR(info.st_mode) && (info.st_mode & 0111) != 0) {
        *out = buf;
        return 0;
      }

      free(buf);
    }
  }
  return -1;
}
