/* Copyright 2016 Connor Taffe */

#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <regex.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "../birch.h"

static birch_message_handlefunc handler;

struct handler {
  int sock;
  regex_t future;
  char *channel;
};

static int handler_init(struct handler *handler);
static void handler_fini(struct handler *handler);

static int test_client(int sock);

static int fortune(void);
static int path(char *name, char **out);

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

/* route stdout from `fortune` to the returned pipe out */
int fortune() {
  pid_t child;
  int fd[2];

  if (pipe(fd) == -1)
    return -1;

  child = fork();
  if (child == -1)
    return -1;
  if (child == 0) {
    char *argv[] = {0, "-sn", "140", 0};

    if (path("fortune", &argv[0]) == -1)
      goto error;

    if (close(fd[0]) == -1)
      goto error;

    /* set stdout to out */
    if (close(1) == -1)
      goto error;
    if (dup(fd[1]) == -1)
      goto error;

    execve(argv[0], argv, 0);
    goto error;

  error:
    free(argv[0]);
    exit(1);
  }
  if (close(fd[1]) == -1)
    return -1;
  return fd[0];
}

int handler_init(struct handler *handler) {
  char *buf;
  size_t sz;

  assert(handler->channel);

  sz = strlen(handler->channel) + 128;
  buf = calloc(sizeof(char), sz);
  snprintf(buf, sz - 1, "^%s[ :]*f!$", handler->channel);
  if (regcomp(&handler->future, buf, 0) != 0)
    return -1;
  return 0;
}

void handler_fini(struct handler *handler) { regfree(&handler->future); }

void handler(void *o, struct birch_token_list *list) {
  struct birch_message msg;
  struct handler *h;

  assert(o != 0);

  h = (struct handler *)o;

  if (!list)
    return; /* empty list */

  memset(&msg, 0, sizeof(msg));

  /* ignore commands that cannot yet be parsed */
  if (birch_token_list_message(list, &msg) == 0) {
    struct birch_message rmsg;

    if (msg.type == BIRCH_MSG_PING) {
      /* automatically reply to pings */

      assert(msg.nparams == 1);
      assert(birch_message_pong(&rmsg, "*", msg.params[0]) != -1);
      assert(birch_message_format(&rmsg, h->sock) != -1);
    } else if (msg.type == BIRCH_MSG_PRIVMSG) {
      /* fork/exec and pipe fortune output */
      if (msg.nparams == 1 &&
          regexec(&h->future, msg.params[0], 0, 0, 0) == 0) {
        char *buf, *ptr[2];
        size_t sz, i, last;
        int fd;

        i = 0;
        sz = 0;
        buf = 0;
        fd = fortune();

        assert(fd != -1);

        for (;;) {
          ssize_t ret;

          if (i == sz) {
            sz = sz * 2 + 1;
            buf = realloc(buf, sz);
          }
          ret = read(fd, &buf[i], sz - i);
          assert(ret != -1);
          if (ret == 0)
            break;
          i += (size_t)ret;
        }
        buf[i] = 0;

        last = 0;
        for (i = 0; buf[i]; i++) {
          /* replace unprintable characters */
          if (buf[i] == '\n' || buf[i] == '\r' || buf[i] == '\0') {
            buf[i] = 0;

            if (i - last > 0) {
              ptr[0] = h->channel; /* send to same entity */
              ptr[1] = &buf[last];

              /* format message */
              rmsg.type = BIRCH_MSG_PRIVMSG;
              rmsg.nparams = 2;
              rmsg.params = ptr;

              assert(birch_message_format(&rmsg, h->sock) != -1);
            }
            last = i + 1;
          }
        }
      }
    }
    assert(birch_message_format(&msg, 1) != -1);
  }
}

int test_client(int sock) {
  struct birch_message msg;
  enum { STAGE_PASS, STAGE_NICK, STAGE_USER, STAGE_JOIN, STAGE_max } i;

  /* generate random password */
  for (i = 0; i < STAGE_max; i++) {
    memset(&msg, 0, sizeof(msg));
    switch (i) {
    case STAGE_PASS:
      if (birch_message_pass_random(&msg) == -1)
        return -1;
      break;
    case STAGE_NICK:
      if (birch_message_nick(&msg, "ualr-acm-bot") == -1)
        return -1;
      break;
    case STAGE_USER:
      if (birch_message_user(&msg, "test__", "UALR ACM IRC Bot") == -1)
        return -1;
      break;
    case STAGE_JOIN:
      if (birch_message_join(&msg, "#ualr-acm") == -1)
        return -1;
      break;
    case STAGE_max:
      __builtin_unreachable();
    }
    birch_message_format(&msg, sock);
  }

  return 0;
}

int main(int argc __attribute__((unused)),
         char **argv __attribute__((unused))) {
  struct birch_message_handler handle;
  int sock;
  struct sockaddr_in addr;
  struct handler h;
  int ecode;

  ecode = 1;
  memset(&addr, 0, sizeof(addr));
  memset(&handle, 0, sizeof(handle));
  memset(&h, 0, sizeof(h));

  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock == -1)
    goto failure;

  addr.sin_family = AF_INET;
  addr.sin_port = htons(6667);
  if (inet_pton(AF_INET, "64.32.24.178", &addr.sin_addr) == 0)
    goto failure;
  if (connect(sock, &addr, sizeof(addr)) == -1)
    goto failure;

  h.sock = sock;
  h.channel = "#ualr-acm";
  if (handler_init(&h) == -1)
    goto failure;
  handle.obj = &h;
  handle.func = handler;

  if (test_client(sock) != 0)
    goto failure;
  if (birch_fetch_message(sock, &handle) == -1)
    goto failure;

  /* cleanup */
  ecode = 0;
failure:
  handler_fini(&h);
  exit(ecode);
}
