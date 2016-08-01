/* Copyright 2016 Connor Taffe */

#include <assert.h>
#include <netinet/in.h>
#include <regex.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "birch.h"

static birch_message_handlefunc handler;
static int fortune(void);

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
    char *argv[] = {"/usr/games/fortune", "-sn", "140", 0};

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
    exit(1);
  }
  if (close(fd[1]) == -1)
    return -1;
  return fd[0];
}

struct handler {
  int sock;
  regex_t future;
  char *channel;
};

static int handler_init(struct handler *handler);
static void handler_fini(struct handler *handler);

int handler_init(struct handler *handler) {
  if (regcomp(&handler->future, "#ualr-acm[ :]*f!$", 0) != 0)
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
          i += ret;
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

static int test_client(int sock);

int test_client(int sock) {
  struct birch_message msg;

  /* generate random password */
  memset(&msg, 0, sizeof(msg));
  if (birch_message_pass_random(&msg) == -1)
    return -1;
  birch_message_format(&msg, sock);

  memset(&msg, 0, sizeof(msg));
  if (birch_message_nick(&msg, "ualr-acm-bot") == -1)
    return -1;
  birch_message_format(&msg, sock);

  memset(&msg, 0, sizeof(msg));
  if (birch_message_user(&msg, "test__", "UALR ACM IRC Bot") == -1)
    return -1;
  birch_message_format(&msg, sock);

  memset(&msg, 0, sizeof(msg));
  if (birch_message_join(&msg, "#ualr-acm") == -1)
    return -1;
  birch_message_format(&msg, sock);

  return 0;
}

int main(int argc __attribute__((unused)),
         char **argv __attribute__((unused))) {
  struct birch_message_handler handle;
  int sock;
  struct sockaddr_in addr;
  struct handler h;

  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock == -1)
    exit(1);

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET, addr.sin_port = htons(6667);
  addr.sin_addr.s_addr = htonl((uint32_t)64 << 24 | (uint32_t)32 << 16 |
                               (uint32_t)24 << 8 | (uint32_t)178);
  if (connect(sock, &addr, sizeof(addr)) == -1)
    exit(1);

  memset(&handle, 0, sizeof(handle));
  if (handler_init(&h) == -1)
    exit(1);
  h.sock = sock;
  h.channel = "#ualr-acm";
  handle.obj = &h;
  handle.func = handler;

  if (test_client(sock) != 0)
    exit(1);
  if (birch_fetch_message(sock, &handle) == -1)
    exit(1);
  handler_fini(&h);
  exit(0);
}
