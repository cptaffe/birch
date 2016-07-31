/* Copyright 2016 Connor Taffe */

#include <assert.h>
#include <netinet/in.h>
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

static void handler(void *o, struct birch_token_list *list) {
  struct birch_message msg;
  int sock;

  assert(o != 0);

  sock = *(int *)o;

  if (!list)
    return; /* empty list */

  memset(&msg, 0, sizeof(msg));

  /* ignore commands that cannot yet be parsed */
  if (birch_token_list_message(list, &msg) == 0) {
    /* automatically reply to pings */
    if (msg.type == BIRCH_MSG_PING) {
      struct birch_message rmsg;

      assert(msg.nparams == 1);
      assert(birch_message_pong(&rmsg, "*", msg.params[0]) != -1);
      assert(birch_message_format(&rmsg, sock) != -1);
    }

    assert(birch_message_format(&msg, STDOUT_FILENO) != -1);
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
  if (birch_message_nick(&msg, "test__") == -1)
    return -1;
  birch_message_format(&msg, sock);

  memset(&msg, 0, sizeof(msg));
  if (birch_message_user(&msg, "test__", "test__") == -1)
    return -1;
  birch_message_format(&msg, sock);

  return 0;
}

int main(int argc __attribute__((unused)),
         char **argv __attribute__((unused))) {
  struct birch_message_handler handle;
  int sock;
  struct sockaddr_in addr;

  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock == -1)
    exit(1);

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET, addr.sin_port = htons(6667);
  addr.sin_addr.s_addr = htonl((uint32_t)54 << 24 | (uint32_t)85 << 16 |
                               (uint32_t)60 << 8 | (uint32_t)193);
  if (connect(sock, &addr, sizeof(addr)) == -1)
    exit(1);

  memset(&handle, 0, sizeof(handle));
  handle.obj = &sock;
  handle.func = handler;

  if (test_client(sock) != 0)
    exit(1);
  if (birch_fetch_message(sock, &handle) == -1)
    exit(1);
  exit(0);
}
