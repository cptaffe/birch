/* Copyright 2016 Connor Taffe */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
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

struct error {
  enum {
    ERROR_NONE,
    ERROR_ERRNO,
    ERROR_GETADDRINFO,
    ERROR_BIRCH,
    ERROR_STRING
  } tag;
  union {
    int eno;
    const char *str;
    struct birch_error berr;
  } v;
};

struct maybe_int {
  enum { MAYBE_INT_OK, MAYBE_INT_ERR } tag;
  union {
    struct error e;
    int i;
  } v;
};

struct maybe_string {
  enum { MAYBE_STRING_OK, MAYBE_STRING_ERR } tag;
  union {
    struct error e;
    char *str;
  } v;
};

static struct error handler_init(struct handler *handler);
static void handler_fini(struct handler *handler);

static struct error irc_handshake(int sock);

static struct maybe_int fortune(void);
static struct maybe_string path(char *name);
static struct maybe_int socket_for_host(const char *host, const char *port);
static struct error make_error_birch(struct birch_error b);
static struct error make_error_string(const char *str);
static struct error make_error_getaddrinfo(int err);
static struct error make_error_errno(void);
static struct error make_error_ok(void);
static struct maybe_string make_maybe_string_ok(char *str);
static struct maybe_string make_maybe_string_err(struct error e);
static struct maybe_int make_maybe_int_ok(int i);
static struct maybe_int make_maybe_int_err(struct error e);
static const char *error_string(struct error e);
static void print_addrinfo(struct addrinfo *rp);

const char *error_string(struct error e) {
  switch (e.tag) {
  case ERROR_NONE:
    return "No error";
  case ERROR_ERRNO:
    return strerror(e.v.eno);
  case ERROR_GETADDRINFO:
    return gai_strerror(e.v.eno);
  case ERROR_BIRCH:
    return birch_error_string(e.v.berr);
  case ERROR_STRING:
    return e.v.str;
  }
}

struct error make_error_birch(struct birch_error b) {
  struct error e;

  e.tag = ERROR_BIRCH;
  e.v.berr = b;

  return e;
}

struct error make_error_errno(void) {
  struct error e;

  e.tag = ERROR_ERRNO;
  e.v.eno = errno;

  return e;
}

struct error make_error_getaddrinfo(int err) {
  struct error e;

  e.tag = ERROR_GETADDRINFO;
  e.v.eno = err;

  return e;
}

struct error make_error_string(const char *str) {
  struct error e;

  e.tag = ERROR_STRING;
  e.v.str = str;

  return e;
}

struct error make_error_ok(void) {
  struct error e;

  memset(&e, 0, sizeof(e));

  return e;
}

struct maybe_string make_maybe_string_ok(char *str) {
  struct maybe_string ms;

  assert(str);

  ms.tag = MAYBE_STRING_OK;
  ms.v.str = str;

  return ms;
}

struct maybe_string make_maybe_string_err(struct error e) {
  struct maybe_string ms;

  ms.tag = MAYBE_STRING_ERR;
  ms.v.e = e;

  return ms;
}

struct maybe_int make_maybe_int_ok(int i) {
  struct maybe_int mi;

  mi.tag = MAYBE_INT_OK;
  mi.v.i = i;

  return mi;
}

struct maybe_int make_maybe_int_err(struct error e) {
  struct maybe_int mi;

  mi.tag = MAYBE_INT_ERR;
  mi.v.e = e;

  return mi;
}

struct maybe_string path(char *name) {
  size_t i, last;
  char *path;

  assert(name);

  if (!(path = getenv("PATH")))
    return make_maybe_string_err(
        make_error_string("no PATH environment variable"));

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
      if (stat(buf, &info) == -1) {
        free(buf);
        continue;
      }

      /* a directory, or executable bit not set */
      if (S_ISDIR(info.st_mode) || (info.st_mode & 0111) == 0) {
        free(buf);
        return make_maybe_string_err(
            make_error_string("`fortune` in PATH is not an executable"));
      }

      return make_maybe_string_ok(buf);
    }
  }
  return make_maybe_string_err(make_error_string("could not fine `fortune`"));
}

/* route stdout from `fortune` to the returned pipe out */
struct maybe_int fortune() {
  struct maybe_string ms;
  pid_t child;
  int fd[2];

  if (pipe(fd) == -1)
    return make_maybe_int_err(make_error_errno());

  child = fork();
  if (child == -1)
    return make_maybe_int_err(make_error_errno());
  if (child == 0) {
    char *argv[] = {0, "-sn", "140", 0};

    if ((ms = path("fortune")).tag)
      return make_maybe_int_err(ms.v.e);
    argv[0] = ms.v.str;

    if (close(fd[0]) == -1)
      goto error;

    /* set stdout to out */
    if (close(1) == -1)
      return make_maybe_int_err(make_error_errno());
    if (dup(fd[1]) == -1)
      return make_maybe_int_err(make_error_errno());

    execve(argv[0], argv, 0);

  error:
    free(argv[0]);
    exit(1);
  }
  if (close(fd[1]) == -1)
    return make_maybe_int_err(make_error_errno());
  return make_maybe_int_ok(fd[0]);
}

struct error handler_init(struct handler *handler) {
  char *buf;
  size_t sz;
  struct error e;

  assert(handler->channel);

  sz = strlen(handler->channel) + 128;
  buf = calloc(sizeof(char), sz);
  snprintf(buf, sz - 1, "^%s[ :]*f!$", handler->channel);
  if (regcomp(&handler->future, buf, 0) != 0) {
    e = make_error_string("regcomp: failed");
    goto cleanup;
  }
  e = make_error_ok();
cleanup:
  free(buf);
  return e;
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

    switch (msg.type) {
    case BIRCH_MSG_PING:
      /* automatically reply to pings */

      assert(msg.nparams == 1);
      assert(birch_message_pong(&rmsg, "*", msg.params[0]) != -1);
      assert(!birch_message_format(&rmsg, h->sock).tag);
      break;
    case BIRCH_MSG_PRIVMSG:
      /* fork/exec and pipe fortune output */
      if (msg.nparams == 1 &&
          regexec(&h->future, msg.params[0], 0, 0, 0) == 0) {
        struct maybe_int mi;
        char *buf, *ptr[2];
        size_t sz, i, last;
        int fd;

        i = 0;
        sz = 0;
        buf = 0;
        mi = fortune();

        assert(!mi.tag);

        fd = mi.v.i;

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

              assert(!birch_message_format(&rmsg, h->sock).tag);
            }
            last = i + 1;
          }
        }
      }
      break;
    default:
      abort();
    }
    assert(!birch_message_format(&msg, 1).tag);
  }
}

struct error irc_handshake(int sock) {
  struct birch_error berr;
  struct birch_message msg;
  enum { STAGE_PASS, STAGE_NICK, STAGE_USER, STAGE_JOIN, STAGE_max } i;

  /* handshake state machine */
  for (i = 0; i < STAGE_max; i++) {
    memset(&msg, 0, sizeof(msg));
    switch (i) {
    case STAGE_PASS:
      if ((berr = birch_message_pass_random(&msg)).tag)
        return make_error_birch(berr);
      break;
    case STAGE_NICK:
      if ((berr = birch_message_nick(&msg, "ualr-acm-bot")).tag)
        return make_error_birch(berr);
      break;
    case STAGE_USER:
      if ((berr = birch_message_user(&msg, "test__", "UALR ACM IRC Bot")).tag)
        return make_error_birch(berr);
      break;
    case STAGE_JOIN:
      if (birch_message_join(&msg, "#ualr-acm") == -1)
        return make_error_string("birch_message_join: failed");
      break;
    case STAGE_max:
      __builtin_unreachable();
    }
    if ((berr = birch_message_format(&msg, sock)).tag)
      return make_error_birch(berr);
  }

  return make_error_ok();
}

void print_addrinfo(struct addrinfo *rp) {
  in_port_t iport;
  char hbuf[NI_MAXHOST];
  const char *iaddr;
  char iaddr4[INET_ADDRSTRLEN];
  char iaddr6[INET6_ADDRSTRLEN];
  struct sockaddr_in *sa4;
  struct sockaddr_in6 *sa6;

  iport = 0;

  assert(rp != 0);

  if (!getnameinfo(rp->ai_addr, rp->ai_addrlen, hbuf, sizeof(hbuf), 0, 0,
                   NI_NAMEREQD)) {
    switch (rp->ai_addr->sa_family) {
    case AF_INET:
      sa4 = (struct sockaddr_in *)rp->ai_addr;
      iaddr = inet_ntop(AF_INET, &sa4->sin_addr, iaddr4, sizeof(iaddr4));
      iport = ntohs(sa4->sin_port);
      break;
    case AF_INET6:
      sa6 = (struct sockaddr_in6 *)rp->ai_addr;
      iaddr = inet_ntop(AF_INET6, &sa6->sin6_addr, iaddr6, sizeof(iaddr6));
      iport = ntohs(sa6->sin6_port);
      break;
    }
    printf("Trying %s(%s):%d\n", hbuf, iaddr, iport);
  }
}

struct maybe_int socket_for_host(const char *host, const char *port) {
  int sock, herr;
  struct addrinfo hints, *results, *rp;

  assert(host != 0);
  assert(port != 0);

  memset(&hints, 0, sizeof(struct addrinfo));

  /* ips from dns name */
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = 0;
  hints.ai_protocol = 0;
  herr = getaddrinfo(host, port, &hints, &results);
  if (herr) {
    return make_maybe_int_err(make_error_getaddrinfo(herr));
  }
  for (rp = results; rp; rp = rp->ai_next) {
    print_addrinfo(rp);
    sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (sock == -1)
      continue;
    if (!connect(sock, rp->ai_addr, rp->ai_addrlen))
      break;
    fprintf(stderr, "couldn't connect: %s\n", strerror(errno));
    close(sock);
  }
  freeaddrinfo(results);
  if (!rp)
    return make_maybe_int_err(
        make_error_string("could not connect to any addresses"));
  return make_maybe_int_ok(sock);
}

int main(int argc __attribute__((unused)),
         char **argv __attribute__((unused))) {
  struct birch_message_handler handle;
  struct maybe_int mi;
  struct error err;
  struct handler h;

  memset(&handle, 0, sizeof(handle));
  memset(&h, 0, sizeof(h));
  memset(&err, 0, sizeof(struct error));

  mi = socket_for_host("chat.freenode.net", "6667");
  if (mi.tag) {
    printf("%s\n", error_string(mi.v.e));
    exit(1);
  }

  h.sock = mi.v.i;
  h.channel = "#ualr-acm";
  if ((err = handler_init(&h)).tag)
    goto cleanup;
  handle.obj = &h;
  handle.func = handler;

  if ((err = irc_handshake(h.sock)).tag)
    goto cleanup;
  if (birch_fetch_message(h.sock, &handle) == -1) {
    err.tag = ERROR_STRING;
    err.v.str = "birch_fetch_message: failed";
    goto cleanup;
  }
cleanup:
  handler_fini(&h);
  if (err.tag) {
    printf("%s\n", error_string(err));
    exit(1);
  }
  exit(0);
}
