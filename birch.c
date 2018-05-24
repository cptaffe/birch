/* Copyright 2016 Connor Taffe */

/* Birch IRC library */

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "birch.h"

char *birch_msg_map[BIRCH_MSG_max];
__attribute__((constructor)) static void birch_msg_map_fill(void);

void birch_msg_map_fill() {
  memset(birch_msg_map, 0, sizeof(birch_msg_map));
  birch_msg_map[BIRCH_MSG_PASS] = "pass";
  birch_msg_map[BIRCH_MSG_NICK] = "nick";
  birch_msg_map[BIRCH_MSG_USER] = "user";
  birch_msg_map[BIRCH_MSG_OPER] = "oper";
  birch_msg_map[BIRCH_MSG_MODE] = "mode";
  birch_msg_map[BIRCH_MSG_SERVICE] = "service";
  birch_msg_map[BIRCH_MSG_QUIT] = "quit";
  birch_msg_map[BIRCH_MSG_SQUIT] = "squit";
  birch_msg_map[BIRCH_MSG_JOIN] = "join";
  birch_msg_map[BIRCH_MSG_PART] = "part";
  birch_msg_map[BIRCH_MSG_TOPIC] = "topic";
  birch_msg_map[BIRCH_MSG_NAMES] = "names";
  birch_msg_map[BIRCH_MSG_LIST] = "list";
  birch_msg_map[BIRCH_MSG_INVITE] = "invite";
  birch_msg_map[BIRCH_MSG_KICK] = "kick";
  birch_msg_map[BIRCH_MSG_PRIVMSG] = "privmsg";
  birch_msg_map[BIRCH_MSG_NOTICE] = "notice";
  birch_msg_map[BIRCH_MSG_MOTD] = "motd";
  birch_msg_map[BIRCH_MSG_LUSERS] = "lusers";
  birch_msg_map[BIRCH_MSG_VERSION] = "version";
  birch_msg_map[BIRCH_MSG_STATS] = "stats";
  birch_msg_map[BIRCH_MSG_LINKS] = "links";
  birch_msg_map[BIRCH_MSG_TIME] = "time";
  birch_msg_map[BIRCH_MSG_CONNECT] = "connect";
  birch_msg_map[BIRCH_MSG_TRACE] = "trace";
  birch_msg_map[BIRCH_MSG_ADMIN] = "admin";
  birch_msg_map[BIRCH_MSG_INFO] = "info";
  birch_msg_map[BIRCH_MSG_SERVLIST] = "servlist";
  birch_msg_map[BIRCH_MSG_SQUERY] = "squery";
  birch_msg_map[BIRCH_MSG_WHO] = "who";
  birch_msg_map[BIRCH_MSG_WHOIS] = "whois";
  birch_msg_map[BIRCH_MSG_WHOWAS] = "whowas";
  birch_msg_map[BIRCH_MSG_KILL] = "kill";
  birch_msg_map[BIRCH_MSG_PING] = "ping";
  birch_msg_map[BIRCH_MSG_PONG] = "pong";
  birch_msg_map[BIRCH_MSG_ERROR] = "error";
  birch_msg_map[BIRCH_MSG_AWAY] = "away";
  birch_msg_map[BIRCH_MSG_REHASH] = "rehash";
  birch_msg_map[BIRCH_MSG_DIE] = "die";
  birch_msg_map[BIRCH_MSG_RESTART] = "restart";
  birch_msg_map[BIRCH_MSG_SUMMON] = "summon";
  birch_msg_map[BIRCH_MSG_USERS] = "users";
  birch_msg_map[BIRCH_MSG_WALLOPS] = "wallops";
  birch_msg_map[BIRCH_MSG_USERHOST] = "userhost";
  birch_msg_map[BIRCH_MSG_ISON] = "ison";
}

static struct birch_error birch_make_error_string(const char *str);
static struct birch_error birch_make_error_errno(void);
static struct birch_error birch_make_error_ok(void);

const char *birch_error_string(struct birch_error e) {
  switch (e.tag) {
  case BIRCH_ERROR_NONE:
    return "No error";
  case BIRCH_ERROR_ERRNO:
    return strerror(e.v.eno);
  case BIRCH_ERROR_STRING:
    return e.v.str;
  }
}

struct birch_error birch_make_error_string(const char *str) {
  struct birch_error e;
  assert(str);

  e.tag = BIRCH_ERROR_STRING;
  e.v.str = str;

  return e;
}

struct birch_error birch_make_error_errno(void) {
  struct birch_error e;

  e.tag = BIRCH_ERROR_ERRNO;
  e.v.eno = errno;

  return e;
}

struct birch_error birch_make_error_ok(void) {
  struct birch_error e;

  memset(&e, 0, sizeof(e));

  return e;
}

struct birch_error birch_message_format(struct birch_message *m, int sock) {
  struct birch_error err;
  char *buf;
  size_t sz;

  memset(&err, 0, sizeof(err));
  buf = 0;

  if ((err = birch_message_format_simple(m, &buf, &sz)).tag)
    goto error;

  if (write(sock, buf, sz) != (ssize_t)sz) {
    err = birch_make_error_errno();
    goto error;
  }
error:
  free(buf);
  return err;
}

struct birch_error birch_message_format_simple(struct birch_message *m,
                                               char **out, size_t *sz) {
  /* message type string, params, last parameter is long-form */
  char *cmd;
  size_t i, len;
  int ncolon;

  assert(m != 0);
  assert(out != 0);
  assert(sz != 0);

  ncolon = 0;
  if (m->nparams > 14)
    return birch_make_error_string("cannot have more than 14 params");

  *sz = 3; /* colon, \r\n, sans trailing space */
  *sz += strlen(birch_msg_map[m->type]);
  for (i = 0; i < m->nparams; i++) {
    *sz += strlen(m->params[i]) + 1; /* space */
  }

  *out = calloc(sizeof(char), *sz);
  if (*out == 0)
    return birch_make_error_errno();
  len = 0; /* use as index of msg */

  /* write prefix? */

  /* write message command */
  cmd = birch_msg_map[m->type];
  if (cmd != 0) {
    size_t n = strlen(cmd);
    memcpy(&(*out)[len], cmd, n);
    len += n;
  }

  /* write params */
  for (i = 0; i < m->nparams; i++) {
    size_t j, n;
    bool contains_space = false;

    /* check for unnacceptable characters */
    for (j = 0; m->params[i][j]; j++)
      if (m->params[i][j] == '\n' || m->params[i][j] == '\r' ||
          ((contains_space |= m->params[i][j] == ' ') && i != (m->nparams - 1)))
        return birch_make_error_string("unacceptable character in params");

    /* prefix with space */
    (*out)[len++] = ' ';
    /* use trailing if the last paramter contains spaces */
    if (i == (m->nparams - 1) && contains_space) {
      ncolon++;
      (*out)[len++] = ':';
    }
    /* write parameter */
    n = strlen(m->params[i]);
    memcpy(&(*out)[len], m->params[i], n);
    len += n;
  }
  memcpy(&(*out)[len], "\r\n", 2);

  if (ncolon == 0)
    *sz = *sz - 1;

  return birch_make_error_ok();
}

bool birch_character_is_letter(char c) {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

bool birch_character_is_digit(char c) { return c >= '1' && c <= '9'; }

/* places the next byte in c, returns -1 if no more characters
   are lexable */
int birch_lex_next(struct birch_lex *l, char *c) {
  char fmt[10]; /* SSIZE_MAX is 32,767 (max width 5) + 5 other characters */
  size_t z;
  ssize_t ret;

  assert(l != 0);

  /* increase buffer size as needed */
  if (l->sz == l->cap) {
    l->cap = 2 * l->cap + 1;
    l->message = realloc(l->message, l->cap);
    assert(l->message != 0);
  }

  if (l->i == l->sz) {
    if (l->sock == -1)
      return -1;
    ret = read(l->sock, &l->message[l->sz], l->cap - l->sz);
    if (ret == -1)
      err(1, "birch_lex_next: read() failed");
    if (!ret)
      return -1;
    /* diagnotics: print read text */
    snprintf(fmt, sizeof(fmt), "%%.%lds\n", ret);
    /* disable errors for format nonliteral */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
    printf(fmt, &l->message[l->sz]);
#pragma GCC diagnostic pop
    l->sz += (size_t)ret;
  }

  if (l->i < l->sz) {
    if (c != 0)
      *c = l->message[l->i];
    l->i++;
    if (l->message[l->i] == '\n') {
      l->line++;
      l->col = 0;
    } else
      l->col++;
    return 0;
  }
  return -1;
}

void birch_lex_back(struct birch_lex *l) {
  assert(l != 0);

  if (l->i > l->l)
    l->i--;
  if (!l->col)
    l->line--;
  else
    l->col--;
}

void birch_lex_emit(struct birch_lex *l, struct birch_token tok) {
  struct birch_token_list *link;

  assert(l != 0);

  link = calloc(sizeof(struct birch_token_list), 1);
  assert(link != 0);
  link->tok = tok;
  if (l->list)
    l->list->next = link;
  l->list = link;
  if (!l->head)
    l->head = link;
}

/* gets & resets buffer */
void birch_lex_tok(struct birch_lex *l, struct birch_token *t) {
  assert(l != 0);

  if (l->i == l->l)
    return;

  t->sz = l->i - l->l;
  t->buf = calloc(sizeof(char), t->sz);
  t->line = l->lline;
  t->col = l->lcol;
  assert(t->buf != 0);
  memcpy(t->buf, &l->message[l->l], t->sz);
  l->l = l->i; /* reset buffer */
  l->lline = l->line;
  l->lcol = l->col;
}

/* respect IRC's scandanavian case handling */
void birch_to_lower(char *out, const char *buf, size_t sz) {
  char *map = "\x0\x1\x2\x3\x4\x5\x6\x7\x8\x9\xa\xb\xc\xd\xe\xf\x10\x11\x12"
              "\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20!\"#$%&"
              "'()*+,-./"
              "0123456789:;<=>?@abcdefghijklmnopqrstuvwzyz{|}^_`"
              "abcdefghijklmnopqrstuvwzyz{|}~\x7f";
  size_t i;

  assert(buf != 0);
  assert(out != 0);

  for (i = 0; i < sz; i++)
    out[i] = map[buf[i] & 0x7f];
}

int birch_lex_message_state_prefix(struct birch_lex *l, void *v) {
  birch_lex_func **func;
  char c;

  assert(l != 0);
  assert(v != 0);

  func = (birch_lex_func **)v;

  printf("%s\n", __func__);

  /* lex up to a space */
  while (birch_lex_next(l, &c) != -1) {
    if (c == ' ') {
      struct birch_token tok;

      birch_lex_back(l);

      /* emit prefix token */
      tok.type = BIRCH_TOK_PREFIX;
      birch_lex_tok(l, &tok);
      birch_lex_emit(l, tok);

      /* emit space token */
      birch_lex_next(l, 0);
      tok.type = BIRCH_TOK_SPACE;
      birch_lex_tok(l, &tok);
      birch_lex_emit(l, tok);

      *func = birch_lex_message_state_command;
      return 0;
    }
  }

  return -1;
}

int birch_lex_message_state_eol(struct birch_lex *l, void *v) {
  birch_lex_func **func;
  char c;

  assert(l != 0);
  assert(v != 0);

  func = (birch_lex_func **)v;

  printf("%s\n", __func__);

  if (birch_lex_next(l, &c) == -1)
    return -1;

  if (c != '\r') {
    /* error */
    char *buf = "Error, expected CR";
    struct birch_token tok;

    tok.type = BIRCH_TOK_ERR;
    tok.buf = buf;
    tok.sz = sizeof(buf);
    birch_lex_emit(l, tok);

    *func = 0;
    return 0;
  }

  if (birch_lex_next(l, &c) == -1)
    return -1;

  if (c == '\n') {
    /* emit token */
    struct birch_token tok;

    tok.type = BIRCH_TOK_EOL;
    birch_lex_tok(l, &tok);
    birch_lex_emit(l, tok);

    *func = 0;
    return 0;
  } else {
    /* error */
    char *buf = "Error, expected LF";
    struct birch_token tok;

    tok.type = BIRCH_TOK_ERR;
    tok.buf = buf;
    tok.sz = sizeof(buf);
    birch_lex_emit(l, tok);

    *func = 0;
    return 0;
  }
}

int birch_lex_message_state_params_trailing(struct birch_lex *l, void *v) {
  birch_lex_func **func;
  char c;

  assert(l != 0);
  assert(v != 0);

  func = (birch_lex_func **)v;

  printf("%s\n", __func__);

  while (birch_lex_next(l, &c) != -1)
    if (c == '\r') {
      /* emit token */
      struct birch_token tok;

      tok.type = BIRCH_TOK_PARAMS;
      birch_lex_back(l);
      birch_lex_tok(l, &tok);
      birch_lex_emit(l, tok);

      *func = birch_lex_message_state_eol;
      return 0;
    } else if (c == '\0' || c == '\n') {
      /* error */
      struct birch_token tok;
      char *buf = "Error, 0 and newline not permitted in params trailing";

      tok.type = BIRCH_TOK_ERR;
      tok.buf = buf;
      tok.sz = sizeof(buf);
      birch_lex_emit(l, tok);

      *func = 0;
      return 0;
    }
  return -1;
}

int birch_lex_message_state_params_middle(struct birch_lex *l, void *v) {
  birch_lex_func **func;
  int i;
  char c;

  assert(l != 0);
  assert(v != 0);

  func = (birch_lex_func **)v;

  for (i = 0; birch_lex_next(l, &c) != -1; i++) {
    if (c == ' ') {
      struct birch_token tok;

      if (i == 0) {
        /* error */
        char *buf = "Error, params middle must be nonempty";

        tok.type = BIRCH_TOK_ERR;
        tok.buf = buf;
        tok.sz = sizeof(buf);
        birch_lex_emit(l, tok);

        *func = 0;
        return 0;
      }

      birch_lex_back(l);

      /* emit token */
      tok.type = BIRCH_TOK_PARAMS;
      birch_lex_tok(l, &tok);
      birch_lex_emit(l, tok);

      /* emit token */
      birch_lex_next(l, 0);
      tok.type = BIRCH_TOK_SPACE;
      birch_lex_tok(l, &tok);
      birch_lex_emit(l, tok);

      l->msg_state.params++; /* count params */

      *func = birch_lex_message_state_params;
      return 0;
    } else if (c == '\0' || c == '\r' || c == '\n') {
      /* error */
      char *buf = "Error, params middle cannot contain 0, CR or LF";
      struct birch_token tok;

      tok.type = BIRCH_TOK_ERR;
      tok.buf = buf;
      tok.sz = sizeof(buf);
      birch_lex_emit(l, tok);

      *func = 0;
      return 0;
    }
  }
  return -1;
}

int birch_lex_message_state_params(struct birch_lex *l, void *v) {
  birch_lex_func **func;
  char c;

  assert(l != 0);
  assert(v != 0);

  func = (birch_lex_func **)v;

  /* lex params */
  if (birch_lex_next(l, &c) == -1)
    return -1;

  if (c == ':') {
    /* emit token */
    struct birch_token tok;

    tok.type = BIRCH_TOK_COLON;
    birch_lex_tok(l, &tok);
    birch_lex_emit(l, tok);

    *func = birch_lex_message_state_params_trailing;
  } else if (l->msg_state.params == 14) {
    /*  */
    *func = birch_lex_message_state_params_trailing;
  } else {
    birch_lex_back(l);
    *func = birch_lex_message_state_params_middle;
  }
  return 0;
}

/* lex string */
int birch_lex_message_state_command_string(struct birch_lex *l, void *v) {
  birch_lex_func **func;
  char c;

  assert(l != 0);
  assert(v != 0);

  func = (birch_lex_func **)v;

  /* lex letters */
  while (birch_lex_next(l, &c) != -1) {
    if (c == ' ') {
      /* emit token */
      struct birch_token tok;

      birch_lex_back(l);

      tok.type = BIRCH_TOK_COMMAND;
      birch_lex_tok(l, &tok);
      birch_lex_emit(l, tok);

      birch_lex_next(l, 0);

      tok.type = BIRCH_TOK_SPACE;
      birch_lex_tok(l, &tok);
      birch_lex_emit(l, tok);

      *func = birch_lex_message_state_params;
      return 0;
    } else if (!birch_character_is_letter(c)) {
      /* error */
      struct birch_token tok;
      char *buf = "Unexpected non-letter in command";

      tok.type = BIRCH_TOK_ERR;
      tok.buf = buf;
      tok.sz = sizeof(buf);
      birch_lex_emit(l, tok);

      *func = 0;
      return 0;
    }
  }
  return -1;
}

/* lex two remaining digits */
int birch_lex_message_state_command_code(struct birch_lex *l, void *v) {
  birch_lex_func **func;
  int i;
  char c;

  assert(l != 0);
  assert(v != 0);

  func = (birch_lex_func **)v;

  for (i = 0; birch_lex_next(l, &c) != -1; i++) {
    if (c == ' ') {
      /* emit token */
      struct birch_token tok;

      if (i != 2) {
        /* error */
        char *buf = "Error, expected 3-digit code, wrong length";

        tok.type = BIRCH_TOK_ERR;
        tok.buf = buf;
        tok.sz = sizeof(buf);
        birch_lex_emit(l, tok);

        *func = 0;
        return 0;
      }

      birch_lex_back(l);

      tok.type = BIRCH_TOK_COMMAND;
      birch_lex_tok(l, &tok);
      birch_lex_emit(l, tok);

      birch_lex_next(l, 0);

      tok.type = BIRCH_TOK_SPACE;
      birch_lex_tok(l, &tok);
      birch_lex_emit(l, tok);

      *func = birch_lex_message_state_params;
      return 0;
    } else if (!birch_character_is_digit(c)) {
      /* error */
      char *buf = "Error, non-digit in numeric command";
      struct birch_token tok;

      tok.type = BIRCH_TOK_ERR;
      tok.buf = buf;
      tok.sz = sizeof(buf);
      birch_lex_emit(l, tok);

      *func = 0;
      return 0;
    }
  }
  return -1;
}

int birch_lex_message_state_command(struct birch_lex *l, void *v) {
  birch_lex_func **func;
  char c;

  assert(l != 0);
  assert(v != 0);

  func = (birch_lex_func **)v;

  printf("%s\n", __func__);

  if (birch_lex_next(l, &c) == -1)
    return -1;
  if (birch_character_is_digit(c)) {
    *func = birch_lex_message_state_command_code;
  } else if (birch_character_is_letter(c)) {
    *func = birch_lex_message_state_command_string;
  } else {
    /* error */
    char *buf = "Unexpected character, expected command.";
    struct birch_token tok;

    tok.type = BIRCH_TOK_ERR;
    tok.buf = buf;
    tok.sz = sizeof(buf);
    birch_lex_emit(l, tok);

    *func = 0;
  }
  return 0;
}

int birch_lex_message_state_start(struct birch_lex *l, void *v) {
  birch_lex_func **func;
  char c;

  assert(l != 0);
  assert(v != 0);

  func = (birch_lex_func **)v;

  printf("%s\n", __func__);

  if (birch_lex_next(l, &c) == -1)
    return -1;
  if (c == ':') {
    /* prefix */
    struct birch_token tok;

    tok.type = BIRCH_TOK_COLON;
    birch_lex_tok(l, &tok);
    birch_lex_emit(l, tok);

    *func = birch_lex_message_state_prefix;
    return 0;
  } else {
    birch_lex_back(l);
    *func = birch_lex_message_state_command;
    return 0;
  }
}

/* lex message separator */
int birch_lex_stream_state_cr(struct birch_lex *l, void *v) {
  birch_lex_func **func;
  char c;

  assert(l != 0);
  assert(v != 0);

  func = (birch_lex_func **)v;

  if (birch_lex_next(l, &c) == -1)
    return -1;
  if (c == '\n') {
    struct birch_token tok;

    /* emit token */
    tok.type = BIRCH_TOK_MSG;
    birch_lex_tok(l, &tok);
    birch_lex_emit(l, tok);
  }

  /* regardless, go back to this state */
  *func = birch_lex_stream_state_start;
  return 0;
}

/* lex message stream looking for separator */
int birch_lex_stream_state_start(struct birch_lex *l, void *v) {
  birch_lex_func **func;
  char c;

  assert(l != 0);
  assert(v != 0);

  func = (birch_lex_func **)v;
  while (birch_lex_next(l, &c) != -1) {
    if (c == '\r') {
      *func = birch_lex_stream_state_cr;
      return 0;
    }
  }
  return -1;
}

int birch_fetch_message_pass(struct birch_lex *l, birch_lex_func *func) {
  assert(l != 0);
  assert(func != 0);

  printf("%s\n", __func__);

  /* lex stream into messages */
  while (func != 0) {
    if (func(l, &func) == -1) {
      return -1;
    }
  }
  return 0;
}

int birch_fetch_message(int sock, struct birch_message_handler *handler) {
  struct birch_lex l;
  birch_lex_func *func;
  int ret;

  assert(handler != 0);

  memset(&l, 0, sizeof(l));
  l.sock = sock;

  ret = 0;
  while (ret == 0) {
    l.list = 0;
    func = birch_lex_message_state_start;
    ret = birch_fetch_message_pass(&l, func);
    handler->func(handler->obj, l.list);
    free(l.list);
  }
  free(l.message);
  return 0;
}

int birch_fetch_message_buf(char *buf, size_t sz,
                            struct birch_message_handler *handler) {
  struct birch_lex l;
  struct birch_token_list *list, *next;
  birch_lex_func *func;
  int ret;

  assert(buf != 0);
  assert(handler != 0);

  memset(&l, 0, sizeof(l));
  l.sock = -1; /* error on reads from socket */
  l.message = buf;
  l.sz = l.cap = sz;

  ret = 0;
  while (ret == 0) {
    l.list = 0;
    func = birch_lex_message_state_start;
    ret = birch_fetch_message_pass(&l, func);
    handler->func(handler->obj, l.list);
    for (list = l.list; list;) {
      next = list->next;
      free(list);
      list = next;
    }
  }
  return 0;
}

int birch_token_list_message(struct birch_token_list *list,
                             struct birch_message *msg) {
  size_t i;

  assert(list != 0); /* empty list */
  assert(msg != 0);

  msg->type = BIRCH_MSG_max;

  /* form message */
  for (i = 0; list != 0; list = list->next, i++) {
    char *buf;
    size_t j;

    assert(list->tok.buf != 0);
    assert(list->tok.type < BIRCH_TOK_max && list->tok.type >= 0);

    switch (list->tok.type) {
    case BIRCH_TOK_PARAMS:
      buf = calloc(sizeof(char), list->tok.sz + 1);
      if (!buf)
        err(1, "birch_token_list_message: calloc() failed");
      memcpy(buf, list->tok.buf, list->tok.sz);
      msg->params = realloc(msg->params, (++msg->nparams) * sizeof(char *));
      if (!msg->params)
        err(1, "birch_token_list_message: realloc() failed");
      /* reverse the order of parameters */
      memmove(&msg->params[1], msg->params,
              (msg->nparams - 1) * sizeof(char *));
      msg->params[0] = buf;
      break;
    case BIRCH_TOK_COMMAND:
      /* TODO: check for numeric commands (reply) */
      for (j = 0; j < BIRCH_MSG_max; j++) {
        /*
        lower case for comparing,
        NOTE: this mutates tok.buf *forever*
        */
        birch_to_lower(list->tok.buf, list->tok.buf, list->tok.sz);
        if (strncmp(birch_msg_map[j], list->tok.buf, list->tok.sz) == 0)
          msg->type = (enum birch_message_type)j;
      }
      break;
    case BIRCH_TOK_COLON:
    case BIRCH_TOK_EOL:
    case BIRCH_TOK_ERR:
    case BIRCH_TOK_MSG:
    case BIRCH_TOK_NONE:
    case BIRCH_TOK_PREFIX:
    case BIRCH_TOK_SPACE:
      /* ignore */
      break;
    case BIRCH_TOK_max:
      /* shouldn't happen */
      assert(false);
    }
  }

  /* require command for all messages */
  if (msg->type == BIRCH_MSG_max)
    return -1;

  return 0;
}

/* generate random pass */
struct birch_error birch_message_pass_random(struct birch_message *msg) {
  uint64_t buf;
  size_t sz;

  assert(msg != 0);

  sz = sizeof(buf) * 3 + 1;

  msg->type = BIRCH_MSG_PASS;
  arc4random_buf(&buf, sizeof(buf));
  msg->params = calloc(sizeof(char *), 1);
  if (msg->params == 0)
    return birch_make_error_errno();
  msg->params[0] = calloc(sizeof(char), sz);
  if (msg->params[0] == 0)
    return birch_make_error_errno();
  msg->nparams++;
  if (sprintf(msg->params[0], "%" PRIu64, buf) > (int)(sz - 1)) {
    return birch_make_error_string("sprintf: string too large");
  }

  return birch_make_error_ok();
}

struct birch_error birch_message_nick(struct birch_message *msg, char *nick) {
  assert(msg != 0);
  assert(nick != 0);

  msg->type = BIRCH_MSG_NICK;
  msg->params = calloc(sizeof(char *), 1);
  if (msg->params == 0)
    return birch_make_error_errno();
  msg->params[0] = calloc(sizeof(char), strlen(nick) + 1);
  if (msg->params[0] == 0)
    return birch_make_error_errno();
  msg->nparams++;
  memcpy(msg->params[0], nick, strlen(nick));

  return birch_make_error_ok();
}

struct birch_error birch_message_user(struct birch_message *msg, char *username,
                                      char *name) {
  size_t i;

  assert(msg != 0);
  assert(name != 0);
  assert(username != 0);

  msg->type = BIRCH_MSG_USER;
  msg->params = calloc(sizeof(char *), 4);
  if (msg->params == 0)
    return birch_make_error_errno();

  msg->nparams = 0;

  /* username */
  msg->params[msg->nparams] = calloc(sizeof(char), strlen(username) + 1);
  if (msg->params[msg->nparams] == 0)
    return birch_make_error_errno();
  memcpy(msg->params[msg->nparams], username, strlen(username));
  msg->nparams++;

  /* ignored */
  for (i = 0; i < 2; i++) {
    msg->params[msg->nparams] = calloc(sizeof(char), strlen(username));
    if (msg->params[msg->nparams] == 0)
      return birch_make_error_errno();
    memcpy(msg->params[msg->nparams], "*", 1);
    msg->nparams++;
  }

  /* real name parameter */
  msg->params[msg->nparams] = calloc(sizeof(char), strlen(name) + 1);
  if (msg->params[msg->nparams] == 0)
    return birch_make_error_errno();
  memcpy(msg->params[msg->nparams], name, strlen(name));
  msg->nparams++;

  return birch_make_error_ok();
}

int birch_message_pong(struct birch_message *msg, char *from, char *to) {
  assert(from != 0);

  msg->type = BIRCH_MSG_PONG;
  msg->params = calloc(sizeof(char *), (to) ? 2 : 1);
  if (msg->params == 0)
    return -1;
  msg->nparams = 0;

  /* from parameter */
  msg->params[msg->nparams] = calloc(sizeof(char), strlen(from) + 1);
  if (msg->params[msg->nparams] == 0)
    return -1;
  memcpy(msg->params[msg->nparams], from, strlen(from));
  msg->nparams++;

  /* to parameter */
  if (to) {
    msg->params[msg->nparams] = calloc(sizeof(char), strlen(to) + 1);
    if (msg->params[msg->nparams] == 0)
      return -1;
    memcpy(msg->params[msg->nparams], to, strlen(to));
    msg->nparams++;
  }

  return 0;
}

/* TODO: support multiple channels and keys */
int birch_message_join(struct birch_message *msg, char *chan) {
  assert(chan != 0);

  msg->type = BIRCH_MSG_JOIN;
  msg->params = calloc(sizeof(char *), 1);
  if (msg->params == 0)
    return -1;
  msg->nparams = 0;

  /* channel parameter */
  msg->params[msg->nparams] = calloc(sizeof(char), strlen(chan) + 1);
  if (msg->params[msg->nparams] == 0)
    return -1;
  memcpy(msg->params[msg->nparams], chan, strlen(chan));
  msg->nparams++;

  return 0;
}
