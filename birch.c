/* Copyright 2016 Connor Taffe */

/* Birch IRC library */

#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wait.h>

struct birch_token {
  enum {
    BIRCH_TOK_NONE,
    BIRCH_TOK_ERR,
    BIRCH_TOK_MSG,
    BIRCH_TOK_COLON,
    BIRCH_TOK_COMMAND,
    BIRCH_TOK_PARAMS,
    BIRCH_TOK_EOL,
    BIRCH_TOK_SPACE,
    BIRCH_TOK_max,
  } type;
  char *begin;
  size_t sz;
};

struct birch_token_list {
  struct birch_token_list *next;
  struct birch_token tok;
};

struct birch_lex {
  char *message;
  int sock;
  size_t sz, cap, l, i;
  struct birch_token_list *list;
};

/* NOTE: must be restartable */
typedef int(birch_lex_func)(struct birch_lex *l,
                            void *func /* birch_lex_func **func */);
typedef bool(birch_lex_check)(char c);

/* stream lexer prototypes */
birch_lex_func birch_lex_stream_state_start;
birch_lex_func birch_lex_stream_state_cr;

/* message lexer prototypes */
birch_lex_func birch_lex_message_state_start;
birch_lex_func birch_lex_message_state_prefix;
birch_lex_func birch_lex_message_state_command;
birch_lex_func birch_lex_message_state_command_string;
birch_lex_func birch_lex_message_state_command_code;
birch_lex_func birch_lex_message_state_params;
birch_lex_func birch_lex_message_state_params_trailing;
birch_lex_func birch_lex_message_state_params_middle;
birch_lex_func birch_lex_message_state_eol;

int birch_lex_next(struct birch_lex *l, char *c);
void birch_lex_back(struct birch_lex *l);
void birch_lex_emit(struct birch_lex *l, struct birch_token tok);
void birch_lex_buf(struct birch_lex *l, char **buf, size_t *sz);
int birch_fetch_message(int sock, struct birch_token_list **list);

bool birch_character_is_letter(char c);
bool birch_character_is_digit(char c);

void birch_handle_to_lower(const char *buf, char *out, size_t sz);

bool birch_character_is_letter(char c) {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

bool birch_character_is_digit(char c) { return c >= '1' && c <= '9'; }

/* places the next byte in c, returns -1 if no more characters
   are lexable */
int birch_lex_next(struct birch_lex *l, char *c) {
  ssize_t ret;

  assert(l != NULL);

  /* increase buffer size as needed */
  if (l->i == l->cap - 1) {
    l->cap = 2 * ((l->cap) ? l->cap : 1);
    l->message = realloc(l->message, l->cap);
    assert(l->message != NULL);
  }

  ret = read(l->sock, &l->message[l->i], l->cap - l->i);
  assert(ret != -1);
  if (ret == 0)
    return -1;
  l->sz = l->i + (size_t)ret;

  if (l->i < l->sz) {
    if (c != NULL)
      *c = l->message[l->i];
    l->i++;
    return 0;
  }
  return -1;
}

void birch_lex_back(struct birch_lex *l) {
  assert(l != NULL);

  if (l->i > 0)
    l->i--;
}

void birch_lex_emit(struct birch_lex *l, struct birch_token tok) {
  struct birch_token_list *link;

  assert(l != NULL);

  link = calloc(sizeof(struct birch_token_list), 1);
  assert(link != NULL);
  link->tok = tok;
  link->next = l->list;
  l->list = link;
}

/* gets & resets buffer */
void birch_lex_buf(struct birch_lex *l, char **buf, size_t *sz) {
  assert(l != NULL);
  assert(buf != NULL);
  assert(sz != NULL);

  *buf = &l->message[l->l];
  *sz = l->i - l->l;
  l->l = l->i; /* reset buffer */
}

/* respect IRC's scandanavian case handling */
void birch_handle_to_lower(const char *buf, char *out, size_t sz) {
  char map[] = "\x0\x1\x2\x3\x4\x5\x6\x7\x8\x9\xa\xb\xc\xd\xe\xf\x10\x11\x12"
               "\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20!\"#$%&"
               "'()*+,-./"
               "0123456789:;<=>?@abcdefghijklmnopqrstuvwzyz{|}^_`"
               "abcdefghijklmnopqrstuvwzyz{|}~\x7f";
  size_t i;

  assert(buf != NULL);
  assert(out != NULL);

  for (i = 0; i < sz; i++) {
    out[i] = map[buf[i] & 0x7f];
  }
}

int birch_lex_message_state_prefix(struct birch_lex *l, void *v) {
  birch_lex_func **func;
  char c;

  assert(l != NULL);
  assert(v != NULL);

  func = (birch_lex_func **)v;
  if (birch_lex_next(l, &c) == -1)
    return -1;
  // TODO: handle prefixed message
  *func = NULL;
  return 0;
}

int birch_lex_message_state_eol(struct birch_lex *l, void *v) {
  birch_lex_func **func;
  char c;

  assert(l != NULL);
  assert(v != NULL);

  func = (birch_lex_func **)v;

  if (birch_lex_next(l, &c) == -1)
    return -1;

  if (c != '\r') {
    /* error */
    char buf[] = "Error, expected CR";
    struct birch_token tok;

    tok.type = BIRCH_TOK_ERR;
    tok.begin = buf;
    tok.sz = sizeof(buf);
    birch_lex_emit(l, tok);

    *func = NULL;
    return 0;
  }

  if (birch_lex_next(l, &c) == -1)
    return -1;

  if (c == '\n') {
    /* emit token */
    struct birch_token tok;

    tok.type = BIRCH_TOK_EOL;
    birch_lex_buf(l, &tok.begin, &tok.sz);
    birch_lex_emit(l, tok);

    *func = NULL;
    return 0;
  } else {
    /* error */
    char buf[] = "Error, expected LF";
    struct birch_token tok;

    tok.type = BIRCH_TOK_ERR;
    tok.begin = buf;
    tok.sz = sizeof(buf);
    birch_lex_emit(l, tok);

    *func = NULL;
    return 0;
  }
}

int birch_lex_message_state_params_trailing(struct birch_lex *l, void *v) {
  birch_lex_func **func;
  char c;

  assert(l != NULL);
  assert(v != NULL);

  func = (birch_lex_func **)v;

  while (birch_lex_next(l, &c) != -1)
    if (c == '\r') {
      /* emit token */
      struct birch_token tok;

      tok.type = BIRCH_TOK_PARAMS;
      birch_lex_back(l);
      birch_lex_buf(l, &tok.begin, &tok.sz);
      birch_lex_emit(l, tok);

      *func = birch_lex_message_state_eol;
      return 0;
    } else if (c == '\0' || c == '\n') {
      /* error */
      struct birch_token tok;
      char buf[] = "Error, null and newline not permitted in params trailing";

      tok.type = BIRCH_TOK_ERR;
      tok.begin = buf;
      tok.sz = sizeof(buf);
      birch_lex_emit(l, tok);

      *func = NULL;
      return 0;
    }

  return -1;
}

int birch_lex_message_state_params_middle(struct birch_lex *l, void *v) {
  birch_lex_func **func;
  int i;
  char c;

  assert(l != NULL);
  assert(v != NULL);

  func = (birch_lex_func **)v;

  for (i = 0; birch_lex_next(l, &c) != -1; i++) {
    if (c == ' ') {
      struct birch_token tok;

      if (i == 0) {
        /* error */
        char buf[] = "Error, params middle must be nonempty";

        tok.type = BIRCH_TOK_ERR;
        tok.begin = buf;
        tok.sz = sizeof(buf);
        birch_lex_emit(l, tok);

        *func = NULL;
        return 0;
      }

      birch_lex_back(l);

      /* emit token */
      tok.type = BIRCH_TOK_PARAMS;
      birch_lex_buf(l, &tok.begin, &tok.sz);
      birch_lex_emit(l, tok);

      /* emit token */
      birch_lex_next(l, NULL);
      tok.type = BIRCH_TOK_SPACE;
      birch_lex_buf(l, &tok.begin, &tok.sz);
      birch_lex_emit(l, tok);

      *func = birch_lex_message_state_params;
      return 0;
    } else if (c == '\0' || c == '\r' || c == '\n') {
      /* error */
      char buf[] = "Error, params middle cannot contain null, CR or LF";
      struct birch_token tok;

      tok.type = BIRCH_TOK_ERR;
      tok.begin = buf;
      tok.sz = sizeof(buf);
      birch_lex_emit(l, tok);

      *func = NULL;
      return 0;
    }
  }
  return -1;
}

int birch_lex_message_state_params(struct birch_lex *l, void *v) {
  birch_lex_func **func;
  char c;

  assert(l != NULL);
  assert(v != NULL);

  func = (birch_lex_func **)v;

  /* lex params */
  if (birch_lex_next(l, &c) == -1)
    return -1;

  if (c == ':') {
    /* emit token */
    struct birch_token tok;

    tok.type = BIRCH_TOK_COLON;
    birch_lex_buf(l, &tok.begin, &tok.sz);
    birch_lex_emit(l, tok);

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

  assert(l != NULL);
  assert(v != NULL);

  func = (birch_lex_func **)v;

  /* lex letters */
  while (birch_lex_next(l, &c) != -1) {
    if (c == ' ') {
      /* emit token */
      struct birch_token tok;

      birch_lex_buf(l, &tok.begin, &tok.sz);
      birch_lex_emit(l, tok);

      *func = birch_lex_message_state_params;
      return 0;
    } else if (!birch_character_is_letter(c)) {
      /* error */
      struct birch_token tok;
      char buf[] = "Unexpected non-letter in command";

      tok.type = BIRCH_TOK_ERR;
      tok.begin = buf;
      tok.sz = sizeof(buf);
      birch_lex_emit(l, tok);

      *func = NULL;
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

  assert(l != NULL);
  assert(v != NULL);

  func = (birch_lex_func **)v;

  for (i = 0; birch_lex_next(l, &c) != -1; i++) {
    if (c == ' ') {
      /* emit token */
      struct birch_token tok;

      if (i != 2) {
        /* error */
        char buf[] = "Error, expected 3-digit code, wrong length";

        tok.type = BIRCH_TOK_ERR;
        tok.begin = buf;
        tok.sz = sizeof(buf);
        birch_lex_emit(l, tok);

        *func = NULL;
        return 0;
      }

      tok.type = BIRCH_TOK_COMMAND;
      birch_lex_buf(l, &tok.begin, &tok.sz);
      birch_lex_emit(l, tok);

      *func = birch_lex_message_state_params;
      return 0;
    } else if (!birch_character_is_digit(c)) {
      /* error */
      char buf[] = "Error, non-digit in numeric command";
      struct birch_token tok;

      tok.type = BIRCH_TOK_ERR;
      tok.begin = buf;
      tok.sz = sizeof(buf);
      birch_lex_emit(l, tok);

      *func = NULL;
      return 0;
    }
  }
  return -1;
}

int birch_lex_message_state_command(struct birch_lex *l, void *v) {
  birch_lex_func **func;
  char c;

  assert(l != NULL);
  assert(v != NULL);

  func = (birch_lex_func **)v;
  if (birch_lex_next(l, &c) == -1)
    return -1;
  if (birch_character_is_digit(c)) {
    *func = birch_lex_message_state_command_code;
  } else if (birch_character_is_letter(c)) {
    *func = birch_lex_message_state_command_string;
  } else {
    /* error */
    char buf[] = "Unexpected character, expected command.";
    struct birch_token tok;

    tok.type = BIRCH_TOK_ERR;
    tok.begin = buf;
    tok.sz = sizeof(buf);
    birch_lex_emit(l, tok);

    *func = NULL;
  }
  return 0;
}

int birch_lex_message_state_start(struct birch_lex *l, void *v) {
  birch_lex_func **func;
  char c;

  assert(l != NULL);
  assert(v != NULL);

  func = (birch_lex_func **)v;
  if (birch_lex_next(l, &c) == -1)
    return -1;
  if (c == ':') {
    /* prefix */
    struct birch_token tok;

    tok.type = BIRCH_TOK_COLON;
    birch_lex_buf(l, &tok.begin, &tok.sz);
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

  assert(l != NULL);
  assert(v != NULL);

  func = (birch_lex_func **)v;
  if (birch_lex_next(l, &c) == -1)
    return -1;
  if (c == '\n') {
    struct birch_token tok;

    /* emit token */
    tok.type = BIRCH_TOK_MSG;
    birch_lex_buf(l, &tok.begin, &tok.sz);
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

  assert(l != NULL);
  assert(v != NULL);

  func = (birch_lex_func **)v;
  for (;;) {
    if (birch_lex_next(l, &c) == -1)
      return -1;
    if (c == '\r') {
      *func = birch_lex_stream_state_cr;
      return 0;
    }
  }
}

int birch_fetch_message(int sock, struct birch_token_list **list) {
  struct birch_lex l;

  assert(list != NULL);

  memset(&l, 0, sizeof(l));
  l.sock = sock;
  l.cap = 4096;
  l.message = calloc(sizeof(char), l.cap);
  assert(l.message != NULL);

  for (;;) {
    birch_lex_func *func = birch_lex_stream_state_start;

    /* 1st pass: lex stream into messages */
    while (l.i < l.sz - 1) {
      assert(func != NULL);
      if (func(&l, &func) == -1)
        break;
    }
  }

  *list = l.list;
  return 0;
}

int main(int argc __attribute__((unused)),
         char **argv __attribute__((unused))) {
  int pfd[2];
  pid_t pid;

  assert(pipe(pfd) != -1);

  pid = fork();
  assert(pid != -1);
  if (pid != 0) {
    int i;
    struct birch_token_list *list;

    assert(close(pfd[1]) != -1);
    list = NULL;
    assert(birch_fetch_message(pfd[0], &list) != -1);

    if (list == NULL)
      printf("no tokens lex'd :(\n");

    /* print tokens */
    for (i = 0; list != NULL; list = list->next, i++) {
      char buf[100];

      assert(list->tok.begin != NULL);

      sprintf(buf, "%%d-> %%d: '%%.%zus'\n", list->tok.sz);
      printf(buf, i, list->tok.type, list->tok.begin);
    }
    exit(0);
  } else {
    int i;
    char buf[] = "MSG bob :some sort of message?\r\n";

    assert(close(pfd[0]) != -1);
    for (i = 0; i < 4; i++) {
      assert(write(pfd[1], buf, sizeof(buf)) == sizeof(buf));
    }
    assert(close(pfd[1]) != -1);
  }
}
