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
  size_t sz, l, i;
  struct birch_token_list *list;
};

/* NOTE: must be restartable */
typedef int(birch_lex_func)(struct birch_lex *l,
                            void *func /* birch_lex_func **func */);

/* lexer prototypes */
birch_lex_func birch_lex_stream_state_none;
birch_lex_func birch_lex_stream_state_cr;

int birch_lex_next(struct birch_lex *l, char *c);
void birch_lex_emit(struct birch_lex *l, struct birch_token tok);
void birch_lex_buf(struct birch_lex *l, char **buf, size_t *sz);
int birch_fetch_message(int sock, struct birch_token_list **list);

/* places the next byte in c, returns -1 if no more characters
   are lexable */
int birch_lex_next(struct birch_lex *l, char *c) {
  assert(l != NULL);
  assert(c != NULL);

  if (l->i < l->sz) {
    *c = l->message[l->i++];
    return 0;
  }
  return -1;
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

  *buf = &l->message[l->l];
  *sz = l->i - l->l;
  l->l = l->i; /* reset buffer */
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
  *func = birch_lex_stream_state_none;
  return 0;
}

/* lex message stream looking for separator */
int birch_lex_stream_state_none(struct birch_lex *l, void *v) {
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
  size_t bufsz;

  assert(list != NULL);

  memset(&l, 0, sizeof(l));
  bufsz = 4096;
  l.message = calloc(sizeof(char), bufsz);
  assert(l.message != NULL);

  for (;;) {
    int ret;
    birch_lex_func *func = birch_lex_stream_state_none;

    memmove(l.message, &l.message[l.l], l.i - l.l);
    l.i = l.i - l.l;
    l.l = 0;
    ret = read(sock, &l.message[l.i], bufsz - l.i);
    assert(ret != -1);
    if (ret == 0)
      break;
    l.sz = l.i + (size_t)ret;

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
  if (pid == 0) {
    struct birch_token_list *list;
    char *map[BIRCH_TOK_max];

    memset(map, 0, sizeof(map));
    map[BIRCH_TOK_NONE] = "none";
    map[BIRCH_TOK_ERR] = "error";
    map[BIRCH_TOK_MSG] = "message";

    assert(close(pfd[1]) != -1);
    list = NULL;
    assert(birch_fetch_message(pfd[0], &list) != -1);

    if (list == NULL)
      printf("no tokens lex'd :(\n");

    /* print tokens */
    for (; list != NULL; list = list->next) {
      char buf[100];

      assert(list->tok.begin != NULL);

      sprintf(buf, "%%s: '%%.%zus'\n", list->tok.sz);
      printf(buf, map[list->tok.type], list->tok.begin);
    }
    exit(0);
  } else {
    char buf[] = ":bob some sort of message?\r\n";
    close(pfd[0]);
    write(pfd[1], buf, sizeof(buf));
    close(pfd[1]);
    wait(NULL);
    exit(0);
  }
}
