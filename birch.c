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
#include <sys/syscall.h>
#include <unistd.h>
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
    BIRCH_TOK_PREFIX, /* until legit prefix parsing */
    BIRCH_TOK_max,
  } type;
  char *begin;
  size_t sz;
};

struct birch_token_list {
  struct birch_token_list *next;
  struct birch_token tok;
};

struct birch_msg_state {
  int params;
};

struct birch_lex {
  char *message;
  int sock;
  size_t sz, cap, l, i;
  struct birch_msg_state msg_state;
  struct birch_token_list *list;
};

typedef void(birch_message_handlefunc)(void *o, struct birch_token_list *list);

struct birch_message_handler {
  void *obj;
  birch_message_handlefunc *func;
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
int birch_fetch_message(int sock, struct birch_message_handler *handler);
int birch_fetch_message_pass(struct birch_lex *l);

bool birch_character_is_letter(char c);
bool birch_character_is_digit(char c);

void birch_handle_to_lower(const char *buf, char *out, size_t sz);

/* Message types */
enum birch_message_type {
  BIRCH_MSG_PASS,
  BIRCH_MSG_NICK, /* channel overload */
  BIRCH_MSG_USER,
  BIRCH_MSG_OPER,
  /* channel version not avaliable to services */
  BIRCH_MSG_MODE,
  BIRCH_MSG_SERVICE,
  BIRCH_MSG_QUIT,
  BIRCH_MSG_SQUIT,
  /* not avaliable to services */
  BIRCH_MSG_JOIN,
  BIRCH_MSG_PART,
  BIRCH_MSG_TOPIC,
  BIRCH_MSG_NAMES,
  BIRCH_MSG_LIST,
  BIRCH_MSG_INVITE,
  BIRCH_MSG_KICK,
  /* delivery of messages */
  BIRCH_MSG_PRIVMSG,
  BIRCH_MSG_NOTICE,
  /* server queries & commands */
  BIRCH_MSG_MOTD,
  BIRCH_MSG_LUSERS,
  BIRCH_MSG_VERSION,
  BIRCH_MSG_STATS,
  BIRCH_MSG_LINKS,
  BIRCH_MSG_TIME,
  BIRCH_MSG_CONNECT,
  BIRCH_MSG_TRACE,
  BIRCH_MSG_ADMIN,
  BIRCH_MSG_INFO,
  /* service query & commands */
  BIRCH_MSG_SERVLIST,
  BIRCH_MSG_SQUERY,
  /* user-based queries */
  BIRCH_MSG_WHO,
  BIRCH_MSG_WHOIS,
  BIRCH_MSG_WHOWAS,
  /* misc */
  BIRCH_MSG_KILL,
  BIRCH_MSG_PING,
  BIRCH_MSG_PONG,
  BIRCH_MSG_ERROR,
  /* optional */
  BIRCH_MSG_AWAY,
  BIRCH_MSG_REHASH,
  BIRCH_MSG_DIE,
  BIRCH_MSG_RESTART,
  BIRCH_MSG_SUMMON,
  BIRCH_MSG_USERS,
  BIRCH_MSG_WALLOPS,
  BIRCH_MSG_USERHOST,
  BIRCH_MSG_ISON,
  BIRCH_MSG_max
};

static char *birch_msg_map[BIRCH_MSG_max];

__attribute__((constructor)) static void birch_msg_map_fill() {
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

enum birch_response_type {
  /* sent on successful registration */
  BIRCH_RPL_WELCOME = 1,
  BIRCH_RPL_YOURHOST = 2,
  BIRCH_RPL_CREATED = 3,
  BIRCH_RPL_MYINFO = 4,
  /* suggest alternative server */
  BIRCH_RPL_BOUNCE = 5,
  BIRCH_RPL_USERHOST = 302,
  BIRCH_RPL_ISON = 303,
  BIRCH_RPL_AWAY = 301,
  BIRCH_RPL_UNAWAY = 305,
  BIRCH_RPL_NOWAWAY = 306,
  /* replies to whois */
  BIRCH_RPL_WHOISUSER = 311,
  BIRCH_RPL_WHOISSERVER = 312,
  BIRCH_RPL_WHOISOPERATOR = 313,
  BIRCH_RPL_WHOISIDLE = 317,
  BIRCH_RPL_ENDOFWHOIS = 318,
  BIRCH_RPL_WHOISCHANNELS = 319,
  /* replies to whowas */
  BIRCH_RPL_WHOWASUSER = 314,
  BIRCH_RPL_ENDOFWHOWAS = 369,
  BIRCH_RPL_LIST = 322,
  BIRCH_RPL_LISTEND = 323,
  BIRCH_RPL_UNIQOPIS = 325,
  BIRCH_RPL_CHANNELMODEIS = 324,
  /* replies to topic */
  BIRCH_RPL_NOTOPIC = 331,
  BIRCH_RPL_TOPIC = 332,
  /* replies to invite */
  BIRCH_RPL_INVITING = 341,
  /* replies to summon */
  BIRCH_RPL_SUMMONING = 342,
  /* replies to invite masks */
  BIRCH_RPL_INVITELIST = 346,
  BIRCH_RPL_ENDOFINVITELIST = 347,
  /* replies to exception masks */
  BIRCH_RPL_EXCEPTLIST = 348,
  BIRCH_RPL_ENDOFEXCEPTLIST = 349,
  /* replies to version */
  BIRCH_RPL_VERSION = 351,
  /* replies to who */
  BIRCH_RPL_WHOREPLY = 352,
  RPL_ENDOFWHO = 315,
  /* replies to names */
  BIRCH_RPL_NAMREPLY = 353,
  BIRCH_RPL_ENDOFNAMES = 366,
  /* replies to links */
  BIRCH_RPL_LINKS = 364,
  BIRCH_RPL_ENDOFLINKS = 365,
  /* replies to bans */
  BIRCH_RPL_BANLIST = 367,
  BIRCH_RPL_ENDOFBANLIST = 368,
  /* replies to info */
  BIRCH_RPL_INFO = 371,
  BIRCH_RPL_ENDOFINFO = 374,
  /* replies to motd */
  BIRCH_RPL_MOTDSTART = 375,
  BIRCH_RPL_MOTD = 372,
  BIRCH_RPL_ENDOFMOTD = 376,
  /* replies to oper */
  BIRCH_RPL_YOUREOPER = 381,
  /* replies to rehash */
  BIRCH_RPL_REHASHING = 382,
  /* replies to service registration */
  BIRCH_RPL_YOURESERVICE = 383,
  /* replies to time */
  BIRCH_RPL_TIME = 391,
  /* replies to users */
  BIRCH_RPL_USERSSTART = 392,
  BIRCH_RPL_USERS = 393,
  BIRCH_RPL_ENDOFUSERS = 394,
  BIRCH_RPL_NOUSERS = 395,
  /* replies to trace */
  BIRCH_RPL_TRACELINK = 200,
  BIRCH_RPL_TRACECONNECTING = 201,
  BIRCH_RPL_TRACEHANDSHAKE = 202,
  BIRCH_RPL_TRACEUNKNOWN = 203,
  BIRCH_RPL_TRACEOPERATOR = 204,
  BIRCH_RPL_TRACEUSER = 205,
  BIRCH_RPL_TRACESERVER = 206,
  BIRCH_RPL_TRACESERVICE = 207,
  BIRCH_RPL_TRACENEWTYPE = 208,
  BIRCH_RPL_TRACECLASS = 209,
  BIRCH_RPL_TRACELOG = 261,
  BIRCH_RPL_TRACEEND = 262,
  /* replies to stats */
  BIRCH_RPL_STATSLINKINFO = 211,
  BIRCH_RPL_STATSCOMMANDS = 212,
  BIRCH_RPL_ENDOFSTATS = 219,
  BIRCH_RPL_STATSUPTIME = 242,
  BIRCH_RPL_STATSOLINE = 243,
  /* replies to query for user's mode */
  BIRCH_RPL_UMODEIS = 221,
  /* replies to servlist */
  BIRCH_RPL_SERVLIST = 234,
  BIRCH_RPL_SERVLISTEND = 235,
  /* replies to lusers */
  BIRCH_RPL_LUSERCLIENT = 251,
  BIRCH_RPL_LUSEROP = 252,
  BIRCH_RPL_LUSERUNKNOWN = 253,
  BIRCH_RPL_LUSERCHANNELS = 254,
  BIRCH_RPL_LUSERME = 255,
  /* replies to admin */
  BIRCH_RPL_ADMINME = 256,
  BIRCH_RPL_ADMINLOC1 = 257,
  BIRCH_RPL_ADMINLOC2 = 258,
  BIRCH_RPL_ADMINEMAIL = 259,
  /* dropping a command */
  BIRCH_RPL_TRYAGAIN = 263,
  /* errors */
  BIRCH_ERR_NOSUCHNICK = 401,
  BIRCH_ERR_NOSUCHSERVER = 402,
  BIRCH_ERR_NOSUCHCHANNEL = 403,
  BIRCH_ERR_CANNOTSENDTOCHAN = 404,
  BIRCH_ERR_TOOMANYCHANNELS = 405,
  BIRCH_ERR_WASNOSUCHNICK = 406,
  BIRCH_ERR_TOOMANYTARGETS = 407,
  BIRCH_ERR_NOSUCHSERVICE = 408,
  BIRCH_ERR_NOORIGIN = 409,
  BIRCH_ERR_NORECIPIENT = 411,
  BIRCH_ERR_NOTEXTTOSEND = 412,
  BIRCH_ERR_NOTOPLEVEL = 413,
  BIRCH_ERR_WILDTOPLEVEL = 414,
  BIRCH_ERR_BADMASK = 415,
  BIRCH_ERR_UNKNOWNCOMMAND = 421,
  BIRCH_ERR_NOMOTD = 422,
  BIRCH_ERR_NOADMININFO = 423,
  BIRCH_ERR_FILEERROR = 424,
  BIRCH_ERR_NONICKNAMEGIVEN = 431,
  BIRCH_ERR_ERRONEUSNICKNAME = 432,
  BIRCH_ERR_NICKNAMEINUSE = 433,
  BIRCH_ERR_NICKCOLLISION = 436,
  BIRCH_ERR_UNAVAILRESOURCE = 437,
  BIRCH_ERR_USERNOTINCHANNEL = 441,
  BIRCH_ERR_NOTONCHANNEL = 442,
  BIRCH_ERR_USERONCHANNEL = 443,
  BIRCH_ERR_NOLOGIN = 444,
  BIRCH_ERR_SUMMONDISABLED = 445,
  BIRCH_ERR_USERSDISABLED = 446,
  BIRCH_ERR_NOTREGISTERED = 451,
  BIRCH_ERR_NEEDMOREPARAMS = 461,
  BIRCH_ERR_ALREADYREGISTRED = 462,
  BIRCH_ERR_NOPERMFORHOST = 463,
  BIRCH_ERR_PASSWDMISMATCH = 464,
  BIRCH_ERR_YOUREBANNEDCREEP = 465,
  BIRCH_ERR_YOUWILLBEBANNED = 466,
  BIRCH_ERR_KEYSET = 467,
  BIRCH_ERR_CHANNELISFULL = 471,
  BIRCH_ERR_UNKNOWNMODE = 472,
  BIRCH_ERR_INVITEONLYCHAN = 473,
  BIRCH_ERR_BANNEDFROMCHAN = 474,
  BIRCH_ERR_BADCHANNELKEY = 475,
  BIRCH_ERR_BADCHANMASK = 476,
  BIRCH_ERR_NOCHANMODES = 477,
  BIRCH_ERR_BANLISTFULL = 478,
  BIRCH_ERR_NOPRIVILEGES = 481,
  BIRCH_ERR_CHANOPRIVSNEEDED = 482,
  BIRCH_ERR_CANTKILLSERVER = 483,
  BIRCH_ERR_RESTRICTED = 484,
  BIRCH_ERR_UNIQOPPRIVSNEEDED = 485,
  BIRCH_ERR_NOOPERHOST = 491,
  BIRCH_ERR_UMODEUNKNOWNFLAG = 501,
  BIRCH_ERR_USERSDONTMATCH = 502,
  /* no longer in use,
  reserved for future use,
  or part of a non-generic "feature" */
  BIRCH_RPL_SERVICEINFO = 231,
  BIRCH_RPL_ENDOFSERVICES = 232,
  BIRCH_RPL_SERVICE = 233,
  BIRCH_RPL_NONE = 300,
  BIRCH_RPL_WHOISCHANOP = 316,
  BIRCH_RPL_KILLDONE = 361,
  BIRCH_RPL_CLOSING = 362,
  BIRCH_RPL_CLOSEEND = 363,
  BIRCH_RPL_INFOSTART = 373,
  BIRCH_RPL_MYPORTIS = 384,
  BIRCH_RPL_STATSCLINE = 213,
  BIRCH_RPL_STATSNLINE = 214,
  BIRCH_RPL_STATSILINE = 215,
  BIRCH_RPL_STATSKLINE = 216,
  BIRCH_RPL_STATSQLINE = 217,
  BIRCH_RPL_STATSYLINE = 218,
  BIRCH_RPL_STATSVLINE = 240,
  BIRCH_RPL_STATSLLINE = 241,
  BIRCH_RPL_STATSHLINE = 244,
  BIRCH_RPL_STATSSLINE = 244,
  BIRCH_RPL_STATSPING = 246,
  BIRCH_RPL_STATSBLINE = 247,
  BIRCH_RPL_STATSDLINE = 250,
  BIRCH_ERR_NOSERVICEHOST = 492,

  /* obsolete */
  BIRCH_RPL_LISTSTART = 321,
  BIRCH_RPL_TRACERECONNECT = 210,
};

struct birch_message {
  enum birch_message_type type;
  char **params;
  size_t nparams;
};

int birch_message_format(struct birch_message *m, int sock);
int birch_message_format_simple(struct birch_message *m, char **out,
                                size_t *sz);

int birch_message_format(struct birch_message *m, int sock) {
  char *buf;
  size_t sz;

  if (birch_message_format_simple(m, &buf, &sz) != 0)
    return -1;

  if (write(sock, buf, sz) != (ssize_t)sz)
    return -1;

  return 0;
}

// returns non-zero on error
int birch_message_format_simple(struct birch_message *m, char **out,
                                size_t *sz) {
  /* message type string, params, last parameter is long-form */
  char *cmd;
  size_t i, len;

  assert(m != 0);
  assert(out != 0);

  if (m->nparams > 14)
    return -1;

  *sz = 3; /* colon, \r\n */
  *sz += strlen(birch_msg_map[m->type]);
  for (i = 0; i < m->nparams; i++) {
    *sz += strlen(m->params[i]) + 1; /* space */
  }

  *out = calloc(sizeof(char), *sz);
  if (*out == 0)
    return -1;
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
        return -1;
    /* prefix with space */
    (*out)[len++] = ' ';
    /* use trailing if the last paramter contains spaces */
    if (i == (m->nparams - 1) && contains_space)
      (*out)[len++] = ':';
    /* write parameter */
    n = strlen(m->params[i]);
    memcpy(&(*out)[len], m->params[i], n);
    len += n;
  }
  memcpy(&(*out)[len], "\r\n", 2);
  len += 2;

  return 0;
}

bool birch_character_is_letter(char c) {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

bool birch_character_is_digit(char c) { return c >= '1' && c <= '9'; }

/* places the next byte in c, returns -1 if no more characters
   are lexable */
int birch_lex_next(struct birch_lex *l, char *c) {
  ssize_t ret;

  assert(l != 0);

  /* increase buffer size as needed */
  if (l->sz == l->cap) {
    l->cap = 2 * l->cap + 1;
    l->message = realloc(l->message, l->cap);
    assert(l->message != 0);
  }

  if (l->i == l->sz) {
    ret = read(l->sock, &l->message[l->sz], l->cap - l->sz);
    assert(ret != -1);
    if (ret == 0)
      return -1;
    l->sz += (size_t)ret;
  }

  if (l->i < l->sz) {
    if (c != 0)
      *c = l->message[l->i];
    l->i++;
    return 0;
  }
  return -1;
}

void birch_lex_back(struct birch_lex *l) {
  assert(l != 0);

  if (l->i > l->l)
    l->i--;
}

void birch_lex_emit(struct birch_lex *l, struct birch_token tok) {
  struct birch_token_list *link;

  assert(l != 0);

  link = calloc(sizeof(struct birch_token_list), 1);
  assert(link != 0);
  link->tok = tok;
  link->next = l->list;
  l->list = link;
}

/* gets & resets buffer */
void birch_lex_buf(struct birch_lex *l, char **buf, size_t *sz) {
  assert(l != 0);
  assert(buf != 0);
  assert(sz != 0);

  *sz = l->i - l->l;
  *buf = calloc(sizeof(char), *sz);
  assert(buf != 0);
  memcpy(*buf, &l->message[l->l], *sz);
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

  assert(buf != 0);
  assert(out != 0);

  for (i = 0; i < sz; i++) {
    out[i] = map[buf[i] & 0x7f];
  }
}

int birch_lex_message_state_prefix(struct birch_lex *l, void *v) {
  birch_lex_func **func;
  char c;

  assert(l != 0);
  assert(v != 0);

  func = (birch_lex_func **)v;

  /* lex up to a space */
  while (birch_lex_next(l, &c) != -1) {
    if (c == ' ') {
      struct birch_token tok;

      birch_lex_back(l);

      /* emit prefix token */
      tok.type = BIRCH_TOK_PREFIX;
      birch_lex_buf(l, &tok.begin, &tok.sz);
      birch_lex_emit(l, tok);

      /* emit space token */
      birch_lex_next(l, 0);
      tok.type = BIRCH_TOK_SPACE;
      birch_lex_buf(l, &tok.begin, &tok.sz);
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

    *func = 0;
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

    *func = 0;
    return 0;
  } else {
    /* error */
    char buf[] = "Error, expected LF";
    struct birch_token tok;

    tok.type = BIRCH_TOK_ERR;
    tok.begin = buf;
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
      char buf[] = "Error, 0 and newline not permitted in params trailing";

      tok.type = BIRCH_TOK_ERR;
      tok.begin = buf;
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
        char buf[] = "Error, params middle must be nonempty";

        tok.type = BIRCH_TOK_ERR;
        tok.begin = buf;
        tok.sz = sizeof(buf);
        birch_lex_emit(l, tok);

        *func = 0;
        return 0;
      }

      birch_lex_back(l);

      /* emit token */
      tok.type = BIRCH_TOK_PARAMS;
      birch_lex_buf(l, &tok.begin, &tok.sz);
      birch_lex_emit(l, tok);

      /* emit token */
      birch_lex_next(l, 0);
      tok.type = BIRCH_TOK_SPACE;
      birch_lex_buf(l, &tok.begin, &tok.sz);
      birch_lex_emit(l, tok);

      l->msg_state.params++; // count params

      *func = birch_lex_message_state_params;
      return 0;
    } else if (c == '\0' || c == '\r' || c == '\n') {
      /* error */
      char buf[] = "Error, params middle cannot contain 0, CR or LF";
      struct birch_token tok;

      tok.type = BIRCH_TOK_ERR;
      tok.begin = buf;
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
    birch_lex_buf(l, &tok.begin, &tok.sz);
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
      birch_lex_buf(l, &tok.begin, &tok.sz);
      birch_lex_emit(l, tok);

      birch_lex_next(l, 0);

      tok.type = BIRCH_TOK_SPACE;
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
        char buf[] = "Error, expected 3-digit code, wrong length";

        tok.type = BIRCH_TOK_ERR;
        tok.begin = buf;
        tok.sz = sizeof(buf);
        birch_lex_emit(l, tok);

        *func = 0;
        return 0;
      }

      birch_lex_back(l);

      tok.type = BIRCH_TOK_COMMAND;
      birch_lex_buf(l, &tok.begin, &tok.sz);
      birch_lex_emit(l, tok);

      birch_lex_next(l, 0);

      tok.type = BIRCH_TOK_SPACE;
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

  assert(l != 0);
  assert(v != 0);

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

int birch_fetch_message_pass(struct birch_lex *l) {
  birch_lex_func *func;

  assert(l != 0);

  /* lex stream into messages */
  func = birch_lex_message_state_start;
  while (func != 0) {
    if (func(l, &func) == -1) {
      return -1;
    }
  }
  return 0;
}

int birch_fetch_message(int sock, struct birch_message_handler *handler) {
  struct birch_lex l;
  int ret;

  assert(handler != 0);

  memset(&l, 0, sizeof(l));
  l.sock = sock;
  l.message = calloc(sizeof(char), l.cap);
  assert(l.message != 0);

  ret = 0;
  while (ret == 0) {
    l.list = 0;
    ret = birch_fetch_message_pass(&l);
    handler->func(handler->obj, l.list);
  }
  return 0;
}

static birch_message_handlefunc handler;

static void handler(void *o __attribute__((unused)),
                    struct birch_token_list *list) {
  int i;
  struct birch_message msg;

  memset(&msg, 0, sizeof(msg));

  if (list == 0)
    /* end of list */
    return;

  /* form message */
  for (i = 0; list != 0; list = list->next, i++) {
    char *buf;
    size_t j;

    assert(list->tok.begin != 0);

    switch (list->tok.type) {
    case BIRCH_TOK_PARAMS:
      buf = calloc(sizeof(char), list->tok.sz + 1);
      memcpy(buf, list->tok.begin, list->tok.sz);
      msg.params = realloc(msg.params, (++msg.nparams) * sizeof(char *));
      /* reverse the order of parameters */
      memmove(&msg.params[1], msg.params, (msg.nparams - 1) * sizeof(char *));
      msg.params[0] = buf;
      break;
    case BIRCH_TOK_COMMAND:
      for (j = 0; j < BIRCH_MSG_max; j++)
        if (strncmp(birch_msg_map[j], list->tok.begin, list->tok.sz) == 0)
          msg.type = (enum birch_message_type)j;
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

  assert(birch_message_format(&msg, STDOUT_FILENO) != -1);
}

enum birch_mode {
  BIRCH_MODE_AWAY = 1 << 0,
  BIRCH_MODE_INVISIBLE = 1 << 1,
  BIRCH_MODE_WALLOPS = 1 << 2,
  BIRCH_MODE_RESTRICTED = 1 << 3,
  BIRCH_MODE_OPERATOR = 1 << 4,
  BIRCH_MODE_LOPERATOR = 1 << 5,
  BIRCH_MODE_NOTICES = 1 << 6,
};

int birch_message_pass_random(struct birch_message *msg);
int birch_message_nick(struct birch_message *msg, char *nick);
int birch_message_user(struct birch_message *msg, enum birch_mode mode,
                       char *name);

/* generate random pass */
int birch_message_pass_random(struct birch_message *msg) {
  uint64_t buf;

  assert(msg != 0);

  msg->type = BIRCH_MSG_PASS;
  if (syscall(SYS_getrandom, &buf, sizeof(buf), 0) == -1)
    return -1;
  msg->params = calloc(sizeof(char *), 1);
  if (msg->params == 0)
    return -1;
  msg->params[0] = calloc(sizeof(char), sizeof(buf) * 2 + 1);
  if (msg->params[0] == 0)
    return -1;
  msg->nparams++;
  sprintf(msg->params[0], "%lx", buf);

  return 0;
}

int birch_message_nick(struct birch_message *msg, char *nick) {
  assert(msg != 0);

  msg->type = BIRCH_MSG_NICK;
  msg->params = calloc(sizeof(char *), 1);
  if (msg->params == 0)
    return -1;
  msg->params[0] = calloc(sizeof(char), strlen(nick) + 1);
  if (msg->params[0] == 0)
    return -1;
  msg->nparams++;
  memcpy(msg->params[0], nick, strlen(nick));

  return 0;
}

int birch_message_user(struct birch_message *msg, enum birch_mode mode,
                       char *name) {
  size_t i;

  assert(msg != 0);

  memset(&msg, 0, sizeof(msg));

  msg->type = BIRCH_MSG_NICK;
  msg->params = calloc(sizeof(char *), 3);
  if (msg->params == 0)
    return -1;
  /* mode parameter */
  msg->params[0] = calloc(sizeof(char), 8);
  if (msg->params[0] == 0)
    return -1;
  msg->nparams++;
  i = 0;
  if (mode & BIRCH_MODE_AWAY)
    msg->params[0][i++] = 'a';
  if (mode & BIRCH_MODE_INVISIBLE)
    msg->params[0][i++] = 'i';
  if (mode & BIRCH_MODE_WALLOPS)
    msg->params[0][i++] = 'w';
  if (mode & BIRCH_MODE_RESTRICTED)
    msg->params[0][i++] = 'r';
  if (mode & BIRCH_MODE_OPERATOR)
    msg->params[0][i++] = 'o';
  if (mode & BIRCH_MODE_LOPERATOR)
    msg->params[0][i++] = 'O';
  if (mode & BIRCH_MODE_NOTICES)
    msg->params[0][i++] = 's';
  /* ignored */
  msg->params[1] = calloc(sizeof(char), 4);
  if (msg->params[1] == 0)
    return -1;
  msg->nparams++;
  memcpy(msg->params[1], "xxx", 4);
  /* real name parameter */
  msg->params[2] = calloc(sizeof(char), strlen(name) + 1);
  if (msg->params[2] == 0)
    return -1;
  msg->nparams++;
  memcpy(msg->params[2], name, strlen(name));

  return 0;
}

static int test_client() {
  struct birch_message msg;

  /* generate random password */
  memset(&msg, 0, sizeof(msg));
  if (birch_message_pass_random(&msg) == -1)
    return -1;
  birch_message_format(&msg, 0);

  memset(&msg, 0, sizeof(msg));
  if (birch_message_nick(&msg, "byteflame") == -1)
    return -1;
  birch_message_format(&msg, 0);

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
    struct birch_message_handler handle;

    assert(close(pfd[1]) != -1);
    handle.obj = 0;
    handle.func = handler;
    assert(birch_fetch_message(pfd[0], &handle) != -1);
    assert(test_client() == 0);
  } else {
    int i;
    char *buf = ":kenny.blah.com MSG bob :some sort of message?\r\n";

    assert(close(pfd[0]) != -1);
    for (i = 0; i < 4; i++) {
      assert(write(pfd[1], buf, strlen(buf)) == (ssize_t)strlen(buf));
    }
    assert(close(pfd[1]) != -1);
  }
  exit(0);
}
