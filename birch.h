/* Copyright 2016 Connor Taffe */

#include <stdbool.h>
#include <stddef.h>

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
    BIRCH_TOK_max
  } type;
  char *buf;
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

void birch_to_lower(char *out, const char *buf, size_t sz);

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

extern char *birch_msg_map[BIRCH_MSG_max];

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
  BIRCH_RPL_TRACERECONNECT = 210
};

struct birch_message {
  enum birch_message_type type;
  char **params;
  size_t nparams;
};

int birch_message_format(struct birch_message *m, int sock);
int birch_message_format_simple(struct birch_message *m, char **out,
                                size_t *sz);
int birch_token_list_message(struct birch_token_list *list,
                             struct birch_message *msg);

enum birch_mode {
  BIRCH_MODE_NONE = 0,
  BIRCH_MODE_AWAY = 1 << 0,
  BIRCH_MODE_INVISIBLE = 1 << 1,
  BIRCH_MODE_WALLOPS = 1 << 2,
  BIRCH_MODE_RESTRICTED = 1 << 3,
  BIRCH_MODE_OPERATOR = 1 << 4,
  BIRCH_MODE_LOPERATOR = 1 << 5,
  BIRCH_MODE_NOTICES = 1 << 6
};

int birch_message_pass_random(struct birch_message *msg);
int birch_message_nick(struct birch_message *msg, char *nick);
int birch_message_user(struct birch_message *msg, char *username, char *name);
int birch_message_pong(struct birch_message *msg, char *from, char *to);
int birch_message_join(struct birch_message *msg, char *chan);
