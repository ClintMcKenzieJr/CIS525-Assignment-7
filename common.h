#ifndef __COMMON_H__
#define __COMMON_H__

#define MAX 100

#define MAX_CLIENTS 5

#define MAX_SERVERS 5


#define MAXTOPICLEN 19

#define MAXNAMELEN 11

#define MAXMSGLEN 88


// Enable or disable debug mode
//
// 0 - disable
// 1 - enable
//
#define DEBUG_MODE 0

// ----------------------- Debug Macros
#ifndef DEBUG_MODE
#define DEBUG_MODE 0
#warning                                                                       \
    "Please define 'DEBUG_MODE' in common.h with either 'true' (enable debugging) or 'false' (disable debugging)!"
#endif

#if DEBUG_MODE
#define DEBUG_MSG(...)                                                         \
  do {                                                                         \
    fprintf(stderr, "[%s:%d]: ", __FILE__, __LINE__);                          \
    fprintf(stderr, __VA_ARGS__);                                              \
  } while (0);

#define DEBUG_DIRTY_MSG(msg, msg_len)                                          \
  do {                                                                         \
    for (size_t i = 0; i < (msg_len); i++) {                                   \
      if ((msg)[i] == '\n')                                                    \
        fprintf(stderr, "\\n");                                                \
      else if ((msg)[i] == '\r')                                               \
        fprintf(stderr, "\\r");                                                \
      else if ((msg)[i] == '\0')                                               \
        fprintf(stderr, "\\0");                                                \
      else                                                                     \
        fprintf(stderr, "%c", (msg)[i]);                                       \
    }                                                                          \
    fprintf(stderr, "\n");                                                     \
  } while (0);
#else
#define DEBUG_MSG(...)
#define DEBUG_DIRTY_MSG(msg, msg_len)
#endif

#endif
