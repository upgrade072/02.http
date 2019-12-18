
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <err.h>
#include <string.h>
#include <errno.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>

#include <event.h>
#include <event2/event.h>
#include <event2/bufferevent_ssl.h>
#include <event2/listener.h>

#include <nghttp2/nghttp2.h>
#include <nghttp2_session.h>

#include <libconfig.h>

#include <gmodule.h>
#include <nrf_comm.h>

#ifdef LOG_LIB
#include <sysconf.h>
#include <loglib.h>
#elif LOG_APP
#include <sysconf.h>
#include <appLog.h>
#elif LOG_PRINT
#endif

#include <libs.h>

#define OUTPUT_WOULDBLOCK_THRESHOLD (1 << 16)

#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))

#undef MAKE_NV
#define MAKE_NV(NAME, VALUE)                                                   \
  {                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1,    \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

#define MAKE_NV_STR(NAME, VALUE)                                                  \
  {                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, strlen(NAME), strlen(VALUE),            \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

