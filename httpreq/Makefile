include ../MakeVars

CFLAG		= $(CFLAGS)

BUILD_INC_PATH	= -I../build/include
BUILD_LIBS_PATH	= ../build/lib
BUILD_LIBS = $(BUILD_LIBS_PATH)/libssl.a \
			 $(BUILD_LIBS_PATH)/libcrypto.a \
			 $(BUILD_LIBS_PATH)/libevent.a \
			 $(BUILD_LIBS_PATH)/libevent_openssl.a \
			 $(BUILD_LIBS_PATH)/libevent_pthreads.a \
			 $(BUILD_LIBS_PATH)/libnghttp2.a \
			 $(BUILD_LIBS_PATH)/libhttp.a \
			 $(BUILD_LIBS_PATH)/libs.a \
			 $(BUILD_LIBS_PATH)/http_parser.a 

SRCS		= request.c

OBJS		= $(SRCS:.c=.o)

AOUT		= libreq.a

DEST		= ../build

all:: clean $(AOUT) install

.SUFFIXES: .c .o
.c.o:
	$(CC) $(CFLAG) $(BUILD_INC_PATH) $(INC_PATH) -c $<

$(AOUT): $(OBJS) 
	$(AR) -rc $(AOUT) $(OBJS)

install:
	\cp $(AOUT) $(DEST)/lib
	\cp libreq.h $(DEST)/include

clean:
	\rm -f $(OBJS) $(AOUT) core.* 
