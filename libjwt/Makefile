include ../MakeVars

CFLAG		= $(CFLAGS) -DHAVE_UNISTD_H -DHAVE_FCNTL_H

BUILD_INC_PATH	= -I../build/include
BUILD_LIBS_PATH	= ../build/lib
BUILD_LIBS = $(BUILD_LIBS_PATH)/libssl.a \
			 $(BUILD_LIBS_PATH)/libcrypto.a \
			 $(BUILD_LIBS_PATH)/libjansson.a

SRCS        = base64.c jwt-openssl.c jwt.c

OBJS        = $(SRCS:.c=.o)

AOUT        = libjwt.a

DEST        = ../build

all:: clean $(AOUT) install

.SUFFIXES: .c .o
.c.o:
	$(CC) $(CFLAG) $(BUILD_INC_PATH) $(INC_PATH) -c $<

$(AOUT): $(OBJS)
	$(AR) -rc $(AOUT) $(OBJS)

install:
	\cp $(AOUT) $(DEST)/lib
	\cp jwt.h $(DEST)/include

clean:
	\rm -f $(OBJS) $(AOUT) core.*
