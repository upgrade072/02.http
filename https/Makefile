include ../../../MakeVars

TARGET		= epcf
CFLAG		= -std=gnu99 $(CFLAGS) -g -DHOLDSESS -DPERFORM
#CFLAG		= $(CFLAGS) -g -DHOLDSESS 
INC_PATH	= -I. -I../../../include -I../../../libsrc/COMM
LIB_PATH	= -L../../../lib
ifeq ($(TARGET),udmr)
LIBS		= -lShmQueue -lcomm -lLog -lpthread -ldl -lrt
else
LIBS		= -lcomm -lpthread -ldl -lrt
endif

BUILD_INC_PATH	= -I../build/include
BUILD_LIBS_PATH	= ../build/lib
BUILD_LIBS = $(BUILD_LIBS_PATH)/libssl.a \
			 $(BUILD_LIBS_PATH)/libcrypto.a \
			 $(BUILD_LIBS_PATH)/libevent.a \
			 $(BUILD_LIBS_PATH)/libevent_openssl.a \
			 $(BUILD_LIBS_PATH)/libevent_pthreads.a \
			 $(BUILD_LIBS_PATH)/libnghttp2.a \
			 $(BUILD_LIBS_PATH)/libconfig.a \
			 $(BUILD_LIBS_PATH)/libhttp.a \
			 $(BUILD_LIBS_PATH)/libs.a 

SRCS		= main.c list.c config.c command.c

OBJS		= $(SRCS:.c=.o)

AOUT		= https

DEST		= ../../../bin

#
#---------------------------------------------------------------------
#
all:: clean $(AOUT) install

.SUFFIXES: .c .o
.c.o:
	$(CC) $(CFLAG) $(BUILD_INC_PATH) $(INC_PATH) -c $<


$(AOUT): $(OBJS) 
	$(CC) $(CFLAG) -o $(AOUT) $(OBJS) $(BUILD_LIBS) $(LIB_PATH) $(LIBS) 

install:
	\cp $(AOUT) $(DEST)
	\cp ./server.crt $(DEST)
	\cp ./server.key $(DEST)

clean:
	\rm -f $(OBJS) $(AOUT) core.*
	\rm -rf log
	\rm -rf cscope.out tceetree.out tceetree.out.png
