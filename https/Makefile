include ../MakeVars

CFLAG		= $(CFLAGS)

BUILD_INC_PATH	= -I../build/include -I../build/include/glib-2.0 -I../build/lib/glib-2.0/include
BUILD_LIBS_PATH	= ../build/lib
BUILD_LIBS = $(BUILD_LIBS_PATH)/libjwt.a \
			 $(BUILD_LIBS_PATH)/libjansson.a \
			 $(BUILD_LIBS_PATH)/lbengine.a \
			 $(BUILD_LIBS_PATH)/libssl.a \
			 $(BUILD_LIBS_PATH)/libcrypto.a \
			 $(BUILD_LIBS_PATH)/libevent.a \
			 $(BUILD_LIBS_PATH)/libevent_openssl.a \
			 $(BUILD_LIBS_PATH)/libevent_pthreads.a \
			 $(BUILD_LIBS_PATH)/libnghttp2.a \
			 $(BUILD_LIBS_PATH)/libglib-2.0.a \
			 $(BUILD_LIBS_PATH)/libconfig.a \
			 $(BUILD_LIBS_PATH)/libhttp.a \
			 $(BUILD_LIBS_PATH)/libs.a

SRCS		= main.c list.c config.c command.c lb.c cert.c ovld.c

OBJS		= $(SRCS:.c=.o)

AOUT		= https

DEST		= ../../../bin
DEST2       = ~/PKG_UDM/MP/T1.0.0/bin
DEST3       = ~/PKG_AUSF/MP/T1.0.0/bin

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
	\cp $(AOUT) $(DEST2)
	\cp $(AOUT) $(DEST3)
	\cp ./server.crt $(DEST)
	\cp ./server.key $(DEST)

clean:
	\rm -f $(OBJS) $(AOUT) core.*
	\rm -rf log
	\rm -rf cscope.out tceetree.out tceetree.out.png
