include ../MakeVars

#CFLAG		= $(CFLAGS) -pg -DHAVE_INTTYPES_H -DDEBUG -DLOCAL
CFLAG		= $(CFLAGS) -g -DHAVE_INTTYPE_H

BUILD_INC_PATH	= -I../build/include -I../build/include/glib-2.0 -I../build/lib/glib-2.0/include
BUILD_LIBS_PATH	= ../build/lib
BUILD_LIBS = $(BUILD_LIBS_PATH)/libevent.a \
			 $(BUILD_LIBS_PATH)/libevent_pthreads.a \
			 $(BUILD_LIBS_PATH)/libconfig.a \
			 $(BUILD_LIBS_PATH)/libjson-c.a \
			 $(BUILD_LIBS_PATH)/libs.a

SRCS		= json.c config.c stat.c func.c main.c

OBJS		= $(SRCS:.c=.o)

AOUT		= perfsim

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

clean:
	\rm -f $(OBJS) $(AOUT) core.* 
	\rm -f *.json
	\rm -rf cscope.out tceetree.out tceetree.out.png
