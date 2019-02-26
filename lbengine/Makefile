include ../MakeVars

CFLAG		= $(CFLAGS)

BUILD_INC_PATH	= -I../build/include  -I../build/include/glib-2.0 -I../build/lib/glib-2.0/include
BUILD_LIBS_PATH	= ../build/lib
BUILD_LIBS = $(BUILD_LIBS_PATH)/libconfig.a \
			 $(BUILD_LIBS_PATH)/libevent.a \
			 $(BUILD_LIBS_PATH)/libevent_pthreads.a  \
			 $(BUILD_LIBS_PATH)/libglib-2.0.a

SRCS		= util.c iolist.c tcp.c

OBJS		= $(SRCS:.c=.o)

AOUT		= lbengine.a

DEST		= ../build

all:: clean $(AOUT) install

.SUFFIXES: .c .o
.c.o:
	$(CC) $(CFLAG) $(BUILD_INC_PATH) $(INC_PATH) -c $<

$(AOUT): $(OBJS) 
	$(AR) -rc $(AOUT) $(OBJS)

install:
	\cp $(AOUT) $(DEST)/lis
	\cp lbengine.h $(DEST)/lib/include

clean:
	\rm -f $(OBJS) $(AOUT) core.* 
