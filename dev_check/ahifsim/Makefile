include ../../MakeVars

CFLAG		= $(CFLAGS) -Wno-unused-label -Wno-missing-braces

BUILD_INC_PATH	= -I../../build/include -I../../../../include
BUILD_LIBS_PATH	= ../../build/lib
BUILD_LIBS = $(BUILD_LIBS_PATH)/libevent.a \
			 $(BUILD_LIBS_PATH)/libevent_pthreads.a \
			 $(BUILD_LIBS_PATH)/libconfig.a \
			 $(BUILD_LIBS_PATH)/libs.a
LIB_PATH = -L../../../../lib

SRCS		= main.c cb.c pkt.c list.c util.c

OBJS		= $(SRCS:.c=.o)

AOUT		= ahifsim

DEST		= ../../../../bin

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
	\cp $(AOUT) ./test1
	\cp $(AOUT) ./test2

clean:
	\rm -f $(OBJS) $(AOUT) core.* *.out
	\rm -rf cscope.out tceetree.out tceetree.out.png
