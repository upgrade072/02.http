include ../../../../MakeVars

CFLAG		= $(CFLAGS) -g -DPERFORM
#CFLAG		= $(CFLAGS) -g
INC_PATH	= -I. -I../../../../include -I../../../../libsrc/COMM
LIB_PATH	= -L../../../../lib
LIBS		= -lShmQueue -lcomm -lpthread -ldl -lrt

BUILD_INC_PATH	= -I../../build/include
BUILD_LIBS_PATH	= ../../build/lib
BUILD_LIBS = $(BUILD_LIBS_PATH)/libs.a

SRCS		= dummy.c

OBJS		= $(SRCS:.c=.o)

AOUT		= dummy

DEST		= ../../

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
