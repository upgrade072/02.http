include ../../../MakeVars

CFLAG		= $(CFLAGS)
INC_PATH	= -I. -I../../../include
LIB_PATH	= 
LIBS		=

BUILD_INC_PATH	= 
BUILD_LIBS_PATH	= 
BUILD_LIBS = 

SRCS		= libshm.c libchk.c
OBJS		= $(SRCS:.c=.o)
AOUT		= libhttp.a
DEST_PKG	= ../../..
DEST_BUILD	= ../build

#
#---------------------------------------------------------------------
#
all:: clean $(AOUT) install

.SUFFIXES: .c .o
.c.o:
	$(CC) $(CFLAGS) $(BUILD_INC_PATH) $(INC_PATH) -c $<

$(AOUT): $(OBJS) 
	$(AR) -rc $(AOUT) $(OBJS) $(BUILD_LIBS) $(LIB_PATH) $(LIBS) 

install:
	\cp ./http_comm.h $(DEST_BUILD)/include
	\cp $(AOUT) $(DEST_PKG)/lib
	\cp $(AOUT) $(DEST_BUILD)/lib
	\gcc ./example.c -o sample -I./ $(INC_PATH) ./$(AOUT) -lpthread -lrt
	\cp sample $(DEST_PKG)/bin

clean:
	\rm -f $(OBJS) $(AOUT) core.* sample
