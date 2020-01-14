include ../MakeVars

CFLAG       = $(CFLAGS)

SRCS		= libshm.c libchk.c libvhdr.c libhutil.c 
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
	$(CC) $(CFLAG) $(BUILD_INC_PATH) $(INC_PATH) -c $<

$(AOUT): $(OBJS) 
	$(AR) -rc $(AOUT) $(OBJS)

install:
	\cp ./http_comm.h $(DEST_BUILD)/include
	\cp $(AOUT) $(DEST_PKG)/lib
	\cp $(AOUT) $(DEST_BUILD)/lib
#	\gcc ./example.c -o sample -I./ $(INC_PATH) ./$(AOUT) -lpthread -lrt  -L../../../lib -lShmQueue -lcomm -lLog
#	\cp sample $(DEST_PKG)/bin

clean:
	\rm -f $(OBJS) $(AOUT) core.* sample
