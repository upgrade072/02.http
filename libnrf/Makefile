include ../MakeVars

CFLAG       = $(CFLAGS)
BUILD_INC_PATH  = -I../build/include -I../build/include/glib-2.0 -I../build/lib/glib-2.0/include

SRCS		= libnrf.c
OBJS		= $(SRCS:.c=.o)

AOUT		= libnrf.a

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
	\cp ./nrf_comm.h $(DEST_BUILD)/include
	\cp $(AOUT) $(DEST_PKG)/lib
	\cp $(AOUT) $(DEST_BUILD)/lib
#	\gcc ./example.c -o sample -I./ $(INC_PATH) ./$(AOUT) -lpthread -lrt
#	\cp sample $(DEST_PKG)/bin

clean:
	\rm -f $(OBJS) $(AOUT) core.* sample
