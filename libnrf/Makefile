include ../MakeVars

CFLAG       = $(CFLAGS)  -D_GNU_SOURCE
BUILD_INC_PATH  = -I../build/include -I../build/include/glib-2.0 -I../build/lib/glib-2.0/include

SRCS		= libnrf.c libnrf_app.c
OBJS		= $(SRCS:.c=.o)

AOUT		= libnrf.a libnrf_app.a

DEST_PKG	= ../../..
DEST_BUILD	= ../build

#
#---------------------------------------------------------------------
#
all:: clean $(AOUT) install

.SUFFIXES: .c .o
.c.o:
	\cp ./nrf_comm.h $(DEST_BUILD)/include
	\cp ./libnrf.h $(DEST_BUILD)/include
	\cp ./libnrf_app.h $(DEST_BUILD)/include
	$(CC) $(CFLAG) $(BUILD_INC_PATH) $(INC_PATH) -c $<

libnrf.a: libnrf.o
	$(AR) -rc libnrf.a libnrf.o

libnrf_app.a: libnrf_app.o
	$(AR) -rc libnrf_app.a libnrf_app.o

install:
	\cp libnrf.a $(DEST_PKG)/lib
	\cp libnrf_app.a $(DEST_PKG)/lib
	\cp libnrf.a $(DEST_BUILD)/lib
	\cp libnrf_app.a $(DEST_BUILD)/lib

clean:
	\rm -f $(OBJS) $(AOUT) core.* sample
