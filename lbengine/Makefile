include ../MakeVars

CFLAG		= $(CFLAGS)

BUILD_INC_PATH	= -I../build/include  -I../build/include/glib-2.0 -I../build/lib/glib-2.0/include

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
	\cp $(AOUT) $(DEST)/lib
	\cp lbengine.h $(DEST)/include

clean:
	\rm -f $(OBJS) $(AOUT) core.* 
