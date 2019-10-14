include ../MakeVars

CFLAG		= $(CFLAGS) -Wno-char-subscripts # option for util.c

SRCS		= libid.c libutil.c libmml.c liblist.c libomp.c libhdr.c liblog.c libfort.c
OBJS		= $(SRCS:.c=.o)

AOUT		= libs.a
DEST		= ../build

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
	\cp $(AOUT) $(DEST)/lib
	\cp libs.h $(DEST)/include
	\cp libfort.h $(DEST)/include
	\cp uninclude.h ../build/include

clean:
	\rm -f $(OBJS) $(AOUT) core.*
