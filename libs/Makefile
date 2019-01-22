include ../../../MakeVars

CFLAG		= -std=gnu99
INC_PATH	= -I. -I../../../include
LIB_PATH	= 
LIBS		= 

BUILD_INC_PATH	=  -I../build/include
BUILD_LIBS_PATH	= 
BUILD_LIBS = 

SRCS		= libid.c libutil.c libmml.c liblist.c libomp.c libhdr.c
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
	$(AR) -rc $(AOUT) $(OBJS) $(BUILD_LIBS) $(LIB_PATH) $(LIBS) 

install:
	\cp $(AOUT) $(DEST)/lib
	\cp libs.h $(DEST)/include
	\cp uninclude.h ../build/include

clean:
	\rm -f $(OBJS) $(AOUT) core.*
