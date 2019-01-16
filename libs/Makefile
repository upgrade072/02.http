include ../../../MakeVars

CFLAG		= 
INC_PATH	= -I. -I../../../include
LIB_PATH	= 
LIBS		= 

BUILD_INC_PATH	=  ../build/include
BUILD_LIBS_PATH	= 
BUILD_LIBS = 

SRCS		= libid.c libutil.c libmml.c liblist.c libomp.c
OBJS		= $(SRCS:.c=.o)
AOUT		= libs.a
DEST		= ../build

#
#---------------------------------------------------------------------
#
all:: clean $(AOUT) install

.SUFFIXES: .c .o
.c.o:
	$(CC) $(BUILD_INC_PATH) $(INC_PATH) -c $<

$(AOUT): $(OBJS) 
	$(AR) -rc $(AOUT) $(OBJS) $(BUILD_LIBS) $(LIB_PATH) $(LIBS) 

install:
	\cp $(AOUT) $(DEST)/lib
	\cp libs.h $(DEST)/include
	\cp uninclude.h $(BUILD_INC_PATH)

clean:
	\rm -f $(OBJS) $(AOUT) core.*
