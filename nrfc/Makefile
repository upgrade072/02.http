include ../MakeVars

CFLAG		= $(CFLAGS) -D_GNU_SOURCE

BUILD_INC_PATH	= -I../build/include -I../build/include/glib-2.0 -I../build/lib/glib-2.0/include
BUILD_LIBS_PATH	= ../build/lib
BUILD_LIBS = $(BUILD_LIBS_PATH)/libnrf.a \
			 $(BUILD_LIBS_PATH)/libnrf_app.a \
			 $(BUILD_LIBS_PATH)/libevent.a \
			 $(BUILD_LIBS_PATH)/libglib-2.0.a \
			 $(BUILD_LIBS_PATH)/libconfig.a \
			 $(BUILD_LIBS_PATH)/libjson-c.a \
			 $(BUILD_LIBS_PATH)/libs.a \
			 $(BUILD_LIBS_PATH)/libhttp.a

SRCS		= main.c config.c isif.c status.c command.c mml.c

OBJS		= $(SRCS:.c=.o)

AOUT		= nrfc

DEST		= ../../../bin
DEST2       = ~/PKG_UDM/MP/T1.0.0/bin
DEST3       = ~/PKG_AUSF/MP/T1.0.0/bin

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
	\cp $(AOUT) $(DEST2)
	\cp $(AOUT) $(DEST3)

clean:
	\rm -f $(OBJS) $(AOUT) core.* 
	\rm -rf log
	rm -rf cscope.out tceetree.out tceetree.out.png
