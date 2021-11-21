# Targets: mdtest

FREEFARE_DIR	:= ../libfreefare
FREEFARE_SRC	:=  \
			$(FREEFARE_DIR)/libfreefare/freefare.c \
			$(FREEFARE_DIR)/libfreefare/mad.c \
			$(FREEFARE_DIR)/libfreefare/mifare_application.c \
			$(FREEFARE_DIR)/libfreefare/mifare_classic.c \
			$(FREEFARE_DIR)/libfreefare/mifare_desfire.c \
			$(FREEFARE_DIR)/libfreefare/mifare_desfire_aid.c \
			$(FREEFARE_DIR)/libfreefare/mifare_desfire_crypto.c \
			$(FREEFARE_DIR)/libfreefare/mifare_desfire_error.c \
			$(FREEFARE_DIR)/libfreefare/mifare_desfire_key.c \
			$(FREEFARE_DIR)/libfreefare/mifare_ultralight.c \
			$(FREEFARE_DIR)/libfreefare/tlv.c \
			$(FREEFARE_DIR)/libfreefare/mifare_desfire_error.c \
			$(FREEFARE_DIR)/contrib/libutil/hexdump.c
FREEFARE_OBJ	:= $(FREEFARE_SRC:.c=.o)

MDTEST		:= mdtest
MDTEST_SRC	:=	\
			proxydriver.cpp \
			mdtest.cpp \
			mdcomm.pb.cpp \
			mycutter.cpp

CC	      	:= gcc
CXX		:= g++
CFLAGS	  	:= -Wall -g -I$(FREEFARE_DIR) -DWITH_DEBUG -I$(FREEFARE_DIR)/libfreefare -I$(FREEFARE_DIR)/contrib/libutil -I../libnfc/include -I../libnfc/libnfc -I/usr/include/cutter -I.
LINKFLAGS       := -Wall -g -L../libnfc/libnfc/.libs -lnfc -lcppcutter -lcrypto -lssl -lusb -lprotobuf
CC_EXTRA	:= -std=c99


MDTEST_OBJ	 := $(MDTEST_SRC:.cpp=.o)

# all dependency files.
DEP	     := $(MDTEST_OBJ:.o=.d) $(FREEFARE_OBJ:.o=.d)

all:	    $(MDTEST)

%.o:	    %.cpp
		$(CXX) $(CFLAGS) -o $@ -c $<

%.o:	    %.c
		$(CC) $(CFLAGS) $(CC_EXTRA) -o $@ -c $<

$(MDTEST):	 $(MDTEST_OBJ) $(FREEFARE_OBJ)
		$(CXX) $^ $(LINKFLAGS) -o $@

mdcomm.pb.cpp mdcomm.pb.h:	../MDComm/mdcomm.proto
	protoc --cpp_out=. --proto_path=../MDComm ../MDComm/mdcomm.proto
	mv mdcomm.pb.cc mdcomm.pb.cpp

clean:
		rm -f $(MDTEST_OBJ)
		rm -f $(FREEFARE_OBJ)
		rm -f $(DEP)
		rm -f $(MDTEST)
		rm -f mdcomm.pb.cpp mdcomm.pb.h

# dependency autogeneration magic.
include $(DEP)

%.d:	    %.cpp
		$(CXX) -MM -MG $(CFLAGS) $*.cpp | sed -e 's@^\(.*\)\.o:@\1.d \1.o:@' > $@

%.d:	    %.c
		$(CC) -MM -MG $(CFLAGS) $(CC_EXTRA) $*.c | sed -e 's@^\(.*\)\.o:@\1.d \1.o:@' > $@

