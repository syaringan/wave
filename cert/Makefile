
TARGET = certifcate_utils
OBJECTS = $(subst .c,.o,$(shell ls *.c))

libs =    -L../cme -lcme -L../sec -lsec -L../pssme -lpssme  -L../utils -lutils -L../data/ -ldata -L../crypto -lcrypto -L../crypto/cryptopp -lcryptopp -L../app -lapp -L../cmp -lcmp 


CFLAGS += -I.. -g -rdynamic
$(TARGET) : $(OBJECTS)
	$(CC) $(OBJECTS) -o $(TARGET) $(CFLAGS) $(libs) -lstdc++ -lm -lpthread

clean :
	rm $(TARGET) $(OBJECTS)

install :
	#do nothing
