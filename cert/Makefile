
TARGET = certifcate_utils
OBJECTS = $(subst .c,.o,$(shell ls *.c))

CFLAGS += -I.. -g -rdynamic
$(TARGET) : $(OBJECTS)
	$(CC) $(OBJECTS) -o $(TARGET) $(CFLAGS) -L../utils -lutils -L../data -ldata -L../crypto -lcrypto -L../crypto/cryptopp -lcryptopp -lstdc++ -lm

clean :
	rm $(TARGET) $(OBJECTS)

install :
	#do nothing
