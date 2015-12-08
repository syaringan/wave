
TARGET = lib$(notdir $(shell pwd)).a

CFLAGS += -I..
TARGET : crypto.o crypto_interface.o
	$(MAKE) -C ./cryptopp/;
	$(AR) -ru $(TARGET) crypto.o crypto_interface.o  

crypto.o: crypto.c crypto.h
	gcc -c crypto.c  $(CFLAGS)

crypto_interface.o: crypto_interface.cpp crypto_interface.h
	gcc -c crypto_interface.cpp -lstdc++

clean :
	rm $(TARGET) crypto.o crypto_interface.o;
	$(MAKE) -C ./cryptopp/ clean;

install :
	#do nothing
