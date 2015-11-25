edit: crypto.o crypto_interface.o 
	gcc crypto.o crypto_interface.o /usr/lib/libcryptopp.a -o  -lstdc++ -lm

crypto.o : crypto.c
	gcc -c crypto.c

crypto_interface.o : crypto_interface.cpp crypto_interface.h
	gcc -c crypto_interface.cpp -lstdc++

clean :
	rm edit crypto.o crypto_interface.o
