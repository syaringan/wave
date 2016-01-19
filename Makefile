
SUBDIRS = $(shell ls -d */)
CFLAGS += -g -rdynamic
CC = gcc
#libs = $(foreach n,$(SUBDIRS),-L./$(n) -l$(subst /,,$(n)))
libs = -L./entry/ -lentry -L./pssme -lpssme  -L./sec -lsec -L./cme -lcme  -L./utils -lutils -L./data/ -ldata -L./crypto -lcrypto -L./crypto/cryptopp -lcryptopp -L./app -lapp -L./cmp -lcmp 
wave_sec:
	#echo $(SUBDIRS)
	for a in $(SUBDIRS);\
		do $(MAKE) -C $$a;done;
	$(CC) main.c  -o $@  -I./ $(libs) -lpthread -lstdc++ -lm 

clean:
	for a in $(SUBDIRS);\
		do $(MAKE) -C $$a clean;done;
	rm wave_sec;
install:
	for a in $(SUBDIRS);\
		do $(MAKE) install -C $$a;done;
