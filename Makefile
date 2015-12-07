
SUBDIRS = $(shell ls -d */)
#libs = $(foreach n,$(SUBDIRS),-L./$(n) -l$(subst /,,$(n)))
libs = -L./entry/ -lentry -L./pssme -lpssme  -L./cme -lcme -L./sec -lsec  -L./utils -lutils -L./data/ -ldata -L./crypto -lcrypto -L./app -lapp -L./cmp -lcmp 
wave_sec:
	#echo $(SUBDIRS)
	for a in $(SUBDIRS);\
		do $(MAKE) -C $$a;done;
	$(CC) main.c  -o $@  $(libs) -lpthread

clean:
	for a in $(SUBDIRS);\
		do $(MAKE) -C $$a clean;done
install:
	for a in $(SUBDORS);\
		do $(MAKE) -C $$a install;done
