
SUBDIRS = $(shell ls -d */)
libs = $(foreach n,$(SUBDIRS),-L./$(n) -l$(subst /,,$(n)))
wave_sec:
	#echo $(SUBDIRS)
	for a in $(SUBDIRS);\
		do $(MAKE) -C $$a;done;
	$(CC) main.c  -o $@  $(libs)

clean:
	for a in $(SUBDIRS);\
		do $(MAKE) -C $$a clean;done
install:
	for a in $(SUBDORS);\
		do $(MAKE) -C $$a install;done
