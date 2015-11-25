CC = gcc
CFLAGS += -I..
SUBDIRS = $(shell ls -d */)

all:
	#echo $(SUBDIRS)
	for a in $(SUBDIRS);\
		do $(MAKE) -C a;done

clean:
	for a in $(SUBDIRS);\
		do $(MAKE) -C a clean;done
install:
	for a in $(SUBDORS);\
		do $(MAKE) -C a install;done
