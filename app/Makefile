
TARGET = lib$(notdir $(shell pwd)).a
OBJECTS = $(subst .c,.o,$(shell ls *.c))
OBJECTS_C = $(shell ls *.c)
CFLAGS += -I..
TARGET : $(OBJECTS)
	#$(AR) -ru $(TARGET) $(OBJECTS) ../af_unix.o

clean :
	-rm $(TARGET) $(OBJECTS);

install :
	$(CC) -c $(OBJECTS_C) -I../;
	$(AR) -ru $(TARGET) $(OBJECTS) ../utils/af_unix.o;
	sudo cp -f $(TARGET) /usr/lib/;
	-sudo mkdir /usr/include/wave/;
	sudo cp -f wave_sec.h /usr/include/wave/;
