
TARGET = lib$(notdir $(shell pwd)).a
OBJECTS = $(subst .c,.o,$(shell ls *.c))

CFLAGS += -I..
TARGET : $(OBJECTS)
	$(AR) -ru $(TARGET) $(OBJECTS)

clean :
	rm $(TARGET) $(OBJECTS)

install :
	#do nothing
