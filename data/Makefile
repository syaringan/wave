
CFLAGS += -I..
TARGET = lib$(notdir $(shell pwd)).a

OBJECTS_C := $(shell ls *.c)
OBJECTS_C:= $(filter-out test.c,$(OBJECTS_C))
OBJECTS := $(subst .c,.o,$(OBJECTS_C))
$(TARGET) :$(OBJECTS)
	$(AR) -ru $(TARGET) $(OBJECTS)
clean:
	rm $(OBJECTS) $(TARGET)

install:
	#do nothing

test :test.c $(TAGET)
	$(CC) $< -o $@ $(CFLAGS) -L. -ldata
