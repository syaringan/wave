
CFLAGS += -I..
LDFLAGS += -L../utils -lutils -L../data -ldata -lpthread

TARGET = lib$(notdir $(shell pwd)).a
OBJECTS = $(subst .c,.o,$(shell ls *.c))


$(TARGET):$(OBJECTS)
	$(AR) -ru $(TARGET) $(OBJECTS)

clean:
	rm $(TARGET) $(OBJECTS)

test:
	$(CC) test.c cme_db.c -o test $(CFLAGS) $(LDFLAGS)
install:
	#do nothing
