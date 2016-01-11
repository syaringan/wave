
OBJECTS = $(subst .c,.o,$(shell ls *.c))

all:app1 app2

app1: app1.o msocket.o
	$(CC) app1.o msocket.o -o app1 -lapp;
app2: app2.o msocket.o
	$(CC) app2.o msocket.o -o app2 -lapp;

clean :
	rm *.o app1 app2

install :
	#do nothing
