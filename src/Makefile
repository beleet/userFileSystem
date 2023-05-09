all: test.o userfs.o heap_help.o
	gcc test.o userfs.o heap_help.o

test.o: test.c
	gcc -g -c test.c -o test.o -I ../utils -Wall

userfs.o: userfs.c
	gcc -g -c userfs.c -o userfs.o -Wall

heap_help.o: ../utils/heap_help/heap_help.c
	gcc -g -c ../utils/heap_help/heap_help.c -o heap_help.o

clean :
	-rm test.o userfs.o a.out