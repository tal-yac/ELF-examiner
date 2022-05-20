all: myELF

myELF: main.o
	gcc -g -m32 main.o -o myELF

main.o: main.c
	gcc -g -m32 -c  -o main.o main.c

clean:
	rm -rf ./*.o myELF