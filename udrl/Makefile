CC_64 = x86_64-w64-mingw32-gcc

all:   bin/loader.x64.o
debug: bin/loader.x64.exe

bin:
	mkdir bin

# x64
bin/loader.x64.o: bin
	$(CC_64) -DWIN_X64 -shared -masm=intel -Wall -Wno-pointer-arith -c src/loader.c -o bin/loader.x64.o

#x 64 debug
bin/loader.x64.exe: bin
	$(CC_64) -DWIN_X64 -D_DEBUG -shared -g -masm=intel -Wall -Wno-pointer-arith -c src/loader.c -o bin/loader.x64.o
	$(CC_64) -DWIN_X64 -D_DEBUG -nostartfiles -g -Wl,-e,go bin/loader.x64.o -o bin/loader.x64.exe

# other
clean:
	rm -f bin/*
