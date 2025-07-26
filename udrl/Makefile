CC_64 = x86_64-w64-mingw32-gcc

all:   bin/loader.x64.o

bin:
	mkdir bin

# x64
bin/loader.x64.o: bin
	$(CC_64) -DWIN_X64 -shared -masm=intel -Wall -Wno-pointer-arith -c src/loader.c -o bin/loader.x64.o

# other
clean:
	rm -f bin/*
