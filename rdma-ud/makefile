.PHONY: clean
CFLAGS  := -Wall -Werror -g
LD      := gcc
LDLIBS  := -lrdmacm -libverbs -lpthread
APPS    := ud-client ud-server
all: ${APPS}
clean:
	rm -f *.o ${APPS}

