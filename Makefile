CFLAGS = -Wall -Wno-format -g

all: pgrep pkill

pgrep: proctools.o pgrep.o
	$(CC) $(CFLAGS) -o $@ $> -lkvm
	sudo chgrp kmem pgrep
	sudo chmod 2555 pgrep

pkill: proctools.o pkill.o
	$(CC) $(CFLAGS) -o $@ $> -lkvm
	sudo chgrp kmem pkill
	sudo chmod 2555 pkill

clean:
	rm -f *core *.o pgrep pkill
