CC=gcc
CFLAGS=-fPIC -O2 $(shell pkg-config --cflags libseccomp)
LDFLAGS=-shared $(shell pkg-config --libs libseccomp)

all: libesquema.so test

libesquema.so:
	$(CC) $(CFLAGS) c/*.c -o $@ $(LDFLAGS)

test:
	GUILE_AUTO_COMPILE=0 \
	LD_LIBRARY_PATH=$(PWD) \
	guile -L scheme \
	  -c '(use-modules (esquema ffi)) (display (esquema-init)) (newline)'

clean:
	rm -f libesquema.so
