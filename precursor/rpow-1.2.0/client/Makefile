# Makefile for RPOW client

HCDIR = ../../hashcash

# For swig
# Mac OSX
PYDIR_OSX = /System/Library/Frameworks/Python.framework/Versions/2.3
PERLDIR_OSX = /System/Library/Perl/5.8.1/darwin-thread-multi-2level/CORE
# Linux
PYDIR_LIN = /usr/include/python2.3
PERLDIR_LIN = /usr/lib/perl/5.8.4/CORE

CFLAGS = -g -c -I. -I../common -I$(HCDIR)
LDFLAGS = -g

HCLIB = $(HCDIR)/libhashcash.a
CLILIB = rpowclient.a

CLIOBJS =  rpowclient.o cryptchan.o certvalid.o util4758.o b64.o keys.o \
		rpio.o rpowutil.o connio.o gbignum.o

all: rpowcli

rpowcli: rpowcli.o $(CLILIB) $(HCLIB)
	gcc $(LDFLAGS) -o rpowcli rpowcli.o $(CLILIB) $(HCLIB) -lcrypto

$(CLILIB):	$(CLIOBJS)
	ar rcs $(CLILIB) $(CLIOBJS)

clean:
	-rm rpowcli rpowcli.o $(CLIOBJS) $(CLILIB) rpow_wrap.* \
		_rpow.so rpow.so rpow.bundle rpow.py rpow.pyc rpow.pm

swig_python_osx:
	swig -python rpow.i
	$(CC) $(CFLAGS) -I$(PYDIR_OSX)/Headers -c rpow_wrap.c
	$(CC) -framework Python -bundle -bundle_loader $(PYDIR_OSX)/bin/python \
	rpow_wrap.o $(CLILIB) $(HCLIB) -lcrypto -o _rpow.so

swig_python_linux:
	swig -python rpow.i
	$(CC) $(CFLAGS) -I$(PYDIR_LIN) -c rpow_wrap.c
	$(CC) -shared rpow_wrap.o $(CLILIB) $(HCLIB) -lcrypto -o _rpow.so

swig_perl_osx:
	swig -perl rpow.i
	$(CC) $(CFLAGS) -I$(PERLDIR_OSX) -c rpow_wrap.c
	$(CC) -bundle -flat_namespace -L$(PERLDIR_OSX) -lperl \
	rpow_wrap.o $(CLILIB) $(HCLIB) -lcrypto -o rpow.bundle

swig_perl_linux:
	swig -perl rpow.i
	$(CC) $(CFLAGS) -D_GNU_SOURCE -I$(PERLDIR_LIN) -c rpow_wrap.c
	$(CC) -shared rpow_wrap.o $(CLILIB) $(HCLIB) -lcrypto -o rpow.so
