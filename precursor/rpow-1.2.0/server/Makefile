# Makefile for host 4758 applications
# Remember to set SCCTK_FS_ROOT!!

SCCTK_FS_ROOT=../../scctk

CFLAGS = -g -c -D_LINUX_  -I. -I../common \
	-I$(SCCTK_FS_ROOT)/include/env/linux -I$(SCCTK_FS_ROOT)/include/host \
	-I$(SCCTK_FS_ROOT)/include/common

SCCLIB = /usr/local/lib/libscc.a

SRVOBJS =  rpowsrv.o dbproof.o sha1.o

all: rpowsrv

rpowsrv: $(SRVOBJS)
	gcc -g $(SRVOBJS) $(SCCLIB) -lcrypto -o rpowsrv

clean:
	-rm rpowsrv $(SRVOBJS)
