#**********************************************************************
#*
#* Makefile for 4758 RPOW server program
#*
#**********************************************************************

# Root directory of IBM Alphaworks toolkit
SCCTK_FS_ROOT=/scctk

# The compiler
CC=i386-linux-gnu-gcc

# The linker
link=$(CC)



bld_env=linux/gcc

cpq_root=$(SCCTK_FS_ROOT)

#
# Directory macros
#
cpqenv=$(cpq_root)/cpqenv/$(bld_env)
libpath=$(cpq_root)/lib/scc/$(bld_env)
cpqxlt_path=$(cpq_root)/bin/linux
osinc=$(cpq_root)/include/env/linux


# The usual libraries
libs1= \
      $(libpath)/clib.a     \
      $(libpath)/cstartex.o \
      $(libpath)/cpqlib.a   \
      $(libpath)/scclib.a   \
      $(libpath)/smlib.a

# need libs several times for Linux 
libs=$(libs1) $(libs1) $(libs1)



# The translator
xlat=$(cpqxlt_path)/cpqxlt

#  specify suffices for MAKE
.SUFFIXES: .c .cpp .o   .xld .a

# Compiler args
#COM_DEF=-D_SCCTK -D_LINUX_ -DPACK_DATA="__attribute__ ((__packed__))"
COM_DEF=-D_SCCTK -D_LINUX_ 
com_inc= -I. -I../common -I$(cpqenv) -I$(cpq_root)/include/scc \
		-I$(cpq_root)/include/common -I$(osinc)
#
#  The next variable controls whether C compiles produce optimised (the
#  second, commented version) or non-optimised (the first, un-commented
#  version) code.
#
# linux -o0 is no optimization.  -o3 is max optimization
#OPTIMIZE=-o0
OPTIMIZE=-O3 -finline-functions -funroll-loops

#
com_opts=-c 
COM_WARN=-Wall
comopts=$(COM_DEF) $(com_inc) $(com_opts) $(COM_WARN) $(OPTIMIZE) $(COM_USER)

#  Linker args
#
#
#link_opts=-static -nostdlib -Xlinker -e -Xlinker _startup 
link_opts=-shared -nostdlib -Xlinker -e -Xlinker startup -Xlinker -Map -Xlinker link.map
linkopts=$(link_opts) $(LINK_USER)

# Translator args
#
xlatopts=$(XLAT_USER)

# Inference Rules
# Note - the "@" on the front of these commands is to suppress the
# echo of the command to the screen by the command processor
#

%.o: %.c
#	@echo ---------  In Source.c to Target.o---in cpqenvtk.mak-----------
	$(CC) $(comopts) -o $*.o $<

%.xld: %.exe
	$(xlat) $< $@ $(xlatopts)


# compiler settings
#
# Linux
# -DDEBUG puts program in spin loop
# -gstabs generates debug info
#COM_USER=-fno-builtin -DDEBUG
#COM_USER=-fno-builtin -gstabs
COM_USER=-fno-builtin

#LINK_USER=
#OPTIMIZE=

# translator options
#   type cpqxlt for options
XLAT_USER=

#**********************************************************************
#* target dependencies
#**********************************************************************

OBJS =	rpow.o keygen.o cryptchan.o dbverify.o hmac.o gbignum.o \
		rpowsign.o rpowutil.o rpio.o persist.o certvalid.o

all:	rpow.rod

rpow.exe: $(OBJS)
	$(link) $(linkopts) -o rpow.exe $(OBJS) $(libs) 

rpow.rod : rpow.xld rpowin.txt
	$(cpq_root)/bin/linux/sccrodsk rpowin.txt $@
	chmod 666 rpow.rod
	./fixrod.pl rpow.rod	# Set date to canonical value



#**********************************************************************
#
#  MAKE rule to clean out the target directory.
#
clean:
	-rm *.o *.exe *.rod *.xld link.map
