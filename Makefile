##Program Written By Hasitha Dias
##Student ID: 789929
##University/GitLab Username: diasi
##Email: i.dias1@student.unimelb.edu.au
##Last Modified Date: 20/05/2018

##Adapted from Workshop 3

CC=gcc
CFLAGS=-lssl -lcrypto
OBJ = certcheck.o
EXE = certcheck

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

$(EXE): $(OBJ)
	$(CC) -o $(EXE) $(OBJ) $(CFLAGS)

certcheck.o: certcheck.h

##Delete object files
clean:
	/bin/rm $(OBJ)
##Performs clean (i.e. delete object files) and deletes executable
clobber: clean
	/bin/rm $(EXE)
