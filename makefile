vpath %.h ./headers
vpath %.c src
cc=gcc
CFLAGS=-g -Wall
LIBS= -lpcap
DIR_SRC=./src
DIR_INC=./headers
DIR_OBJ=./obj
DIR_BIN=.
TARGET=afu

BIN_TARGET=$(DIR_BIN)/$(TARGET)
SRC=${wildcard $(DIR_SRC)/*.c}
OBJECTS=$(patsubst %.c, ${DIR_OBJ}/%.o, $(notdir ${SRC}))

$(BIN_TARGET) : $(OBJECTS)
	@echo '[Linking...]'$(OBJECTS)
	cc $(OBJECTS) $(LIBS) -o $@
	@echo '[Done]'	

$(DIR_OBJ)/%.o : $(DIR_SRC)/%.c
	@echo '[Compiling...]' $@
	cc $(CFLAGS) -c  $^ -o $@

.PHONY : clean	
clean : 
	-rm $(OBJECTS) $(BIN_TARGET)
