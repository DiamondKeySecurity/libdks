# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#
LIBDKS_SRC ?= .
LIBDKS_BUILD ?= .

SOURCES := $(wildcard $(LIBDKS_SRC)/*.c)
OBJECTS := $(patsubst $(LIBDKS_SRC)/%.c, $(LIBDKS_BUILD)/%.o, $(SOURCES))

LIB		= $(LIBDKS_BUILD)/libdks.a

all: $(LIB)

${LIB}: ${OBJECTS}
	${AR} rcs $@ $^ 

$(LIBDKS_BUILD)/%.o: $(LIBDKS_SRC)/%.c $(LIBDKS_SRC)/%.h
	$(CC) -fPIC -c $< -O -o $@

clean:
	rm -rf $(LIBDKS_BUILD)/*.o
	rm -rf $(LIB)