#!/usr/bin/env python
# Copyright (c) 2019  Diamond Key Security, NFP
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; version 2
# of the License only.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, If not, see <https://www.gnu.org/licenses/>.
#
# Script to import CrypTech code into DKS HSM folders.
#
LIBDKS_SRC ?= .
LIBDKS_BUILD ?= .

SOURCES := $(wildcard $(LIBDKS_SRC)/*.c)
OBJECTS := $(patsubst $(LIBDKS_SRC)/%.c, $(LIBDKS_BUILD)/%.o, $(SOURCES))
LIBRESSL_BLD := ${DKS_ROOT}/sw/thirdparty/libressl
LIBERSSL_INCLUDE := ${LIBRESSL_BLD}/include

LIB		= $(LIBDKS_BUILD)/libdks.a

all: $(LIB)

${LIB}: ${OBJECTS}
	${AR} rcs $@ $^ 

$(LIBDKS_BUILD)/%.o: $(LIBDKS_SRC)/%.c $(LIBDKS_SRC)/%.h
	$(CC) -I${LIBERSSL_INCLUDE} -fPIC -c $< -O -o $@

clean:
	rm -rf $(LIBDKS_BUILD)/*.o
	rm -rf $(LIB)