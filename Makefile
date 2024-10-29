#   Copyright (C) 2024 John Törnblom
#
# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING. If not see
# <http://www.gnu.org/licenses/>.

PS5_HOST ?= ps5
PS5_PORT ?= 9020

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is undefined)
endif

CFLAGS := -Wall -Werror

all: elfldr.elf

socksrv_elf.c: socksrv.elf
bootstrap_elf.c: bootstrap.elf

bootstrap.o: socksrv_elf.c
main.o: bootstrap_elf.c

bootstrap.elf: bootstrap.o elfldr.o pt.o notify.o
	$(CC) -lkernel_sys -o $@ $^

bootstrap_elf.c: bootstrap.elf
	xxd -i $^ > $@

socksrv.elf: socksrv.o elfldr.o pt.o notify.o
	$(CC) -lkernel_sys -o $@ $^

socksrv_elf.c: socksrv.elf
	xxd -i $^ > $@

elfldr.elf: main.o elfldr.o pt.o notify.o
	$(CC) -o $@ $^

clean:
	rm -f bootstrap_elf.c socksrv_elf.c *.o *.elf

test: elfldr.elf
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $^

.INTERMEDIATE: socksrv_elf.c socksrv.elf bootstrap_elf.c bootstrap.elf
