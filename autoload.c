/* Copyright (C) 2024 John Törnblom
   Copyright (C) 2025 Sunny Qeen

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>.  */

#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include <sys/mman.h>
#include <sys/syscall.h>

#include <ps5/kernel.h>

#include "elfldr.h"
#include "log.h"
#include "notify.h"


/**
 * Process elf file and spawn
 **/
static void
process_elf(const char* fname, int fd) {
  uint8_t* elf;
  size_t len;

  notify("Spawning %s ...", fname);

  if(elfldr_find_pid(fname) > 0) {
    LOG_PERROR("elfldr_find_pid");
  } else if(elfldr_read(fd | 0x80000000, &elf, &len)) {
    LOG_PERROR("elfldr_read");
  } else {
    if(elfldr_spawn(fname, -1, elf) < 0) {
      LOG_PERROR("elfldr_spawn");
    }
    free(elf);
  }
}

/**
 * Process config file
 **/
static void
process_config(int fd) {
  #define CONFIG_SIZE_MAX 1024
  char buf[CONFIG_SIZE_MAX];
  int ret = read(fd, buf, CONFIG_SIZE_MAX - 1);
  buf[ret > 0 ? ret : 0] = 0;
  if (ret > 0) {
    char *start = buf, *end = buf;
    for (; *start != 0;) {
      char ch = *start;
      if (ch == '\r' || ch == '\n') {
        start++;
        end = start;
        continue;
      }

      ch = *end;
      if (ch == '\r' || ch =='\n' || ch == 0) {
        *end = 0;
        if (end > start) {
          if (*start == '#') {
            if (strncmp(start, "##wait ", 7) == 0) {
              if (start[7] > 0x30 && start[7] < 0x3A) {
                sleep(start[7] - 0x30);
              }
            }
          } else {
            int fd1 = open(start, O_RDONLY);
            if (fd1 != -1) {
              process_elf(start, fd1);
              close(fd1);
            }
          }
        }
        start = (ch == 0) ? end : (end + 1);
        end = start;
      } else {
        end++;
      }
    }
  }
}

/**
 * Autoload ELF files.
 **/
static void
autoload_elf() {
  const int conf_path_usb_offset = 16;
  const int conf_path_data_offset = 12;
  char conf_path_usb[] = "/mnt/usb0/elfldr/autoload.cfg";
  char conf_path_data[] = "/data/elfldr/autoload.cfg";

  for (int i = 0; i < 9; i++) {
    char* path;
    int path_offset;
    if (i < 8) {
      conf_path_usb[8] = 0x30 + i;
      path = conf_path_usb;
      path_offset = conf_path_usb_offset;
    } else {
      path = conf_path_data;
      path_offset = conf_path_data_offset;
    }

    int fd = open(path, O_RDONLY);
    if (fd != -1) {
      path[path_offset] = 0;
      if (chdir(path) == 0) {
        process_config(fd);
      }
      close(fd);
      break;
    }
  }
}

/**
 *
 **/
int main() {
  pid_t pid;

  LOG_PRINTF("autoload was compiled at %s %s\n", __DATE__, __TIME__);

  if(chdir("/")) {
    LOG_PERROR("chdir");
    return -1;
  }

  syscall(SYS_setsid);
  if((pid=elfldr_find_pid("autoload.elf")) > 0) {
    return 0;
  }

  syscall(SYS_thr_set_name, -1, "autoload.elf");
  signal(SIGCHLD, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);

  autoload_elf();

  return 0;
}
