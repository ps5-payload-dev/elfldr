/* Copyright (C) 2024 John Törnblom

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

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#include <ps5/kernel.h>
#include <ps5/klog.h>

#include "elfldr.h"
#include "notify.h"


/**
 * Read an ELF from a given file descriptor.
 **/
static size_t
readsock(int fd, uint8_t** elf) {
  uint8_t buf[0x4000];
  uint8_t* data = 0;
  uint8_t* bak = 0;
  off_t offset = 0;
  ssize_t len;

  while((len=read(fd, buf, sizeof(buf))) > 0) {
    bak = data;
    if(!(data=realloc(data, offset+len+1))) {
      klog_perror("realloc");
      if(bak) {
        free(bak);
      }
      return 0;
    }

    memcpy(data + offset, buf, len);
    offset += len;
  }

  if(len < 0) {
    klog_perror("read");
    free(data);
    return 0;
  }

  if(offset) {
    data[offset] = 0;
    *elf = data;
  }

  return offset;
}


/**
 * Process connections in induvidual threads.
 **/
static void
on_connection(int fd) {
  uint8_t* elf;
  size_t len;

  if(!(len=readsock(fd, &elf))) {
    return;
  }

  if(elfldr_sanity_check(elf, len)) {
    write(fd, "[elfldr.elf] Malformed ELF file\n\r\0", 34);
  } else {
    elfldr_spawn("payload.elf", fd, elf);
  }

  free(elf);
}


/**
 * Serve ELF loader via a socket.
 **/
static int
serve_elfldr(uint16_t port) {
  static int notify_user = 0;
  struct sockaddr_in srvaddr;
  struct sockaddr_in cliaddr;
  char ip[INET_ADDRSTRLEN];
  struct ifaddrs *ifaddr;
  int ifaddr_wait = 1;
  socklen_t socklen;
  int connfd;
  int srvfd;

  if(getifaddrs(&ifaddr) == -1) {
    klog_perror("getifaddrs");
    return -1;
  }

  // Enumerate all AF_INET IPs
  for(struct ifaddrs *ifa=ifaddr; ifa!=NULL; ifa=ifa->ifa_next) {
    if(ifa->ifa_addr == NULL) {
      continue;
    }

    if(ifa->ifa_addr->sa_family != AF_INET) {
      continue;
    }

    // Skip localhost
    if(!strncmp("lo", ifa->ifa_name, 2)) {
      continue;
    }

    struct sockaddr_in *in = (struct sockaddr_in*)ifa->ifa_addr;
    inet_ntop(AF_INET, &(in->sin_addr), ip, sizeof(ip));

    // Skip interfaces without an IP
    if(!strncmp("0.", ip, 2)) {
      continue;
    }
    ifaddr_wait = 0;

    if(!notify_user) {
      notify("Serving ELF loader on %s:%d (%s)\n", ip, port, ifa->ifa_name);
      notify_user = 1;
    }
    klog_printf("Serving ELF loader on %s:%d (%s)\n", ip, port, ifa->ifa_name);
  }

  freeifaddrs(ifaddr);

  if(ifaddr_wait) {
    return 0;
  }

  if((srvfd=socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    klog_perror("socket");
    return -1;
  }

  if(setsockopt(srvfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
    klog_perror("setsockopt");
    return -1;
  }

  memset(&srvaddr, 0, sizeof(srvaddr));
  srvaddr.sin_family = AF_INET;
  srvaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  srvaddr.sin_port = htons(port);

  if(bind(srvfd, (struct sockaddr*)&srvaddr, sizeof(srvaddr)) != 0) {
    klog_perror("bind");
    return -1;
  }

  if(listen(srvfd, 5) != 0) {
    klog_perror("listen");
    return -1;
  }

  while(1) {
    socklen = sizeof(cliaddr);
    if((connfd=accept(srvfd, (struct sockaddr*)&cliaddr, &socklen)) < 0) {
      klog_perror("accept");
      break;
    }

    on_connection(connfd);
    close(connfd);
  }

  return close(srvfd);
}


/**
 *
 **/
int main() {
  const int port = 9021;
  pid_t pid;

  klog_printf("Socket server was compiled at %s %s\n", __DATE__, __TIME__);

  if(chdir("/")) {
    klog_perror("chdir");
    return -1;
  }

  syscall(SYS_setsid);
  while((pid=elfldr_find_pid("elfldr.elf")) > 0) {
    if(kill(pid, SIGKILL)) {
      klog_perror("kill");
      _exit(-1);
    }
    sleep(1);
  }

  syscall(SYS_thr_set_name, -1, "elfldr.elf");
  signal(SIGCHLD, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);

  while(1) {
    serve_elfldr(port);
    sleep(3);
  }

  return 0;
}

