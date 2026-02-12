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
#include <limits.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#include <ps5/kernel.h>

#include "elfldr.h"
#include "log.h"
#include "notify.h"
#include "selfldr.h"
#include "uri.h"


/**
 * Magic number that socket input starts with (little endian).
 **/
#define PAYLOAD_MAGIC_ELF      0x464C457F // ELF payload
#define PAYLOAD_MAGIC_FILE     0x656C6966 // file:// URI
#define PAYLOAD_MAGIC_HTTP     0x70747468 // http:// or https:// URI
#define PAYLOAD_MAGIC_PS4_SELF 0x1D3D154F // PS4 SELF payload
#define PAYLOAD_MAGIC_PS5_SELF 0xEEF51454 // PS5 SELF payload


/**
 * Spawn an ELF or a SELF payload.
 **/
static int
payload_spawn(int fd, const char* progname, uint8_t* payload, size_t payload_size) {
  int magic = *((int*)payload);

  if(magic == PAYLOAD_MAGIC_ELF) {
    return elfldr_spawn(progname, fd, payload, payload_size);
  }

  if(magic == PAYLOAD_MAGIC_PS4_SELF || magic == PAYLOAD_MAGIC_PS5_SELF) {
    return selfldr_spawn(fd, payload, payload_size);
  }

  return -1;
}


/**
 * Extract the progname from an URI.
 **/
static const char*
payload_progname(const char* uri) {
  const char* progname = "payload.elf";
  size_t len = strlen(uri);

  for(int i=0; i<len; i++) {
    if(uri[i] == '/' && uri[i+1]) {
      progname = uri+i+1;
    }
    else if(uri[i] == '?') {
      break;
    }
  }

  return progname;
}


/**
 *
 **/
static int
read_uri(int fd, char* uri, size_t size) {
  int c;

  for(int i=0; i<size; i++) {
    if(read(fd, &c, 1) != 1) {
      return -1;
    }
    if(c == '\n') {
      uri[i] = 0;
      return 0;
    }
    uri[i] = c;
  }

  return -1;
}


/**
 * Process connection input.
 **/
static void
on_connection(int fd) {
  char uri[PATH_MAX+1] = {0};
  const char* progname;
  uint8_t* buf = 0;
  size_t len = 0;
  int optval = 1;
  int magic = 0;

  if(setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &optval, sizeof(optval)) < 0) {
    LOG_PERROR("setsockopt");
    return;
  }

  if(recv(fd, &magic, sizeof(magic), MSG_PEEK | MSG_WAITALL) != sizeof(magic)) {
    LOG_PERROR("recv");
    write(fd, "[elfldr.elf] Unknown payload format\n\r\0", 38);
    return;
  }

  if(magic == PAYLOAD_MAGIC_FILE || magic == PAYLOAD_MAGIC_HTTP) {
    if(read_uri(fd, uri, PATH_MAX) < 0 || uri_read(uri, &buf, &len)) {
      LOG_PERROR("read_uri");
      write(fd, "[elfldr.elf] Error reading URI payload\n\r\0", 41);
    }

  } else if(magic == PAYLOAD_MAGIC_ELF) {
    if(elfldr_read(fd, &buf, &len)) {
      LOG_PERROR("elfldr_read");
      write(fd, "[elfldr.elf] Error reading ELF payload\n\r\0", 41);
    }

  } else if(magic == PAYLOAD_MAGIC_PS4_SELF || magic == PAYLOAD_MAGIC_PS5_SELF) {
    if(selfldr_read(fd, &buf, &len)) {
      LOG_PERROR("selfldr_read");
      write(fd, "[elfldr.elf] Error reading SELF payload\n\r\0", 42);
    }
  } else {
    write(fd, "[elfldr.elf] Unknown payload format\n\r\0", 38);
  }

  if(buf) {
    progname = payload_progname(uri);
    if(payload_spawn(fd, progname, buf, len) < 0) {
      write(fd, "[elfldr.elf] Error spawning payload\n\r\0", 38);
    }
    free(buf);
  }
}


/**
 * Serve ELF loader via a socket.
 **/
static int
serve_elfldr(uint16_t port) {
  struct sockaddr_in srvaddr;
  struct sockaddr_in cliaddr;
  socklen_t socklen;
  int connfd;
  int srvfd;

  if((srvfd=socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    LOG_PERROR("socket");
    return -1;
  }

  if(setsockopt(srvfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
    LOG_PERROR("setsockopt");
    return -1;
  }

  memset(&srvaddr, 0, sizeof(srvaddr));
  srvaddr.sin_family = AF_INET;
  srvaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  srvaddr.sin_port = htons(port);

  if(bind(srvfd, (struct sockaddr*)&srvaddr, sizeof(srvaddr)) != 0) {
    LOG_PERROR("bind");
    return -1;
  }

  if(listen(srvfd, 5) != 0) {
    LOG_PERROR("listen");
    return -1;
  }

  while(1) {
    socklen = sizeof(cliaddr);
    if((connfd=accept(srvfd, (struct sockaddr*)&cliaddr, &socklen)) < 0) {
      LOG_PERROR("accept");
      break;
    }

    on_connection(connfd);
    close(connfd);
  }

  return close(srvfd);
}


static int
notify_address(const char* prefix, int port) {
  char ip[INET_ADDRSTRLEN] = "127.0.0.1";
  struct ifaddrs *ifaddr;

  if(getifaddrs(&ifaddr) == -1) {
    LOG_PERROR("getifaddrs");
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

    // skip localhost
    if(!strncmp("lo", ifa->ifa_name, 2)) {
      continue;
    }

    struct sockaddr_in *in = (struct sockaddr_in*)ifa->ifa_addr;
    inet_ntop(AF_INET, &(in->sin_addr), ip, sizeof(ip));

    // skip interfaces without an ip
    if(!strncmp("0.", ip, 2)) {
      continue;
    }
  }

  freeifaddrs(ifaddr);

  notify("%s %s:%d", prefix, ip, port);
  LOG_PRINTF("%s %s:%d\n", prefix, ip, port);

  return 0;
}


/**
 *
 **/
int main() {
  int port = 9021;
  pid_t pid;

  LOG_PRINTF("Socket server was compiled at %s %s\n", __DATE__, __TIME__);

  if(chdir("/")) {
    LOG_PERROR("chdir");
    return -1;
  }

  syscall(SYS_setsid);
  while((pid=elfldr_find_pid("elfldr.elf")) > 0) {
    if(kill(pid, SIGKILL)) {
      LOG_PERROR("kill");
      _exit(-1);
    }
    sleep(1);
  }

  syscall(SYS_thr_set_name, -1, "elfldr.elf");
  signal(SIGCHLD, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);

  notify_address("Serving ELF loader on", port);
  while(1) {
    serve_elfldr(port);
    sleep(3);
  }

  return 0;
}
