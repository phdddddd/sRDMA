#pragma once
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <cassert>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

typedef struct {
  uint64_t remote;
  uint32_t rkey;
  uint32_t length;
  uint32_t psn;
  uint32_t qpn;
  uint64_t reg_begin;
  uint32_t reg_length;
  unsigned char memkey[16];
} exchange_params;

exchange_params server_exchange(uint16_t port, exchange_params *params) {
  int s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (s == -1) {
    perror("socket");
    exit(1);
  }

  int on = 1;
  if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1) {
    perror("setsockopt");
    exit(1);
  }

  struct sockaddr_in sin;
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = PF_INET;
  sin.sin_port = htons(port);
  sin.sin_addr.s_addr = htonl(INADDR_ANY);

  if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) == -1) {
    perror("bind");
    exit(1);
  }

  if (listen(s, 1) == -1) {
    perror("listen");
    exit(1);
  }

  struct sockaddr_in csin;
  socklen_t csinsize = sizeof(csin);
  int c = accept(s, (struct sockaddr *)&csin, &csinsize);
  if (c == -1) {
    perror("accept");
    exit(1);
  }

  int ret = write(c, params, sizeof(*params));
  assert(ret == sizeof(*params));
  ret = read(c, params, sizeof(*params));
  assert(ret == sizeof(*params));

  close(c);
  close(s);
  printf("server exchange done\n");
  return *params;
}

exchange_params client_exchange(const char *server, uint16_t port,
                                exchange_params *params) {
  int s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (s == -1) {
    perror("TCP socket");
    exit(1);
  }

  struct hostent *hent = gethostbyname(server);
  if (hent == NULL) {
    perror("gethostbyname");
    exit(1);
  }

  struct sockaddr_in sin;
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = PF_INET;
  sin.sin_port = htons(port);
  sin.sin_addr = *((struct in_addr *)hent->h_addr);

  if (connect(s, (struct sockaddr *)&sin, sizeof(sin)) == -1) {
    perror(" TCP connect");
    exit(1);
  }

  int ret = write(s, params, sizeof(*params));
  assert(ret == sizeof(*params));
  ret = read(s, params, sizeof(*params));
  assert(ret == sizeof(*params));

  close(s);

  printf("TCP client exchange done\n");
  return *params;
}