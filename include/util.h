#pragma once

#include "common.h"

#include <sys/types.h>

int parse_token(const char *token, tunnel_token_t *out);
int parse_route_arg(route_method_t method, const char *arg, route_t *out);
const route_t *find_route(const route_t *routes, size_t route_count, const char *domain,
                          route_method_t preferred);
int tcp_connect_host(const char *host, const char *port);
int udp_connect_host(const char *host, const char *port);
int set_nonblock(int fd, bool nonblock);
void uuid_v4(uint8_t out[16]);
char *header_value(h2_header_t *headers, size_t count, const char *name);
int websocket_accept(const char *key, char *out, size_t out_len);
ssize_t ws_read_frame(uint8_t *in, size_t in_len, size_t *used, uint8_t *out, size_t out_cap,
                      int *opcode);
int ws_write_binary(int fd, const uint8_t *data, size_t len);
