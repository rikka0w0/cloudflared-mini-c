#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MINI_VERSION "cloudflared-mini-c/0.1"
#define EDGE_SNI "h2.cftunnel.com"
#define EDGE_HOST "region1.v2.argotunnel.com"
#define EDGE_PORT "7844"

#define HEADER_UPGRADE "cf-cloudflared-proxy-connection-upgrade"
#define HEADER_TCP_SRC "cf-cloudflared-proxy-src"

#define MAX_ROUTES 32
#define MAX_HEADERS 128
#define BUF_SIZE 16384

typedef enum {
    ROUTE_WEBSOCKIFY = 1,
    ROUTE_HTTP = 2,
} route_method_t;

typedef struct {
    route_method_t method;
    char domain[256];
    char host[256];
    char port[16];
} route_t;

typedef struct {
    char account_tag[128];
    uint8_t tunnel_id[16];
    uint8_t tunnel_secret[128];
    size_t tunnel_secret_len;
} tunnel_token_t;

typedef struct {
    const char *account_tag;
    const uint8_t *tunnel_secret;
    size_t tunnel_secret_len;
} tunnel_auth_t;

typedef struct {
    const uint8_t *client_id;
    const char *version;
    const char *arch;
    bool replace_existing;
    uint8_t compression_quality;
    uint8_t num_previous_attempts;
} conn_options_t;

typedef struct {
    bool success;
    bool is_bootstrap;
    bool tunnel_is_remote;
    bool should_retry;
    int64_t retry_after_ns;
    char uuid[64];
    char location[32];
    char error[256];
} registration_result_t;

typedef struct {
    char name[128];
    char value[1024];
} h2_header_t;

typedef struct {
    uint8_t *buf;
    size_t cap;
    size_t pos;
} capnp_builder_t;

typedef struct {
    const uint8_t *seg;
    size_t seg_len;
} capnp_reader_t;

static inline void log_info(const char *msg) {
    (void)msg;
}
