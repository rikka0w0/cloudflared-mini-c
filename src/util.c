#include "util.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

static int b64_decode(const char *in, uint8_t *out, size_t out_cap, size_t *out_len) {
    size_t len = strlen(in);
    size_t padded = len + ((4 - len % 4) % 4);
    char *tmp = calloc(1, padded + 1);
    if (!tmp) return -1;
    memcpy(tmp, in, len);
    for (size_t i = len; i < padded; i++) tmp[i] = '=';
    int n = EVP_DecodeBlock(out, (const unsigned char *)tmp, (int)padded);
    if (n < 0 || (size_t)n > out_cap) {
        free(tmp);
        return -1;
    }
    while (padded && tmp[padded - 1] == '=') {
        n--;
        padded--;
    }
    *out_len = (size_t)n;
    free(tmp);
    return 0;
}

static int json_string(const char *json, const char *key, char *out, size_t out_cap) {
    char pat[32];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) return -1;
    p = strchr(p + strlen(pat), ':');
    if (!p) return -1;
    p++;
    while (isspace((unsigned char)*p)) p++;
    if (*p != '"') return -1;
    p++;
    size_t n = 0;
    while (*p && *p != '"' && n + 1 < out_cap) {
        if (*p == '\\' && p[1]) p++;
        out[n++] = *p++;
    }
    out[n] = 0;
    return *p == '"' ? 0 : -1;
}

static int uuid_parse(const char *s, uint8_t out[16]) {
    char hex[33];
    size_t n = 0;
    for (const char *p = s; *p; p++) {
        if (*p == '-') continue;
        if (!isxdigit((unsigned char)*p) || n >= 32) return -1;
        hex[n++] = *p;
    }
    if (n != 32) return -1;
    hex[32] = 0;
    for (int i = 0; i < 16; i++) {
        unsigned int v;
        if (sscanf(hex + i * 2, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

int parse_token(const char *token, tunnel_token_t *out) {
    uint8_t decoded[2048];
    size_t decoded_len = 0;
    memset(out, 0, sizeof(*out));
    if (b64_decode(token, decoded, sizeof(decoded) - 1, &decoded_len) != 0) return -1;
    decoded[decoded_len] = 0;
    char tid[80], secret_b64[256];
    if (json_string((char *)decoded, "a", out->account_tag, sizeof(out->account_tag)) != 0)
        return -1;
    if (json_string((char *)decoded, "t", tid, sizeof(tid)) != 0) return -1;
    if (json_string((char *)decoded, "s", secret_b64, sizeof(secret_b64)) != 0) return -1;
    if (uuid_parse(tid, out->tunnel_id) != 0) return -1;
    if (b64_decode(secret_b64, out->tunnel_secret, sizeof(out->tunnel_secret),
                   &out->tunnel_secret_len) != 0)
        return -1;
    return 0;
}

int parse_route_arg(route_method_t method, const char *arg, route_t *out) {
    memset(out, 0, sizeof(*out));
    out->method = method;
    const char *p1 = strchr(arg, ':');
    const char *p2 = p1 ? strrchr(p1 + 1, ':') : NULL;
    if (!p1 || !p2 || p2 <= p1 + 1) return -1;
    size_t dlen = (size_t)(p1 - arg);
    size_t hlen = (size_t)(p2 - p1 - 1);
    if (dlen >= sizeof(out->domain) || hlen >= sizeof(out->host) ||
        strlen(p2 + 1) >= sizeof(out->port))
        return -1;
    memcpy(out->domain, arg, dlen);
    memcpy(out->host, p1 + 1, hlen);
    strcpy(out->port, p2 + 1);
    return 0;
}

const route_t *find_route(const route_t *routes, size_t route_count, const char *domain,
                          route_method_t preferred) {
    if (!domain || !*domain) return NULL;
    char host[256];
    snprintf(host, sizeof(host), "%s", domain);
    char *colon = strchr(host, ':');
    if (colon) *colon = 0;
    for (size_t i = 0; i < route_count; i++) {
        if (routes[i].method == preferred && strcasecmp(routes[i].domain, host) == 0) return &routes[i];
    }
    return NULL;
}

int tcp_connect_host(const char *host, const char *port) {
    struct addrinfo hints, *res = NULL, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    if (getaddrinfo(host, port, &hints, &res) != 0) return -1;
    int fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

int set_nonblock(int fd, bool nonblock) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    if (nonblock) flags |= O_NONBLOCK;
    else flags &= ~O_NONBLOCK;
    return fcntl(fd, F_SETFL, flags);
}

void uuid_v4(uint8_t out[16]) {
    if (RAND_bytes(out, 16) != 1) {
        for (int i = 0; i < 16; i++) out[i] = (uint8_t)rand();
    }
    out[6] = (out[6] & 0x0f) | 0x40;
    out[8] = (out[8] & 0x3f) | 0x80;
}

char *header_value(h2_header_t *headers, size_t count, const char *name) {
    for (size_t i = 0; i < count; i++) {
        if (strcasecmp(headers[i].name, name) == 0) return headers[i].value;
    }
    return NULL;
}

int websocket_accept(const char *key, char *out, size_t out_len) {
    const char *guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    char tmp[256];
    unsigned char sha[SHA_DIGEST_LENGTH];
    snprintf(tmp, sizeof(tmp), "%s%s", key ? key : "", guid);
    SHA1((const unsigned char *)tmp, strlen(tmp), sha);
    int n = EVP_EncodeBlock((unsigned char *)out, sha, SHA_DIGEST_LENGTH);
    if (n < 0 || (size_t)n >= out_len) return -1;
    out[n] = 0;
    return 0;
}

ssize_t ws_read_frame(uint8_t *in, size_t in_len, size_t *used, uint8_t *out, size_t out_cap,
                      int *opcode) {
    *used = 0;
    if (in_len < 2) return 0;
    uint8_t b0 = in[0], b1 = in[1];
    *opcode = b0 & 0x0f;
    bool masked = (b1 & 0x80) != 0;
    uint64_t len = b1 & 0x7f;
    size_t pos = 2;
    if (len == 126) {
        if (in_len < 4) return 0;
        len = ((uint64_t)in[2] << 8) | in[3];
        pos = 4;
    } else if (len == 127) {
        if (in_len < 10) return 0;
        len = 0;
        for (int i = 0; i < 8; i++) len = (len << 8) | in[2 + i];
        pos = 10;
    }
    uint8_t mask[4] = {0};
    if (masked) {
        if (in_len < pos + 4) return 0;
        memcpy(mask, in + pos, 4);
        pos += 4;
    }
    if (in_len < pos + len) return 0;
    if (len > out_cap) return -1;
    for (uint64_t i = 0; i < len; i++) out[i] = in[pos + i] ^ (masked ? mask[i & 3] : 0);
    *used = pos + (size_t)len;
    return (ssize_t)len;
}

int ws_write_binary(int fd, const uint8_t *data, size_t len) {
    uint8_t hdr[10];
    size_t h = 0;
    hdr[h++] = 0x82;
    if (len < 126) {
        hdr[h++] = (uint8_t)len;
    } else if (len <= 0xffff) {
        hdr[h++] = 126;
        hdr[h++] = (uint8_t)(len >> 8);
        hdr[h++] = (uint8_t)len;
    } else {
        hdr[h++] = 127;
        for (int i = 7; i >= 0; i--) hdr[h++] = (uint8_t)((uint64_t)len >> (i * 8));
    }
    if (write(fd, hdr, h) != (ssize_t)h) return -1;
    return write(fd, data, len) == (ssize_t)len ? 0 : -1;
}

