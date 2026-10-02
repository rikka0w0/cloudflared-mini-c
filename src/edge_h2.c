#include "common.h"
#include "capnp_minimal.h"
#include "control_stream.h"
#include "util.h"

#include <errno.h>
#include <ctype.h>
#include <nghttp2/nghttp2.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

typedef enum {
    STREAM_NEW,
    STREAM_CONTROL,
    STREAM_CONFIG_UPDATE,
    STREAM_HTTP,
    STREAM_WS,
    STREAM_REJECT
} stream_kind_t;

static const char *const DEFAULT_FEATURES[] = {"allow_remote_config"};

static volatile sig_atomic_t g_shutdown_requested = 0;

static void handle_shutdown_signal(int signo) {
    (void)signo;
    g_shutdown_requested = 1;
}

typedef struct out_chunk {
    uint8_t *data;
    size_t len;
    size_t off;
    int eof;
} out_chunk_t;

typedef struct stream {
    int32_t id;
    stream_kind_t kind;
    h2_header_t headers[MAX_HEADERS];
    size_t header_count;
    int origin_fd;
    int response_started;
    int eof_sent;
    int origin_headers_done;
    int http_is_ws;
    int http_has_content_length;
    size_t http_content_length;
    size_t http_body_sent;
    int http_status;
    uint8_t ws_in[BUF_SIZE * 4];
    size_t ws_in_len;
    uint8_t origin_in[BUF_SIZE * 4];
    size_t origin_in_len;
    uint8_t ctrl_in[BUF_SIZE * 4];
    size_t ctrl_in_len;
    uint8_t config_in[BUF_SIZE * 8];
    size_t config_in_len;
    struct stream *next;
} stream_t;

typedef struct {
    SSL *ssl;
    nghttp2_session *session;
    route_t *routes;
    size_t route_count;
    size_t route_capacity;
    int32_t config_version;
    const char *websockify_path;
    tunnel_token_t token;
    uint8_t client_id[16];
    stream_t *streams;
    int32_t control_stream_id;
    int registered;
    int unregister_acked;
    int stopping;
} h2_ctx_t;

static nghttp2_nv nv_lit(const char *name, const char *value) {
    nghttp2_nv nv;
    nv.name = (uint8_t *)name;
    nv.value = (uint8_t *)value;
    nv.namelen = strlen(name);
    nv.valuelen = strlen(value);
    nv.flags = NGHTTP2_NV_FLAG_NONE;
    return nv;
}

static stream_t *find_stream(h2_ctx_t *ctx, int32_t id) {
    for (stream_t *s = ctx->streams; s; s = s->next)
        if (s->id == id) return s;
    return NULL;
}

static stream_t *add_stream(h2_ctx_t *ctx, int32_t id) {
    stream_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->id = id;
    s->origin_fd = -1;
    s->next = ctx->streams;
    ctx->streams = s;
    return s;
}

static void remove_stream(h2_ctx_t *ctx, int32_t id) {
    stream_t **pp = &ctx->streams;
    while (*pp) {
        stream_t *s = *pp;
        if (s->id == id) {
            *pp = s->next;
            if (s->origin_fd >= 0) close(s->origin_fd);
            free(s);
            return;
        }
        pp = &s->next;
    }
}

static ssize_t data_read_cb(nghttp2_session *session, int32_t stream_id, uint8_t *buf,
                            size_t length, uint32_t *data_flags, nghttp2_data_source *source,
                            void *user_data) {
    (void)session;
    (void)stream_id;
    (void)user_data;
    out_chunk_t *c = source->ptr;
    size_t left = c->len - c->off;
    if (left > length) left = length;
    if (left) memcpy(buf, c->data + c->off, left);
    c->off += left;
    if (c->off == c->len) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        if (!c->eof) *data_flags |= NGHTTP2_DATA_FLAG_NO_END_STREAM;
        free(c->data);
        free(c);
    }
    return (ssize_t)left;
}

static int submit_data(h2_ctx_t *ctx, int32_t stream_id, const uint8_t *data, size_t len, int eof) {
    out_chunk_t *c = calloc(1, sizeof(*c));
    if (!c) return -1;
    if (len) {
        c->data = malloc(len);
        if (!c->data) {
            free(c);
            return -1;
        }
        memcpy(c->data, data, len);
    }
    c->len = len;
    c->eof = eof;
    nghttp2_data_provider prd = {.source.ptr = c, .read_callback = data_read_cb};
    int rv = nghttp2_submit_data(ctx->session, NGHTTP2_FLAG_NONE, stream_id, &prd);
    if (rv != 0) {
        free(c->data);
        free(c);
        return -1;
    }
    return 0;
}

static int submit_status_response_data(h2_ctx_t *ctx, stream_t *s, int status, const uint8_t *data,
                                       size_t len, int eof) {
    out_chunk_t *c = calloc(1, sizeof(*c));
    if (!c) return -1;
    if (len) {
        c->data = malloc(len);
        if (!c->data) {
            free(c);
            return -1;
        }
        memcpy(c->data, data, len);
    }
    c->len = len;
    c->eof = eof;
    char st[8];
    snprintf(st, sizeof(st), "%d", status);
    nghttp2_nv nva[] = {nv_lit(":status", st)};
    nghttp2_data_provider prd = {.source.ptr = c, .read_callback = data_read_cb};
    int rv = nghttp2_submit_response(ctx->session, s->id, nva, 1, &prd);
    if (rv != 0) {
        free(c->data);
        free(c);
        return -1;
    }
    s->response_started = 1;
    s->eof_sent = eof;
    return 0;
}

static int send_response(h2_ctx_t *ctx, stream_t *s, int status, nghttp2_nv *extra, size_t extra_n,
                         int end_stream) {
    char st[8];
    snprintf(st, sizeof(st), "%d", status);
    nghttp2_nv nva[8];
    size_t n = 0;
    nva[n++] = nv_lit(":status", st);
    for (size_t i = 0; i < extra_n && n < 8; i++) nva[n++] = extra[i];
    int rv = nghttp2_submit_headers(ctx->session, end_stream ? NGHTTP2_FLAG_END_STREAM : NGHTTP2_FLAG_NONE,
                                    s->id, NULL, nva, n, NULL);
    s->response_started = 1;
    s->eof_sent = end_stream;
    return rv == 0 ? 0 : -1;
}

static int build_h2_headers_from_http(stream_t *s, char *headers, int ws_mode, nghttp2_nv *nva,
                                      size_t *nva_len) {
    char *line_end = strstr(headers, "\r\n");
    if (!line_end) return -1;
    *line_end = 0;
    int status = 502;
    sscanf(headers, "HTTP/%*s %d", &status);
    if (ws_mode && status == 101) status = 200;

    char st[8];
    snprintf(st, sizeof(st), "%d", status);
    size_t n = 0;
    nva[n++] = nv_lit(":status", st);

    char *p = line_end + 2;
    while (*p && n < 64) {
        char *e = strstr(p, "\r\n");
        if (!e) break;
        if (e == p) break;
        *e = 0;
        char *colon = strchr(p, ':');
        if (colon) {
            *colon = 0;
            char *name = p;
            char *value = colon + 1;
            while (*value == ' ' || *value == '\t') value++;
            if (strcasecmp(name, "content-length") == 0) {
                char *endp = NULL;
                unsigned long long v = strtoull(value, &endp, 10);
                if (endp && endp != value) {
                    s->http_has_content_length = 1;
                    s->http_content_length = (size_t)v;
                }
            }
            if (strcasecmp(name, "connection") != 0 && strcasecmp(name, "transfer-encoding") != 0 &&
                strcasecmp(name, "content-length") != 0) {
                for (char *c = name; *c; c++) *c = (char)tolower((unsigned char)*c);
                nva[n++] = nv_lit(name, value);
            }
        }
        p = e + 2;
    }
    *nva_len = n;
    return 0;
}

static void scan_http_content_length(stream_t *s, const char *headers) {
    const char *p = strstr(headers, "\r\n");
    if (!p) return;
    p += 2;
    while (*p) {
        const char *e = strstr(p, "\r\n");
        if (!e || e == p) break;
        const char *colon = memchr(p, ':', (size_t)(e - p));
        if (colon && (size_t)(colon - p) == strlen("content-length") &&
            strncasecmp(p, "content-length", strlen("content-length")) == 0) {
            const char *value = colon + 1;
            while (*value == ' ' || *value == '\t') value++;
            char *endp = NULL;
            unsigned long long v = strtoull(value, &endp, 10);
            if (endp && endp != value) {
                s->http_has_content_length = 1;
                s->http_content_length = (size_t)v;
            }
            return;
        }
        p = e + 2;
    }
}

static int submit_h2_headers_from_http(h2_ctx_t *ctx, stream_t *s, char *headers, int ws_mode) {
    nghttp2_nv nva[64];
    size_t n = 0;
    if (build_h2_headers_from_http(s, headers, ws_mode, nva, &n) != 0) return -1;
    int rv = nghttp2_submit_headers(ctx->session, NGHTTP2_FLAG_NONE, s->id, NULL, nva, n, NULL);
    s->response_started = 1;
    return rv == 0 ? 0 : -1;
}

static int parse_http_status(stream_t *s, const char *headers) {
    int status = 502;
    sscanf(headers, "HTTP/%*s %d", &status);
    s->http_status = status;
    return status;
}

static int parse_websockify_path(const char *path, const char *prefix, char *host, size_t host_len,
                                 char *port, size_t port_len) {
    if (!path || !prefix || !*prefix) return 0;
    if (*path != '/') return 0;
    path++;
    size_t prefix_len = strlen(prefix);
    if (strncmp(path, prefix, prefix_len) != 0) return 0;
    path += prefix_len;
    if (*path != '/') return 0;
    path++;

    const char *slash = strchr(path, '/');
    if (!slash || slash == path) return -1;
    size_t hlen = (size_t)(slash - path);
    if (hlen >= host_len) return -1;
    memcpy(host, path, hlen);
    host[hlen] = 0;

    const char *p = slash + 1;
    const char *end = p;
    while (*end && *end != '/' && *end != '?' && *end != '#') end++;
    if (end == p) return -1;
    size_t plen = (size_t)(end - p);
    if (plen >= port_len) return -1;
    memcpy(port, p, plen);
    port[plen] = 0;
    return 1;
}

static const char *skip_ws(const char *p, const char *end) {
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) p++;
    return p;
}

static const char *find_json_key(const char *start, const char *end, const char *key) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    size_t pat_len = strlen(pat);
    for (const char *p = start; p + pat_len <= end; p++) {
        if (memcmp(p, pat, pat_len) == 0) return p + pat_len;
    }
    return NULL;
}

static int json_string_in_range(const char *start, const char *end, const char *key, char *out,
                                size_t out_cap) {
    const char *p = find_json_key(start, end, key);
    if (!p) return -1;
    p = memchr(p, ':', (size_t)(end - p));
    if (!p) return -1;
    p = skip_ws(p + 1, end);
    if (p >= end || *p != '"') return -1;
    p++;
    size_t n = 0;
    while (p < end && *p != '"') {
        if (*p == '\\' && p + 1 < end) p++;
        if (n + 1 < out_cap) out[n++] = *p;
        p++;
    }
    if (p >= end || *p != '"') return -1;
    out[n] = 0;
    return 0;
}

static int json_int_in_range(const char *start, const char *end, const char *key, int *out) {
    const char *p = find_json_key(start, end, key);
    if (!p) return -1;
    p = memchr(p, ':', (size_t)(end - p));
    if (!p) return -1;
    p = skip_ws(p + 1, end);
    if (p >= end) return -1;
    *out = atoi(p);
    return 0;
}

static const char *json_matching(const char *p, const char *end, char open, char close) {
    int depth = 0;
    int in_str = 0;
    int esc = 0;
    for (; p < end; p++) {
        if (in_str) {
            if (esc) esc = 0;
            else if (*p == '\\') esc = 1;
            else if (*p == '"') in_str = 0;
            continue;
        }
        if (*p == '"') in_str = 1;
        else if (*p == open) depth++;
        else if (*p == close) {
            depth--;
            if (depth == 0) return p + 1;
        }
    }
    return NULL;
}

static int parse_service_url(const char *service, route_t *r) {
    const char *scheme_end = strstr(service, "://");
    if (!scheme_end) return -1;
    size_t scheme_len = (size_t)(scheme_end - service);
    if (scheme_len == 4 && strncasecmp(service, "http", 4) == 0) {
        r->method = ROUTE_HTTP;
    } else {
        return -1;
    }

    const char *hp = scheme_end + 3;
    const char *path = strchr(hp, '/');
    size_t hp_len = path ? (size_t)(path - hp) : strlen(hp);
    if (hp_len == 0 || hp_len >= 300) return -1;

    const char *colon = NULL;
    for (const char *p = hp; p < hp + hp_len; p++) {
        if (*p == ':') colon = p;
    }
    size_t host_len = colon ? (size_t)(colon - hp) : hp_len;
    if (host_len == 0 || host_len >= sizeof(r->host)) return -1;
    memcpy(r->host, hp, host_len);
    r->host[host_len] = 0;

    const char *port = NULL;
    char default_port[4];
    if (colon && colon + 1 < hp + hp_len) {
        port = colon + 1;
        size_t port_len = (size_t)(hp + hp_len - port);
        if (port_len == 0 || port_len >= sizeof(r->port)) return -1;
        memcpy(r->port, port, port_len);
        r->port[port_len] = 0;
    } else {
        snprintf(default_port, sizeof(default_port), "%d", 80);
        snprintf(r->port, sizeof(r->port), "%s", default_port);
    }
    return 0;
}

static int apply_remote_config(h2_ctx_t *ctx, const uint8_t *data, size_t len, int *version_out,
                               char *err, size_t err_len) {
    const char *json = (const char *)data;
    const char *end = json + len;
    int version = 0;
    json_int_in_range(json, end, "version", &version);
    if (version_out) *version_out = version;

    const char *ing = find_json_key(json, end, "ingress");
    if (!ing) {
        snprintf(err, err_len, "missing ingress");
        return -1;
    }
    ing = memchr(ing, '[', (size_t)(end - ing));
    if (!ing) {
        snprintf(err, err_len, "missing ingress array");
        return -1;
    }
    const char *arr_end = json_matching(ing, end, '[', ']');
    if (!arr_end) {
        snprintf(err, err_len, "unterminated ingress array");
        return -1;
    }

    route_t next[MAX_ROUTES];
    size_t next_count = 0;
    const char *p = ing + 1;
    while (p < arr_end) {
        p = skip_ws(p, arr_end);
        if (p >= arr_end || *p == ']') break;
        if (*p != '{') {
            p++;
            continue;
        }
        const char *obj_end = json_matching(p, arr_end, '{', '}');
        if (!obj_end) break;

        char hostname[256] = {0};
        char service[512] = {0};
        if (json_string_in_range(p, obj_end, "service", service, sizeof(service)) == 0 &&
            json_string_in_range(p, obj_end, "hostname", hostname, sizeof(hostname)) == 0) {
            route_t r;
            memset(&r, 0, sizeof(r));
            snprintf(r.domain, sizeof(r.domain), "%s", hostname);
            if (parse_service_url(service, &r) == 0) {
                if (next_count < ctx->route_capacity) {
                    next[next_count++] = r;
                    fprintf(stderr, "remote route: %s -> http://%s:%s\n", r.domain, r.host,
                            r.port);
                }
            }
        }
        p = obj_end;
    }

    memcpy(ctx->routes, next, next_count * sizeof(next[0]));
    ctx->route_count = next_count;
    ctx->config_version = version;
    fprintf(stderr, "applied remote config version=%d routes=%zu\n", version, next_count);
    return 0;
}

static void append_origin_request_header(char *buf, size_t cap, size_t *pos, const char *name,
                                         const char *value) {
    if (!name || !value || !*name) return;
    if (name[0] == ':') return;
    if (strcasecmp(name, HEADER_UPGRADE) == 0 || strcasecmp(name, HEADER_TCP_SRC) == 0) return;
    if (strcasecmp(name, "connection") == 0 || strcasecmp(name, "keep-alive") == 0 ||
        strcasecmp(name, "proxy-connection") == 0 || strcasecmp(name, "transfer-encoding") == 0)
        return;
    int n = snprintf(buf + *pos, cap - *pos, "%s: %s\r\n", name, value);
    if (n > 0 && (size_t)n < cap - *pos) *pos += (size_t)n;
}

static int send_http_origin_request(stream_t *s, int ws_mode) {
    char *method = header_value(s->headers, s->header_count, ":method");
    char *path = header_value(s->headers, s->header_count, ":path");
    char *host = header_value(s->headers, s->header_count, ":authority");
    if (!method) method = "GET";
    if (!path) path = "/";
    if (!host) host = header_value(s->headers, s->header_count, "host");

    char req[BUF_SIZE];
    size_t pos = 0;
    int n = snprintf(req + pos, sizeof(req) - pos, "%s %s HTTP/1.1\r\n", method, path);
    if (n <= 0 || (size_t)n >= sizeof(req) - pos) return -1;
    pos += (size_t)n;
    if (host) {
        n = snprintf(req + pos, sizeof(req) - pos, "Host: %s\r\n", host);
        if (n <= 0 || (size_t)n >= sizeof(req) - pos) return -1;
        pos += (size_t)n;
    }
    if (ws_mode) {
        n = snprintf(req + pos, sizeof(req) - pos, "Connection: Upgrade\r\nUpgrade: websocket\r\n");
        if (n <= 0 || (size_t)n >= sizeof(req) - pos) return -1;
        pos += (size_t)n;
    } else {
        n = snprintf(req + pos, sizeof(req) - pos, "Connection: close\r\n");
        if (n <= 0 || (size_t)n >= sizeof(req) - pos) return -1;
        pos += (size_t)n;
    }
    for (size_t i = 0; i < s->header_count; i++) {
        append_origin_request_header(req, sizeof(req), &pos, s->headers[i].name, s->headers[i].value);
    }
    if (pos + 2 >= sizeof(req)) return -1;
    memcpy(req + pos, "\r\n", 2);
    pos += 2;
    return send(s->origin_fd, req, pos, MSG_NOSIGNAL) == (ssize_t)pos ? 0 : -1;
}

static int encode_ws_binary(const uint8_t *data, size_t len, uint8_t **out, size_t *out_len) {
    size_t hdr = len < 126 ? 2 : (len <= 0xffff ? 4 : 10);
    uint8_t *b = malloc(hdr + len);
    if (!b) return -1;
    size_t p = 0;
    b[p++] = 0x82;
    if (len < 126) {
        b[p++] = (uint8_t)len;
    } else if (len <= 0xffff) {
        b[p++] = 126;
        b[p++] = (uint8_t)(len >> 8);
        b[p++] = (uint8_t)len;
    } else {
        b[p++] = 127;
        for (int i = 7; i >= 0; i--) b[p++] = (uint8_t)((uint64_t)len >> (i * 8));
    }
    memcpy(b + p, data, len);
    *out = b;
    *out_len = hdr + len;
    return 0;
}

static int start_stream(h2_ctx_t *ctx, stream_t *s) {
    char *internal = header_value(s->headers, s->header_count, HEADER_UPGRADE);
    char *host = header_value(s->headers, s->header_count, ":authority");
    if (!host) host = header_value(s->headers, s->header_count, "host");
    char *path = header_value(s->headers, s->header_count, ":path");

    if (internal && strcasecmp(internal, "control-stream") == 0) {
        s->kind = STREAM_CONTROL;
        ctx->control_stream_id = s->id;
        if (send_response(ctx, s, 200, NULL, 0, 0) != 0) return -1;
        tunnel_auth_t auth = {.account_tag = ctx->token.account_tag,
                              .tunnel_secret = ctx->token.tunnel_secret,
                              .tunnel_secret_len = ctx->token.tunnel_secret_len};
        conn_options_t opts = {.client_id = ctx->client_id,
                               .version = MINI_VERSION,
                               .arch = "linux",
                               .features = DEFAULT_FEATURES,
                               .feature_count = sizeof(DEFAULT_FEATURES) / sizeof(DEFAULT_FEATURES[0]),
                               .compression_quality = 0,
                               .replace_existing = false,
                               .num_previous_attempts = 0};
        uint8_t reg[8192];
        size_t reg_len = 0;
        if (control_stream_encode_register(&auth, ctx->token.tunnel_id, 16, 0, &opts, reg,
                                           sizeof(reg), &reg_len) != 0) {
            fprintf(stderr, "failed to encode registration RPC\n");
            return -1;
        }
        fprintf(stderr, "control stream: sending registration (%zu bytes)\n", reg_len);
        return submit_data(ctx, s->id, reg, reg_len, 0);
    }

    if (internal && strcasecmp(internal, "update-configuration") == 0) {
        s->kind = STREAM_CONFIG_UPDATE;
        fprintf(stderr, "configuration update stream %d opened\n", s->id);
        return send_response(ctx, s, 200, NULL, 0, 0);
    }

    int ws_mode = internal && strcasecmp(internal, "websocket") == 0;
    const route_t *hr = find_route(ctx->routes, ctx->route_count, host, ROUTE_HTTP);
    if (hr) {
        char ws_host[256], ws_port[16];
        int ws_path = parse_websockify_path(path, ctx->websockify_path, ws_host, sizeof(ws_host),
                                            ws_port, sizeof(ws_port));
        if (ws_path != 0) {
            if (ws_path < 0 || !ws_mode) {
                s->kind = STREAM_REJECT;
                return send_response(ctx, s, 404, NULL, 0, 1);
            }
            char *key = header_value(s->headers, s->header_count, "sec-websocket-key");
            if (!key) {
                s->kind = STREAM_REJECT;
                return send_response(ctx, s, 404, NULL, 0, 1);
            }
            s->origin_fd = tcp_connect_host(ws_host, ws_port);
            if (s->origin_fd < 0) {
                s->kind = STREAM_REJECT;
                return send_response(ctx, s, 502, NULL, 0, 1);
            }
            set_nonblock(s->origin_fd, true);
            char accept[128];
            websocket_accept(key, accept, sizeof(accept));
            nghttp2_nv extra[] = {nv_lit("connection", "Upgrade"),
                                  nv_lit("upgrade", "websocket"),
                                  nv_lit("sec-websocket-accept", accept)};
            s->kind = STREAM_WS;
            fprintf(stderr, "websockify path stream %d: /%s -> %s:%s\n", s->id,
                    ctx->websockify_path, ws_host, ws_port);
            return send_response(ctx, s, 200, extra, 3, 0);
        }

        s->origin_fd = tcp_connect_host(hr->host, hr->port);
        if (s->origin_fd < 0) {
            s->kind = STREAM_REJECT;
            return send_response(ctx, s, 502, NULL, 0, 1);
        }
        set_nonblock(s->origin_fd, true);
        s->kind = STREAM_HTTP;
        s->http_is_ws = ws_mode;
        fprintf(stderr, "http stream %d%s: %s -> %s:%s\n", s->id, ws_mode ? " websocket" : "",
                hr->domain, hr->host, hr->port);
        if (send_http_origin_request(s, ws_mode) != 0) {
            s->kind = STREAM_REJECT;
            return send_response(ctx, s, 502, NULL, 0, 1);
        }
        return 0;
    }

    if (ws_mode) {
        s->kind = STREAM_REJECT;
        return send_response(ctx, s, 403, NULL, 0, 1);
    }

    s->kind = STREAM_REJECT;
    return send_response(ctx, s, 404, NULL, 0, 1);
}

static int on_begin_headers_cb(nghttp2_session *session, const nghttp2_frame *frame,
                               void *user_data) {
    (void)session;
    h2_ctx_t *ctx = user_data;
    if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
        if (!find_stream(ctx, frame->hd.stream_id)) add_stream(ctx, frame->hd.stream_id);
    }
    return 0;
}

static int on_header_cb(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name,
                        size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags,
                        void *user_data) {
    (void)session;
    (void)flags;
    h2_ctx_t *ctx = user_data;
    stream_t *s = find_stream(ctx, frame->hd.stream_id);
    if (!s || s->header_count >= MAX_HEADERS) return 0;
    snprintf(s->headers[s->header_count].name, sizeof(s->headers[s->header_count].name), "%.*s",
             (int)namelen, name);
    snprintf(s->headers[s->header_count].value, sizeof(s->headers[s->header_count].value), "%.*s",
             (int)valuelen, value);
    s->header_count++;
    return 0;
}

static int on_frame_recv_cb(nghttp2_session *session, const nghttp2_frame *frame, void *user_data) {
    (void)session;
    h2_ctx_t *ctx = user_data;
    if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
        stream_t *s = find_stream(ctx, frame->hd.stream_id);
        if (s) start_stream(ctx, s);
    }
    return 0;
}

static int on_stream_close_cb(nghttp2_session *session, int32_t stream_id, uint32_t error_code,
                              void *user_data) {
    (void)session;
    (void)error_code;
    h2_ctx_t *ctx = user_data;
    remove_stream(ctx, stream_id);
    return 0;
}

static int on_data_chunk_recv_cb(nghttp2_session *session, uint8_t flags, int32_t stream_id,
                                 const uint8_t *data, size_t len, void *user_data) {
    (void)session;
    (void)flags;
    h2_ctx_t *ctx = user_data;
    stream_t *s = find_stream(ctx, stream_id);
    if (!s) return 0;
    if (s->kind == STREAM_CONTROL) {
        if (s->ctrl_in_len + len > sizeof(s->ctrl_in)) {
            s->ctrl_in_len = 0;
            return 0;
        }
        memcpy(s->ctrl_in + s->ctrl_in_len, data, len);
        s->ctrl_in_len += len;
        for (;;) {
            size_t msg = capnp_wire_message_size(s->ctrl_in, s->ctrl_in_len);
            if (!msg) break;
            registration_result_t rr;
            if (control_stream_decode_response(s->ctrl_in, msg, &rr) == 0) {
                if (rr.is_bootstrap) {
                    fprintf(stderr, "control stream: bootstrap acknowledged\n");
                } else if (rr.success) {
                    if (rr.unregister_ack) {
                        ctx->unregister_acked = 1;
                        fprintf(stderr, "unregistered tunnel connection\n");
                    } else {
                        ctx->registered = 1;
                        fprintf(stderr, "registered: uuid=%s location=%s remote=%d\n", rr.uuid,
                                rr.location, rr.tunnel_is_remote);
                    }
                } else {
                    fprintf(stderr, "registration error: %s retry=%d\n", rr.error, rr.should_retry);
                }
            }
            memmove(s->ctrl_in, s->ctrl_in + msg, s->ctrl_in_len - msg);
            s->ctrl_in_len -= msg;
        }
    } else if (s->kind == STREAM_HTTP && s->origin_fd >= 0) {
        send(s->origin_fd, data, len, MSG_NOSIGNAL);
    } else if (s->kind == STREAM_CONFIG_UPDATE) {
        if (s->config_in_len + len > sizeof(s->config_in)) {
            fprintf(stderr, "configuration update too large; dropping buffer\n");
            s->config_in_len = 0;
            return 0;
        }
        memcpy(s->config_in + s->config_in_len, data, len);
        s->config_in_len += len;
        if (flags & NGHTTP2_FLAG_END_STREAM) {
            int version = 0;
            char err[256] = {0};
            int ok = apply_remote_config(ctx, s->config_in, s->config_in_len, &version, err,
                                         sizeof(err)) == 0;
            char resp[384];
            if (ok) {
                snprintf(resp, sizeof(resp), "{\"latestAppliedVersion\":%d,\"err\":\"\"}\n",
                         version);
            } else {
                snprintf(resp, sizeof(resp), "{\"latestAppliedVersion\":%d,\"err\":\"%s\"}\n",
                         ctx->config_version, err);
            }
            submit_data(ctx, s->id, (const uint8_t *)resp, strlen(resp), 1);
        }
    } else if (s->kind == STREAM_WS && s->origin_fd >= 0) {
        if (s->ws_in_len + len > sizeof(s->ws_in)) {
            s->ws_in_len = 0;
            return 0;
        }
        memcpy(s->ws_in + s->ws_in_len, data, len);
        s->ws_in_len += len;
        for (;;) {
            uint8_t plain[BUF_SIZE];
            size_t used = 0;
            int opcode = 0;
            ssize_t n = ws_read_frame(s->ws_in, s->ws_in_len, &used, plain, sizeof(plain), &opcode);
            if (n == 0) break;
            if (n < 0 || opcode == 0x8) {
                close(s->origin_fd);
                s->origin_fd = -1;
                break;
            }
            if (opcode == 0x2 || opcode == 0x1 || opcode == 0x0) {
                send(s->origin_fd, plain, (size_t)n, MSG_NOSIGNAL);
            }
            memmove(s->ws_in, s->ws_in + used, s->ws_in_len - used);
            s->ws_in_len -= used;
        }
    }
    return 0;
}

static int send_pending(h2_ctx_t *ctx) {
    const uint8_t *data;
    for (;;) {
        ssize_t len = nghttp2_session_mem_send(ctx->session, &data);
        if (len < 0) return -1;
        if (len == 0) return 0;
        size_t off = 0;
        while (off < (size_t)len) {
            int n = SSL_write(ctx->ssl, data + off, (int)((size_t)len - off));
            if (n <= 0) return -1;
            off += (size_t)n;
        }
    }
}

static void recv_edge_once(h2_ctx_t *ctx, SSL *ssl) {
    uint8_t buf[BUF_SIZE];
    int n = SSL_read(ssl, buf, sizeof(buf));
    if (n > 0) {
        ssize_t rv = nghttp2_session_mem_recv(ctx->session, buf, (size_t)n);
        if (rv < 0) {
            fprintf(stderr, "nghttp2 recv error during shutdown: %s\n", nghttp2_strerror((int)rv));
            ctx->stopping = 1;
        }
    }
}

static void graceful_shutdown_control(h2_ctx_t *ctx, int edge_fd) {
    if (!ctx->registered || ctx->control_stream_id <= 0) return;

    uint8_t msg[512];
    size_t msg_len = 0;
    if (control_stream_encode_unregister(msg, sizeof(msg), &msg_len) != 0) {
        fprintf(stderr, "failed to encode unregister RPC\n");
        return;
    }

    fprintf(stderr, "control stream: sending unregister (%zu bytes)\n", msg_len);
    if (submit_data(ctx, ctx->control_stream_id, msg, msg_len, 0) != 0 || send_pending(ctx) != 0) {
        fprintf(stderr, "failed to send unregister RPC\n");
        return;
    }

    for (int waited_ms = 0; waited_ms < 5000 && !ctx->unregister_acked; waited_ms += 100) {
        struct pollfd pfd;
        pfd.fd = edge_fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        int pr = poll(&pfd, 1, 100);
        if (pr < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (pr > 0 && (pfd.revents & (POLLIN | POLLHUP | POLLERR))) recv_edge_once(ctx, ctx->ssl);
        if (send_pending(ctx) != 0) break;
    }

    if (!ctx->unregister_acked) fprintf(stderr, "unregister sent; closing edge connection\n");

    submit_data(ctx, ctx->control_stream_id, NULL, 0, 1);
    nghttp2_submit_goaway(ctx->session, NGHTTP2_FLAG_NONE, 0, NGHTTP2_NO_ERROR, NULL, 0);
    send_pending(ctx);
}

static int tls_connect_edge(SSL_CTX **out_ctx, SSL **out_ssl) {
    int fd = tcp_connect_host(EDGE_HOST, EDGE_PORT);
    if (fd < 0) return -1;
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return -1;
    SSL_CTX_set_default_verify_paths(ctx);
    SSL_CTX_load_verify_locations(ctx, "/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/certs");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, EDGE_SNI);
    const unsigned char alpn[] = {2, 'h', '2'};
    SSL_set_alpn_protos(ssl, alpn, sizeof(alpn));
    if (SSL_connect(ssl) != 1) {
        ERR_print_errors_fp(stderr);
        close(fd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return -1;
    }
    const unsigned char *proto = NULL;
    unsigned int proto_len = 0;
    SSL_get0_alpn_selected(ssl, &proto, &proto_len);
    if (proto_len == 2 && memcmp(proto, "h2", 2) == 0) {
        fprintf(stderr, "edge negotiated ALPN h2\n");
    } else {
        fprintf(stderr, "edge did not negotiate ALPN h2; continuing with HTTP/2 framing\n");
    }
    set_nonblock(fd, true);
    *out_ctx = ctx;
    *out_ssl = ssl;
    return fd;
}

static int init_h2(h2_ctx_t *ctx) {
    nghttp2_session_callbacks *cb;
    nghttp2_session_callbacks_new(&cb);
    nghttp2_session_callbacks_set_on_begin_headers_callback(cb, on_begin_headers_cb);
    nghttp2_session_callbacks_set_on_header_callback(cb, on_header_cb);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cb, on_frame_recv_cb);
    nghttp2_session_callbacks_set_on_stream_close_callback(cb, on_stream_close_cb);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cb, on_data_chunk_recv_cb);
    nghttp2_session_server_new(&ctx->session, cb, ctx);
    nghttp2_session_callbacks_del(cb);
    nghttp2_settings_entry iv[] = {{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 1024},
                                   {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 1024 * 1024}};
    return nghttp2_submit_settings(ctx->session, NGHTTP2_FLAG_NONE, iv, 2);
}

static void pump_origins(h2_ctx_t *ctx, struct pollfd *pfds, int base, int nfds) {
    int idx = base;
    for (stream_t *s = ctx->streams; s; s = s->next) {
        if (s->origin_fd < 0) continue;
        if (idx >= nfds) break;
        if (pfds[idx].revents & (POLLIN | POLLHUP | POLLERR)) {
            uint8_t buf[BUF_SIZE];
            ssize_t n = recv(s->origin_fd, buf, sizeof(buf), 0);
            if (n > 0) {
            if (s->kind == STREAM_WS) {
                uint8_t *fr = NULL;
                size_t fr_len = 0;
                if (encode_ws_binary(buf, (size_t)n, &fr, &fr_len) == 0) {
                    submit_data(ctx, s->id, fr, fr_len, 0);
                    free(fr);
                }
            } else if (s->kind == STREAM_HTTP && !s->origin_headers_done) {
                if (s->origin_in_len + (size_t)n > sizeof(s->origin_in)) {
                    submit_data(ctx, s->id, NULL, 0, 1);
                    s->eof_sent = 1;
                    close(s->origin_fd);
                    s->origin_fd = -1;
                    idx++;
                    continue;
                }
                memcpy(s->origin_in + s->origin_in_len, buf, (size_t)n);
                s->origin_in_len += (size_t)n;
                uint8_t *end = NULL;
                for (size_t j = 3; j < s->origin_in_len; j++) {
                    if (s->origin_in[j - 3] == '\r' && s->origin_in[j - 2] == '\n' &&
                        s->origin_in[j - 1] == '\r' && s->origin_in[j] == '\n') {
                        end = s->origin_in + j + 1;
                        break;
                    }
                }
                if (end) {
                    size_t header_len = (size_t)(end - s->origin_in);
                    char hdrbuf[BUF_SIZE * 4];
                    memcpy(hdrbuf, s->origin_in, header_len);
                    hdrbuf[header_len] = 0;
                    scan_http_content_length(s, hdrbuf);
                    size_t body_len = s->origin_in_len - header_len;
                    if (!s->http_is_ws && s->http_has_content_length &&
                        body_len > s->http_content_length) {
                        body_len = s->http_content_length;
                    }
                    if (s->http_is_ws) {
                        submit_h2_headers_from_http(ctx, s, hdrbuf, 1);
                    } else {
                        parse_http_status(s, hdrbuf);
                        int done = s->http_has_content_length &&
                                   body_len >= s->http_content_length;
                        if (body_len) {
                            submit_status_response_data(ctx, s, s->http_status,
                                                        s->origin_in + header_len, body_len, done);
                            s->http_body_sent += body_len;
                        } else if (s->http_has_content_length && s->http_content_length == 0) {
                            submit_status_response_data(ctx, s, s->http_status, NULL, 0, 1);
                            done = 1;
                        }
                        if (done) {
                            s->eof_sent = 1;
                            close(s->origin_fd);
                            s->origin_fd = -1;
                        }
                    }
                    s->origin_headers_done = 1;
                    s->origin_in_len = 0;
                }
            } else if (s->kind == STREAM_HTTP && !s->http_is_ws && s->http_has_content_length) {
                size_t remaining = s->http_content_length - s->http_body_sent;
                size_t send_len = (size_t)n < remaining ? (size_t)n : remaining;
                s->http_body_sent += send_len;
                int done = s->http_body_sent >= s->http_content_length;
                if (!s->response_started) {
                    submit_status_response_data(ctx, s, s->http_status ? s->http_status : 200, buf,
                                                send_len, done);
                } else if (send_len || done) {
                    submit_data(ctx, s->id, buf, send_len, done);
                }
                if (done) {
                    s->eof_sent = 1;
                    close(s->origin_fd);
                    s->origin_fd = -1;
                }
            } else {
                submit_data(ctx, s->id, buf, (size_t)n, 0);
            }
            } else if (!s->eof_sent) {
                submit_data(ctx, s->id, NULL, 0, 1);
                s->eof_sent = 1;
                close(s->origin_fd);
                s->origin_fd = -1;
            }
        }
        idx++;
    }
}

int run_edge_h2(const tunnel_token_t *token, route_t *routes, size_t route_count,
                const char *websockify_path) {
    SSL_library_init();
    SSL_load_error_strings();
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, handle_shutdown_signal);
    signal(SIGTERM, handle_shutdown_signal);

    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;
    int edge_fd = tls_connect_edge(&ssl_ctx, &ssl);
    if (edge_fd < 0) {
        fprintf(stderr, "failed to connect edge %s:%s\n", EDGE_HOST, EDGE_PORT);
        return 1;
    }
    fprintf(stderr, "connected to edge %s:%s using h2\n", EDGE_HOST, EDGE_PORT);

    h2_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ssl = ssl;
    ctx.routes = routes;
    ctx.route_count = route_count;
    ctx.route_capacity = MAX_ROUTES;
    ctx.token = *token;
    ctx.websockify_path = websockify_path;
    ctx.control_stream_id = -1;
    uuid_v4(ctx.client_id);
    if (init_h2(&ctx) != 0) return 1;
    send_pending(&ctx);

    while (!ctx.stopping) {
        if (g_shutdown_requested) {
            ctx.stopping = 1;
            break;
        }
        int count = 1;
        for (stream_t *s = ctx.streams; s && count < 256; s = s->next)
            if (s->origin_fd >= 0) count++;
        struct pollfd pfds[256];
        pfds[0].fd = edge_fd;
        pfds[0].events = POLLIN;
        int i = 1;
        for (stream_t *s = ctx.streams; s && i < 256; s = s->next) {
            if (s->origin_fd >= 0) {
                pfds[i].fd = s->origin_fd;
                pfds[i].events = POLLIN;
                i++;
            }
        }
        int pr = poll(pfds, i, 1000);
        if (pr < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (pfds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            uint8_t buf[BUF_SIZE];
            int n = SSL_read(ssl, buf, sizeof(buf));
            if (n > 0) {
                ssize_t rv = nghttp2_session_mem_recv(ctx.session, buf, (size_t)n);
                if (rv < 0) {
                    fprintf(stderr, "nghttp2 recv error: %s\n", nghttp2_strerror((int)rv));
                    break;
                }
            } else {
                int e = SSL_get_error(ssl, n);
                if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) break;
            }
        }
        pump_origins(&ctx, pfds, 1, i);
        if (send_pending(&ctx) != 0) break;
    }

    if (g_shutdown_requested) graceful_shutdown_control(&ctx, edge_fd);
    SSL_shutdown(ssl);
    nghttp2_session_del(ctx.session);
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
    return 0;
}
